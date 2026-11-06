"""Supply-chain lane (`mcpeval static`): provenance of the packages and images a server is launched from.

Sources, all verified against the live registries on 2026-11-06:
  npm   GET https://registry.npmjs.org/<pkg>/<version>  -> dist.integrity, dist.attestations.provenance (SLSA v1 when trusted-published)
  PyPI  GET https://pypi.org/pypi/<pkg>/<version>/json  -> urls[].digests, urls[].provenance (PEP 740 integrity API URL; 404 = none)
        GET https://pypi.org/integrity/<pkg>/<ver>/<file>/provenance -> attestation_bundles[].publisher{kind,repository,workflow}
  OSV   POST https://api.osv.dev/v1/query {"package":{"name","ecosystem"},"version"} -> vulns[] (MAL-* entries = known malicious)
  cosign / gh / notation, when installed, for image signatures (keyless identity must come from policy.supply_chain).

Checks:
  SUPPLY-001  launch package has no provenance attestation (or publisher repo does not match the allowlist)
  SUPPLY-002  launch package / version has an OSV advisory (MAL-* -> critical)
  SUPPLY-003  container image referenced without a digest, or cosign verification failed
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

import httpx

from ..models import Confidence, Finding, Lane, Severity
from .base import Check, CheckContext, register
from .static import _files

NPX = re.compile(r"\b(?:npx|bunx|pnpm dlx)\s+(?:-y\s+|--yes\s+)?(?P<pkg>@?[\w.-]+(?:/[\w.-]+)?)(?:@(?P<ver>[\w.+-]+))?")
UVX = re.compile(r"\buvx\s+(?:--from\s+['\"]?(?P<from>[\w.-]+)==(?P<fver>[\w.+-]+)['\"]?\s+)?(?P<pkg>[\w.-]+)(?:@(?P<ver>[\w.+-]+))?")
DOCKER = re.compile(r"\bdocker\s+run\b.*?\s(?P<image>[\w./-]+(?::[\w.-]+)?(?:@sha256:[0-9a-f]{64})?)(?:\s|$)")
# Known malicious MCP packages / backdoored versions (OSV MAL-* / GHSA, verified 2026-11-06). Keep short; OSV is the live source.
DENYLIST = {
    ("npm", "postmark-mcp"): "MAL-2025-47604 backdoor exfiltrates email via BCC (v1.0.16+)",
    ("npm", "mcp-menu"): "MAL-2025-26053 typosquat/malware",
    ("npm", "mcp-server-everything"): "MAL-2025-46986 malware (not the official @modelcontextprotocol package)",
    ("npm", "vscode-azure-mcp-server"): "MAL-2025-192601 malware",
    ("npm", "mcp-server-fixthis"): "MAL-2025-47929 malware",
    ("npm", "solana-dev-mcp"): "MAL-2025-191527 malware",
}


def _launches_from_configs(root: str) -> list[dict[str, Any]]:
    out = []
    for cf in _files(root, "mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json", "cline_mcp_settings.json", "mcp-config.json"):
        try:
            d = json.loads(cf.read_text(errors="ignore"))
        except json.JSONDecodeError:
            continue
        servers = d.get("mcpServers") or d.get("servers") or {}
        for name, s in (servers.items() if isinstance(servers, dict) else []):
            cmd = " ".join([str((s or {}).get("command", "")), *map(str, (s or {}).get("args") or [])])
            if m := NPX.search(cmd):
                out.append({"file": str(cf), "server": name, "eco": "npm", "pkg": m.group("pkg"), "version": m.group("ver"), "cmd": cmd})
            elif m := UVX.search(cmd):
                pkg = m.group("from") or m.group("pkg")
                out.append({"file": str(cf), "server": name, "eco": "pypi", "pkg": pkg, "version": m.group("fver") or m.group("ver"), "cmd": cmd})
            elif m := DOCKER.search(cmd):
                out.append({"file": str(cf), "server": name, "eco": "oci", "pkg": m.group("image"), "version": None, "cmd": cmd})
    return out


def _npm(pkg: str, version: str | None, client: httpx.Client) -> dict[str, Any]:
    r = client.get(f"https://registry.npmjs.org/{quote(pkg, safe='@')}/{version or 'latest'}")
    if r.status_code != 200:
        return {"error": f"npm registry {r.status_code}"}
    d = r.json()
    dist = d.get("dist") or {}
    att = (dist.get("attestations") or {}).get("provenance") or {}
    info = {"resolved_version": d.get("version"), "integrity": dist.get("integrity"), "has_provenance": bool(att),
            "predicate": att.get("predicateType"), "has_registry_signature": bool(dist.get("signatures"))}
    if att.get("predicateType") == "https://slsa.dev/provenance/v1":
        ra = client.get(f"https://registry.npmjs.org/-/npm/v1/attestations/{quote(pkg, safe='@')}@{d.get('version')}")
        if ra.status_code == 200:
            try:
                import base64
                for a in ra.json().get("attestations", []):
                    if a.get("predicateType") == "https://slsa.dev/provenance/v1":
                        payload = json.loads(base64.b64decode(a["bundle"]["dsseEnvelope"]["payload"]))
                        ext = (payload.get("predicate") or {}).get("buildDefinition", {}).get("externalParameters", {})
                        info["source_repo"] = (ext.get("workflow") or {}).get("repository") or payload.get("predicate", {}).get("invocation", {}).get("configSource", {}).get("uri")
            except Exception:  # noqa: BLE001
                pass
    return info


def _pypi(pkg: str, version: str | None, client: httpx.Client) -> dict[str, Any]:
    url = f"https://pypi.org/pypi/{pkg}/{version}/json" if version else f"https://pypi.org/pypi/{pkg}/json"
    r = client.get(url)
    if r.status_code != 200:
        return {"error": f"pypi {r.status_code}"}
    d = r.json()
    ver = d["info"]["version"]
    files = d.get("urls") or []
    wheel = next((f for f in files if f.get("packagetype") == "bdist_wheel"), files[0] if files else None)
    info: dict[str, Any] = {"resolved_version": ver, "has_provenance": False}
    if wheel:
        info["sha256"] = (wheel.get("digests") or {}).get("sha256")
        prov_url = wheel.get("provenance") or f"https://pypi.org/integrity/{pkg}/{ver}/{wheel['filename']}/provenance"
        rp = client.get(prov_url, headers={"Accept": "application/vnd.pypi.integrity.v1+json"})
        if rp.status_code == 200:
            info["has_provenance"] = True
            pubs = [b.get("publisher") for b in rp.json().get("attestation_bundles", [])]
            info["publishers"] = pubs
            info["source_repo"] = next((p.get("repository") for p in pubs if p), None)
    return info


def _osv(eco: str, pkg: str, version: str | None, client: httpx.Client) -> list[dict[str, Any]]:
    body: dict[str, Any] = {"package": {"name": pkg, "ecosystem": {"npm": "npm", "pypi": "PyPI"}[eco]}}
    if version:
        body["version"] = version
    r = client.post("https://api.osv.dev/v1/query", json=body)
    if r.status_code != 200:
        return []
    return [{"id": v.get("id"), "summary": (v.get("summary") or "")[:160], "aliases": v.get("aliases", [])[:3]} for v in r.json().get("vulns", [])]


@register
class PackageProvenance(Check):
    id = "SUPPLY-001"
    title = "MCP server package has no verifiable provenance"
    controls = ["BP-SIGNED"]
    lane = Lane.SUPPLY_CHAIN
    default_severity = Severity.MEDIUM
    requires_manifest = False
    references = ["https://docs.npmjs.com/generating-provenance-statements", "https://docs.pypi.org/api/integrity/",
                  "https://modelcontextprotocol.io/docs/tutorials/security/local-server-security"]
    mappings = {"owasp_mcp": ["MCP04 Supply Chain Attacks"], "owasp_agentic": ["ASI04 Agentic Supply Chain"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        if ctx.options.get("offline"):
            return
        allowed = {r.lower() for r in (ctx.policy.get("supply_chain", {}).get("allowed_source_repos") or [])}
        with httpx.Client(timeout=15, follow_redirects=True, headers={"User-Agent": "mcpeval/0.1"}) as c:
            for l in _launches_from_configs(ctx.source_dir or "."):
                if l["eco"] not in ("npm", "pypi"):
                    continue
                try:
                    info = _npm(l["pkg"], l["version"], c) if l["eco"] == "npm" else _pypi(l["pkg"], l["version"], c)
                except httpx.HTTPError as e:
                    yield self.finding(ctx, f"{l['pkg']}: registry lookup failed ({type(e).__name__}).", severity=Severity.INFO, subject=l["pkg"])
                    continue
                subj = f"{Path(l['file']).name}#{l['server']}"
                if info.get("error"):
                    yield self.finding(ctx, f"{l['eco']} package `{l['pkg']}`{'@' + l['version'] if l['version'] else ''} not found ({info['error']}); check for typosquat or private registry.",
                                       subject=subj, severity=Severity.HIGH, location={"file": l["file"], "line": 1}, evidence=l)
                    continue
                ev = {**l, **info}
                if not info.get("has_provenance"):
                    yield self.finding(ctx, f"`{l['pkg']}@{info.get('resolved_version')}` ({l['eco']}) is published without a provenance attestation; nothing ties the artifact to a source repo or build.",
                                       subject=subj, location={"file": l["file"], "line": 1}, evidence=ev,
                                       remediation="Prefer packages published with npm provenance / PyPI trusted publishing, or vendor the exact artifact (integrity hash) after review.")
                elif allowed and (info.get("source_repo") or "").lower().removeprefix("https://github.com/") not in allowed:
                    yield self.finding(ctx, f"`{l['pkg']}@{info.get('resolved_version')}` provenance comes from `{info.get('source_repo')}`, not in policy.supply_chain.allowed_source_repos.",
                                       subject=subj, severity=Severity.HIGH, location={"file": l["file"], "line": 1}, evidence=ev)
                else:
                    yield self.finding(ctx, f"`{l['pkg']}@{info.get('resolved_version')}` has provenance from `{info.get('source_repo')}`.", subject=subj, severity=Severity.INFO,
                                       title="Package provenance verified", evidence=ev)
                if not l["version"]:
                    yield self.finding(ctx, f"`{l['pkg']}` is launched unpinned; today it resolves to {info.get('resolved_version')} (integrity {str(info.get('integrity') or info.get('sha256'))[:24]}…). "
                                            f"Pin this version in the config.", subject=subj, severity=Severity.MEDIUM, title="Unpinned launch resolved", location={"file": l["file"], "line": 1}, evidence=ev)


@register
class KnownVulnerablePackage(Check):
    id = "SUPPLY-002"
    title = "MCP server package has a known advisory"
    controls = ["BP-SIGNED", "BP-LEAST-PRIV"]
    lane = Lane.SUPPLY_CHAIN
    default_severity = Severity.HIGH
    requires_manifest = False
    references = ["https://osv.dev"]
    mappings = {"owasp_mcp": ["MCP04 Supply Chain Attacks"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        launches = _launches_from_configs(ctx.source_dir or ".")
        for l in launches:
            key = (l["eco"], l["pkg"])
            if key in DENYLIST:
                yield self.finding(ctx, f"`{l['pkg']}` is on the known-malicious list: {DENYLIST[key]}.", subject=f"{Path(l['file']).name}#{l['server']}",
                                   severity=Severity.CRITICAL, title="Known malicious MCP package", location={"file": l["file"], "line": 1}, evidence=l)
        if ctx.options.get("offline"):
            return
        with httpx.Client(timeout=15, headers={"User-Agent": "mcpeval/0.1"}) as c:
            for l in launches:
                if l["eco"] not in ("npm", "pypi"):
                    continue
                try:
                    vulns = _osv(l["eco"], l["pkg"], l["version"], c)
                except httpx.HTTPError:
                    continue
                if vulns:
                    mal = [v for v in vulns if str(v["id"]).startswith("MAL-")]
                    sev = Severity.CRITICAL if mal else Severity.HIGH
                    yield self.finding(ctx, f"`{l['pkg']}{'@' + l['version'] if l['version'] else ' (all versions)'}` has {len(vulns)} OSV entr{'y' if len(vulns) == 1 else 'ies'}: "
                                            f"{', '.join(v['id'] for v in vulns[:5])}.", subject=f"{Path(l['file']).name}#{l['server']}", severity=sev,
                                       location={"file": l["file"], "line": 1}, evidence={"vulns": vulns[:10], **l}, confidence=Confidence.HIGH if l["version"] else Confidence.MEDIUM,
                                       remediation="Upgrade to a fixed version and pin it; for MAL-* entries remove the package and rotate any credentials it could reach.")


@register
class ImageSignature(Check):
    id = "SUPPLY-003"
    title = "Container image not pinned by digest or signature not verifiable"
    controls = ["BP-SIGNED"]
    lane = Lane.SUPPLY_CHAIN
    default_severity = Severity.MEDIUM
    requires_manifest = False
    references = ["https://github.com/sigstore/cosign/blob/main/doc/cosign_verify.md", "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-signing.html"]
    mappings = {"owasp_mcp": ["MCP04 Supply Chain Attacks"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        sc = ctx.policy.get("supply_chain", {})
        images = [l for l in _launches_from_configs(ctx.source_dir or ".") if l["eco"] == "oci"]
        for tf in _files(ctx.source_dir or ".", suffixes=(".json",)):
            if "task" in tf.name.lower() or "ecs" in tf.name.lower():
                try:
                    for cd in (json.loads(tf.read_text(errors="ignore")).get("containerDefinitions") or []):
                        images.append({"file": str(tf), "server": cd.get("name"), "eco": "oci", "pkg": cd.get("image", ""), "version": None, "cmd": ""})
                except (json.JSONDecodeError, AttributeError):
                    pass
        for l in images:
            img = l["pkg"]
            subj = f"{Path(l['file']).name}#{l['server']}"
            if "@sha256:" not in img:
                yield self.finding(ctx, f"Image `{img}` is referenced by tag; a tag can be re-pointed after review. Pin by digest.", subject=subj, location={"file": l["file"], "line": 1}, evidence=l)
                continue
            if not shutil.which("cosign"):
                yield self.finding(ctx, f"Image `{img[:60]}…` is digest-pinned; cosign is not installed so the signature was not verified.", subject=subj, severity=Severity.INFO, evidence=l)
                continue
            args = ["cosign", "verify", img, "-o", "json"]
            if img.startswith("mcp/"):  # Docker MCP Catalog: static key published by Docker
                args += ["--key", sc.get("docker_mcp_key", "https://raw.githubusercontent.com/docker/keyring/refs/heads/main/public/mcp/latest.pub")]
            elif sc.get("cosign_identity_regexp"):
                args += ["--certificate-identity-regexp", sc["cosign_identity_regexp"], "--certificate-oidc-issuer", sc.get("cosign_oidc_issuer", "https://token.actions.githubusercontent.com")]
            else:
                yield self.finding(ctx, f"Image `{img[:60]}…`: policy.supply_chain.cosign_identity_regexp not set; cannot verify keyless signature.", subject=subj, severity=Severity.LOW, evidence=l)
                continue
            env = {"COSIGN_REPOSITORY": "mcp/signatures"} if img.startswith("mcp/") else {}
            try:
                proc = subprocess.run(args, capture_output=True, text=True, timeout=120, env={**__import__("os").environ, **env})
            except (subprocess.SubprocessError, OSError) as e:
                yield self.finding(ctx, f"cosign failed to run: {e}", severity=Severity.INFO, subject=subj)
                continue
            ok = proc.returncode == 0 and proc.stdout.strip() not in ("", "[]")
            if not ok:
                yield self.finding(ctx, f"cosign could not verify `{img[:70]}…`: {(proc.stderr or proc.stdout).strip()[:200]}", subject=subj, severity=Severity.HIGH,
                                   title="Container image signature verification failed", evidence={**l, "stderr": proc.stderr[:500]})
            else:
                yield self.finding(ctx, f"`{img[:70]}…` signature verified.", subject=subj, severity=Severity.INFO, title="Container image signature verified", evidence=l)
