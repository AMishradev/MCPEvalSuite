"""Shadow-MCP inventory: merge endpoint, repo and AWS discovery, compare with the policy allowlist, emit findings."""
from __future__ import annotations

import fnmatch
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models import Confidence, Finding, Lane, ScanResult, Severity

OWASP = {"owasp_mcp": ["MCP09 Shadow MCP Servers"]}


def _sanctioned(item: dict[str, Any], allow: list[dict[str, Any]]) -> str | None:
    """Return the allowlist entry name that matches this inventory item, or None."""
    launch = (item.get("launch") or "").lower()
    name = (item.get("name") or "").lower()
    for entry in allow:
        m = entry.get("match") or {}
        if m.get("package") and m["package"].lower() in launch:
            return entry.get("name")
        if m.get("url_prefix") and launch.startswith(m["url_prefix"].lower()):
            return entry.get("name")
        if m.get("name") and fnmatch.fnmatch(name, m["name"].lower()):
            return entry.get("name")
        if m.get("launch_glob") and fnmatch.fnmatch(launch, m["launch_glob"].lower()):
            return entry.get("name")
    return None


def run_discovery(policy: dict[str, Any], *, endpoint: bool = True, repo: Path | None = None, aws: bool = False) -> ScanResult:
    result = ScanResult(target="discovery")
    allow = (policy.get("allowlist") or {}).get("servers") or []
    inventory: list[dict[str, Any]] = []
    notes: list[str] = []

    if endpoint:
        from .endpoint import discover_endpoint

        ep = discover_endpoint()
        notes += ep.get("errors", [])
        for s in ep["servers"]:
            inventory.append({"source": s["file"], "name": s["name"], "launch": s["launch"], "kind": "endpoint-config", "client": s["client"],
                              "env_keys": s.get("env_keys", []), "literal_secrets": s.get("literal_secrets", []), "unpinned": s.get("unpinned", False),
                              "plaintext_http": s.get("plaintext_http", False)})
        for p in ep.get("processes", []):
            inventory.append({"source": "process", "name": p["name"], "launch": p["cmdline"], "kind": "process", "pid": p["pid"], "bypass_flag": p.get("bypass_flag", False)})
        result.metadata["policy_files_present"] = ep.get("policy_files_present", [])
        for e in ep.get("extensions", []):
            inventory.append({"source": e["file"], "name": e["name"], "launch": e.get("launch", ""), "kind": e["kind"]})

    if repo:
        from .repo import discover_repo

        r = discover_repo(Path(repo))
        for s in r["servers"]:
            inventory.append({"source": f"repo:{s['file']}", "name": s["match"], "launch": s["kind"], "kind": "repo-server"})
        for c in r["configs"]:
            inventory.append({"source": f"repo:{c['file']}", "name": c["name"], "launch": c["launch"], "kind": "repo-config", "env_keys": c.get("env_keys", [])})
        result.metadata["repo_clients"] = r["clients"]

    aws_issues: list[dict[str, Any]] = []
    if aws:
        from .aws import discover_aws

        a = discover_aws()
        notes += a.get("errors", [])
        inventory += a["inventory"]
        aws_issues = a["issues"]
        result.metadata["aws_region"] = a.get("region")

    for item in inventory:
        item["sanctioned"] = _sanctioned(item, allow) is not None
    result.metadata["inventory"] = inventory
    result.metadata["notes"] = notes

    def finding(check_id, title, sev, msg, subject, evidence=None, controls=("SEC-SHADOW",), remediation="", confidence=Confidence.HIGH):
        return Finding(check_id=check_id, control_ids=list(controls), title=title, severity=sev, lane=Lane.DISCOVERY, message=msg, target="discovery",
                       subject=subject, evidence=evidence or {}, mappings=OWASP, remediation=remediation, confidence=confidence)

    for item in inventory:
        subj = f"{item['source']}#{item['name']}"
        if item["kind"] in ("endpoint-config", "repo-config", "process", "agentcore-gateway", "ecs-container", "lambda") and not item["sanctioned"]:
            sev = Severity.MEDIUM if allow else Severity.LOW  # with no allowlist configured, everything is "unknown", not "shadow"
            result.findings.append(finding("SHADOW-001", "MCP server not on the sanctioned allowlist", sev,
                                           f"{item['kind']} `{item['name']}` ({item['launch'][:100]}) found in {item['source']} is not in policy.allowlist.servers.",
                                           subj, {"item": item}, remediation="Add to the allowlist after AppSec review, or remove it."))
        if item.get("literal_secrets"):
            result.findings.append(finding("SHADOW-002", "Long-lived credential in MCP client config", Severity.CRITICAL,
                                           f"{item['source']} server `{item['name']}` env {item['literal_secrets']} holds literal credentials.", subj,
                                           {"env_keys": item["literal_secrets"]}, controls=("SEC-SECRETS", "BP-SHORT-TOKENS"),
                                           remediation="Replace with OAuth (remote server) or short-lived credentials; rotate the exposed value."))
        if item.get("unpinned"):
            result.findings.append(finding("SHADOW-003", "MCP server launched from unpinned package", Severity.MEDIUM,
                                           f"{item['source']} server `{item['name']}` runs `{item['launch'][:100]}` without a pinned version.", subj,
                                           controls=("BP-SIGNED",), remediation="Pin pkg@version, or run a vetted image by digest."))
        if item.get("plaintext_http"):
            result.findings.append(finding("SHADOW-004", "Remote MCP server over plaintext HTTP", Severity.HIGH,
                                           f"{item['source']} server `{item['name']}` uses {item['launch']}.", subj, controls=("BP-SHORT-TOKENS",)))
    if endpoint:
        if not result.metadata.get("policy_files_present"):
            result.findings.append(finding("SHADOW-005", "No enterprise MCP policy files on this machine", Severity.LOW,
                                           "None of the managed-settings / managed-mcp / requirements files of Claude Code, Claude Desktop, Copilot, Codex, Gemini CLI, Kiro or VS Code exist; "
                                           "MCP use on this endpoint is governed only by the user.", "endpoint", controls=("SEC-SHADOW", "BP-SECURE-DEFAULT"),
                                           remediation="Deploy allow/deny lists via MDM (see docs/SHADOW.md section 5).", confidence=Confidence.MEDIUM))
        for item in inventory:
            if item.get("bypass_flag"):
                result.findings.append(finding("SHADOW-006", "Agent running with permission prompts disabled", Severity.HIGH,
                                               f"Process {item.get('pid')} `{item['launch'][:120]}` runs with a confirmation-bypass flag; any MCP tool it has is executed without HITL.",
                                               f"pid:{item.get('pid')}", controls=("BP-SECURE-DEFAULT", "BP-HITL-DML"), remediation="Block these flags with managed settings (Claude Code: permissions.disableBypassPermissionsMode) and alert on them in EDR."))
    for iss in aws_issues:
        ctl = (iss.get("control"),) if iss.get("control") else (("BP-NON-ROOT", "BP-LEAST-PRIV") if "root" in iss["title"].lower() else ("BP-LEAST-PRIV",))
        result.findings.append(finding("SHADOW-AWS", iss["title"], Severity(iss["severity"]), iss["message"], iss["subject"], controls=ctl))
    result.checks_run = ["SHADOW-001", "SHADOW-002", "SHADOW-003", "SHADOW-004", "SHADOW-005", "SHADOW-006", "SHADOW-AWS"]
    result.finished_at = datetime.now(timezone.utc)
    blocking = sorted({f.check_id for f in result.findings if f.severity.rank >= Severity.HIGH.rank})
    result.gate = {"passed": not blocking, "reason": (f"{len(inventory)} servers inventoried; blocking: {', '.join(blocking)}" if blocking else f"{len(inventory)} servers inventoried, nothing blocking")}
    return result
