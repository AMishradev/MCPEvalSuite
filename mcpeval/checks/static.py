"""Static-lane checks over a source tree (`mcpeval static PATH`). No server is started.

  STATIC-001  Dockerfile runs as root / ECS task def or K8s manifest lacks non-root
  STATIC-002  credentials in MCP client config env blocks or source
  STATIC-003  unauthenticated or unsafe SDK defaults (FastMCP / official SDKs)
  STATIC-004  unpinned npx/uvx/pip/npm launch commands in configs
  STATIC-005  Semgrep bundled rules (if semgrep is installed)
  STATIC-006  no structured auth logging middleware detected
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable

import yaml

from ..models import Confidence, Finding, Lane, Severity
from .base import Check, CheckContext, register
from .manifest import SECRET_PATTERNS

RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "semgrep"
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".mcpeval", "out"}


def _files(root: str, *names: str, suffixes: tuple[str, ...] = ()) -> list[Path]:
    out = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for f in fns:
            if f in names or (suffixes and f.endswith(suffixes)):
                out.append(Path(dp) / f)
    return out


def _src_files(root: str) -> list[Path]:
    return _files(root, suffixes=(".py", ".ts", ".js", ".mjs", ".tsx"))


@register
class ContainerRunsAsRoot(Check):
    id = "STATIC-001"
    title = "Container definition runs the MCP server as root"
    controls = ["BP-NON-ROOT"]
    lane = Lane.STATIC
    default_severity = Severity.HIGH
    requires_manifest = False
    references = ["https://github.com/hadolint/hadolint/wiki/DL3002", "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html"]
    mappings = {"cwe": ["CWE-250"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        root = ctx.source_dir or "."
        for df in _files(root, "Dockerfile", suffixes=(".Dockerfile", ".dockerfile")):
            lines = df.read_text(errors="ignore").splitlines()
            users = [(i + 1, l.split(None, 1)[1].strip()) for i, l in enumerate(lines) if l.strip().upper().startswith("USER ")]
            if not users:
                yield self.finding(ctx, f"{df.relative_to(root)} has no USER instruction; the process runs as root.", location={"file": str(df), "line": len(lines)},
                                   subject=str(df.relative_to(root)), remediation="Add a non-root user and `USER <name>` before CMD/ENTRYPOINT.")
            elif users[-1][1].split(":")[0] in ("root", "0"):
                yield self.finding(ctx, f"{df.relative_to(root)} last USER is root.", location={"file": str(df), "line": users[-1][0]}, subject=str(df.relative_to(root)))
        for tf in _files(root, suffixes=(".json",)):
            if "task" not in tf.name.lower() and "ecs" not in tf.name.lower():
                continue
            try:
                d = json.loads(tf.read_text(errors="ignore"))
            except json.JSONDecodeError:
                continue
            for cd in (d.get("containerDefinitions") or []):
                if not cd.get("user") or str(cd.get("user")).split(":")[0] in ("root", "0") or cd.get("privileged"):
                    yield self.finding(ctx, f"ECS container `{cd.get('name')}` in {tf.name}: user={cd.get('user')!r} privileged={cd.get('privileged')}.",
                                       location={"file": str(tf), "line": 1}, subject=cd.get("name", ""), evidence={"user": cd.get("user"), "privileged": cd.get("privileged")})
        for kf in _files(root, suffixes=(".yaml", ".yml")):
            txt = kf.read_text(errors="ignore")
            if "kind:" not in txt or "containers:" not in txt:
                continue
            try:
                docs = [d for d in yaml.safe_load_all(txt) if isinstance(d, dict)]
            except yaml.YAMLError:
                continue
            for d in docs:
                spec = (d.get("spec") or {})
                pod = (spec.get("template") or {}).get("spec") or spec
                sc = pod.get("securityContext") or {}
                for cdef in pod.get("containers") or []:
                    csc = cdef.get("securityContext") or {}
                    if csc.get("runAsNonRoot") is not True and sc.get("runAsNonRoot") is not True and not (csc.get("runAsUser") or sc.get("runAsUser")):
                        yield self.finding(ctx, f"K8s {d.get('kind')} `{(d.get('metadata') or {}).get('name')}` container `{cdef.get('name')}` lacks runAsNonRoot.",
                                           location={"file": str(kf), "line": 1}, subject=cdef.get("name", ""))
                    if csc.get("privileged") or csc.get("allowPrivilegeEscalation") is True:
                        yield self.finding(ctx, f"K8s container `{cdef.get('name')}` is privileged or allows privilege escalation.", location={"file": str(kf), "line": 1},
                                           subject=cdef.get("name", ""))


@register
class SecretsInConfigsAndSource(Check):
    id = "STATIC-002"
    title = "Credential committed in MCP config or source"
    controls = ["SEC-SECRETS", "BP-SHORT-TOKENS"]
    lane = Lane.STATIC
    default_severity = Severity.CRITICAL
    requires_manifest = False
    mappings = {"owasp_mcp": ["MCP01 Token Mismanagement"], "cwe": ["CWE-798"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        root = ctx.source_dir or "."
        cfgs = _files(root, "mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json", "cline_mcp_settings.json", "settings.json", "config.toml", "config.yaml")
        for cf in cfgs:
            txt = cf.read_text(errors="ignore")
            if "mcpServers" in txt or "mcp_servers" in txt or "context_servers" in txt or '"servers"' in txt:
                try:
                    d = json.loads(txt)
                except json.JSONDecodeError:
                    d = {}
                servers = d.get("mcpServers") or d.get("servers") or {}
                for name, s in (servers.items() if isinstance(servers, dict) else []):
                    for k, v in ((s or {}).get("env") or {}).items():
                        if isinstance(v, str) and v and not v.startswith("${") and (re.search(r"(KEY|TOKEN|SECRET|PASSWORD|PASS|CRED)", k, re.I) or any(p.search(v) for p in SECRET_PATTERNS.values())):
                            yield self.finding(ctx, f"{cf.name}: server `{name}` env `{k}` holds a literal credential (long-lived by construction).",
                                               location={"file": str(cf), "line": 1}, subject=f"{cf.name}#{name}", evidence={"env_key": k, "value_prefix": v[:4] + "…"},
                                               remediation="Use short-lived credentials from the runtime (IAM role, OAuth) or a secret reference, never a literal.")
                    for h, v in ((s or {}).get("headers") or {}).items():
                        if isinstance(v, str) and len(v) > 16 and not v.startswith("${"):
                            yield self.finding(ctx, f"{cf.name}: server `{name}` header `{h}` holds a literal token.", location={"file": str(cf), "line": 1}, subject=f"{cf.name}#{name}")
        for sf in _src_files(root)[:5000]:
            try:
                for i, line in enumerate(sf.read_text(errors="ignore").splitlines(), 1):
                    if "example" in line.lower() or "FAKE" in line or "placeholder" in line.lower():
                        continue
                    for kind, pat in SECRET_PATTERNS.items():
                        if kind in ("password_assignment", "bearer_header"):
                            continue
                        if pat.search(line):
                            yield self.finding(ctx, f"{sf.relative_to(root)}:{i} looks like a {kind}.", location={"file": str(sf), "line": i}, subject=str(sf.relative_to(root)),
                                               confidence=Confidence.MEDIUM, evidence={"kind": kind})
                            break
            except OSError:
                continue


_SDK_RULES: list[tuple[str, re.Pattern, Severity, str, list[str]]] = [
    ("fastmcp-http-no-origin-protection", re.compile(r"\.run\(\s*transport\s*=\s*[\"'](http|streamable-http|sse)[\"'](?![^)]*host_origin_protection)"), Severity.MEDIUM,
     "FastMCP HTTP transport without host_origin_protection (defaults to off; spec says invalid Origin MUST get 403).", ["BP-LEAST-PRIV"]),
    ("fastmcp-bind-all-interfaces", re.compile(r"host\s*=\s*[\"']0\.0\.0\.0[\"']"), Severity.MEDIUM, "Server binds 0.0.0.0; spec says local servers SHOULD bind 127.0.0.1.", ["BP-LEAST-PRIV"]),
    ("fastmcp-static-token-verifier", re.compile(r"StaticTokenVerifier\("), Severity.HIGH, "StaticTokenVerifier is a dev-only shared secret (long-lived token).", ["BP-SHORT-TOKENS"]),
    ("fastmcp-oauthproxy-no-consent", re.compile(r"require_authorization_consent\s*=\s*(False|[\"']external[\"'])"), Severity.HIGH,
     "OAuthProxy consent disabled: confused-deputy protection the spec requires for proxies.", ["BP-PKCE"]),
    ("fastmcp-oauthproxy-no-pkce-forward", re.compile(r"forward_pkce\s*=\s*False"), Severity.HIGH, "OAuthProxy forward_pkce=False drops PKCE toward the upstream AS.", ["BP-PKCE"]),
    ("pysdk-auth-without-resource-validation", re.compile(r"AuthSettings\((?![^)]*validate_token_resource\s*=\s*True)[^)]*\)"), Severity.HIGH,
     "Python SDK AuthSettings without validate_token_resource=True: tokens for other audiences are accepted (token passthrough).", ["BP-SHORT-TOKENS", "BP-LEAST-PRIV"]),
    ("tssdk-bearer-without-expected-resource", re.compile(r"requireBearerAuth\((?![^)]*expectedResource)[^)]*\)"), Severity.HIGH,
     "TypeScript SDK requireBearerAuth without expectedResource: audience is not compared.", ["BP-SHORT-TOKENS", "BP-LEAST-PRIV"]),
    ("shell-true-with-tool-arg", re.compile(r"subprocess\.(run|Popen|call|check_output)\([^)]*shell\s*=\s*True"), Severity.HIGH, "subprocess with shell=True inside an MCP server (command injection if any arg is tool input).", ["BP-INPUT-VALIDATION"]),
    ("os-system", re.compile(r"\bos\.system\(|\bos\.popen\(|\bchild_process\.exec\(|\bexecSync\("), Severity.HIGH, "Shell execution primitive in an MCP server.", ["BP-INPUT-VALIDATION"]),
    ("eval-exec", re.compile(r"(?<![\w.])(eval|exec)\(\s*[a-zA-Z_]"), Severity.HIGH, "eval/exec of a variable in an MCP server.", ["BP-INPUT-VALIDATION"]),
    ("sql-fstring", re.compile(r"(execute|query|raw)\(\s*f[\"']|(execute|query)\(\s*[\"'][^\"']*[\"']\s*%|\+\s*[\"']\s*(WHERE|SELECT|INSERT|UPDATE|DELETE)\b", re.I), Severity.HIGH,
     "SQL built by string formatting.", ["BP-INPUT-VALIDATION"]),
    ("long-lived-aws-keys", re.compile(r"AWS_SECRET_ACCESS_KEY|aws_secret_access_key\s*="), Severity.MEDIUM, "Static AWS keys referenced; use an IAM role / STS instead.", ["BP-SHORT-TOKENS"]),
    ("tool-without-annotations", re.compile(r"@(mcp|server|app)\.tool\(\s*\)|@(mcp|server|app)\.tool\s*$"), Severity.LOW, "Tool registered without annotations= (readOnlyHint etc.).", ["BP-CATEGORIZE"]),
]


@register
class UnsafeSdkDefaults(Check):
    id = "STATIC-003"
    title = "Unsafe MCP SDK usage or default"
    controls = ["BP-LEAST-PRIV"]
    lane = Lane.STATIC
    default_severity = Severity.MEDIUM
    requires_manifest = False
    references = ["https://gofastmcp.com/docs/deployment/http", "https://py.sdk.modelcontextprotocol.io/run/authorization"]
    mappings = {"owasp_mcp": ["MCP07 Insufficient Authentication & Authorization"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        root = ctx.source_dir or "."
        for sf in _src_files(root)[:5000]:
            try:
                txt = sf.read_text(errors="ignore")
            except OSError:
                continue
            if not re.search(r"fastmcp|modelcontextprotocol|from mcp|import mcp|McpServer|MCPServer", txt):
                continue
            # unauthenticated HTTP: FastMCP(...) without auth= and run(transport=http)
            if re.search(r"FastMCP\((?![^)]*auth\s*=)[^)]*\)", txt) and re.search(r"transport\s*=\s*[\"'](http|streamable-http|sse)[\"']", txt):
                line = next((i for i, l in enumerate(txt.splitlines(), 1) if "transport" in l and "http" in l), 1)
                yield self.finding(ctx, f"{sf.relative_to(root)}: FastMCP server served over HTTP with no auth= provider.", location={"file": str(sf), "line": line},
                                   subject=str(sf.relative_to(root)), severity=Severity.HIGH, title="HTTP MCP server without authentication", evidence={"rule": "fastmcp-http-no-auth"})
            for rule, pat, sev, msg, controls in _SDK_RULES:
                for m in pat.finditer(txt):
                    line = txt.count("\n", 0, m.start()) + 1
                    f = self.finding(ctx, f"{sf.relative_to(root)}:{line}: {msg}", location={"file": str(sf), "line": line}, subject=str(sf.relative_to(root)),
                                     severity=sev, evidence={"rule": rule, "match": m.group(0)[:120]})
                    f.control_ids = controls
                    yield f


@register
class UnpinnedLaunchers(Check):
    id = "STATIC-004"
    title = "MCP server launched from an unpinned package"
    controls = ["BP-SIGNED", "SEC-SHADOW"]
    lane = Lane.STATIC
    default_severity = Severity.MEDIUM
    requires_manifest = False
    mappings = {"owasp_mcp": ["MCP04 Supply Chain Attacks"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        root = ctx.source_dir or "."
        for cf in _files(root, "mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json", "cline_mcp_settings.json"):
            try:
                d = json.loads(cf.read_text(errors="ignore"))
            except json.JSONDecodeError:
                continue
            servers = d.get("mcpServers") or d.get("servers") or {}
            for name, s in (servers.items() if isinstance(servers, dict) else []):
                cmd = " ".join([str((s or {}).get("command", "")), *map(str, (s or {}).get("args") or [])])
                if re.search(r"\b(npx|uvx|pipx run|bunx|dlx)\b", cmd):
                    pkgs = re.findall(r"(?:npx|uvx|bunx|dlx)\s+(?:-y\s+|--yes\s+)?(@?[\w./-]+)", cmd)
                    unpinned = [p for p in pkgs if "@" not in p.lstrip("@") and "==" not in p]
                    if unpinned:
                        yield self.finding(ctx, f"{cf.name}: server `{name}` runs `{cmd[:80]}`; package {unpinned} resolves to whatever is latest at launch time.",
                                           location={"file": str(cf), "line": 1}, subject=f"{cf.name}#{name}",
                                           remediation="Pin an exact version (pkg@1.2.3 / pkg==1.2.3), verify its attestation, or run from a vetted container image by digest.")
                if re.search(r"\bdocker\b.*\brun\b", cmd) and "@sha256:" not in cmd:
                    yield self.finding(ctx, f"{cf.name}: server `{name}` runs a container image without a digest.", location={"file": str(cf), "line": 1}, subject=f"{cf.name}#{name}", severity=Severity.LOW)


@register
class SemgrepRules(Check):
    id = "STATIC-005"
    title = "Semgrep finding (bundled MCP rules)"
    controls = ["BP-INPUT-VALIDATION"]
    lane = Lane.STATIC
    default_severity = Severity.MEDIUM
    requires_manifest = False

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        candidates = [Path(sys.executable).parent / "semgrep", Path.home() / ".local/bin/semgrep", Path("/opt/homebrew/bin/semgrep"), Path("/usr/local/bin/semgrep")]
        semgrep = shutil.which("semgrep") or next((str(c) for c in candidates if c.exists()), None)
        if not ctx.options.get("semgrep", True) or not semgrep or not RULES_DIR.exists():
            if ctx.options.get("semgrep", True) and not semgrep:
                yield self.finding(ctx, "semgrep is not installed; bundled MCP rules were skipped (install it isolated: `uv tool install semgrep` or `pipx install semgrep`; it pins mcp 1.x and must not share the scanner's venv).", severity=Severity.INFO, title="Semgrep not available")
            return
        root = ctx.source_dir or "."
        try:
            proc = subprocess.run([semgrep, "scan", "--config", str(RULES_DIR), "--json", "--quiet", "--metrics=off", root], capture_output=True, text=True, timeout=600)
            data = json.loads(proc.stdout or "{}")
        except (subprocess.SubprocessError, json.JSONDecodeError) as e:
            yield self.finding(ctx, f"semgrep failed: {e}", severity=Severity.INFO)
            return
        sevmap = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
        for r in data.get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {})
            f = self.finding(ctx, f"{r.get('path')}:{r.get('start', {}).get('line')}: {extra.get('message', '')[:300]}",
                             location={"file": r.get("path"), "line": r.get("start", {}).get("line", 1)}, subject=str(r.get("check_id", "")).split(".")[-1],
                             severity=sevmap.get(extra.get("severity", "WARNING"), Severity.MEDIUM), evidence={"rule": r.get("check_id"), "lines": extra.get("lines", "")[:200]})
            if meta.get("controls"):
                f.control_ids = list(meta["controls"])
            yield f


@register
class NoAuthLogging(Check):
    id = "STATIC-006"
    title = "No authN/authZ or tool-call audit logging detected"
    controls = ["BP-AUTH-LOGGING"]
    lane = Lane.STATIC
    default_severity = Severity.MEDIUM
    requires_manifest = False
    mappings = {"owasp_mcp": ["MCP08 Lack of Audit and Telemetry"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        root = ctx.source_dir or "."
        srcs = [f for f in _src_files(root)[:5000]]
        server_files = []
        for sf in srcs:
            try:
                txt = sf.read_text(errors="ignore")
            except OSError:
                continue
            if re.search(r"FastMCP\(|MCPServer\(|McpServer\(|new Server\(", txt):
                server_files.append((sf, txt))
        if not server_files:
            return
        has_logging = any(re.search(r"LoggingMiddleware|StructuredLoggingMiddleware|on_call_tool|AuditMiddleware|audit|logging\.getLogger|winston|pino|console\.(log|info)\(.*tool", txt, re.I) for _, txt in server_files)
        if not has_logging:
            yield self.finding(ctx, f"{len(server_files)} MCP server file(s) found but no logging/audit middleware or logger usage; authN/authZ decisions and tool calls are not recorded.",
                               subject=str(server_files[0][0].relative_to(root)), location={"file": str(server_files[0][0]), "line": 1}, confidence=Confidence.MEDIUM,
                               remediation="Add middleware that logs principal, tool name, decision and request id for every call (FastMCP StructuredLoggingMiddleware or equivalent) and ship to CloudWatch.")
