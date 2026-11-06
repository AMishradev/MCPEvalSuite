"""Endpoint discovery: MCP client configs and running MCP processes on this machine.

Covers the config locations of the common clients on macOS / Linux / Windows. Each entry is
normalized to {client, file, name, launch, env_keys, literal_secrets, unpinned, plaintext_http}.
Run it under an MDM/SSM job and ship the JSON to your inventory; compare with policy.allowlist.
"""
from __future__ import annotations

import glob
import json
import os
import platform
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any

import yaml

HOME = Path.home()
_OS = platform.system()  # Darwin | Linux | Windows


def _p(*parts: str) -> str:
    return str(Path(*parts).expanduser())


def _appdata(sub: str) -> list[str]:
    if _OS == "Darwin":
        return [_p("~/Library/Application Support", sub)]
    if _OS == "Windows":
        return [str(Path(os.environ.get("APPDATA", HOME / "AppData/Roaming")) / sub)]
    return [_p("~/.config", sub)]


# (client, glob pattern, format)
# formats: mcpServers | servers | claude-json | codex-toml | goose-yaml | zed-json | continue | docker-mcp | vscode-settings | q-agents
CONFIG_LOCATIONS: list[tuple[str, str, str]] = [
    *[("claude-desktop", f"{d}/claude_desktop_config.json", "mcpServers") for d in _appdata("Claude")],
    ("claude-code", _p("~/.claude.json"), "claude-json"),
    ("claude-code", _p("~/.claude/settings.json"), "mcpServers"),
    ("claude-code-managed", "/Library/Application Support/ClaudeCode/managed-settings.json", "mcpServers"),
    ("claude-code-managed", "/Library/Application Support/ClaudeCode/managed-mcp.json", "mcpServers"),
    ("claude-code-managed", "/etc/claude-code/managed-settings.json", "mcpServers"),
    ("claude-code-managed", "/etc/claude-code/managed-mcp.json", "mcpServers"),
    ("claude-code-plugins", _p("~/.claude/plugins/**/.mcp.json"), "mcpServers"),
    ("cursor", _p("~/.cursor/mcp.json"), "mcpServers"),
    ("windsurf", _p("~/.codeium/windsurf/mcp_config.json"), "mcpServers"),
    ("devin-desktop", _p("~/.config/devin/mcp_config.json"), "mcpServers"),
    *[("devin-desktop", f"{d}/devin/mcp_config.json", "mcpServers") for d in _appdata("") if _OS == "Windows"],
    *[("vscode", f"{d}/User/mcp.json", "servers") for d in _appdata("Code")],
    *[("vscode-insiders", f"{d}/User/mcp.json", "servers") for d in _appdata("Code - Insiders")],
    *[("vscode", f"{d}/User/profiles/*/mcp.json", "servers") for d in _appdata("Code")],
    *[("vscode", f"{d}/User/settings.json", "vscode-settings") for d in _appdata("Code")],
    *[("cursor-cline", f"{d}/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", "mcpServers") for d in _appdata("Cursor")],
    *[("cline", f"{d}/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", "mcpServers") for d in _appdata("Code")],
    *[("roo-code", f"{d}/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json", "mcpServers") for d in _appdata("Code")],
    ("cline-cli", _p("~/.cline/data/settings/cline_mcp_settings.json"), "mcpServers"),
    ("continue", _p("~/.continue/config.yaml"), "continue"),
    ("continue", _p("~/.continue/config.json"), "continue"),
    ("zed", _p("~/.config/zed/settings.json"), "zed-json"),
    ("goose", _p("~/.config/goose/config.yaml"), "goose-yaml"),
    ("amazon-q-cli", _p("~/.aws/amazonq/mcp.json"), "mcpServers"),
    ("amazon-q-cli", _p("~/.aws/amazonq/cli-agents/*.json"), "q-agents"),
    ("kiro", _p("~/.kiro/settings/mcp.json"), "mcpServers"),
    ("kiro", _p("~/.kiro/agents/*.json"), "q-agents"),
    ("kiro-managed", "/Library/Application Support/Kiro/managed-settings.json", "mcpServers"),
    ("kiro-managed", "/etc/kiro/managed-settings.json", "mcpServers"),
    ("amazon-q-cli", _p("~/.aws/amazonq/default.json"), "q-agents"),
    ("amazon-q-cli", _p("~/.aws/amazonq/agents/*.json"), "q-agents"),
    ("codex-cli", _p("~/.codex/config.toml"), "codex-toml"),
    ("codex-managed", "/etc/codex/managed_config.toml", "codex-toml"),
    ("codex-managed", _p("~/.codex/managed_config.toml"), "codex-toml"),
    ("gemini-cli", _p("~/.gemini/settings.json"), "mcpServers"),
    ("gemini-cli-system", "/etc/gemini-cli/settings.json", "mcpServers"),
    ("gemini-cli-system", "/Library/Application Support/GeminiCli/settings.json", "mcpServers"),
    ("antigravity", _p("~/.gemini/config/mcp_config.json"), "mcpServers"),
    ("antigravity", _p("~/.gemini/antigravity/mcp_config.json"), "mcpServers"),
    ("copilot-cli", _p("~/.copilot/mcp-config.json"), "mcpServers"),
    ("lm-studio", _p("~/.lmstudio/mcp.json"), "mcpServers"),
    ("lm-studio", _p("~/.cache/lm-studio/mcp.json"), "mcpServers"),
    ("docker-mcp-toolkit", _p("~/.docker/mcp/registry.yaml"), "docker-mcp"),
    ("junie", _p("~/.junie/mcp/mcp.json"), "mcpServers"),
    ("warp", _p("~/.warp/.mcp.json"), "mcpServers"),
    ("tabnine", _p("~/.tabnine/mcp_servers.json"), "mcpServers"),
    ("amp", _p("~/.config/amp/settings.json"), "amp-json"),
    ("opencode", _p("~/.config/opencode/opencode.json"), "opencode-json"),
    ("opencode", _p("~/.config/opencode/opencode.jsonc"), "opencode-json"),
    ("crush", _p("~/.config/crush/crushrc"), "opencode-json"),
    *[("5ire", f"{d}/mcp.json", "mcpServers") for d in _appdata("5ire")],
    ("cherry-studio", _p("~/.cherrystudio/config/mcp-registry.json"), "mcpServers"),
]
# Enterprise policy files. Presence means the client is centrally governed; absence on a corporate machine is itself a finding.
POLICY_FILES = [
    ("claude-code", "/Library/Application Support/ClaudeCode/managed-settings.json"), ("claude-code", "/Library/Application Support/ClaudeCode/managed-mcp.json"),
    ("claude-code", "/etc/claude-code/managed-settings.json"), ("claude-code", "/etc/claude-code/managed-mcp.json"),
    ("claude-code", r"C:\Program Files\ClaudeCode\managed-settings.json"), ("claude-code", r"C:\Program Files\ClaudeCode\managed-mcp.json"),
    ("claude-desktop", "/Library/Managed Preferences/com.anthropic.claudefordesktop.plist"), ("claude-desktop", "/etc/claude-desktop/managed-settings.json"),
    ("claude-code", "/Library/Managed Preferences/com.anthropic.claudecode.plist"),
    ("github-copilot", "/Library/Application Support/GitHubCopilot/managed-settings.json"), ("github-copilot", "/etc/github-copilot/managed-settings.json"),
    ("github-copilot", r"C:\Program Files\GitHubCopilot\managed-settings.json"),
    ("codex", "/etc/codex/requirements.toml"), ("codex", r"C:\ProgramData\OpenAI\Codex\requirements.toml"),
    ("gemini-cli", "/etc/gemini-cli/settings.json"), ("gemini-cli", "/Library/Application Support/GeminiCli/settings.json"), ("gemini-cli", r"C:\ProgramData\gemini-cli\settings.json"),
    ("kiro", "/Library/Application Support/Kiro/managed-settings.json"), ("kiro", "/etc/kiro/managed-settings.json"), ("kiro", r"C:\ProgramData\Kiro\managed-settings.json"),
    ("vscode", "/etc/vscode/policy.json"),
]
# Agent CLI flags that disable confirmation; alongside MCP use they remove the only HITL layer a local server has.
BYPASS_FLAGS = re.compile(r"--dangerously-skip-permissions|--permission-mode\s+bypassPermissions|--dangerously-bypass-approvals-and-sandbox|--full-auto|--yolo|danger-full-access|--trust-all-tools|--trust-tools", re.I)
# project-level files found by walking common code roots (shallow)
PROJECT_FILES = [".mcp.json", ".github/mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".kiro/settings/mcp.json", ".amazonq/mcp.json", ".windsurf/mcp.json",
                 ".devin/mcp_config.json", ".devin/mcp_config.local.json", ".gemini/settings.json", ".roo/mcp.json", ".codex/config.toml", ".junie/mcp/mcp.json",
                 ".warp/.mcp.json", ".tabnine/mcp_servers.json", ".agents/mcp_config.json", ".amp/settings.json", "opencode.json", ".zed/settings.json",
                 ".claude/settings.json", ".claude/settings.local.json"]
CODE_ROOTS = ["~/Downloads", "~/Documents", "~/Projects", "~/projects", "~/src", "~/code", "~/dev", "~/work", "~/repos", "~/git", "~/Desktop"]

SECRET_KEY = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS$|CRED|AUTH)", re.I)
SECRET_VALUE = re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}|sk-ant-|sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_|xox[baprs]-|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.eyJ")
PROCESS_HINT = re.compile(r"mcp-remote|modelcontextprotocol|fastmcp|mcp[-_]server|mcp\.json|server-(filesystem|github|slack|postgres|puppeteer|fetch|memory)|uvx .*mcp|npx .*mcp|mcp-proxy|supergateway|\bmcpo\b|@smithery/cli|@playwright/mcp|claude mcp serve|docker mcp gateway", re.I)


def _norm(client: str, file: str, name: str, s: dict[str, Any]) -> dict[str, Any]:
    s = s or {}
    url = s.get("url") or s.get("serverUrl") or s.get("httpUrl") or s.get("uri")
    if url:
        launch = str(url)
    else:
        launch = " ".join([str(s.get("command", "")), *map(str, s.get("args") or [])]).strip()
    env = s.get("env") or s.get("environment") or {}
    literal = [k for k, v in env.items() if isinstance(v, str) and v and not v.startswith("${") and (SECRET_KEY.search(k) or SECRET_VALUE.search(v))]
    for h, v in (s.get("headers") or {}).items():
        if isinstance(v, str) and len(v) > 16 and not v.startswith("${"):
            literal.append(f"header:{h}")
    unpinned = bool(re.search(r"\b(npx|uvx|bunx|pipx run)\b", launch)) and not re.search(r"@\d|==\d|@latest", launch) and not re.search(r"(npx|uvx|bunx)\s+(-y\s+|--yes\s+)?[\w@./-]+@[\w.]+", launch)
    return {"client": client, "file": file, "name": name, "launch": launch, "env_keys": sorted(env.keys()), "literal_secrets": literal,
            "unpinned": unpinned, "plaintext_http": launch.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])", launch),
            "disabled": bool(s.get("disabled")), "allowed_tools": s.get("alwaysAllow") or s.get("autoApprove") or s.get("allowedTools")}


def _parse(client: str, file: str, fmt: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    p = Path(file)
    txt = p.read_text(errors="ignore")
    if fmt in ("mcpServers", "servers", "claude-json", "vscode-settings", "zed-json", "q-agents", "continue", "amp-json", "opencode-json") and p.suffix in (".json", ".jsonc", "") :
        try:
            d = json.loads(re.sub(r"^\s*//.*$", "", txt, flags=re.M))  # tolerate // comments in jsonc / crushrc
        except json.JSONDecodeError:
            return out
        if fmt == "amp-json":
            for n, sv in (d.get("amp.mcpServers") or {}).items():
                out.append(_norm(client, file, n, sv))
        elif fmt == "opencode-json":
            servers = ((d.get("mcp") or {}).get("servers") if isinstance((d.get("mcp") or {}).get("servers"), dict) else d.get("mcp")) or {}
            for n, sv in servers.items():
                if isinstance(sv, dict):
                    out.append(_norm(client, file, n, {"command": (sv.get("command") or [None])[0] if isinstance(sv.get("command"), list) else sv.get("command"),
                                                      "args": sv.get("command", [])[1:] if isinstance(sv.get("command"), list) else sv.get("args"),
                                                      "url": sv.get("url"), "env": sv.get("environment") or sv.get("env"), "headers": sv.get("headers")}))
        elif fmt == "claude-json":
            for n, s in (d.get("mcpServers") or {}).items():
                out.append(_norm(client, file, n, s))
            for proj, pv in (d.get("projects") or {}).items():
                for n, s in (pv.get("mcpServers") or {}).items():
                    out.append(_norm(client, f"{file}#projects[{proj}]", n, s))
        elif fmt == "vscode-settings":
            for n, s in ((d.get("mcp") or {}).get("servers") or {}).items():
                out.append(_norm(client, file, n, s))
        elif fmt == "zed-json":
            for n, s in (d.get("context_servers") or {}).items():
                out.append(_norm(client, file, n, (s.get("command") if isinstance(s.get("command"), dict) else s) or {}))
        elif fmt == "q-agents":
            for n, s in (d.get("mcpServers") or {}).items():
                out.append(_norm(client, file, n, s))
        else:
            for n, s in (d.get("mcpServers") or d.get("servers") or {}).items():
                out.append(_norm(client, file, n, s))
    elif fmt == "codex-toml":
        try:
            d = tomllib.loads(txt)
        except tomllib.TOMLDecodeError:
            return out
        for n, s in (d.get("mcp_servers") or {}).items():
            out.append(_norm(client, file, n, s))
    elif fmt in ("goose-yaml", "continue", "docker-mcp"):
        try:
            d = yaml.safe_load(txt) or {}
        except yaml.YAMLError:
            return out
        if fmt == "goose-yaml":
            for n, s in (d.get("extensions") or {}).items():
                if isinstance(s, dict) and s.get("type") in ("stdio", "streamable_http", "sse", "remote"):
                    out.append(_norm(client, file, n, {"command": s.get("cmd"), "args": s.get("args"), "url": s.get("uri"), "env": s.get("envs")}))
        elif fmt == "continue":
            for s in (d.get("mcpServers") or []):
                out.append(_norm(client, file, s.get("name", "?"), s))
        else:  # docker mcp toolkit registry
            for n, s in (d.get("registry") or {}).items():
                out.append(_norm(client, file, n, {"command": "docker", "args": ["mcp", n]}))
    return out


def discover_endpoint(*, scan_projects: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {"servers": [], "processes": [], "extensions": [], "errors": [], "host": platform.node(), "os": _OS,
                           "policy_files_present": [f"{c}:{f}" for c, f in POLICY_FILES if os.path.isfile(f)]}
    seen: set[str] = set()
    for client, pattern, fmt in CONFIG_LOCATIONS:
        for file in glob.glob(pattern, recursive=True):
            if file in seen or not os.path.isfile(file):
                continue
            seen.add(file)
            try:
                out["servers"] += _parse(client, file, fmt)
            except Exception as e:  # noqa: BLE001
                out["errors"].append(f"{file}: {type(e).__name__}: {e}")
    if scan_projects:
        for root in CODE_ROOTS:
            r = Path(root).expanduser()
            if not r.is_dir():
                continue
            try:
                children = list(r.iterdir())[:400]
            except (PermissionError, OSError) as e:  # macOS TCC-protected folders (Documents, Desktop) without Full Disk Access
                out["errors"].append(f"{r}: {e.strerror or e}")
                continue
            for d in children:
                if not d.is_dir():
                    continue
                for rel in PROJECT_FILES:
                    f = d / rel
                    try:
                        is_file = f.is_file()
                    except (PermissionError, OSError):
                        continue
                    if is_file and str(f) not in seen:
                        seen.add(str(f))
                        fmt = "codex-toml" if f.suffix == ".toml" else ("servers" if ".vscode" in rel else "mcpServers")
                        try:
                            out["servers"] += _parse(f"project:{rel}", str(f), fmt)
                        except Exception as e:  # noqa: BLE001
                            out["errors"].append(f"{f}: {type(e).__name__}: {e}")
    # running processes
    try:
        if _OS == "Windows":
            ps = subprocess.run(["wmic", "process", "get", "ProcessId,CommandLine"], capture_output=True, text=True, timeout=20).stdout
        else:
            ps = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True, timeout=20).stdout
        for line in ps.splitlines():
            if "mcpeval" in line:
                continue
            if PROCESS_HINT.search(line) or BYPASS_FLAGS.search(line):
                pid, _, cmd = line.strip().partition(" ")
                out["processes"].append({"pid": pid, "name": (cmd.split() or ["?"])[0][-40:], "cmdline": cmd[:240], "bypass_flag": bool(BYPASS_FLAGS.search(line))})
    except (OSError, subprocess.SubprocessError) as e:
        out["errors"].append(f"process listing: {e}")
    return out
