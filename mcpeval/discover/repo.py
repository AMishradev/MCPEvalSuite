"""Repository discovery: find MCP servers and client configs in a source tree (`mcpeval discover --repo PATH`)."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".mcpeval", "out", ".tox", "target"}

# dependency names by ecosystem
DEP_PATTERNS = [
    ("python", re.compile(r'^\s*"?(mcp|fastmcp|mcp-server-[\w-]+|awslabs[.-][\w-]*mcp[\w-]*)\b', re.M)),
    ("npm", re.compile(r'"(@modelcontextprotocol/(sdk|server|client)[^"]*|mcp-framework|litemcp|@mcp-?[\w/-]*|fastmcp)"\s*:', re.M)),
    ("go", re.compile(r"github\.com/(modelcontextprotocol/go-sdk|mark3labs/mcp-go)")),
    ("java", re.compile(r"io\.modelcontextprotocol")),
    ("dotnet", re.compile(r'PackageReference Include="ModelContextProtocol')),
    ("rust", re.compile(r'^\s*rmcp\s*=', re.M)),
]
DEP_FILES = {"requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "package.json", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "Cargo.toml"}
CODE_PATTERNS = [
    ("python-fastmcp", re.compile(r"\bFastMCP\(")),
    ("python-sdk", re.compile(r"\bMCPServer\(|from mcp\.server|mcp\.server\.fastmcp")),
    ("ts-sdk", re.compile(r"@modelcontextprotocol/(sdk|server)|new McpServer\(|registerTool\(")),
    ("go-sdk", re.compile(r"mcp\.NewServer\(|server\.NewMCPServer\(")),
]
CONFIG_NAMES = {".mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json", "cline_mcp_settings.json", "mcp-config.json"}


def discover_repo(root: Path) -> dict[str, Any]:
    out: dict[str, Any] = {"servers": [], "clients": [], "configs": []}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP]
        for fn in fns:
            p = Path(dp) / fn
            rel = str(p.relative_to(root))
            try:
                if fn in DEP_FILES:
                    txt = p.read_text(errors="ignore")
                    for eco, pat in DEP_PATTERNS:
                        m = pat.search(txt)
                        if m:
                            out["servers"].append({"file": rel, "kind": f"dependency:{eco}", "match": m.group(0).strip()[:80]})
                elif fn in CONFIG_NAMES or (fn == "settings.json" and ".vscode" in dp):
                    txt = p.read_text(errors="ignore")
                    try:
                        d = json.loads(txt)
                    except json.JSONDecodeError:
                        d = {}
                    servers = d.get("mcpServers") or d.get("servers") or {}
                    for name, s in (servers.items() if isinstance(servers, dict) else []):
                        s = s or {}
                        launch = s.get("url") or " ".join([str(s.get("command", "")), *map(str, s.get("args") or [])])
                        out["configs"].append({"file": rel, "name": name, "launch": launch.strip(), "env_keys": sorted((s.get("env") or {}).keys())})
                elif fn.endswith((".py", ".ts", ".js", ".mjs", ".go")):
                    if p.stat().st_size > 2_000_000:
                        continue
                    txt = p.read_text(errors="ignore")
                    for kind, pat in CODE_PATTERNS:
                        if pat.search(txt):
                            out["servers"].append({"file": rel, "kind": f"code:{kind}", "match": pat.pattern[:40]})
                            break
                    if re.search(r"ClientSession\(|streamable_http_client\(|from mcp\.client|@modelcontextprotocol/client|new Client\(\s*\{", txt):
                        out["clients"].append({"file": rel})
            except OSError:
                continue
    return out
