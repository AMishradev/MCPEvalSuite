"""Connect to an MCP server and capture a ServerManifest.

Uses the official SDK's high-level Client with mode="auto": it probes `server/discover`
(2026-07-28) and falls back to `initialize` (2025-11-25 and earlier), so both protocol
eras are handled without custom negotiation code.

Target syntax (parse_target):
  "https://host/mcp"                      streamable HTTP
  "stdio:npx -y @scope/pkg --flag"        spawn a command
  "python server.py"                      spawn a command (bare)
  "config:/path/mcp.json#serverName"      pick one entry from an mcpServers-style config
  '{"command": "...", "args": [...]}'     inline JSON entry

The probe is passive: discover/initialize + the four list methods. Server-initiated
requests (sampling, elicitation) and notifications are recorded, never acted on.
"""
from __future__ import annotations

import asyncio
import json
import os
import shlex
from typing import Any

from mcp import types
from mcp.client.client import Client
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from ..models import PromptRecord, ResourceRecord, ServerManifest, ToolRecord


class TargetSpec:
    def __init__(self, kind: str, *, url: str | None = None, command: str | None = None, args: list[str] | None = None,
                 env: dict[str, str] | None = None, headers: dict[str, str] | None = None, cwd: str | None = None, label: str | None = None):
        self.kind = kind  # stdio | http | sse
        self.url = url
        self.command = command
        self.args = args or []
        self.env = env or {}
        self.headers = headers or {}
        self.cwd = cwd
        self.label = label or (url if url else " ".join([command or "", *self.args]).strip())

    def __str__(self) -> str:
        return self.label


def _from_config_entry(name: str, entry: dict[str, Any]) -> TargetSpec:
    url = entry.get("url") or entry.get("serverUrl") or entry.get("httpUrl")
    if url:
        ttype = (entry.get("type") or entry.get("transport") or "").lower()
        kind = "sse" if ttype == "sse" or url.rstrip("/").endswith("/sse") else "http"
        return TargetSpec(kind, url=url, headers=entry.get("headers") or {}, label=name)
    return TargetSpec("stdio", command=entry.get("command"), args=list(entry.get("args") or []), env=entry.get("env") or {},
                      cwd=entry.get("cwd"), label=name)


def parse_target(target: str) -> TargetSpec:
    t = target.strip()
    if t.startswith("{"):
        entry = json.loads(t)
        return _from_config_entry(entry.get("name", "inline"), entry)
    if t.startswith("config:"):
        path, _, name = t[len("config:"):].partition("#")
        cfg = json.load(open(os.path.expanduser(path)))
        servers = cfg.get("mcpServers") or cfg.get("servers") or (cfg.get("mcp") or {}).get("servers") or {}
        if not name:
            if len(servers) != 1:
                raise ValueError(f"config has {len(servers)} servers; use config:{path}#<name>")
            name = next(iter(servers))
        if name not in servers:
            raise ValueError(f"server '{name}' not in {path}; available: {list(servers)}")
        spec = _from_config_entry(name, servers[name])
        spec.label = f"{os.path.basename(path)}#{name}"
        return spec
    if t.startswith("sse+"):
        return TargetSpec("sse", url=t[4:])
    if t.startswith(("http://", "https://")):
        return TargetSpec("sse" if t.rstrip("/").endswith("/sse") else "http", url=t)
    if t.startswith("stdio:"):
        t = t[len("stdio:"):]
    parts = shlex.split(t)
    if not parts:
        raise ValueError("empty target")
    return TargetSpec("stdio", command=parts[0], args=parts[1:])


def _dump(obj: Any) -> Any:
    if hasattr(obj, "model_dump"):
        try:
            return obj.model_dump(by_alias=True, exclude_none=True, mode="json")
        except Exception:  # noqa: BLE001
            return str(obj)
    if hasattr(obj, "root"):
        return _dump(obj.root)
    return obj if isinstance(obj, (dict, list, str, int, float, bool)) or obj is None else str(obj)


class Recorder:
    """Collects server-initiated traffic during a probe."""

    def __init__(self, manifest: ServerManifest):
        self.m = manifest

    async def on_elicit(self, context: Any, params: Any) -> Any:
        self.m.elicitation_requests.append(_dump(params))
        return types.ElicitResult(action="decline")

    async def on_sample(self, context: Any, params: Any) -> Any:
        self.m.sampling_requests.append(_dump(params))
        return types.ErrorData(code=types.INVALID_REQUEST, message="sampling denied by mcpeval")

    async def on_log(self, params: Any) -> None:
        self.m.log_messages.append(_dump(params))

    async def on_message(self, message: Any) -> None:
        if isinstance(message, Exception):
            self.m.errors.append(f"transport: {type(message).__name__}: {message}")
            return
        d = _dump(message)
        if isinstance(d, dict) and d.get("method"):
            self.m.notifications.append(d)


def expand_headers(headers: dict[str, str]) -> dict[str, str]:
    """Expand ${VAR} references (same convention as client configs) so secrets stay in the environment."""
    return {k: os.path.expandvars(str(v)) for k, v in (headers or {}).items()}


def make_client(spec: TargetSpec, rec: Recorder, *, timeout: float = 30.0) -> Client:
    headers = expand_headers(spec.headers)
    if spec.kind == "stdio":
        server: Any = StdioServerParameters(command=spec.command, args=spec.args, env={**os.environ, **spec.env}, cwd=spec.cwd)
    elif spec.kind == "sse":
        server = sse_client(spec.url, headers=headers or None, timeout=timeout)
    elif headers:  # authenticated streamable HTTP (gateway API key, bearer token, ...)
        server = streamable_http_client(spec.url, http_client=create_mcp_http_client(headers=headers))
    else:
        server = spec.url
    return Client(server, mode="auto", read_timeout_seconds=timeout, sampling_callback=rec.on_sample,
                  elicitation_callback=rec.on_elicit, logging_callback=rec.on_log, message_handler=rec.on_message,
                  client_info=types.Implementation(name="mcpeval", version="0.1.0"))


async def _paginate(fn, attr: str) -> list[Any]:
    items: list[Any] = []
    cursor: str | None = None
    for _ in range(50):
        res = await fn(params=types.PaginatedRequestParams(cursor=cursor)) if cursor else await fn()
        items.extend(getattr(res, attr, None) or [])
        cursor = getattr(res, "next_cursor", None)
        if not cursor:
            break
    return items


async def capture_manifest(spec: TargetSpec, *, timeout: float = 30.0, settle_seconds: float = 1.0) -> ServerManifest:
    manifest = ServerManifest(target=str(spec), transport={"http": "streamable-http", "sse": "sse", "stdio": "stdio"}[spec.kind])
    rec = Recorder(manifest)
    try:
        async with make_client(spec, rec, timeout=timeout) as c:
            manifest.protocol_version = c.protocol_version
            manifest.server_info = _dump(c.server_info) or {}
            manifest.capabilities = _dump(c.server_capabilities) or {}
            manifest.instructions = c.instructions
            caps = manifest.capabilities
            try:
                for t in await _paginate(c.list_tools, "tools"):
                    d = _dump(t)
                    manifest.tools.append(ToolRecord(name=d.get("name", ""), title=d.get("title"), description=d.get("description"),
                                                     input_schema=d.get("inputSchema") or {}, output_schema=d.get("outputSchema"),
                                                     annotations=d.get("annotations"), meta=d.get("_meta"), raw=d))
            except Exception as e:  # noqa: BLE001
                manifest.errors.append(f"tools/list: {type(e).__name__}: {e}")
            if caps.get("resources") is not None:
                try:
                    for r in await _paginate(c.list_resources, "resources"):
                        d = _dump(r)
                        manifest.resources.append(ResourceRecord(uri=str(d.get("uri")), name=d.get("name"), title=d.get("title"),
                                                                 description=d.get("description"), mime_type=d.get("mimeType"), raw=d))
                    for r in await _paginate(c.list_resource_templates, "resource_templates"):
                        d = _dump(r)
                        manifest.resources.append(ResourceRecord(uri=str(d.get("uriTemplate")), name=d.get("name"), title=d.get("title"),
                                                                 description=d.get("description"), mime_type=d.get("mimeType"), is_template=True, raw=d))
                except Exception as e:  # noqa: BLE001
                    manifest.errors.append(f"resources/list: {type(e).__name__}: {e}")
            if caps.get("prompts") is not None:
                try:
                    for p in await _paginate(c.list_prompts, "prompts"):
                        d = _dump(p)
                        manifest.prompts.append(PromptRecord(name=d.get("name", ""), title=d.get("title"), description=d.get("description"),
                                                             arguments=d.get("arguments") or [], raw=d))
                except Exception as e:  # noqa: BLE001
                    manifest.errors.append(f"prompts/list: {type(e).__name__}: {e}")
            await asyncio.sleep(settle_seconds)  # let unsolicited notifications arrive (rug-pull servers push early)
    except Exception as e:  # noqa: BLE001
        inner = getattr(e, "exceptions", None)
        detail = "; ".join(f"{type(x).__name__}: {x}" for x in inner) if inner else f"{type(e).__name__}: {e}"
        manifest.errors.append(f"connect: {detail[:500]}")
    return manifest


def capture_manifest_sync(spec: TargetSpec, **kw) -> ServerManifest:
    return asyncio.run(capture_manifest(spec, **kw))
