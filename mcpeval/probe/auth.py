"""Authorization posture probe for HTTP-transport MCP servers (passive, no credentials unless supplied).

Steps:
  1. Era detection + unauthenticated access: POST server/discover (2026-07-28 headers/_meta); if the server
     does not understand it, POST a legacy initialize. Expect 401 + WWW-Authenticate.
  2. Protected Resource Metadata (RFC 9728): path-aware URL first, then root.
  3. Authorization Server metadata (RFC 8414 / OIDC) in the spec's discovery order; check issuer equality,
     PKCE S256, CIMD / DCR support, iss parameter support.
  4. Origin spoof: spec says invalid Origin MUST get 403.
  5. If MCPEVAL_BEARER is set: decode the JWT (no verification) to report lifetime and audience.
Observations go to manifest.http; checks/auth.py turns them into findings.
"""
from __future__ import annotations

import base64
import json
import os
import time
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

MODERN = "2026-07-28"
LEGACY = "2025-11-25"


def _modern_headers(method: str) -> dict[str, str]:
    return {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
            "MCP-Protocol-Version": MODERN, "Mcp-Method": method}


def _modern_body(method: str, params: dict | None = None, id_: int = 1) -> dict:
    p = dict(params or {})
    p["_meta"] = {"io.modelcontextprotocol/protocolVersion": MODERN,
                  "io.modelcontextprotocol/clientCapabilities": {},
                  "io.modelcontextprotocol/clientInfo": {"name": "mcpeval", "version": "0.1.0"}}
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": p}


_LEGACY_HDRS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json", "MCP-Protocol-Version": LEGACY}
_LEGACY_INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": LEGACY, "capabilities": {}, "clientInfo": {"name": "mcpeval", "version": "0.1.0"}}}


def _parse_www_authenticate(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not value:
        return out
    scheme, _, rest = value.partition(" ")
    out["scheme"] = scheme
    for part in rest.split(","):
        k, _, v = part.strip().partition("=")
        if k:
            out[k.strip()] = v.strip().strip('"')
    return out


def _jwt_claims(token: str) -> dict[str, Any] | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
        return {"header": json.loads(base64.urlsafe_b64decode(pad(parts[0]))),
                "claims": json.loads(base64.urlsafe_b64decode(pad(parts[1])))}
    except Exception:  # noqa: BLE001
        return None


def _body_json(r: httpx.Response) -> dict | None:
    try:
        if r.headers.get("content-type", "").startswith("text/event-stream"):
            for line in r.text.splitlines():
                if line.startswith("data:"):
                    return json.loads(line[5:].strip())
            return None
        return r.json()
    except Exception:  # noqa: BLE001
        return None


def _as_metadata_urls(issuer: str) -> list[str]:
    u = urlparse(issuer)
    base = urlunparse((u.scheme, u.netloc, "", "", "", ""))
    path = u.path.rstrip("/")
    if path:
        return [f"{base}/.well-known/oauth-authorization-server{path}",
                f"{base}/.well-known/openid-configuration{path}",
                f"{base}{path}/.well-known/openid-configuration"]
    return [f"{base}/.well-known/oauth-authorization-server", f"{base}/.well-known/openid-configuration"]


async def probe_http_auth(url: str, *, headers: dict[str, str] | None = None, timeout: float = 15.0) -> dict[str, Any]:
    obs: dict[str, Any] = {"url": url, "steps": [], "tls": url.lower().startswith("https://")}
    host = urlparse(url).hostname or ""
    obs["is_local"] = host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or host.startswith(("10.", "192.168.", "172."))

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
        # 1. era detection + unauthenticated access ------------------------------------------------
        era = None
        try:
            r = await c.post(url, json=_modern_body("server/discover"), headers=_modern_headers("server/discover"))
            body = _body_json(r) or {}
            err = (body.get("error") or {}).get("code")
            obs["steps"].append(f"server/discover(no auth) -> {r.status_code} err={err}")
            if r.status_code == 200 and "result" in body:
                era = "modern"
                obs["unauth_discover_ok"] = True
            elif r.status_code in (400,) and err in (-32020, -32021, -32022):
                era = "modern"
            elif r.status_code == 401:
                era = "modern-or-legacy"
            obs["unauth_status"] = r.status_code
            obs["www_authenticate"] = _parse_www_authenticate(r.headers.get("WWW-Authenticate", ""))
            obs["server_header"] = r.headers.get("server")
        except Exception as e:  # noqa: BLE001
            obs["unauth_error"] = f"{type(e).__name__}: {e}"

        if era in (None, "modern-or-legacy") and "unauth_error" not in obs:
            try:
                r = await c.post(url, json=_LEGACY_INIT, headers=_LEGACY_HDRS)
                body = _body_json(r) or {}
                obs["steps"].append(f"initialize(no auth) -> {r.status_code}")
                if r.status_code == 200 and "result" in body:
                    era = "legacy"
                    obs["unauth_status"] = 200
                    obs["mcp_session_id_on_unauth"] = r.headers.get("Mcp-Session-Id")
                    sid = r.headers.get("Mcp-Session-Id")
                    h = dict(_LEGACY_HDRS)
                    if sid:
                        h["Mcp-Session-Id"] = sid
                    await c.post(url, json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=h)
                    r2 = await c.post(url, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=h)
                    b2 = _body_json(r2) or {}
                    obs["unauth_tools_list_ok"] = r2.status_code == 200 and "tools" in (b2.get("result") or {})
                    obs["steps"].append(f"tools/list(no auth) -> {r2.status_code}")
                elif r.status_code == 401:
                    obs["unauth_status"] = 401
                    obs["www_authenticate"] = obs.get("www_authenticate") or _parse_www_authenticate(r.headers.get("WWW-Authenticate", ""))
                    era = era or "legacy"
            except Exception as e:  # noqa: BLE001
                obs["unauth_error"] = f"{type(e).__name__}: {e}"
        if obs.get("unauth_discover_ok"):
            try:
                r2 = await c.post(url, json=_modern_body("tools/list", id_=2), headers=_modern_headers("tools/list"))
                b2 = _body_json(r2) or {}
                obs["unauth_tools_list_ok"] = r2.status_code == 200 and "tools" in (b2.get("result") or {})
                obs["steps"].append(f"tools/list(no auth, modern) -> {r2.status_code}")
            except Exception as e:  # noqa: BLE001
                obs["steps"].append(f"tools/list(no auth, modern) error {type(e).__name__}")
        obs["era"] = era

        # 2. protected resource metadata -------------------------------------------------------------
        u = urlparse(url)
        base = urlunparse((u.scheme, u.netloc, "", "", "", ""))
        path = u.path.rstrip("/")
        prm_urls = []
        rm = (obs.get("www_authenticate") or {}).get("resource_metadata")
        if rm:
            prm_urls.append(rm)
        if path:
            prm_urls.append(f"{base}/.well-known/oauth-protected-resource{path}")
        prm_urls.append(f"{base}/.well-known/oauth-protected-resource")
        for pu in dict.fromkeys(prm_urls):
            try:
                r = await c.get(pu, headers={"Accept": "application/json"})
                if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
                    obs["protected_resource_metadata"] = r.json()
                    obs["protected_resource_metadata_url"] = pu
                    obs["steps"].append(f"PRM {pu} -> 200")
                    break
                obs["steps"].append(f"PRM {pu} -> {r.status_code}")
            except Exception as e:  # noqa: BLE001
                obs["steps"].append(f"PRM {pu} error {type(e).__name__}")

        # 3. authorization server metadata -----------------------------------------------------------
        prm = obs.get("protected_resource_metadata") or {}
        issuers = list(prm.get("authorization_servers") or []) or [base]
        obs["authorization_servers"] = []
        for issuer in issuers[:3]:
            entry: dict[str, Any] = {"issuer": issuer}
            for cu in _as_metadata_urls(issuer):
                try:
                    r = await c.get(cu, headers={"Accept": "application/json"})
                    if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
                        md = r.json()
                        entry["metadata_url"] = cu
                        for k in ("issuer", "code_challenge_methods_supported", "registration_endpoint", "grant_types_supported",
                                  "token_endpoint_auth_methods_supported", "scopes_supported", "client_id_metadata_document_supported",
                                  "authorization_response_iss_parameter_supported", "authorization_grant_profiles_supported"):
                            if k in md:
                                entry[k] = md[k]
                        entry["issuer_matches"] = (md.get("issuer", "").rstrip("/") == issuer.rstrip("/"))
                        break
                except Exception:  # noqa: BLE001
                    continue
            obs["authorization_servers"].append(entry)

        # 4. Origin spoof ---------------------------------------------------------------------------
        try:
            r = await c.post(url, json=_modern_body("server/discover"), headers={**_modern_headers("server/discover"), "Origin": "http://evil.example.invalid"})
            obs["evil_origin_status"] = r.status_code
            if r.status_code in (404, 405):  # legacy-only server: repeat with initialize
                r = await c.post(url, json=_LEGACY_INIT, headers={**_LEGACY_HDRS, "Origin": "http://evil.example.invalid"})
                obs["evil_origin_status"] = r.status_code
            obs["steps"].append(f"Origin=evil -> {obs['evil_origin_status']}")
        except Exception as e:  # noqa: BLE001
            obs["evil_origin_error"] = type(e).__name__

        # 5. bearer token analysis (never logged in full) --------------------------------------------
        tok = os.environ.get("MCPEVAL_BEARER") or (headers or {}).get("Authorization", "").removeprefix("Bearer ").strip()
        if tok:
            j = _jwt_claims(tok)
            if j:
                cl = j["claims"]
                life = (cl["exp"] - cl["iat"]) if cl.get("exp") and cl.get("iat") else None
                obs["token"] = {"is_jwt": True, "alg": j["header"].get("alg"), "aud": cl.get("aud"), "iss": cl.get("iss"),
                                "scope": cl.get("scope") or cl.get("scp"), "lifetime_seconds": life, "has_exp": "exp" in cl,
                                "expires_in_seconds": (cl["exp"] - int(time.time())) if cl.get("exp") else None}
            else:
                obs["token"] = {"is_jwt": False, "length": len(tok)}
    return obs
