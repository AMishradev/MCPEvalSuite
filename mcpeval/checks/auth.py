"""Auth-lane checks over manifest.http (populated by probe/auth.py for HTTP transports)."""
from __future__ import annotations

from typing import Iterable

from ..models import Confidence, Finding, Lane, Severity
from .base import Check, CheckContext, register

SPEC_AUTH = "https://modelcontextprotocol.io/specification/draft/basic/authorization"
SPEC_SBP = "https://modelcontextprotocol.io/specification/draft/basic/security_best_practices"
SPEC_TRANSPORT = "https://modelcontextprotocol.io/specification/draft/basic/transports"


def _http(ctx: CheckContext) -> dict | None:
    if not ctx.manifest or ctx.manifest.transport == "stdio":
        return None
    return ctx.manifest.http or None


@register
class UnauthenticatedAccess(Check):
    id = "AUTH-001"
    title = "MCP endpoint usable without authentication"
    controls = ["BP-LEAST-PRIV", "BP-PKCE"]
    lane = Lane.AUTH
    default_severity = Severity.CRITICAL
    references = [SPEC_AUTH]
    mappings = {"owasp_mcp": ["MCP07 Insufficient Authentication & Authorization"], "owasp_agentic": ["ASI02 Tool Misuse"], "cwe": ["CWE-306"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        h = _http(ctx)
        if not h:
            return
        if h.get("unauth_tools_list_ok") or h.get("unauth_discover_ok"):
            sev = Severity.HIGH if h.get("is_local") else Severity.CRITICAL
            yield self.finding(ctx, f"initialize and tools/list succeeded with no credentials (HTTP {h.get('unauth_status')}). Anyone who can reach {h.get('url')} "
                                    f"can enumerate and likely invoke tools.", severity=sev, evidence={"steps": h.get("steps")},
                               remediation="Require OAuth 2.1 bearer tokens on every request (FastMCP JWTVerifier/RemoteAuthProvider, AgentCore Gateway inbound auth, "
                                           "API Gateway JWT authorizer). Return 401 with WWW-Authenticate resource_metadata.")
        elif h.get("unauth_status") == 200:
            yield self.finding(ctx, "initialize succeeded without credentials; tools/list could not be confirmed.", severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                               evidence={"steps": h.get("steps")})


@register
class MissingWwwAuthenticate(Check):
    id = "AUTH-002"
    title = "401 response lacks WWW-Authenticate with resource_metadata"
    controls = ["BP-PKCE"]
    lane = Lane.AUTH
    default_severity = Severity.MEDIUM
    references = [SPEC_AUTH, "https://www.rfc-editor.org/rfc/rfc9728"]

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        h = _http(ctx)
        if not h or h.get("unauth_status") not in (401, 403):
            return
        wa = h.get("www_authenticate") or {}
        if not wa:
            yield self.finding(ctx, f"Server returned {h.get('unauth_status')} without a WWW-Authenticate header; spec-compliant clients cannot discover the "
                                    f"authorization server and will fall back to guessing or to pasted long-lived tokens.",
                               evidence={"status": h.get("unauth_status")}, remediation='Send `WWW-Authenticate: Bearer resource_metadata="https://host/.well-known/oauth-protected-resource"`.')
        elif "resource_metadata" not in wa:
            yield self.finding(ctx, f"WWW-Authenticate present ({wa.get('scheme')}) but has no resource_metadata parameter (RFC 9728).", severity=Severity.LOW, evidence={"www_authenticate": wa})


@register
class ProtectedResourceMetadata(Check):
    id = "AUTH-003"
    title = "Protected Resource Metadata (RFC 9728) missing or incomplete"
    controls = ["BP-PKCE", "BP-SHORT-TOKENS"]
    lane = Lane.AUTH
    default_severity = Severity.MEDIUM
    references = [SPEC_AUTH]

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        h = _http(ctx)
        if not h or h.get("unauth_tools_list_ok"):
            return
        prm = h.get("protected_resource_metadata")
        if not prm:
            yield self.finding(ctx, "No /.well-known/oauth-protected-resource document found. Clients cannot learn the authorization server or the resource identifier "
                                    "needed for audience-bound tokens (RFC 8707).", evidence={"steps": h.get("steps")},
                               remediation="Publish RFC 9728 metadata with `resource`, `authorization_servers`, `scopes_supported`, `bearer_methods_supported`.")
            return
        missing = [k for k in ("resource", "authorization_servers") if not prm.get(k)]
        if missing:
            yield self.finding(ctx, f"Protected resource metadata lacks {missing}.", evidence={"prm": prm})
        if prm.get("resource") and prm["resource"].rstrip("/") != h.get("url", "").rstrip("/") and not h.get("url", "").startswith(prm["resource"].rstrip("/")):
            yield self.finding(ctx, f"PRM `resource` ({prm['resource']}) does not match the MCP endpoint ({h.get('url')}); audience binding will be wrong or clients will reject it.",
                               severity=Severity.LOW, evidence={"resource": prm["resource"]})


@register
class PkceSupport(Check):
    id = "AUTH-004"
    title = "Authorization server does not advertise PKCE S256"
    controls = ["BP-PKCE"]
    lane = Lane.AUTH
    default_severity = Severity.HIGH
    references = [SPEC_AUTH, "https://www.rfc-editor.org/rfc/rfc7636"]

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        h = _http(ctx)
        if not h or h.get("unauth_tools_list_ok"):
            return
        servers = h.get("authorization_servers") or []
        if not servers or not any(s.get("metadata_url") for s in servers):
            if h.get("protected_resource_metadata"):
                yield self.finding(ctx, "Authorization server metadata (RFC 8414 / OIDC discovery) could not be fetched; PKCE support cannot be verified.",
                                   severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, evidence={"authorization_servers": servers})
            return
        for s in servers:
            if not s.get("metadata_url"):
                continue
            methods = s.get("code_challenge_methods_supported")
            if methods is None:
                yield self.finding(ctx, f"{s['issuer']}: metadata omits code_challenge_methods_supported. Per MCP spec clients MUST refuse to proceed when PKCE support "
                                        f"cannot be confirmed.", evidence=s, remediation="Advertise `code_challenge_methods_supported: [\"S256\"]` and enforce PKCE at the token endpoint.")
            elif "S256" not in methods:
                yield self.finding(ctx, f"{s['issuer']}: PKCE methods {methods} do not include S256.", evidence=s)
            if s.get("token_endpoint_auth_methods_supported") and "none" not in s["token_endpoint_auth_methods_supported"] and not s.get("registration_endpoint") and not s.get("client_id_metadata_document_supported"):
                yield self.finding(ctx, f"{s['issuer']}: no dynamic client registration and no public-client auth method; MCP clients will need pre-shared client secrets "
                                        f"(a long-lived credential).", severity=Severity.LOW, evidence=s, title="No DCR / CIMD for MCP clients", controls=["BP-SHORT-TOKENS"])


@register
class TokenHygiene(Check):
    id = "AUTH-005"
    title = "Supplied bearer token is long-lived or not audience-bound"
    controls = ["BP-SHORT-TOKENS", "BP-LEAST-PRIV"]
    lane = Lane.AUTH
    default_severity = Severity.HIGH
    references = [SPEC_SBP, "https://www.rfc-editor.org/rfc/rfc8707"]

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        h = _http(ctx)
        tok = (h or {}).get("token")
        if not tok:
            return
        max_life = int(ctx.policy.get("auth", {}).get("max_token_lifetime_seconds", 3600))
        if not tok.get("is_jwt"):
            yield self.finding(ctx, f"Token is opaque (length {tok.get('length')}); lifetime and audience cannot be verified client-side. Confirm with the issuer that it "
                                    f"expires within {max_life}s and is bound to this resource.", severity=Severity.LOW, confidence=Confidence.LOW)
            return
        if not tok.get("has_exp"):
            yield self.finding(ctx, "JWT has no `exp` claim: it never expires.", severity=Severity.CRITICAL, evidence=tok)
        elif tok.get("lifetime_seconds") and tok["lifetime_seconds"] > max_life:
            yield self.finding(ctx, f"JWT lifetime is {tok['lifetime_seconds']}s (policy max {max_life}s).", evidence=tok,
                               remediation="Issue short-lived access tokens with refresh rotation; for AWS use STS/Cognito with ≤1h sessions.")
        aud = tok.get("aud")
        res = (h.get("protected_resource_metadata") or {}).get("resource")
        if not aud:
            yield self.finding(ctx, "JWT has no `aud` claim; it can be replayed against any resource server (confused-deputy / token passthrough risk).", evidence={"aud": None})
        elif res and (res not in (aud if isinstance(aud, list) else [aud])):
            yield self.finding(ctx, f"JWT audience {aud} does not include this resource {res}.", severity=Severity.HIGH, evidence={"aud": aud, "resource": res})
        if tok.get("alg") in ("none", "HS256"):
            yield self.finding(ctx, f"JWT alg={tok.get('alg')}.", severity=Severity.HIGH if tok.get("alg") == "none" else Severity.LOW, evidence={"alg": tok.get("alg")})


@register
class OriginValidation(Check):
    id = "AUTH-006"
    title = "Local HTTP server accepts arbitrary Origin (DNS rebinding)"
    controls = ["BP-LEAST-PRIV"]
    lane = Lane.AUTH
    default_severity = Severity.HIGH
    references = [SPEC_TRANSPORT]
    mappings = {"cwe": ["CWE-346", "CWE-1385"], "attack": ["dns-rebinding"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        h = _http(ctx)
        if not h or not h.get("is_local"):
            return
        if h.get("evil_origin_status") and h["evil_origin_status"] < 400 and h.get("unauth_status", 0) < 400:
            yield self.finding(ctx, f"Server on {h.get('url')} answered an initialize with `Origin: http://evil.example.invalid` (HTTP {h['evil_origin_status']}). "
                                    f"A malicious web page can reach it via DNS rebinding and drive tools with the user's local privileges.",
                               evidence={"evil_origin_status": h["evil_origin_status"]},
                               remediation="Validate the Origin header, bind to 127.0.0.1 only, and require authentication even on localhost (spec MUST).")


@register
class PlaintextTransport(Check):
    id = "AUTH-007"
    title = "MCP over plaintext HTTP to a non-local host"
    controls = ["BP-SHORT-TOKENS"]
    lane = Lane.AUTH
    default_severity = Severity.HIGH
    mappings = {"cwe": ["CWE-319"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        h = _http(ctx)
        if h and h.get("tls") is False and not h.get("is_local"):
            yield self.finding(ctx, f"{h.get('url')} is plain http://; bearer tokens and tool data travel unencrypted.", evidence={"url": h.get("url")})


@register
class IssuerMismatch(Check):
    id = "AUTH-008"
    title = "Authorization server metadata issuer does not match the discovery URL"
    controls = ["BP-PKCE"]
    lane = Lane.AUTH
    default_severity = Severity.HIGH
    references = [SPEC_AUTH]
    mappings = {"owasp_mcp": ["MCP07 Insufficient Authentication & Authorization"], "attack": ["mix-up"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        h = _http(ctx)
        for s in (h or {}).get("authorization_servers") or []:
            if s.get("metadata_url") and s.get("issuer_matches") is False:
                yield self.finding(ctx, f"Metadata at {s['metadata_url']} declares issuer `{s.get('issuer_declared') or s.get('issuer')}` which differs from the "
                                        f"authorization server URL `{s['issuer']}` in the protected resource metadata. Spec: clients MUST reject this.",
                                   evidence=s)


@register
class ScopeHygiene(Check):
    id = "AUTH-009"
    title = "Scope challenge missing or over-broad"
    controls = ["BP-LEAST-PRIV"]
    lane = Lane.AUTH
    default_severity = Severity.LOW
    references = [SPEC_AUTH]
    mappings = {"owasp_mcp": ["MCP02 Privilege Escalation via Scope Creep"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        h = _http(ctx)
        if not h or h.get("unauth_status") != 401:
            return
        wa = h.get("www_authenticate") or {}
        if "scope" not in wa:
            yield self.finding(ctx, "401 challenge carries no `scope` parameter; clients cannot request least-privilege scopes.", evidence={"www_authenticate": wa})
        scopes = set((h.get("protected_resource_metadata") or {}).get("scopes_supported") or []) | set((wa.get("scope") or "").split())
        broad = {s for s in scopes if s.lower() in {"*", "all", "admin", "full", "full_access", "full-access", "root"} or s.lower().endswith((":*", ".*"))}
        if broad:
            yield self.finding(ctx, f"Omnibus scopes advertised: {sorted(broad)}.", severity=Severity.MEDIUM, evidence={"scopes": sorted(scopes)})
        if "offline_access" in scopes:
            yield self.finding(ctx, "`offline_access` advertised for an MCP server (long-lived refresh grants); spec says SHOULD NOT.", evidence={"scopes": sorted(scopes)},
                               controls=["BP-SHORT-TOKENS"])
