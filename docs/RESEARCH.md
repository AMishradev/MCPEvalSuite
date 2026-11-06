# Research notes (2026-11-06)

Six research passes fed the design. Each claim below was checked against a primary source on 2026-11-06; items the researchers could not verify are marked as such.
This file is the "why" behind the checks; `docs/CONTROLS.md` is the "what".

## 1. MCP specification: what a scanner can rely on

- **Current spec is `2026-07-28`** (released 2026-07-28; `2025-11-25` is the prior stable). It is a stateless redesign: `initialize`, `ping`, `Mcp-Session-Id`, the GET SSE stream and `Last-Event-ID` are gone; `server/discover` is mandatory; every request carries `_meta` with protocol version and client capabilities; headers `Mcp-Method` / `Mcp-Name` are required over HTTP; server-initiated requests are replaced by the multi-round-trip pattern (`resultType: "input_required"`, `inputRequests`, `requestState`). Sampling, Roots, Logging and Dynamic Client Registration are deprecated. Both eras are deployed side by side; all tier-1 SDKs serve both. Sources: https://modelcontextprotocol.io/specification/versioning , https://modelcontextprotocol.io/specification/2026-07-28/changelog
- **Tool annotations** (`readOnlyHint` default false, `destructiveHint` default true, `idempotentHint` default false, `openWorldHint` default true) are unchanged since 2025-03-26 and the spec says clients MUST treat them as untrusted. So the scanner infers the category and treats annotations as a hint; a contradiction is a finding (`ANNOT-002`). https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- **Naming**: SHOULD be 1-128 chars of `A-Za-z0-9_.-`, unique per server; aggregators SHOULD prefix (AgentCore uses `target___tool`). No stronger rule exists in the spec, which is why the `<backend>_<verb>_<noun>` convention has to be a policy check (`NAME-001/002`).
- **Authorization**: OAuth 2.1; servers MUST publish RFC 9728 protected-resource metadata and MUST validate token audience (RFC 8707); clients MUST use PKCE S256 and MUST refuse to proceed when `code_challenge_methods_supported` is absent; the 2026-07-28 revision adds RFC 9207 `iss` validation, issuer-bound credentials and Client ID Metadata Documents (DCR deprecated). Authorization-server discovery order for an issuer with a path: `/.well-known/oauth-authorization-server/<path>`, `/.well-known/openid-configuration/<path>`, `<path>/.well-known/openid-configuration`. All encoded in `probe/auth.py` and `AUTH-00x`. https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- **Transports**: invalid `Origin` MUST get 403; local servers SHOULD bind 127.0.0.1 and SHOULD authenticate. The official Python SDK only enables DNS-rebinding protection when it assumes localhost; FastMCP's `host_origin_protection` defaults to off; the TypeScript `createMcpHandler` validates neither Host nor Origin. Hence `AUTH-006` and the static rules.
- **HITL**: the spec's own position is that there SHOULD always be a human able to deny tool calls, implemented as client policy; elicitation is the server-side mechanism. `_meta["anthropic/requiresUserInteraction"]: true` forces a prompt in Claude Code on every call and counts as HITL evidence here. Claude Agent SDK treats an unset `destructiveHint` as false for its `always_ask` policy, so mutating tools must set it explicitly.
- **Registry** (`registry.modelcontextprotocol.io`, preview) proves namespace ownership (GitHub OAuth, DNS TXT, HTTP well-known) and package-name binding, but carries no signatures or attestations; use it only to resolve name to exact package/version.
- **2026-07-28 extras worth checking**: `x-mcp-header` on secret-named params (`SCHEMA-001`), network `$ref` in schemas (`SCHEMA-002`), icon URI schemes (`SCHEMA-003`), `cacheScope: public` on per-tenant results.

## 2. Existing scanners (reuse vs build)

| Tool | State | Use it for |
|---|---|---|
| Snyk Agent Scan (ex Invariant mcp-scan) | active, v0.6.x, needs `SNYK_TOKEN`, sends tool text to Snyk, no SARIF, proxy mode dropped | optional second opinion on tool poisoning |
| Cisco `mcp-scanner` v4.8.x | active, Apache-2.0, YARA + LLM + behavioral source analysis + readiness heuristics, JSON only | offline source and YARA lane in CI |
| Semgrep `p/ai` MCP rules | active, Python taint rules for command injection / SSRF; TS rules added 2026-09 | run alongside the 15 bundled rules |
| Ramparts (Highflame) | active, Rust, SARIF, OWASP MCP tagging, small community | live-server scan with native SARIF |
| MCP Inspector CLI | active, exit-code map | harvesting `tools/list` in scripts |
| mcp-shield, mcp-guardian, MCPSafetyScanner, Trail of Bits mcp-context-protector | abandoned or archived | do not depend on |
| ToolHive, Docker MCP Gateway, Microsoft mcp-gateway, Teleport | runtime gateways, no scanning | per-call policy and audit at runtime |

None of them classify tools by side effect, enforce naming, check HITL per category, verify PKCE / token lifetime / audience, check idempotency hints, or budget tool definitions. That list is exactly what this project implements.
OWASP MCP Top 10 (beta): MCP01 token mismanagement, MCP02 scope creep, MCP03 tool poisoning, MCP04 supply chain, MCP05 command injection, MCP06 prompt injection, MCP07 insufficient authN/authZ, MCP08 lack of audit, MCP09 shadow servers, MCP10 context injection. Findings carry these IDs so they merge with other scanners' output. https://owasp.org/www-project-mcp-top-10/

## 3. Attack classes encoded as checks

tool poisoning and schema poisoning (`POISN-001`, Invariant 2025; CyberArk full-schema poisoning), invisible Unicode and ANSI tricks (`POISN-002`, Trail of Bits), cross-server shadowing (`POISN-003`), server `instructions` injection (`POISN-004`), rug pull via baseline diff and `tools/list_changed` (`RUG-001/002`), sampling and elicitation abuse (`RUG-003`, Unit 42 2025-12), free-form execution tools (`CAT-004`), unconstrained mutator inputs (`INPUT-001/002`), secrets in definitions and configs (`SECRT-001`, `STATIC-002`, `SHADOW-002`), unauthenticated endpoints (`AUTH-001`; Wiz 2026-07: about one in six cloud environments with MCP exposes a server, most list tools anonymously), DNS rebinding (`AUTH-006`; CVE-2025-49596 MCP Inspector), token passthrough and audience (`AUTH-005`, Semgrep `mcp-token-passthrough-*`; CVE-2026-116684 / CVE-2026-111771 in the SDKs themselves), command injection in launchers (CVE-2025-6514 mcp-remote), known-malicious packages (`SUPPLY-002`; MAL-2025-47604 postmark-mcp, SANDWORM_MODE typosquats 2026-02).
Benchmarks that can be used to measure the classifier and poisoning heuristics: MCPTox (353 tools, 1,348 cases), MCPSecBench, MCP-SafetyBench, MCP-AttackBench. The LLM prompt follows the Cisco pattern: tool text is data, self-classification claims are ignored, ambiguity resolves to the riskier class.

## 4. Classification approach

Prior art (CARE, SEAgent, ToolEmu, Anthropic's connector review criteria) converges on: static heuristics first, LLM only for the ambiguous remainder, take the maximum risk, force HITL on contradiction. Validation plan: hand-label tools from real servers (filesystem, git, GitHub, Slack, Postgres, fetch) plus MCPTox negatives, score macro-F1 with a cost-weighted penalty for under-classification (DML labelled read costs far more than the reverse), and use a different model family than the agent under test for the judge.

## 5. AWS

Summarized in `docs/AWS.md`. Key verified points: AgentCore Policy (Cedar) is the only AWS-native per-tool authorization layer (GA 2026-03-03) and names tools `target___tool`; Agent Registry org auto-detection (GA Aug 2026) catalogs AgentCore Runtimes and Gateways only; Security Hub AI inventory (GA 2026-07-14) explicitly does not detect MCP servers; custom findings still enter Security Hub via CSPM `BatchImportFindings` (ASFF); Config records 16 `AWS::BedrockAgentCore::*` types but not classic Bedrock Agents; CloudTrail data event `InvokeGateway` logs the MCP method and tool name; Kiro / Q Developer governance is client-side only and emits no MCP telemetry; awslabs/mcp is a legacy tier with inconsistent read-only flags, PEP 740 provenance on PyPI but unsigned ECR Public images; the managed AWS MCP Server has IAM condition keys but no VPC endpoint.

## 6. Supply chain, containers, credentials

- npm provenance: `dist.attestations.provenance.predicateType == https://slsa.dev/provenance/v1` on the packument; attestation bundle at `/-/npm/v1/attestations/<pkg>@<ver>` holds the source repo. `npm audit signatures` verifies in CI. `@modelcontextprotocol/sdk` carries provenance.
- PyPI: PEP 740 integrity API `GET /integrity/<pkg>/<ver>/<file>/provenance` (404 = none); `pypi-attestations verify pypi --repository <url> pypi:<file>` fails when the publisher repo does not match. `mcp` 2.3.0 is published by `modelcontextprotocol/python-sdk` via trusted publishing.
- Docker Content Trust is retired (shutdown 2026-12-08); do not build checks on it. Docker MCP Catalog images (`mcp/*`) are signed with a static cosign key from `docker/keyring` (repo archived but keys still served and signatures still pushed). ECR: managed signing with AWS Signer + Notation. Keyless cosign needs `--certificate-identity` and `--certificate-oidc-issuer`.
- Container root user: Hadolint DL3002, Dockle CIS-DI-0001, Trivy AVD-DS-0002, Checkov CKV_DOCKER_3/8; Kubernetes `runAsNonRoot`, `allowPrivilegeEscalation`; ECS `user`, `privileged`, `readonlyRootFilesystem` (Security Hub ECS.4/ECS.5); Lambda defines a non-root user by default. `STATIC-001` implements the Dockerfile / ECS / K8s checks directly so no extra tool is required.
- Secrets: gitleaks, trufflehog, detect-secrets and Trivy cover most token formats; none except gitleaks and Semgrep `p/ai` know Anthropic keys; the bundled Semgrep rule `mcp-config-env-long-lived-credential` covers MCP config env blocks.
- Token lifetime and audience: decode JWT `exp - iat` and `aud` (`AUTH-005`); AWS temporary keys start with `ASIA`, long-lived user keys with `AKIA` (`STATIC-002`, `SHADOW-002`).
- Environment isolation: Config advanced queries over `tags`, `required-tags` rule, Organizations tag policies; strongest control is account separation. `discover --aws` flags prod and non-prod MCP services sharing one ECS cluster.
- Auth logging: FastMCP `StructuredLoggingMiddleware` or a custom `on_call_tool` middleware reading `get_access_token()`; CloudTrail data events for Lambda-hosted servers. `STATIC-006` checks that a server file has some logging / middleware at all; the gateway is the authoritative audit source.

## 7. Evaluation frameworks

promptfoo has an MCP provider (server under test, model-free `tools/call`) and an `mcp` red-team plugin (agent under test); Inspect AI (UK AISI) has native MCP tool support and approval policies that double as a HITL test bed; OpenAI Evals has no MCP awareness; garak and PyRIT have no MCP target; fuzzers mcp-gauntlet, fuzzd and mcp-tool-schema-fuzzer produce SARIF. The behavior lane here uses the same oracle as those fuzzers: schema-invalid input must come back as a protocol error (`-32602`) or `isError: true`; a normal result is an "accepted-invalid" finding (`INPUT-002`).

## 8. Shadow MCP detection

See `discover/endpoint.py` for the client config locations and `docs/AWS.md` for the cloud side. (Endpoint-side research notes are appended below when the final pass completes.)
