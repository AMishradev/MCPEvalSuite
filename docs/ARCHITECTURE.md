# Architecture

## Pipeline

```
 target ──► probe ──► manifest ──► classify ──► checks ──► gate ──► reports
            │                       │             │                  json / sarif / asff / md
            │                       │             └─ manifest, auth, behavior (opt-in), llm_lane
            │                       └─ lexicon + schema + annotations; LLM only when ambiguous
            └─ SDK Client (mode=auto): server/discover (2026-07-28) or initialize (legacy)

 source tree ──► static + supply_chain checks ──────────────────────────────► same gate / reports
 machine / repo / AWS ──► discover ──► inventory vs allowlist ──► SHADOW-* ─► same reports
```

One `Finding` model everywhere: `check_id`, `control_ids` (from the best-practices doc), severity, lane, subject, evidence, remediation,
and mappings to OWASP MCP Top 10 / Agentic Top 10 / LLM Top 10 / CWE / MITRE ATLAS where they apply. Reporters never special-case a lane.

## Probe

`probe/connect.py` wraps the official Python SDK `Client` with `mode="auto"`, which first sends `server/discover` and falls back to
`initialize`, so both protocol eras work without custom negotiation. It only calls the four list methods. Server-initiated traffic
(sampling, elicitation, notifications) is recorded, never acted on; the elicitation callback always declines.

`probe/auth.py` (HTTP targets only) sends an unauthenticated `server/discover`, then a legacy `initialize`, reads `WWW-Authenticate`,
fetches RFC 9728 protected-resource metadata (path-aware URL first, then root), fetches authorization-server metadata in the spec's
discovery order, and checks issuer equality, `code_challenge_methods_supported`, CIMD / DCR flags and `iss` support. It repeats the
first request with a hostile `Origin` to test DNS-rebinding defences. If `MCPEVAL_BEARER` is set the JWT is decoded (not verified)
to report lifetime and audience.

`probe/behavior.py` (opt-in `--behavior`) calls mutating tools with placeholder arguments and records whether the server asked for
confirmation (legacy elicitation request or 2026-07-28 `input_required` result), calls each tool with schema-violating input and
records whether it was rejected, and calls create-style tools twice to compare results. It uses its own recorder so probe traffic
never counts as "unsolicited" in the manifest checks.

## Classification

`classify/lexicon.py` splits names into `<backend>_<verb>_<noun>`, maps verbs to read / aggregate / DML / DDL (DML verbs on
structural nouns such as `table`, `bucket`, `instance`, `role` become DDL), reads annotations as capped-confidence hints, and looks at
schema property names. Disagreement between signals picks the riskier category and lowers confidence, which is what triggers the LLM
lane and the `CAT-001` review finding. Policy treats `unknown` as DDL (HITL required) so an unclassifiable tool can never be waved through.

`classify/llm.py` sends the tool definition as untrusted data to Claude with a JSON-schema-constrained output and a cached system
prompt, records every call to a JSONL ledger with tokens and USD, caches verdicts by content hash, stops at the per-scan budget, and
treats a refusal as "suspicious, DDL" (fail closed).

## Checks

Each check is a class with `id`, `controls`, `lane`, `default_severity`, `run(ctx)`. `run_checks` never lets one check's crash hide the
others and rolls up more than 15 same-title findings into one. Policy YAML can disable a check or override its severity.
`docs/CONTROLS.md` is generated from the registry so the mapping cannot drift from the code.

## Gate

Fails on: any finding at or above `gate.fail_on`; any non-info finding on a `gate.fail_on_controls` control; more than
`gate.max_unknown_category_ratio` of tools unclassified; or a connection failure. Exit code 1 is the only contract CI needs.

## Baselines (rug pulls)

`mcpeval baseline approve` stores the manifest under `$MCPEVAL_HOME/baselines/<hash-of-target>.json`. Later scans diff per-tool content
hashes (name, description, schema, annotations) and report added, removed and changed tools with before/after descriptions.

## Discovery

`discover/endpoint.py` reads the config files of ~25 clients plus project-level files under common code directories, normalizes every
server definition, flags literal credentials, unpinned launchers and plaintext HTTP, and lists running processes that look like MCP servers.
`discover/repo.py` finds SDK dependencies, server code patterns and committed configs. `discover/aws.py` (boto3, read-only) lists AgentCore
gateways and their authorizers, ECS task definitions and Lambda functions that mention MCP, recent `CreateGateway*` CloudTrail events,
Config items, prod/non-prod co-location in one ECS cluster, and task roles that humans can also assume. `discover/inventory.py` merges all
of it and compares with `policy.allowlist.servers`.

## What is deliberately not here

A runtime proxy or gateway. Per-call authorization and audit belong in Bedrock AgentCore Gateway (Policy), ToolHive, Docker MCP Gateway or
Teleport; the scanner produces the evidence those policies should encode. Also not here: a vulnerability scanner for the server's own
dependency tree (use Trivy / Grype / OSV-Scanner on the resolved artifact; `SUPPLY-002` only queries OSV for the launched package itself).
