"""Manifest-lane checks: run against the captured ServerManifest (no tool is ever invoked).

Check ID prefixes:
  NAME   tool naming convention            (BP-NAMING)
  ANNOT  tool annotations                  (BP-CATEGORIZE)
  CAT    category + HITL expectations      (BP-CATEGORIZE, BP-HITL-DML, BP-HITL-DDL, BP-SECURE-DEFAULT)
  DECPL  tool vs resource separation       (BP-DECOUPLE)
  LAZY   token budget / lazy fetch         (BP-LAZY-FETCH)
  IDEMP  idempotency                       (BP-IDEMPOTENT)
  INPUT  input validation on mutators      (BP-INPUT-VALIDATION)
  SECRT  secrets in definitions            (SEC-SECRETS, BP-SHORT-TOKENS)
  POISN  tool poisoning / injection        (SEC-TOOL-POISONING)
  RUG    drift / rug pull / server-initiated requests (SEC-RUG-PULL)
  META   server metadata hygiene
"""
from __future__ import annotations

import json
import re
import unicodedata
from collections import Counter
from typing import Iterable

from ..classify.lexicon import (AGGREGATE_VERBS, DDL_VERBS, DML_VERBS, READ_VERBS, split_name, tokenize)
from ..models import Category, Confidence, Finding, Lane, Severity, ToolRecord
from .base import Check, CheckContext, register

SPEC_SBP = "https://modelcontextprotocol.io/specification/draft/basic/security_best_practices"
SPEC_TOOLS = "https://modelcontextprotocol.io/specification/draft/server/tools"
MUTATING = {Category.DML, Category.DDL}


def _text_blobs(tool: ToolRecord) -> list[tuple[str, str]]:
    """All human-readable text attached to a tool: (where, text)."""
    out = [("description", tool.description or ""), ("title", tool.title or "")]
    if tool.annotations and tool.annotations.get("title"):
        out.append(("annotations.title", str(tool.annotations["title"])))

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("description", "title", "default", "examples", "const", "pattern") and isinstance(v, (str, int, float)):
                    out.append((f"inputSchema.{path}{k}", str(v)))
                elif k == "enum" and isinstance(v, list):
                    out.append((f"inputSchema.{path}enum", " ".join(map(str, v))))
                else:
                    walk(v, f"{path}{k}.")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}{i}.")
    walk(tool.input_schema or {}, "")
    walk(tool.output_schema or {}, "outputSchema.")
    if tool.meta:
        out.append(("_meta", json.dumps(tool.meta)))
    return out


def hitl_evidence(tool: ToolRecord, ctx: CheckContext) -> list[str]:
    ev = []
    desc = (tool.description or "").lower()
    if re.search(r"\b(confirm|confirmation|approval|approve[sd]?|ask(s|ed)? (the )?user|requires? (user )?consent|human[- ]in[- ]the[- ]loop|hitl)\b", desc):
        ev.append("description mentions confirmation/approval")
    props = {k.lower() for k in (tool.input_schema or {}).get("properties", {})}
    if props & {"confirm", "confirmed", "confirmation", "dry_run", "dryrun", "approve", "approved", "i_understand", "acknowledge"}:
        ev.append("input schema has a confirm/dry-run parameter")
    elicited = set(ctx.options.get("elicited_tools") or [])
    if tool.name in elicited:
        ev.append("behavior probe observed an elicitation request")
    if (tool.meta or {}).get("anthropic/requiresUserInteraction") is True:
        ev.append("_meta anthropic/requiresUserInteraction=true (client forces a prompt on every call)")
    return ev


# --------------------------------------------------------------------------- #
# NAME
# --------------------------------------------------------------------------- #
@register
class NamePattern(Check):
    id = "NAME-001"
    title = "Tool name does not follow snake_case <backend>_<verb>_<noun> convention"
    controls = ["BP-NAMING"]
    default_severity = Severity.LOW
    references = [SPEC_TOOLS]

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        pol = ctx.policy.get("naming", {})
        pat = re.compile(pol.get("pattern", r"^[a-z][a-z0-9]*(_[a-z0-9]+){1,}$"))
        max_len = int(pol.get("max_length", 64))
        for t in ctx.manifest.tools:
            name = t.name
            if pol.get("accept_gateway_separator", True) and "___" in name:
                name = name.split("___", 1)[1]
            problems = []
            if not pat.match(name):
                problems.append("does not match naming pattern")
            if len(t.name) > max_len:
                problems.append(f"longer than {max_len} chars")
            if not re.match(r"^[A-Za-z0-9_.\-]{1,128}$", t.name):
                problems.append("contains characters outside [A-Za-z0-9_.-] or exceeds 128 chars (spec guidance)")
            if problems:
                yield self.finding(ctx, f"Tool `{t.name}`: {'; '.join(problems)}.", subject=t.name,
                                   remediation="Rename to `<backend>_<verb>_<noun>` in snake_case, e.g. `snow_get_ticket`.",
                                   evidence={"name": t.name, "pattern": pat.pattern})


@register
class NameBackendPrefix(Check):
    id = "NAME-002"
    title = "Tool name lacks a backend-system prefix (collision risk)"
    controls = ["BP-NAMING"]
    default_severity = Severity.MEDIUM

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        pol = ctx.policy.get("naming", {})
        if not pol.get("require_backend_prefix", True):
            return
        known = {k.lower() for k in pol.get("known_backends") or []}
        for t in ctx.manifest.tools:
            name = t.name.split("___", 1)[1] if "___" in t.name else t.name
            parts = split_name(name)
            if parts.verb is None:
                continue  # NAME-001 / CAT handles unrecognizable names
            if not parts.backend:
                yield self.finding(ctx, f"Tool `{t.name}` starts with the verb `{parts.verb}`; no backend prefix. "
                                        f"Two servers exposing `{t.name}` will collide in the client's tool namespace and in authorization policy.",
                                   subject=t.name, remediation=f"Rename to e.g. `<backend>_{name}`.",
                                   evidence={"verb": parts.verb, "tokens": parts.tokens})
            elif known and parts.backend not in known:
                yield self.finding(ctx, f"Tool `{t.name}` uses backend prefix `{parts.backend}` which is not in the policy's known_backends list.",
                                   subject=t.name, severity=Severity.LOW,
                                   remediation=f"Use one of {sorted(known)} or add `{parts.backend}` to policy.naming.known_backends.",
                                   evidence={"backend": parts.backend})


@register
class NameCollision(Check):
    id = "NAME-003"
    title = "Tool names collide or are near-duplicates"
    controls = ["BP-NAMING"]
    default_severity = Severity.MEDIUM
    mappings = {"owasp_mcp": ["MCP03 Tool Poisoning"], "attack": ["tool-shadowing", "typosquatting"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        norm = Counter("".join(tokenize(t.name)) for t in ctx.manifest.tools)
        for key, n in norm.items():
            if n > 1:
                names = [t.name for t in ctx.manifest.tools if "".join(tokenize(t.name)) == key]
                yield self.finding(ctx, f"Tools {names} normalize to the same identifier; clients and authorization policies cannot distinguish them.",
                                   subject=names[0], evidence={"names": names})
        exact = Counter(t.name for t in ctx.manifest.tools)
        for name, n in exact.items():
            if n > 1:
                yield self.finding(ctx, f"Tool `{name}` is advertised {n} times.", subject=name, severity=Severity.HIGH)


# --------------------------------------------------------------------------- #
# ANNOT
# --------------------------------------------------------------------------- #
@register
class AnnotationsMissing(Check):
    id = "ANNOT-001"
    title = "Tool has no ToolAnnotations (readOnlyHint/destructiveHint/idempotentHint)"
    controls = ["BP-CATEGORIZE"]
    default_severity = Severity.LOW
    references = [SPEC_TOOLS]

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for t in ctx.manifest.tools:
            ann = t.annotations or {}
            if not any(k in ann for k in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")):
                sev = Severity.MEDIUM if t.category in MUTATING else Severity.LOW
                yield self.finding(ctx, f"Tool `{t.name}` (classified {t.category.value}) declares no behavioral annotations; clients cannot apply "
                                        f"category-based confirmation or least-privilege policy.",
                                   subject=t.name, severity=sev,
                                   remediation="Set annotations {readOnlyHint, destructiveHint, idempotentHint, openWorldHint} accurately on every tool.")


@register
class AnnotationsContradict(Check):
    id = "ANNOT-002"
    title = "Tool annotations contradict the tool's evident behavior"
    controls = ["BP-CATEGORIZE", "SEC-TOOL-POISONING"]
    default_severity = Severity.HIGH
    references = [SPEC_TOOLS]
    mappings = {"attack": ["annotation-spoofing"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for t in ctx.manifest.tools:
            ro = t.hint("readOnlyHint")
            lex = t.category_sources.get("lexicon")
            if ro is True and lex in ("dml", "ddl"):
                yield self.finding(ctx, f"Tool `{t.name}` is annotated readOnlyHint=true but its name/schema indicate a {lex.upper()} operation. "
                                        f"A client trusting the hint would skip confirmation for a mutating action.",
                                   subject=t.name, evidence={"annotations": t.annotations, "lexicon": lex, "rationale": t.category_rationale},
                                   remediation="Fix the annotation (readOnlyHint=false, destructiveHint as appropriate) or rename the tool.")
            d = t.hint("destructiveHint")
            parts = split_name(t.name.split("___")[-1])
            if d is False and parts.verb in {"delete", "remove", "drop", "destroy", "purge", "terminate", "truncate", "teardown", "revoke"}:
                yield self.finding(ctx, f"Tool `{t.name}` is annotated destructiveHint=false but the verb `{parts.verb}` is destructive.",
                                   subject=t.name, severity=Severity.MEDIUM, evidence={"annotations": t.annotations})


# --------------------------------------------------------------------------- #
# CAT / HITL
# --------------------------------------------------------------------------- #
@register
class CategoryUnknown(Check):
    id = "CAT-001"
    title = "Tool could not be classified into Read/Aggregate/DML/DDL"
    controls = ["BP-CATEGORIZE", "BP-SECURE-DEFAULT"]
    default_severity = Severity.MEDIUM

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        floor = float(ctx.policy.get("classifier", {}).get("escalate_below_confidence", 0.6))
        for t in ctx.manifest.tools:
            if t.category is Category.UNKNOWN or t.category_confidence < floor:
                yield self.finding(ctx, f"Tool `{t.name}` classified as `{t.category.value}` with confidence {t.category_confidence} "
                                        f"({t.category_rationale or 'no signal'}). Policy fails closed: treat as DDL (HITL required) until a human assigns a category.",
                                   subject=t.name, confidence=Confidence.MEDIUM,
                                   evidence={"category": t.category.value, "confidence": t.category_confidence, "sources": t.category_sources},
                                   remediation="Use an action verb from the lexicon in the name, add accurate annotations, and write a description that states side effects.")


@register
class DdlRequiresHitl(Check):
    id = "CAT-002"
    title = "DDL tool without human-in-the-loop evidence"
    controls = ["BP-HITL-DDL", "BP-SECURE-DEFAULT", "BP-HITL-IMPACT"]
    default_severity = Severity.HIGH
    references = [SPEC_SBP]
    mappings = {"owasp_agentic": ["ASI03 Excessive Agency"], "owasp_llm": ["LLM06 Excessive Agency"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for t in ctx.manifest.tools:
            if t.category is not Category.DDL:
                continue
            ev = hitl_evidence(t, ctx)
            if not ev:
                yield self.finding(ctx, f"Tool `{t.name}` is a DDL/infra-definition operation ({t.category_rationale}). Policy requires HITL and denies "
                                        f"autonomous use, but nothing indicates a confirmation step (no elicitation, no confirm parameter, no mention in description).",
                                   subject=t.name, evidence={"rationale": t.category_rationale, "annotations": t.annotations},
                                   remediation="Implement elicitation (ctx.elicit) with an impact statement naming the resource and account, or gate the tool "
                                               "behind a client-side 'always ask' policy and document it. Deny this tool to autonomous agent roles.")
            else:
                yield self.finding(ctx, f"DDL tool `{t.name}` has HITL evidence: {ev}. Verify the confirmation states impact explicitly.",
                                   subject=t.name, severity=Severity.INFO, evidence={"hitl_evidence": ev})


@register
class DmlRecommendsHitl(Check):
    id = "CAT-003"
    title = "DML tool without human-in-the-loop evidence"
    controls = ["BP-HITL-DML", "BP-SECURE-DEFAULT"]
    default_severity = Severity.MEDIUM
    references = [SPEC_SBP]
    mappings = {"owasp_agentic": ["ASI03 Excessive Agency"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for t in ctx.manifest.tools:
            if t.category is not Category.DML:
                continue
            if not hitl_evidence(t, ctx):
                sev = Severity.HIGH if t.hint("destructiveHint") is not False and split_name(t.name.split("___")[-1]).verb in {"delete", "remove", "purge", "destroy"} else Severity.MEDIUM
                yield self.finding(ctx, f"Tool `{t.name}` mutates business data ({t.category_rationale}) with no confirmation evidence.",
                                   subject=t.name, severity=sev,
                                   remediation="Add elicitation-based confirmation stating what will change and where; mark destructiveHint accurately.")


@register
class FreeFormExecution(Check):
    id = "CAT-004"
    title = "Tool accepts free-form code / SQL / shell commands"
    controls = ["BP-HITL-DDL", "BP-INPUT-VALIDATION", "BP-LEAST-PRIV"]
    default_severity = Severity.HIGH
    mappings = {"owasp_mcp": ["MCP05 Command Injection"], "owasp_agentic": ["ASI05 Unexpected Code Execution"], "cwe": ["CWE-78", "CWE-89", "CWE-94"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for t in ctx.manifest.tools:
            props = {k.lower(): v for k, v in (t.input_schema or {}).get("properties", {}).items()}
            hits = [k for k in props if k in {"sql", "query_string", "statement", "command", "cmd", "script", "code", "shell", "bash", "expression", "jq", "regex_replace"}]
            toks = set(tokenize(t.name))
            if toks & {"sql", "exec", "execute", "shell", "bash", "eval", "run"} and not hits:
                hits = [k for k in props if props[k].get("type") == "string"]
            if hits:
                yield self.finding(ctx, f"Tool `{t.name}` takes free-form executable input via {hits}. This is unbounded DDL-class capability: "
                                        f"any prompt injection becomes code execution against the backend.",
                                   subject=t.name, evidence={"params": hits},
                                   remediation="Replace with narrowly-typed tools per operation (enum of allowed actions, parameterized queries), enforce read-only "
                                               "connections for query tools, and require HITL for anything else.")


@register
class MixedCategoriesNoGrouping(Check):
    id = "CAT-005"
    title = "Server mixes DDL/DML and read tools without a grouping structure"
    controls = ["BP-STRUCTURE", "BP-LEAST-PRIV"]
    default_severity = Severity.LOW
    requires_manifest = True

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        cats = Counter(t.category for t in ctx.manifest.tools)
        backends = Counter((split_name(t.name.split("___")[-1]).backend or "<none>") for t in ctx.manifest.tools)
        if cats.get(Category.DDL) and (cats.get(Category.READ) or cats.get(Category.AGGREGATE)) and len(cats) >= 3:
            yield self.finding(ctx, f"Server exposes {dict((k.value, v) for k, v in cats.items())} across backends {dict(backends)}. One credential/role "
                                    f"covers both passive reads and infrastructure definition; least privilege cannot be applied per category.",
                               remediation="Split into separate servers (or FastMCP mounted sub-servers / AgentCore Gateway targets) per category or backend "
                                           "so that agent roles can be granted read/aggregate only.",
                               evidence={"categories": {k.value: v for k, v in cats.items()}, "backends": dict(backends)})


# --------------------------------------------------------------------------- #
# DECPL (tools vs resources)
# --------------------------------------------------------------------------- #
@register
class StaticDocAsTool(Check):
    id = "DECPL-001"
    title = "Static/read-only document exposed as a tool instead of a resource"
    controls = ["BP-DECOUPLE"]
    default_severity = Severity.MEDIUM
    references = ["https://modelcontextprotocol.io/specification/draft/server/resources"]

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        doc_nouns = {"doc", "docs", "document", "documentation", "readme", "runbook", "guide", "manual", "policy", "faq", "help", "schema", "spec", "changelog", "template"}
        for t in ctx.manifest.tools:
            props = (t.input_schema or {}).get("properties", {}) or {}
            toks = set(tokenize(t.name))
            if t.category in (Category.READ, Category.UNKNOWN) and (toks & doc_nouns) and len(props) == 0:
                yield self.finding(ctx, f"Tool `{t.name}` takes no arguments and returns a document; it is a resource, not a tool. Tools are model-controlled "
                                        f"(the LLM decides to call them); resources are application-controlled and cannot be weaponized by injection.",
                                   subject=t.name, remediation="Expose it via resources/list with a stable URI (e.g. `snow://runbook/on-call`).")


# --------------------------------------------------------------------------- #
# LAZY
# --------------------------------------------------------------------------- #
def _approx_tokens(s: str) -> int:
    return max(1, len(s) // 4)


@register
class TooManyTools(Check):
    id = "LAZY-001"
    title = "Tool surface too large for eager discovery"
    controls = ["BP-LAZY-FETCH"]
    default_severity = Severity.MEDIUM

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        pol = ctx.policy.get("lazy_fetch", {})
        mx = int(pol.get("max_tools_per_server", 40))
        n = len(ctx.manifest.tools)
        if n > mx:
            yield self.finding(ctx, f"Server advertises {n} tools (policy max {mx}). Every tool definition is sent to the model on each session; "
                                    f"this wastes tokens and widens the injection surface.",
                               evidence={"tool_count": n},
                               remediation="Front with a gateway that routes dynamically (Bedrock AgentCore Gateway semantic search, MCP gateway) or split into "
                                           "domain servers; use FastMCP tag filtering / mounting to expose only the needed subset.")


@register
class DefinitionTokenBudget(Check):
    id = "LAZY-002"
    title = "tools/list payload exceeds token budget"
    controls = ["BP-LAZY-FETCH"]
    default_severity = Severity.MEDIUM

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        pol = ctx.policy.get("lazy_fetch", {})
        budget = int(pol.get("max_definition_tokens", 12000))
        payload = json.dumps([t.raw for t in ctx.manifest.tools], separators=(",", ":"))
        toks = _approx_tokens(payload)
        if toks > budget:
            yield self.finding(ctx, f"Full tool definitions are ~{toks} tokens (policy budget {budget}).", evidence={"approx_tokens": toks, "bytes": len(payload)},
                               remediation="Shorten descriptions, drop redundant schema prose, and adopt lazy discovery.")
        mx_desc = int(pol.get("max_description_chars", 1500))
        for t in ctx.manifest.tools:
            if len(t.description or "") > mx_desc:
                yield self.finding(ctx, f"Tool `{t.name}` description is {len(t.description)} chars (> {mx_desc}).", subject=t.name, severity=Severity.LOW,
                                   title="Tool description bloat")


# --------------------------------------------------------------------------- #
# IDEMP
# --------------------------------------------------------------------------- #
@register
class CreateNotIdempotent(Check):
    id = "IDEMP-001"
    title = "Create/update tool gives no idempotency guarantee"
    controls = ["BP-IDEMPOTENT"]
    default_severity = Severity.LOW

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for t in ctx.manifest.tools:
            if t.category not in MUTATING:
                continue
            parts = split_name(t.name.split("___")[-1])
            if parts.verb not in {"create", "add", "insert", "new", "post", "submit", "send", "upload", "provision", "launch", "deploy"}:
                continue
            props = {k.lower() for k in (t.input_schema or {}).get("properties", {})}
            has_key = bool(props & {"id", "key", "idempotency_key", "idempotencykey", "external_id", "externalid", "request_id", "client_token", "clienttoken", "ticket_id", "name"})
            if t.hint("idempotentHint") is True and has_key:
                continue
            yield self.finding(ctx, f"Tool `{t.name}` creates records but {'does not declare idempotentHint=true' if t.hint('idempotentHint') is not True else ''}"
                                    f"{' and ' if t.hint('idempotentHint') is not True and not has_key else ''}"
                                    f"{'accepts no natural/idempotency key' if not has_key else ''}. Retries by an agent will create duplicates.",
                               subject=t.name, evidence={"idempotentHint": t.hint("idempotentHint"), "has_key_param": has_key},
                               remediation="Implement create-if-absent / update-if-present keyed on a client-supplied id, and set idempotentHint=true.")


# --------------------------------------------------------------------------- #
# INPUT
# --------------------------------------------------------------------------- #
@register
class UnconstrainedMutatorInputs(Check):
    id = "INPUT-001"
    title = "Mutating tool accepts unconstrained free-text parameters"
    controls = ["BP-INPUT-VALIDATION"]
    default_severity = Severity.MEDIUM
    mappings = {"owasp_llm": ["LLM01 Prompt Injection"], "cwe": ["CWE-20"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for t in ctx.manifest.tools:
            if t.category not in MUTATING:
                continue
            schema = t.input_schema or {}
            props = schema.get("properties", {}) or {}
            loose = []
            for k, v in props.items():
                if not isinstance(v, dict):
                    continue
                if v.get("type") == "string" and not any(x in v for x in ("pattern", "enum", "maxLength", "format", "const")):
                    loose.append(k)
            if not props:
                continue
            if loose:
                yield self.finding(ctx, f"Tool `{t.name}` ({t.category.value}) has unconstrained string parameters {loose} (no pattern/enum/maxLength/format). "
                                        f"The server must validate these before acting; the schema gives no evidence that it does.",
                                   subject=t.name, confidence=Confidence.MEDIUM, evidence={"loose_params": loose},
                                   remediation="Constrain with pattern/enum/maxLength in the schema (pydantic Field in FastMCP) and validate server-side before the mutation.")
            if schema.get("additionalProperties") not in (False, None) or ("additionalProperties" not in schema):
                yield self.finding(ctx, f"Tool `{t.name}` schema does not set additionalProperties=false; unexpected arguments are silently accepted.",
                                   subject=t.name, severity=Severity.LOW, title="Mutating tool schema allows additional properties")


# --------------------------------------------------------------------------- #
# SECRT
# --------------------------------------------------------------------------- #
SECRET_PATTERNS = {
    "aws_access_key_id": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws_secret_key": re.compile(r"(?i)aws(.{0,20})?(secret|private)?(.{0,20})?['\"]?[0-9a-zA-Z/+]{40}['\"]?"),
    "anthropic_api_key": re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    "openai_api_key": re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{20,}\b"),
    "github_token": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|github_pat_[A-Za-z0-9_]{60,}"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "bearer_header": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-_\.=]{20,}"),
    "password_assignment": re.compile(r"(?i)\b(password|passwd|pwd|api[_-]?key|secret|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
    "stripe_key": re.compile(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\b"),
    "basic_auth_url": re.compile(r"[a-z]+://[^/\s:]+:[^@/\s]+@"),
}


@register
class SecretsInDefinitions(Check):
    id = "SECRT-001"
    title = "Credential material embedded in tool/prompt/server definitions"
    controls = ["SEC-SECRETS", "BP-SHORT-TOKENS"]
    default_severity = Severity.CRITICAL
    mappings = {"owasp_mcp": ["MCP01 Token Mismanagement"], "owasp_llm": ["LLM02 Sensitive Information Disclosure"], "cwe": ["CWE-798"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        blobs: list[tuple[str, str, str]] = []
        for t in ctx.manifest.tools:
            blobs += [(t.name, w, s) for w, s in _text_blobs(t)]
        for p in ctx.manifest.prompts:
            blobs.append((p.name, "prompt.description", p.description or ""))
        for r in ctx.manifest.resources:
            blobs.append((r.uri, "resource.uri", r.uri))
            blobs.append((r.uri, "resource.description", r.description or ""))
        blobs.append(("<server>", "instructions", ctx.manifest.instructions or ""))
        for subject, where, text in blobs:
            for kind, pat in SECRET_PATTERNS.items():
                m = pat.search(text)
                if m:
                    yield self.finding(ctx, f"`{subject}` {where} contains what looks like a {kind}: `{m.group(0)[:12]}…`.",
                                       subject=subject, evidence={"kind": kind, "where": where, "sample": m.group(0)[:16] + "…"},
                                       remediation="Remove the credential, rotate it immediately, and source credentials from the runtime (IAM role / OAuth) not from definitions.")


# --------------------------------------------------------------------------- #
# POISN
# --------------------------------------------------------------------------- #
INJECTION_PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
    ("hidden-instruction-tag", re.compile(r"<\s*/?\s*(important|system|instructions?|hidden|secret|admin|override|rule|sys)\b[^>]*>", re.I), Severity.CRITICAL),
    ("ignore-previous", re.compile(r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|system)\b.{0,30}\b(instructions?|prompts?|rules?|guidelines?)\b", re.I), Severity.CRITICAL),
    ("conceal-from-user", re.compile(r"\b(do not|don'?t|never)\b.{0,30}\b(tell|mention|reveal|show|disclose|inform|explain)\b.{0,30}\b(user|human|them|anyone)\b", re.I), Severity.CRITICAL),
    ("sensitive-file-path", re.compile(r"(~|\$HOME|/root|/home/\w+|/Users/\w+)?/(\.ssh|\.aws|\.gnupg|\.config/gh|\.netrc|\.env|\.kube|\.docker/config\.json)\b|\b(id_rsa|id_ed25519|credentials|\.npmrc|\.pypirc)\b", re.I), Severity.CRITICAL),
    ("exfil-channel", re.compile(r"\b(send|forward|post|upload|transmit|bcc|cc|email)\b.{0,60}\b(to|at)\b.{0,10}([\w.+-]+@[\w-]+\.[\w.]+|https?://)", re.I), Severity.CRITICAL),
    ("pre-call-coercion", re.compile(r"\b(before|prior to|first|always)\b.{0,20}\b(using|calling|invoking|running)\b.{0,20}\b(this|any|the)\b.{0,10}\btools?\b", re.I), Severity.HIGH),
    ("other-tool-override", re.compile(r"\b(when|whenever|if)\b.{0,30}\b(user|agent|you)\b.{0,30}\b(use|call|invoke)s?\b.{0,40}\b(other|another|any)\b.{0,10}\btools?\b", re.I), Severity.HIGH),
    ("always-never-directive", re.compile(r"\b(always|never)\b.{0,10}\b(include|add|append|prepend|set|use|pass|send|call|reveal|say)\b", re.I), Severity.MEDIUM),
    ("system-prompt-ref", re.compile(r"\bsystem prompt\b|\bdeveloper message\b|\byou are (now )?(a|an)\b.{0,30}\b(assistant|agent|model)\b", re.I), Severity.HIGH),
    ("env-var-harvest", re.compile(r"\b(environment variables?|env vars?|process\.env|os\.environ|printenv)\b", re.I), Severity.HIGH),
    ("urgency-social", re.compile(r"\b(critical|urgent|immediately|must comply|mandatory|required by (law|policy|admin))\b", re.I), Severity.LOW),
    ("markdown-image-exfil", re.compile(r"!\[[^\]]*\]\(https?://[^)]+\)", re.I), Severity.HIGH),
]
_INVISIBLE = {"​", "‌", "‍", "⁠", "﻿", "­", "‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩", "͏", "ᅟ", "ᅠ", "឴", "឵", "᠎", "ㅤ", "ﾠ"}


@register
class ToolPoisoningHeuristics(Check):
    id = "POISN-001"
    title = "Tool description contains hidden instructions / prompt injection patterns"
    controls = ["SEC-TOOL-POISONING"]
    default_severity = Severity.CRITICAL
    references = ["https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks", SPEC_SBP]
    mappings = {"owasp_mcp": ["MCP03 Tool Poisoning"], "owasp_llm": ["LLM01 Prompt Injection"], "owasp_agentic": ["ASI01 Agent Goal Hijack"], "mitre_atlas": ["AML.T0051 LLM Prompt Injection"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        items: list[tuple[str, str, str]] = []
        for t in ctx.manifest.tools:
            items += [(t.name, w, s) for w, s in _text_blobs(t)]
        for p in ctx.manifest.prompts:
            items.append((p.name, "prompt.description", p.description or ""))
            for a in p.arguments:
                items.append((p.name, f"prompt.argument.{a.get('name')}", str(a.get("description") or "")))
        for subject, where, text in items:
            if not text:
                continue
            hits = [(name, pat.search(text), sev) for name, pat, sev in INJECTION_PATTERNS]
            hits = [(n, m, s) for n, m, s in hits if m]
            if not hits:
                continue
            top = max(hits, key=lambda h: h[2].rank)
            # Low-severity patterns alone (urgency words) are noise; only report if paired or in a schema field
            if top[2] == Severity.LOW and len(hits) == 1 and where == "description":
                continue
            yield self.finding(ctx, f"`{subject}` {where} matches injection pattern(s) {[h[0] for h in hits]}: “{top[1].group(0)[:120]}”.",
                               subject=subject, severity=top[2],
                               evidence={"where": where, "patterns": [h[0] for h in hits], "snippet": text[max(0, top[1].start() - 60): top[1].end() + 60]},
                               remediation="Descriptions must describe what the tool does, never instruct the model. Reject the server (third-party) or fix the text (in-house) and pin the manifest baseline.")


@register
class InvisibleUnicode(Check):
    id = "POISN-002"
    title = "Invisible / bidirectional Unicode in tool text"
    controls = ["SEC-TOOL-POISONING"]
    default_severity = Severity.HIGH
    mappings = {"cwe": ["CWE-94"], "attack": ["ascii-smuggling", "trojan-source"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for t in ctx.manifest.tools:
            for where, text in _text_blobs(t):
                bad = sorted({c for c in text if c in _INVISIBLE or unicodedata.category(c) in ("Cf", "Co", "Cn") or (0xE0000 <= ord(c) <= 0xE007F)})
                if bad:
                    yield self.finding(ctx, f"Tool `{t.name}` {where} contains {len(bad)} kind(s) of invisible/format characters {[f'U+{ord(c):04X}' for c in bad]}; "
                                            f"this is the classic way to hide instructions from human reviewers.",
                                       subject=t.name, evidence={"where": where, "codepoints": [f"U+{ord(c):04X}" for c in bad]},
                                       remediation="Strip non-printing characters; reject servers that ship them.")
            mixed = {unicodedata.name(c, "?").split()[0] for c in t.name if c.isalpha()}
            if len(mixed - {"LATIN"}) and "LATIN" in mixed:
                yield self.finding(ctx, f"Tool name `{t.name}` mixes scripts {sorted(mixed)} (homoglyph / typosquat risk).", subject=t.name, severity=Severity.HIGH,
                                   title="Mixed-script tool name")


@register
class CrossToolReference(Check):
    id = "POISN-003"
    title = "Tool description references other tools or servers (shadowing)"
    controls = ["SEC-TOOL-POISONING"]
    default_severity = Severity.HIGH
    references = ["https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"]
    mappings = {"attack": ["tool-shadowing", "cross-server-escalation"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        names = {t.name for t in ctx.manifest.tools}
        common_foreign = {"send_email", "sendemail", "send_message", "slack_post_message", "create_pull_request", "execute_command", "run_command", "write_file", "read_file", "bash", "shell"}
        for t in ctx.manifest.tools:
            desc = t.description or ""
            others = [n for n in names if n != t.name and len(n) > 4 and re.search(rf"\b{re.escape(n)}\b", desc)]
            foreign = [n for n in common_foreign if re.search(rf"\b{re.escape(n)}\b", desc, re.I)]
            if others or foreign:
                yield self.finding(ctx, f"Tool `{t.name}` description references other tools {others + foreign}. Descriptions that steer how OTHER tools behave are the "
                                        f"signature of cross-server shadowing attacks.",
                                   subject=t.name, evidence={"referenced": others + foreign}, confidence=Confidence.MEDIUM,
                                   remediation="A tool description must only describe that tool. Remove cross-references.")


@register
class ServerInstructionsInjection(Check):
    id = "POISN-004"
    title = "Server `instructions` contain injection patterns"
    controls = ["SEC-TOOL-POISONING"]
    default_severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        text = ctx.manifest.instructions or ""
        hits = [(n, pat.search(text)) for n, pat, _ in INJECTION_PATTERNS if pat.search(text)]
        if hits:
            yield self.finding(ctx, f"initialize.instructions matches {[h[0] for h in hits]}: “{hits[0][1].group(0)[:100]}”. Instructions are injected into the "
                                    f"client's system prompt by many hosts.",
                               subject="<server>", evidence={"instructions": text[:500]})


# --------------------------------------------------------------------------- #
# RUG / drift / server-initiated traffic
# --------------------------------------------------------------------------- #
@register
class BaselineDrift(Check):
    id = "RUG-001"
    title = "Tool definitions drifted from the approved baseline"
    controls = ["SEC-RUG-PULL"]
    default_severity = Severity.HIGH
    mappings = {"owasp_mcp": ["MCP03 Tool Poisoning", "MCP04 Supply Chain"], "attack": ["rug-pull"]}
    requires_manifest = True

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        base = ctx.baseline
        if base is None:
            yield self.finding(ctx, "No approved baseline manifest found for this target; nothing to compare against. Approve one with `mcpeval baseline approve`.",
                               severity=Severity.INFO, title="No baseline for drift detection")
            return
        cur = {t.name: t for t in ctx.manifest.tools}
        old = {t.name: t for t in base.tools}
        added, removed = sorted(set(cur) - set(old)), sorted(set(old) - set(cur))
        changed = sorted(n for n in set(cur) & set(old) if cur[n].content_hash != old[n].content_hash)
        if added or removed or changed:
            details = {}
            for n in changed:
                d = {}
                if cur[n].description != old[n].description:
                    d["description"] = {"old": (old[n].description or "")[:300], "new": (cur[n].description or "")[:300]}
                if cur[n].input_schema != old[n].input_schema:
                    d["input_schema"] = "changed"
                if cur[n].annotations != old[n].annotations:
                    d["annotations"] = {"old": old[n].annotations, "new": cur[n].annotations}
                details[n] = d
            yield self.finding(ctx, f"Manifest changed since approval {base.captured_at.date()}: added={added} removed={removed} changed={changed}. "
                                    f"A server that changes tool semantics after approval is executing a rug pull unless this change was reviewed.",
                               evidence={"added": added, "removed": removed, "changed": details, "baseline_hash": base.manifest_hash[:16], "current_hash": ctx.manifest.manifest_hash[:16]},
                               remediation="Review the diff; re-approve with `mcpeval baseline approve` only after AppSec sign-off.")


@register
class ListChangedDuringProbe(Check):
    id = "RUG-002"
    title = "Server pushed tools/list_changed during a passive probe"
    controls = ["SEC-RUG-PULL"]
    default_severity = Severity.MEDIUM

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for n in ctx.manifest.notifications:
            if "list_changed" in str(n.get("method", "")):
                yield self.finding(ctx, f"Server sent `{n.get('method')}` unsolicited right after initialize; tool definitions may differ between what was reviewed and what runs.",
                                   evidence={"notification": n}, remediation="Re-fetch tools after the notification and diff against the baseline; treat changes as new approvals.")


@register
class ServerInitiatedRequests(Check):
    id = "RUG-003"
    title = "Server attempted sampling or elicitation during a passive probe"
    controls = ["BP-LEAST-PRIV", "SEC-TOOL-POISONING"]
    default_severity = Severity.HIGH
    mappings = {"attack": ["sampling-abuse", "elicitation-abuse"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        if ctx.manifest.sampling_requests:
            yield self.finding(ctx, f"Server issued {len(ctx.manifest.sampling_requests)} sampling/createMessage request(s) without any tool being called. "
                                    f"The server is trying to drive the client's model (and spend the client's inference budget).",
                               evidence={"first": ctx.manifest.sampling_requests[0]}, remediation="Deny sampling capability for this server; reject if third-party.")
        if ctx.manifest.elicitation_requests:
            yield self.finding(ctx, f"Server issued {len(ctx.manifest.elicitation_requests)} elicitation request(s) during discovery (no tool called). Elicitation is for "
                                    f"confirming a tool action, not for harvesting input at connect time.",
                               severity=Severity.MEDIUM, evidence={"first": ctx.manifest.elicitation_requests[0]})


# --------------------------------------------------------------------------- #
# META
# --------------------------------------------------------------------------- #
@register
class ServerMetadata(Check):
    id = "META-001"
    title = "Server metadata hygiene"
    controls = ["BP-SIGNED", "SEC-SHADOW"]
    default_severity = Severity.LOW

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        info = ctx.manifest.server_info or {}
        if not info.get("version") or info.get("version") in ("0.0.0", "unknown"):
            yield self.finding(ctx, "serverInfo.version is missing; approvals and baselines cannot be tied to a release.", remediation="Set an explicit semantic version.")
        name = (info.get("name") or "").lower()
        if any(name.endswith(x) for x in ("fastmcp", "mcp", "server", "helper")) or name in ("", "fastmcp", "mcp-server", "server"):
            yield self.finding(ctx, f"serverInfo.name `{info.get('name')}` is generic; inventory and allow-listing need a unique, owned name.", severity=Severity.LOW)
        if not ctx.manifest.instructions:
            yield self.finding(ctx, "Server provides no `instructions`; clients get no guidance on intended use or confirmation expectations.", severity=Severity.INFO)
        if ctx.manifest.protocol_version and ctx.manifest.protocol_version < "2025-06-18":
            yield self.finding(ctx, f"Negotiated protocol version {ctx.manifest.protocol_version} predates the OAuth 2.1 / Resource Indicators authorization spec (2025-06-18).",
                               severity=Severity.MEDIUM, title="Outdated MCP protocol version", controls=["BP-PKCE"])


# --------------------------------------------------------------------------- #
# SCHEMA (2026-07-28 spec rules on tool definitions)
# --------------------------------------------------------------------------- #
@register
class SecretInHeaderParam(Check):
    id = "SCHEMA-001"
    title = "Secret-like parameter marked x-mcp-header"
    controls = ["SEC-SECRETS", "BP-SHORT-TOKENS"]
    default_severity = Severity.HIGH
    references = ["https://modelcontextprotocol.io/specification/2026-07-28/server/tools"]
    mappings = {"owasp_mcp": ["MCP01 Token Mismanagement"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        secretish = re.compile(r"(password|passwd|secret|token|api[_-]?key|apikey|credential|auth|ssn|card|cvv|pii)", re.I)
        for t in ctx.manifest.tools:
            for k, v in ((t.input_schema or {}).get("properties") or {}).items():
                if isinstance(v, dict) and v.get("x-mcp-header") and secretish.search(k):
                    yield self.finding(ctx, f"Tool `{t.name}` parameter `{k}` is sent as HTTP header `{v['x-mcp-header']}`; header values are visible to every proxy and log on the path. "
                                            f"Spec: SHOULD NOT mark sensitive parameters with x-mcp-header.", subject=t.name, evidence={"param": k, "header": v["x-mcp-header"]})


@register
class NetworkRefInSchema(Check):
    id = "SCHEMA-002"
    title = "Tool schema references a network URI via $ref"
    controls = ["BP-INPUT-VALIDATION"]
    default_severity = Severity.MEDIUM
    references = ["https://modelcontextprotocol.io/specification/2026-07-28/basic"]
    mappings = {"cwe": ["CWE-918"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        def refs(node, acc):
            if isinstance(node, dict):
                r = node.get("$ref")
                if isinstance(r, str) and r.startswith(("http://", "https://")):
                    acc.append(r)
                for v in node.values():
                    refs(v, acc)
            elif isinstance(node, list):
                for v in node:
                    refs(v, acc)
            return acc
        for t in ctx.manifest.tools:
            found = refs(t.input_schema or {}, []) + refs(t.output_schema or {}, [])
            if found:
                yield self.finding(ctx, f"Tool `{t.name}` schema has network $ref {found[:3]}; clients MUST NOT dereference these automatically (SSRF / schema swap).",
                                   subject=t.name, evidence={"refs": found})
            # crude bloat guard: deeply nested or huge schemas are a DoS vector
            size = len(json.dumps(t.input_schema or {}))
            if size > 50_000:
                yield self.finding(ctx, f"Tool `{t.name}` inputSchema is {size} bytes.", subject=t.name, severity=Severity.LOW, title="Oversized input schema", controls=["BP-LAZY-FETCH"])


@register
class IconScheme(Check):
    id = "SCHEMA-003"
    title = "Tool icon uses a disallowed URI scheme"
    controls = ["SEC-TOOL-POISONING"]
    default_severity = Severity.MEDIUM

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for t in ctx.manifest.tools:
            for icon in (t.raw.get("icons") or []):
                src = str((icon or {}).get("src", ""))
                if src and not src.startswith(("https://", "data:image/")):
                    yield self.finding(ctx, f"Tool `{t.name}` icon src `{src[:80]}` is not https:// or data:image/.", subject=t.name, evidence={"src": src[:200]})


@register
class DeprecatedCapabilities(Check):
    id = "META-002"
    title = "Server relies on capabilities deprecated in MCP 2026-07-28"
    controls = ["BP-LEAST-PRIV"]
    default_severity = Severity.LOW
    references = ["https://modelcontextprotocol.io/specification/2026-07-28/deprecated"]

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        caps = ctx.manifest.capabilities or {}
        if "logging" in caps:
            yield self.finding(ctx, "Server declares the `logging` capability (deprecated; log messages MUST NOT carry secrets or PII).", severity=Severity.INFO)
        if ctx.manifest.sampling_requests:
            yield self.finding(ctx, "Server uses sampling/createMessage (deprecated in 2026-07-28; lets a server drive the client's model and budget).", severity=Severity.MEDIUM)
        if ctx.manifest.transport == "sse":
            yield self.finding(ctx, "Server uses the deprecated HTTP+SSE transport.", severity=Severity.LOW)
