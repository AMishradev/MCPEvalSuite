"""Behavior-lane checks over result.metadata["behavior"] (populated by `scan --behavior`)."""
from __future__ import annotations

from typing import Iterable

from ..models import Category, Finding, Lane, Severity
from .base import Check, CheckContext, register


def _beh(ctx: CheckContext) -> dict | None:
    return ctx.options.get("behavior")


@register
class ValidationBypass(Check):
    id = "INPUT-002"
    title = "Tool accepted schema-violating input"
    controls = ["BP-INPUT-VALIDATION"]
    lane = Lane.BEHAVIOR
    default_severity = Severity.HIGH
    mappings = {"owasp_mcp": ["MCP05 Command Injection"], "cwe": ["CWE-20"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        b = _beh(ctx)
        if not b:
            return
        for name, cases in (b.get("input_validation") or {}).items():
            accepted = [k for k, v in cases.items() if v == "accepted"]
            if accepted:
                t = ctx.manifest.tool(name)
                sev = Severity.HIGH if t and t.category in (Category.DML, Category.DDL) else Severity.MEDIUM
                yield self.finding(ctx, f"Tool `{name}` returned a normal result for invalid input cases {accepted}.", subject=name, severity=sev,
                                   evidence={"cases": cases}, remediation="Validate against the schema (types, patterns, lengths) and return isError=true before touching the backend.")


@register
class NotIdempotentObserved(Check):
    id = "IDEMP-002"
    title = "Repeated identical call produced a different result"
    controls = ["BP-IDEMPOTENT"]
    lane = Lane.BEHAVIOR
    default_severity = Severity.MEDIUM

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        b = _beh(ctx)
        if not b:
            return
        for name, r in (b.get("idempotency") or {}).items():
            if r.get("same_result") is False and not r.get("errored"):
                yield self.finding(ctx, f"Tool `{name}` returned different results for two identical calls (e.g. created a duplicate).", subject=name, evidence=r)


@register
class MutationWithoutConfirmation(Check):
    id = "HITL-001"
    title = "Mutating tool executed without asking for confirmation"
    controls = ["BP-HITL-DML", "BP-HITL-DDL", "BP-SECURE-DEFAULT"]
    lane = Lane.BEHAVIOR
    default_severity = Severity.HIGH
    mappings = {"owasp_agentic": ["ASI03 Excessive Agency"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        b = _beh(ctx)
        if not b:
            return
        elicited = set(b.get("elicited_tools") or [])
        for name, r in (b.get("idempotency") or {}).items():
            t = ctx.manifest.tool(name)
            if t and t.category in (Category.DML, Category.DDL) and name not in elicited and not r.get("errored"):
                sev = Severity.CRITICAL if t.category is Category.DDL else Severity.HIGH
                yield self.finding(ctx, f"Tool `{name}` ({t.category.value}) ran to completion on the first call with no elicitation / input_required round-trip.",
                                   subject=name, severity=sev, evidence=r,
                                   remediation="Add elicitation with an explicit impact statement, or deny the tool to autonomous agent roles at the gateway.")


@register
class ConfirmationMessageQuality(Check):
    id = "HITL-002"
    title = "Confirmation message does not state the impact explicitly"
    controls = ["BP-HITL-IMPACT"]
    lane = Lane.BEHAVIOR
    default_severity = Severity.MEDIUM

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        import re

        b = _beh(ctx)
        if not b:
            return
        for name, msgs in (b.get("elicitation_messages") or {}).items():
            t = ctx.manifest.tool(name)
            for msg in msgs:
                m = msg or ""
                missing = []
                if not re.search(r"\b(will|is going to|about to)\b", m, re.I):
                    missing.append("states the action ('This will ...')")
                if not re.search(r"[A-Z]{2,}-?\d{2,}|\b\d{3,}\b|'[^']{2,}'|`[^`]{2,}`|<new>", m):
                    missing.append("names the specific resource")
                if not re.search(r"\b(account|instance|environment|region|tenant|workspace|project|org|prod|production|staging|cluster|database|repo)\b", m, re.I):
                    missing.append("names where (account / instance / environment)")
                destructive = t is not None and (t.hint("destructiveHint") is True or t.category is Category.DDL or
                                                 re.search(r"\b(delete|remove|drop|destroy|terminate|purge)\b", name, re.I))
                if destructive and not re.search(r"\b(permanent|permanently|cannot be undone|irreversible|not reversible|no undo)\b", m, re.I):
                    missing.append("states irreversibility for a destructive action")
                if missing:
                    yield self.finding(ctx, f"Tool `{name}` confirmation “{m[:140]}” is missing: {missing}.", subject=name, evidence={"message": m, "missing": missing},
                                       remediation='Follow the pattern "This will <action> <resource> in <account/instance>. <Irreversibility>. Proceed?"')
