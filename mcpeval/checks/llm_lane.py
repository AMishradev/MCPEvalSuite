"""Findings derived from the LLM lane (stored on tool.meta["mcpeval/llm"] by classify/llm.py)."""
from __future__ import annotations

from typing import Iterable

from ..models import Category, Confidence, Finding, Severity
from .base import Check, CheckContext, register


@register
class LlmInjectionVerdict(Check):
    id = "POISN-005"
    title = "LLM judge flagged hidden instructions in tool text"
    controls = ["SEC-TOOL-POISONING"]
    default_severity = Severity.HIGH
    mappings = {"owasp_mcp": ["MCP03 Tool Poisoning"], "owasp_llm": ["LLM01 Prompt Injection"]}

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for t in ctx.manifest.tools:
            v = (t.meta or {}).get("mcpeval/llm") or {}
            if v.get("injection_suspected"):
                yield self.finding(ctx, f"Tool `{t.name}`: {v.get('injection_rationale', '')[:300]}", subject=t.name, confidence=Confidence.MEDIUM,
                                   evidence={"llm": v}, remediation="Review the description manually; reject or fix.")


@register
class LlmHitlDisagreement(Check):
    id = "CAT-006"
    title = "LLM judge says the tool needs confirmation but no HITL evidence exists"
    controls = ["BP-SECURE-DEFAULT", "BP-HITL-DML"]
    default_severity = Severity.MEDIUM

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        from .manifest import hitl_evidence

        for t in ctx.manifest.tools:
            v = (t.meta or {}).get("mcpeval/llm") or {}
            if v.get("requires_hitl") and t.category in (Category.READ, Category.AGGREGATE) and not hitl_evidence(t, ctx):
                yield self.finding(ctx, f"Tool `{t.name}` is classified {t.category.value} but the LLM judge believes it has side effects: {v.get('side_effects')}",
                                   subject=t.name, confidence=Confidence.LOW, evidence={"llm": v})
