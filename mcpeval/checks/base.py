"""Check framework.

A Check is a small, stateless object with:
  id          stable identifier, e.g. "NAME-001"
  controls    best-practice control IDs it enforces (see policy/default.yaml)
  lane        which pipeline lane it belongs to
  run(ctx)    returns a list of Findings

Checks never raise; a crash becomes an INFO finding "check errored" so one bad
check cannot hide the others in a CI run.
"""
from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..models import Confidence, Finding, Lane, ServerManifest, Severity


@dataclass
class CheckContext:
    manifest: ServerManifest | None = None
    policy: dict[str, Any] = field(default_factory=dict)
    source_dir: str | None = None          # for static lane
    baseline: ServerManifest | None = None  # previously approved manifest (rug-pull diff)
    options: dict[str, Any] = field(default_factory=dict)
    llm: Any | None = None                  # optional LLM client wrapper

    @property
    def target(self) -> str:
        return self.manifest.target if self.manifest else (self.source_dir or "")


class Check:
    id: str = "X-000"
    title: str = ""
    controls: list[str] = []
    lane: Lane = Lane.MANIFEST
    default_severity: Severity = Severity.MEDIUM
    references: list[str] = []
    mappings: dict[str, list[str]] = {}
    requires_manifest: bool = True

    def run(self, ctx: CheckContext) -> Iterable[Finding]:  # pragma: no cover - interface
        return []

    # helper
    def finding(
        self,
        ctx: CheckContext,
        message: str,
        *,
        subject: str = "",
        severity: Severity | None = None,
        remediation: str = "",
        evidence: dict[str, Any] | None = None,
        confidence: Confidence = Confidence.HIGH,
        location: dict[str, Any] | None = None,
        title: str | None = None,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            control_ids=list(self.controls),
            title=title or self.title or self.id,
            severity=severity or self.default_severity,
            lane=self.lane,
            message=message,
            remediation=remediation,
            confidence=confidence,
            target=ctx.target,
            subject=subject,
            location=location or {},
            evidence=evidence or {},
            references=list(self.references),
            mappings=dict(self.mappings),
        )


_REGISTRY: dict[str, type[Check]] = {}


def register(cls: type[Check]) -> type[Check]:
    _REGISTRY[cls.id] = cls
    return cls


def all_checks(lanes: set[Lane] | None = None) -> list[Check]:
    out = []
    for cid in sorted(_REGISTRY):
        c = _REGISTRY[cid]()
        if lanes is None or c.lane in lanes:
            out.append(c)
    return out


def run_checks(ctx: CheckContext, checks: Iterable[Check], on_error: Callable[[str, str], None] | None = None) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    ran: list[str] = []
    for chk in checks:
        if chk.requires_manifest and ctx.manifest is None:
            continue
        # policy can disable checks or override severity
        cfg = (ctx.policy.get("checks") or {}).get(chk.id, {})
        if cfg.get("enabled") is False:
            continue
        ran.append(chk.id)
        try:
            produced: list[Finding] = []
            for f in chk.run(ctx):
                if "severity" in cfg:
                    f.severity = Severity(cfg["severity"])
                produced.append(f)
            findings.extend(_collapse(produced, int(ctx.policy.get("max_findings_per_check", 15))))
        except Exception as e:  # noqa: BLE001
            tb = traceback.format_exc(limit=3)
            if on_error:
                on_error(chk.id, tb)
            findings.append(
                Finding(
                    check_id=chk.id, control_ids=list(chk.controls), title=f"{chk.id} errored",
                    severity=Severity.INFO, lane=chk.lane, message=f"check raised {type(e).__name__}: {e}",
                    target=ctx.target, evidence={"traceback": tb},
                )
            )
    return findings, ran


def _collapse(items: list[Finding], limit: int) -> list[Finding]:
    """Fold >limit findings that share (check_id, title, severity) into one roll-up finding.

    Keeps CI output readable when e.g. 40 tools all lack annotations; the full
    subject list is preserved in evidence so nothing is lost.
    """
    if len(items) <= limit:
        return items
    groups: dict[tuple[str, str, str], list[Finding]] = {}
    for f in items:
        groups.setdefault((f.check_id, f.title, f.severity.value), []).append(f)
    out: list[Finding] = []
    for (_, title, _), fs in groups.items():
        if len(fs) <= limit:
            out.extend(fs)
            continue
        head = fs[0].model_copy(deep=True)
        head.subject = f"{len(fs)} subjects"
        head.message = f"{len(fs)} occurrences of: {title}. First: {fs[0].message}"
        head.evidence = {"subjects": [f.subject for f in fs], "sample_evidence": fs[0].evidence}
        out.append(head)
    return out
