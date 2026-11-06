"""Policy loading, baseline store, and CI gate."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import yaml

from ..models import Category, Finding, ScanResult, ServerManifest, Severity

DEFAULT_POLICY = Path(__file__).with_name("default.yaml")


def _deep_merge(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in (b or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_policy(path: str | None = None, *, search_from: str | None = None) -> dict[str, Any]:
    base = yaml.safe_load(DEFAULT_POLICY.read_text()) or {}
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path))
    else:
        root = Path(search_from or os.getcwd())
        for d in [root, *root.parents]:
            candidates.append(d / ".mcpeval" / "policy.yaml")
            candidates.append(d / "mcpeval.policy.yaml")
    for c in candidates:
        if c.exists():
            override = yaml.safe_load(c.read_text()) or {}
            merged = _deep_merge(base, override)
            merged["_policy_file"] = str(c)
            return merged
    base["_policy_file"] = str(DEFAULT_POLICY)
    return base


# --------------------------------------------------------------------------- #
# Baseline store (.mcpeval/baselines/<hash>.json) -- approved manifests
# --------------------------------------------------------------------------- #
class BaselineStore:
    def __init__(self, root: str | None = None):
        self.root = Path(root or os.environ.get("MCPEVAL_HOME") or ".mcpeval") / "baselines"

    @staticmethod
    def key(target: str) -> str:
        return hashlib.sha256(target.encode()).hexdigest()[:20]

    def path(self, target: str) -> Path:
        return self.root / f"{self.key(target)}.json"

    def load(self, target: str) -> ServerManifest | None:
        p = self.path(target)
        if not p.exists():
            return None
        return ServerManifest.model_validate_json(p.read_text())

    def save(self, manifest: ServerManifest, *, approved_by: str = "") -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        p = self.path(manifest.target)
        data = json.loads(manifest.model_dump_json())
        data["_approved_by"] = approved_by
        p.write_text(json.dumps(data, indent=2, default=str))
        return p


# --------------------------------------------------------------------------- #
# Gate
# --------------------------------------------------------------------------- #
def evaluate_gate(result: ScanResult, policy: dict[str, Any]) -> dict[str, Any]:
    g = policy.get("gate", {})
    fail_on = Severity(g.get("fail_on", "high"))
    fail_controls = set(g.get("fail_on_controls") or [])
    reasons: list[str] = []

    sev_hits = [f for f in result.findings if f.severity.rank >= fail_on.rank]
    if sev_hits:
        reasons.append(f"{len(sev_hits)} finding(s) at or above {fail_on.value}: " + ", ".join(sorted({f.check_id for f in sev_hits})))

    ctrl_hits = [f for f in result.findings if f.severity != Severity.INFO and fail_controls & set(f.control_ids)]
    if ctrl_hits:
        reasons.append("required controls violated: " + ", ".join(sorted({c for f in ctrl_hits for c in f.control_ids if c in fail_controls})))

    if result.manifest and result.manifest.tools:
        unknown = sum(1 for t in result.manifest.tools if t.category is Category.UNKNOWN)
        ratio = unknown / len(result.manifest.tools)
        mx = float(g.get("max_unknown_category_ratio", 0.2))
        if ratio > mx:
            reasons.append(f"{unknown}/{len(result.manifest.tools)} tools unclassifiable ({ratio:.0%} > {mx:.0%})")

    if result.manifest and any(e.startswith("connect:") for e in result.manifest.errors):
        reasons.append("could not connect to the server: " + "; ".join(result.manifest.errors)[:200])

    return {"passed": not reasons, "reason": " | ".join(reasons) if reasons else "no blocking findings",
            "fail_on": fail_on.value, "fail_on_controls": sorted(fail_controls)}
