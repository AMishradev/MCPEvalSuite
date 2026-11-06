"""Opt-in behavior probes (`mcpeval scan --behavior`). Run only against servers you own, in non-prod.

For every tool classified DML/DDL (and, for input validation, every tool with parameters):
  1. input validation: call with arguments that violate the declared schema (wrong types, oversized
     strings, injection-shaped strings). A correct server returns isError=true or a validation error;
     a server that returns a normal result executed on bad input.
  2. HITL: record whether the server asked for confirmation (elicitation / input_required) before acting.
  3. idempotency (create-style tools only): call twice with identical valid-looking arguments and compare.

Nothing here tries to be clever about building valid arguments; it uses schema defaults/examples and
simple placeholders. The point is evidence for the HITL and validation controls, not full fuzzing.
"""
from __future__ import annotations

import json
from typing import Any

from ..models import Category, ServerManifest, ToolRecord
from .connect import Recorder, TargetSpec, make_client

_INJECTION_STRINGS = ["' OR 1=1 --", "$(id)", "../../../../etc/passwd", "<script>alert(1)</script>", "x" * 5000]


def _placeholder(schema: dict[str, Any]) -> Any:
    t = schema.get("type")
    if "default" in schema:
        return schema["default"]
    if schema.get("examples"):
        return schema["examples"][0]
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]
    if t == "string":
        return "INC00001" if schema.get("pattern", "").startswith("^INC") else "mcpeval-probe"
    if t in ("integer", "number"):
        return schema.get("minimum", 1)
    if t == "boolean":
        return True
    if t == "array":
        return []
    if t == "object":
        return {}
    return "mcpeval-probe"


def _valid_args(tool: ToolRecord) -> dict[str, Any]:
    props = (tool.input_schema or {}).get("properties") or {}
    req = set((tool.input_schema or {}).get("required") or props.keys())
    return {k: _placeholder(v if isinstance(v, dict) else {}) for k, v in props.items() if k in req}


def _invalid_args(tool: ToolRecord) -> list[tuple[str, dict[str, Any]]]:
    props = (tool.input_schema or {}).get("properties") or {}
    base = _valid_args(tool)
    cases = []
    for k, v in props.items():
        if not isinstance(v, dict):
            continue
        if v.get("type") == "string":
            cases.append((f"{k}=wrong-type", {**base, k: 12345}))
            cases.append((f"{k}=injection", {**base, k: _INJECTION_STRINGS[0]}))
            if "maxLength" in v or "pattern" in v or "enum" in v:
                cases.append((f"{k}=constraint-violation", {**base, k: "\x00" + "z" * 6000}))
        elif v.get("type") in ("integer", "number"):
            cases.append((f"{k}=wrong-type", {**base, k: "not-a-number"}))
    cases.append(("extra-property", {**base, "mcpeval_unexpected": "x"}))
    return cases[:6]


def _is_error(res: Any) -> bool:
    if getattr(res, "is_error", False):
        return True
    rt = getattr(res, "result_type", None)
    if rt == "input_required":
        return False
    text = json.dumps(getattr(res, "content", None), default=str).lower()
    return any(w in text for w in ("validation error", "invalid", "must be", "expected", "does not match"))


async def run_behavior_probes(spec: TargetSpec, manifest: ServerManifest, *, timeout: float = 30.0) -> dict[str, Any]:
    out: dict[str, Any] = {"elicited_tools": [], "elicitation_messages": {}, "input_validation": {}, "idempotency": {}, "errors": []}
    scratch = ServerManifest(target=manifest.target, transport=manifest.transport)  # keep probe traffic out of the passive manifest
    rec = Recorder(scratch)
    try:
        async with make_client(spec, rec, timeout=timeout) as c:
            for tool in manifest.tools:
                props = (tool.input_schema or {}).get("properties") or {}
                before = len(scratch.elicitation_requests)
                # 1. HITL + idempotency on mutating tools
                if tool.category in (Category.DML, Category.DDL):
                    args = _valid_args(tool)
                    try:
                        r1 = await c.call_tool(tool.name, args)
                        if getattr(r1, "result_type", None) == "input_required" or len(scratch.elicitation_requests) > before:
                            out["elicited_tools"].append(tool.name)
                            out["elicitation_messages"][tool.name] = [e.get("message", "") for e in scratch.elicitation_requests[before:]]
                        else:
                            r2 = await c.call_tool(tool.name, args)
                            same = json.dumps(_dump(r1), sort_keys=True, default=str) == json.dumps(_dump(r2), sort_keys=True, default=str)
                            out["idempotency"][tool.name] = {"same_result": same, "errored": _is_error(r1)}
                    except Exception as e:  # noqa: BLE001
                        if len(scratch.elicitation_requests) > before:
                            out["elicited_tools"].append(tool.name)
                            out["elicitation_messages"][tool.name] = [e.get("message", "") for e in scratch.elicitation_requests[before:]]
                        else:
                            out["errors"].append(f"{tool.name}: {type(e).__name__}: {str(e)[:120]}")
                # 2. input validation on any tool with string/number params
                if props:
                    results = {}
                    for label, bad in _invalid_args(tool):
                        try:
                            r = await c.call_tool(tool.name, bad)
                            results[label] = "rejected" if _is_error(r) else ("elicited" if getattr(r, "result_type", None) == "input_required" else "accepted")
                        except Exception as e:  # noqa: BLE001
                            results[label] = f"rejected({type(e).__name__})"
                    out["input_validation"][tool.name] = results
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"connect: {type(e).__name__}: {e}")
    out["elicited_tools"] = sorted(set(out["elicited_tools"]))
    out["sampling_requests_during_calls"] = len(scratch.sampling_requests)
    return out


def _dump(obj: Any) -> Any:
    if hasattr(obj, "model_dump"):
        return obj.model_dump(by_alias=True, exclude_none=True, mode="json")
    return obj
