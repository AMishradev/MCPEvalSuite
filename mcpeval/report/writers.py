"""Report writers: JSON, SARIF 2.1.0 (GitHub code scanning), ASFF (AWS Security Hub), Markdown."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from ..models import Finding, ScanResult, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
    Severity.LOW: "note", Severity.INFO: "note",
}
_SARIF_SECURITY_SEVERITY = {  # GitHub uses this to bucket critical/high/medium/low
    Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "2.5", Severity.INFO: "0.5",
}
_ASFF_SEVERITY = {
    Severity.CRITICAL: "CRITICAL", Severity.HIGH: "HIGH", Severity.MEDIUM: "MEDIUM", Severity.LOW: "LOW", Severity.INFO: "INFORMATIONAL",
}


def to_json(result: ScanResult, *, include_manifest: bool = True) -> str:
    data = result.model_dump(mode="json", exclude_none=True)
    if not include_manifest:
        data.pop("manifest", None)
    data["summary"] = result.summary()
    return json.dumps(data, indent=2, default=str)


def _sarif_uri(file: str | None, target: str) -> str:
    """GitHub code scanning wants repo-relative paths without a scheme; non-file findings get a stable pseudo-path."""
    if file:
        try:
            return os.path.relpath(file, os.getcwd()).replace(os.sep, "/")
        except ValueError:
            return file.replace(os.sep, "/")
    return "mcpeval/targets/" + re.sub(r"[^A-Za-z0-9._-]+", "_", target or "unknown").strip("_")[:120] + ".mcp"


def to_sarif(result: ScanResult) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in result.findings:
        if f.check_id not in rules:
            rules[f.check_id] = {
                "id": f.check_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.title},
                "help": {"text": f.remediation or f.title, "markdown": f.remediation or f.title},
                "helpUri": (f.references[0] if f.references else "https://modelcontextprotocol.io/specification/draft/basic/security_best_practices"),
                "properties": {
                    "tags": ["security", "mcp", *[f"control/{c}" for c in f.control_ids],
                             *[f"{k}/{v}" for k, vs in f.mappings.items() for v in vs]],
                    "security-severity": _SARIF_SECURITY_SEVERITY[f.severity],
                    "precision": {"high": "high", "medium": "medium", "low": "low"}[f.confidence.value],
                },
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
            }
        loc_file = _sarif_uri(f.location.get("file"), f.target)
        region = {"startLine": int(f.location.get("line", 1) or 1)}
        results.append({
            "ruleId": f.check_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.message}" + (f"\n\nRemediation: {f.remediation}" if f.remediation else "")},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": loc_file}, "region": region},
                "logicalLocations": [{"name": f.subject or f.target, "kind": "tool" if f.subject else "server"}],
            }],
            "partialFingerprints": {"mcpeval/v1": f.fingerprint},
            "properties": {"lane": f.lane.value, "subject": f.subject, "evidence": f.evidence, "controls": f.control_ids},
        })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": result.tool_name, "version": result.tool_version,
                "informationUri": "https://github.com/your-org/MCPEvalSuite",
                "rules": list(rules.values()),
            }},
            "invocations": [{"executionSuccessful": True, "endTimeUtc": (result.finished_at or datetime.now(timezone.utc)).isoformat()}],
            "results": results,
            "properties": {"target": result.target, "gate": result.gate, "summary": result.summary()},
        }],
    }
    return json.dumps(sarif, indent=2, default=str)


def to_asff(result: ScanResult, *, aws_account_id: str = "000000000000", region: str = "us-east-1",
            product_name: str = "MCPEvalSuite", company_name: str = "AppSec") -> str:
    """AWS Security Finding Format for `securityhub batch-import-findings` (custom product).

    ProductArn for a custom integration: arn:aws:securityhub:<region>:<account>:product/<account>/default
    """
    now = datetime.now(timezone.utc).isoformat()
    product_arn = f"arn:aws:securityhub:{region}:{aws_account_id}:product/{aws_account_id}/default"
    findings = []
    for f in result.findings:
        if f.severity == Severity.INFO:
            continue
        findings.append({
            "SchemaVersion": "2018-10-08",
            "Id": f"mcpeval/{f.fingerprint}",
            "ProductArn": product_arn,
            "ProductName": product_name,
            "CompanyName": company_name,
            "GeneratorId": f"mcpeval/{f.check_id}",
            "AwsAccountId": aws_account_id,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices/MCP"],
            "CreatedAt": now,
            "UpdatedAt": now,
            "Severity": {"Label": _ASFF_SEVERITY[f.severity]},
            "Confidence": {"high": 90, "medium": 60, "low": 30}[f.confidence.value],
            "Title": f"[MCP] {f.title}"[:256],
            "Description": f.message[:1024],
            "Remediation": {"Recommendation": {"Text": (f.remediation or "See MCPEvalSuite report")[:512],
                                                "Url": f.references[0] if f.references else "https://modelcontextprotocol.io/specification"}},
            "Resources": [{
                "Type": "Other",
                "Id": f"mcp-server:{f.target}" + (f"#tool:{f.subject}" if f.subject else ""),
                "Region": region,
                "Details": {"Other": {"lane": f.lane.value, "controls": ",".join(f.control_ids),
                                      **{f"evidence.{k}": str(v)[:1024] for k, v in list(f.evidence.items())[:20]}}},
            }],
            "Compliance": {"Status": "FAILED", "RelatedRequirements": [f"MCP-BP/{c}" for c in f.control_ids][:32]},
            "RecordState": "ACTIVE",
            "Workflow": {"Status": "NEW"},
        })
    return json.dumps({"Findings": findings}, indent=2, default=str)


def to_markdown(result: ScanResult) -> str:
    s = result.summary()
    lines = [f"# MCPEvalSuite report: `{result.target}`", ""]
    gate = result.gate or {}
    lines.append(f"**Gate:** {'PASS' if gate.get('passed') else 'FAIL'} — {gate.get('reason', '')}")
    lines.append("")
    lines.append("| Critical | High | Medium | Low | Info |")
    lines.append("|---|---|---|---|---|")
    lines.append(f"| {s['critical']} | {s['high']} | {s['medium']} | {s['low']} | {s['info']} |")
    lines.append("")
    if result.manifest:
        m = result.manifest
        lines.append(f"Server: `{m.server_info.get('name')}` v`{m.server_info.get('version')}` protocol `{m.protocol_version}` "
                     f"transport `{m.transport}` tools={len(m.tools)} resources={len(m.resources)} prompts={len(m.prompts)}")
        lines.append("")
        if m.tools:
            lines.append("## Tool classification")
            lines.append("")
            lines.append("| Tool | Category | Conf | readOnly | destructive | idempotent | Rationale |")
            lines.append("|---|---|---|---|---|---|---|")
            for t in m.tools:
                lines.append(f"| `{t.name}` | {t.category.value} | {t.category_confidence} | {t.hint('readOnlyHint')} | "
                             f"{t.hint('destructiveHint')} | {t.hint('idempotentHint')} | {t.category_rationale[:80]} |")
            lines.append("")
    lines.append("## Findings")
    lines.append("")
    order = sorted(result.findings, key=lambda f: -f.severity.rank)
    for f in order:
        lines.append(f"### [{f.severity.value.upper()}] {f.check_id} — {f.title}")
        if f.subject:
            lines.append(f"*Subject:* `{f.subject}`  ")
        lines.append(f"*Controls:* {', '.join(f.control_ids) or '-'}  *Lane:* {f.lane.value}  *Confidence:* {f.confidence.value}")
        lines.append("")
        lines.append(f.message)
        if f.remediation:
            lines.append("")
            lines.append(f"**Remediation:** {f.remediation}")
        if f.evidence:
            lines.append("")
            lines.append("<details><summary>Evidence</summary>\n\n```json\n" + json.dumps(f.evidence, indent=2, default=str)[:3000] + "\n```\n</details>")
        lines.append("")
    return "\n".join(lines)
