"""Core data models for MCPEvalSuite.

Everything a scan produces flows through these models so that every lane
(probe, static, discover, infra) emits the same Finding shape and every
reporter (JSON / SARIF / ASFF / Markdown) consumes the same ScanResult.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class Category(str, Enum):
    """Tool risk categories from the AppSec best-practices document."""

    READ = "read"            # passive, read-only, non-aggregating; HITL optional
    AGGREGATE = "aggregate"  # multi-source / computed reports; non-mutating
    DML = "dml"              # create / update / delete business data; HITL recommended
    DDL = "ddl"              # define / provision / destroy structures & infra; HITL REQUIRED
    UNKNOWN = "unknown"      # could not classify with confidence -> human review


class Lane(str, Enum):
    MANIFEST = "manifest"      # checks on the enumerated tools/resources/prompts
    AUTH = "auth"              # HTTP authorization probing
    BEHAVIOR = "behavior"      # live tool invocation probes (opt-in)
    STATIC = "static"          # source code / Dockerfile / deps
    SUPPLY_CHAIN = "supply_chain"
    INFRA = "infra"            # AWS runtime posture
    DISCOVERY = "discovery"    # shadow MCP inventory


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# --------------------------------------------------------------------------- #
# Manifest: a normalized, hashable snapshot of what a server advertises
# --------------------------------------------------------------------------- #
class ToolRecord(BaseModel):
    name: str
    title: str | None = None
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None  # wire format: readOnlyHint, destructiveHint, ...
    meta: dict[str, Any] | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    # Populated by the classifier
    category: Category = Category.UNKNOWN
    category_confidence: float = 0.0
    category_rationale: str = ""
    category_sources: dict[str, str] = Field(default_factory=dict)  # lexicon/annotations/llm -> label

    @property
    def content_hash(self) -> str:
        payload = json.dumps(
            {"name": self.name, "description": self.description, "input_schema": self.input_schema,
             "annotations": self.annotations, "output_schema": self.output_schema},
            sort_keys=True, default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def hint(self, key: str) -> bool | None:
        if not self.annotations:
            return None
        return self.annotations.get(key)


class ResourceRecord(BaseModel):
    uri: str
    name: str | None = None
    title: str | None = None
    description: str | None = None
    mime_type: str | None = None
    is_template: bool = False
    raw: dict[str, Any] = Field(default_factory=dict)


class PromptRecord(BaseModel):
    name: str
    title: str | None = None
    description: str | None = None
    arguments: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class ServerManifest(BaseModel):
    target: str
    transport: str  # stdio | streamable-http | sse
    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    protocol_version: str | None = None
    server_info: dict[str, Any] = Field(default_factory=dict)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    instructions: str | None = None
    tools: list[ToolRecord] = Field(default_factory=list)
    resources: list[ResourceRecord] = Field(default_factory=list)
    prompts: list[PromptRecord] = Field(default_factory=list)
    # Side-channel observations captured during the probe
    notifications: list[dict[str, Any]] = Field(default_factory=list)
    sampling_requests: list[dict[str, Any]] = Field(default_factory=list)
    elicitation_requests: list[dict[str, Any]] = Field(default_factory=list)
    log_messages: list[dict[str, Any]] = Field(default_factory=list)
    http: dict[str, Any] = Field(default_factory=dict)  # auth probe observations for HTTP transports
    errors: list[str] = Field(default_factory=list)

    @property
    def manifest_hash(self) -> str:
        h = hashlib.sha256()
        for t in sorted(self.tools, key=lambda x: x.name):
            h.update(t.content_hash.encode())
        for r in sorted(self.resources, key=lambda x: x.uri):
            h.update(json.dumps(r.raw, sort_keys=True, default=str).encode())
        for p in sorted(self.prompts, key=lambda x: x.name):
            h.update(json.dumps(p.raw, sort_keys=True, default=str).encode())
        return h.hexdigest()

    def tool(self, name: str) -> ToolRecord | None:
        return next((t for t in self.tools if t.name == name), None)


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
class Finding(BaseModel):
    check_id: str                      # e.g. NAME-001
    control_ids: list[str] = Field(default_factory=list)  # best-practice control IDs, e.g. ["BP-NAMING"]
    title: str
    severity: Severity
    lane: Lane
    message: str
    remediation: str = ""
    confidence: Confidence = Confidence.HIGH
    target: str = ""                   # server target string
    subject: str = ""                  # tool name / file path / resource ARN
    location: dict[str, Any] = Field(default_factory=dict)  # {"file":..., "line":...}
    evidence: dict[str, Any] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    mappings: dict[str, list[str]] = Field(default_factory=dict)  # {"owasp_mcp": [...], "owasp_agentic": [...]}

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.check_id}|{self.target}|{self.subject}|{self.title}".encode()).hexdigest()[:16]


class ScanResult(BaseModel):
    tool_name: str = "mcpeval"
    tool_version: str = "0.1.0"
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    target: str
    manifest: ServerManifest | None = None
    findings: list[Finding] = Field(default_factory=list)
    checks_run: list[str] = Field(default_factory=list)
    gate: dict[str, Any] = Field(default_factory=dict)  # {"passed": bool, "reason": str}
    metadata: dict[str, Any] = Field(default_factory=dict)

    def summary(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)
