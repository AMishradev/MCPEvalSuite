"""Heuristic (no-LLM) tool classifier.

Three signals, combined by `classify_tool`:
  1. MCP ToolAnnotations hints  (readOnlyHint / destructiveHint / idempotentHint)
  2. Verb lexicon on the tool name (and title)
  3. JSON-schema shape of the input (e.g. presence of `confirm`, `dry_run`, ids)

The result is a (Category, confidence, rationale) triple. Confidence below
CONFIDENCE_FLOOR means "needs LLM or human review"; the ensemble classifier
escalates such cases to the LLM lane when available.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Category, ToolRecord

CONFIDENCE_FLOOR = 0.6

# Verb -> category. Order matters only for the DDL list (checked first because
# words like "create" are ambiguous: create_ticket (DML) vs create_table (DDL)).
DDL_VERBS = {
    "provision", "deprovision", "deploy", "undeploy", "terminate", "launch", "scale",
    "migrate", "drop", "truncate", "alter", "define", "grant", "revoke", "attach", "detach",
    "rotate", "bootstrap", "destroy", "teardown", "format", "partition", "reindex", "install",
    "uninstall", "configure", "reconfigure", "upgrade", "downgrade", "apply", "exec", "execute",
    "run", "shell", "ssh", "sudo", "chmod", "chown",
}
# Nouns that turn a DML verb into DDL (schema / infra / identity definitions)
DDL_NOUNS = {
    "table", "tables", "schema", "schemas", "database", "db", "index", "indexes", "bucket",
    "buckets", "blob", "container", "cluster", "clusters", "instance", "instances", "vm", "vms",
    "ec2", "ecs", "eks", "lambda", "function", "functions", "stack", "stacks", "vpc", "subnet",
    "securitygroup", "security_group", "role", "roles", "policy", "policies", "iam", "user",
    "users", "group", "groups", "key", "keys", "secret", "secrets", "certificate", "cert",
    "namespace", "namespaces", "pod", "pods", "deployment", "deployments", "node", "nodes",
    "volume", "volumes", "snapshot", "snapshots", "image", "images", "repository", "repo",
    "pipeline", "pipelines", "webhook", "webhooks", "topic", "topics", "queue", "queues",
    "collection", "collections", "column", "columns", "view", "views", "trigger", "triggers",
    "procedure", "migration", "migrations", "environment", "environments", "project", "projects",
    "workspace", "workspaces", "tenant", "tenants", "org", "organization", "domain", "dns",
    "firewall", "rule", "rules", "branch", "branches", "tag", "tags", "release", "releases",
}
DML_VERBS = {
    "create", "add", "insert", "new", "post", "submit", "update", "edit", "modify", "patch",
    "put", "set", "change", "rename", "move", "delete", "remove", "destroy", "purge", "archive",
    "restore", "assign", "unassign", "approve", "reject", "close", "reopen", "resolve", "merge",
    "send", "notify", "email", "message", "publish", "upload", "write", "save", "store", "mark",
    "complete", "cancel", "start", "stop", "pause", "resume", "trigger", "invoke", "transfer",
    "pay", "charge", "refund", "order", "book", "reserve", "schedule", "reschedule", "enable",
    "disable", "lock", "unlock", "reset", "clear", "flush", "import", "sync", "push", "comment",
    "reply", "react", "like", "follow", "share", "invite", "kick", "ban", "mute", "label",
    "transition", "escalate", "acknowledge", "ack", "snooze", "dismiss",
}
AGGREGATE_VERBS = {
    "aggregate", "summarize", "summarise", "report", "analyze", "analyse", "analytics", "stats",
    "statistics", "metrics", "average", "avg", "mean", "median", "count", "sum", "total",
    "trend", "trends", "forecast", "compare", "correlate", "rollup", "dashboard", "kpi",
    "histogram", "distribution", "breakdown", "overview", "insights", "health", "score",
    "rank", "top", "leaderboard", "age", "aging", "leadtime", "lead_time", "velocity",
    "burndown", "throughput", "sla", "slo",
}
READ_VERBS = {
    "get", "list", "read", "fetch", "find", "search", "query", "lookup", "describe", "show",
    "view", "retrieve", "load", "browse", "inspect", "check", "head", "exists", "validate",
    "verify", "preview", "peek", "tail", "cat", "ls", "dir", "status", "info", "details",
    "download", "export", "whoami", "ping", "echo", "help", "explain", "resolve", "parse",
    "render", "translate", "convert", "format_text", "diff", "grep", "scan",
}
# "export"/"download"/"scan"/"validate" are reads from the backend's point of view.

_SPLIT = re.compile(r"[^a-z0-9]+")


def tokenize(name: str) -> list[str]:
    """snake_case, camelCase, kebab-case, dotted and `__` namespaced names -> lowercase tokens."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    return [t for t in _SPLIT.split(s.lower()) if t]


@dataclass
class NameParts:
    backend: str | None
    verb: str | None
    noun_tokens: list[str]
    tokens: list[str]


def split_name(name: str) -> NameParts:
    """Interpret `<backend>_<verb>_<noun...>` naming (snow_get_ticket).

    Also tolerates AgentCore Gateway style `target___tool` and dotted `jira.get_ticket`.
    """
    toks = tokenize(name)
    all_verbs = DDL_VERBS | DML_VERBS | AGGREGATE_VERBS | READ_VERBS
    if not toks:
        return NameParts(None, None, [], toks)
    # find first verb position
    vi = next((i for i, t in enumerate(toks) if t in all_verbs), None)
    if vi is None:
        return NameParts(None, None, toks, toks)
    backend = "_".join(toks[:vi]) if vi > 0 else None
    return NameParts(backend, toks[vi], toks[vi + 1:], toks)


def classify_by_name(name: str, title: str | None = None, description: str | None = None) -> tuple[Category, float, str]:
    parts = split_name(name)
    toks = set(parts.tokens)
    if title:
        toks |= set(tokenize(title))
    desc_toks = set(tokenize(description or ""))

    # DDL: verb in DDL set, or DML verb applied to a DDL noun
    if parts.verb in DDL_VERBS:
        return Category.DDL, 0.85, f"verb '{parts.verb}' is a definition/infra verb"
    if parts.verb in DML_VERBS and (set(parts.noun_tokens) & DDL_NOUNS):
        noun = next(iter(set(parts.noun_tokens) & DDL_NOUNS))
        return Category.DDL, 0.8, f"mutating verb '{parts.verb}' on structural noun '{noun}'"
    if parts.verb in DML_VERBS:
        return Category.DML, 0.8, f"verb '{parts.verb}' mutates business data"
    if parts.verb in AGGREGATE_VERBS or (toks & AGGREGATE_VERBS):
        return Category.AGGREGATE, 0.7, "aggregation/report vocabulary in name"
    if parts.verb in READ_VERBS:
        # get_avg_open_ticket_age -> aggregate even though verb is 'get'
        if set(parts.noun_tokens) & AGGREGATE_VERBS:
            return Category.AGGREGATE, 0.7, f"read verb '{parts.verb}' over an aggregate noun"
        return Category.READ, 0.75, f"verb '{parts.verb}' is read-only"
    # fall back to description vocabulary (weak)
    if desc_toks & (DDL_VERBS | {"infrastructure", "infra", "provisioning"}):
        return Category.DDL, 0.4, "description mentions infra/definition verbs"
    if desc_toks & DML_VERBS:
        return Category.DML, 0.4, "description mentions mutating verbs"
    if desc_toks & AGGREGATE_VERBS:
        return Category.AGGREGATE, 0.4, "description mentions aggregation"
    if desc_toks & READ_VERBS:
        return Category.READ, 0.4, "description mentions read verbs"
    return Category.UNKNOWN, 0.0, "no recognizable verb"


def classify_by_annotations(tool: ToolRecord) -> tuple[Category | None, float, str]:
    """Annotations are untrusted hints (spec), so confidence is capped at 0.6."""
    ro = tool.hint("readOnlyHint")
    if ro is True:
        return Category.READ, 0.6, "readOnlyHint=true"
    if ro is False:
        d = tool.hint("destructiveHint")
        if d is True:
            return Category.DML, 0.55, "readOnlyHint=false, destructiveHint=true"
        return Category.DML, 0.5, "readOnlyHint=false"
    return None, 0.0, "no annotations"


def classify_by_schema(tool: ToolRecord) -> tuple[Category | None, float, str]:
    props = (tool.input_schema or {}).get("properties", {}) or {}
    keys = {k.lower() for k in props}
    if {"sql", "statement", "ddl"} & keys:
        return Category.DDL, 0.5, "free-form SQL/statement parameter"
    if {"command", "cmd", "script", "shell"} & keys:
        return Category.DDL, 0.55, "free-form command/script parameter"
    if {"body", "payload", "data", "fields", "content", "message", "text"} & keys and not ({"query", "q", "search"} & keys):
        return Category.DML, 0.35, "payload-like parameters suggest a write"
    if {"group_by", "groupby", "aggregate", "metric", "interval", "bucket"} & keys:
        return Category.AGGREGATE, 0.45, "aggregation parameters"
    if {"query", "q", "search", "filter", "limit", "page", "cursor"} & keys:
        return Category.READ, 0.35, "query/pagination parameters"
    return None, 0.0, "schema inconclusive"


_RANK = {Category.READ: 0, Category.AGGREGATE: 1, Category.DML: 2, Category.DDL: 3}


def classify_tool(tool: ToolRecord) -> ToolRecord:
    """Ensemble of the three heuristic signals. Mutates and returns the tool.

    Policy: when signals disagree we take the RISKIER category (fail closed) and
    lower the confidence so the LLM/human lane is triggered.
    """
    votes: list[tuple[Category, float, str, str]] = []
    c, conf, why = classify_by_name(tool.name, tool.title, tool.description)
    if c is not Category.UNKNOWN:
        votes.append((c, conf, why, "lexicon"))
    c2, conf2, why2 = classify_by_annotations(tool)
    if c2:
        votes.append((c2, conf2, why2, "annotations"))
    c3, conf3, why3 = classify_by_schema(tool)
    if c3:
        votes.append((c3, conf3, why3, "schema"))

    tool.category_sources = {src: cat.value for cat, _, _, src in votes}
    if not votes:
        tool.category, tool.category_confidence, tool.category_rationale = Category.UNKNOWN, 0.0, "no signal"
        return tool

    riskiest = max(votes, key=lambda v: _RANK[v[0]])
    nonmut = {Category.READ, Category.AGGREGATE}

    def compatible(cat: Category) -> bool:
        # annotations can only say "read-only" or "mutating"; READ vs AGGREGATE is not a disagreement
        return cat == riskiest[0] or (cat in nonmut and riskiest[0] in nonmut)

    agree = all(compatible(v[0]) for v in votes)
    confidence = riskiest[1] if agree else max(0.3, riskiest[1] - 0.25)
    if agree and len(votes) > 1:
        confidence = min(0.95, riskiest[1] + 0.1 * (len(votes) - 1))
    tool.category = riskiest[0]
    tool.category_confidence = round(confidence, 2)
    tool.category_rationale = "; ".join(f"{src}: {why}" for _, _, why, src in votes)
    return tool
