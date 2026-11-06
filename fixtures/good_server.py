"""Reference COMPLIANT MCP server that follows the AppSec best practices.

Patterns demonstrated:
  * <backend>_<verb>_<noun> tool names, grouped into Read / Aggregate / DML / DDL
  * Accurate ToolAnnotations on every tool
  * Static documents exposed as resources (not tools)
  * HITL via elicitation for DML and DDL, with an explicit impact statement
  * Input validation before any mutation; idempotent create (upsert)
  * Structured authN/authZ logging via middleware
  * Small, focused tool surface (lazy-fetch friendly)
"""
from __future__ import annotations

import logging
import re
import sys
from typing import Annotated

from fastmcp import Context, FastMCP
from mcp.types import ElicitRequest, ElicitRequestFormParams, InputRequiredResult
from fastmcp.server.middleware import Middleware, MiddlewareContext
from pydantic import Field

log = logging.getLogger("snow-mcp.audit")
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")


class AuditMiddleware(Middleware):
    """Logs every tool call with the caller principal (authZ event)."""

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        principal = getattr(getattr(context, "fastmcp_context", None), "client_id", None) or "anonymous"
        log.info('{"event":"tool_call","tool":"%s","principal":"%s"}', context.message.name, principal)
        return await call_next(context)


mcp = FastMCP(
    "snow",
    version="1.0.0",
    instructions="ServiceNow ticketing tools. Mutating tools ask for confirmation.",
    middleware=[AuditMiddleware()],
)

_DB: dict[str, dict] = {"INC00001": {"id": "INC00001", "title": "Printer on fire", "status": "open", "age_days": 3}}
_TICKET_ID = re.compile(r"^INC\d{5}$")


_CONFIRM_SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean", "title": "Proceed?"}}, "required": ["ok"]}


async def confirm(ctx: Context, message: str):
    """Human-in-the-loop confirmation that works on both protocol eras.

    Returns True (accepted), False (declined), or an InputRequiredResult the tool must return
    so the client asks the user and re-invokes the tool with ctx.input_responses filled in.
    """
    answers = ctx.input_responses or {}
    if "confirm" in answers:  # second leg of a 2026-07-28 multi-round-trip call
        r = answers["confirm"]
        return getattr(r, "action", None) == "accept" and bool((getattr(r, "content", None) or {}).get("ok"))
    try:
        res = await ctx.elicit(message, response_type=bool)  # 2025-11-25 and earlier: server-initiated request
        return res.action == "accept" and bool(res.data)
    except Exception as e:  # noqa: BLE001 - FastMCP raises a ToolError on 2026-07-28 connections
        if "2026-07-28" not in str(e):
            raise
    return InputRequiredResult(
        result_type="input_required",
        input_requests={"confirm": ElicitRequest(method="elicitation/create",
                                                 params=ElicitRequestFormParams(mode="form", message=message, requested_schema=_CONFIRM_SCHEMA))},
    )


# ---- Read / Discover --------------------------------------------------------
@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
def snow_get_ticket(ticket_id: Annotated[str, Field(pattern=r"^INC\d{5}$")]) -> dict:
    """Return one ServiceNow incident by id."""
    return _DB.get(ticket_id, {"error": "not found"})


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
def snow_list_tickets(status: Annotated[str, Field(pattern=r"^(open|closed)$")] = "open") -> list[dict]:
    """List ServiceNow incidents filtered by status."""
    return [t for t in _DB.values() if t["status"] == status]


# ---- Aggregate --------------------------------------------------------------
@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
def snow_get_avg_open_ticket_age() -> dict:
    """Average age (days) of open incidents, computed across all open tickets."""
    open_ = [t for t in _DB.values() if t["status"] == "open"]
    return {"avg_age_days": sum(t["age_days"] for t in open_) / max(1, len(open_)), "count": len(open_)}


# ---- DML (HITL recommended) ------------------------------------------------
@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def snow_create_ticket(
    title: Annotated[str, Field(min_length=3, max_length=200)],
    ticket_id: Annotated[str | None, Field(pattern=r"^INC\d{5}$")] = None,
    ctx: Context = None,
) -> dict | InputRequiredResult:
    """Create a ServiceNow incident. Asks the user for confirmation before writing. Idempotent: if `ticket_id` exists it is updated instead."""
    if ctx is not None:
        ok = await confirm(ctx, f"This will create (or update) incident {ticket_id or '<new>'} titled '{title}' in ServiceNow instance PROD. Proceed?")
        if isinstance(ok, InputRequiredResult):
            return ok
        if not ok:
            return {"status": "cancelled"}
    tid = ticket_id or f"INC{len(_DB) + 1:05d}"
    _DB[tid] = {**_DB.get(tid, {}), "id": tid, "title": title, "status": "open", "age_days": 0}
    return _DB[tid]


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False})
async def snow_delete_ticket(ticket_id: Annotated[str, Field(pattern=r"^INC\d{5}$")], ctx: Context = None) -> dict | InputRequiredResult:
    """Permanently delete a ServiceNow incident. Asks the user for confirmation (names the incident and instance) before deleting."""
    if not _TICKET_ID.match(ticket_id):
        raise ValueError("invalid ticket id")
    if ctx is not None:
        ok = await confirm(ctx, f"This will PERMANENTLY delete incident {ticket_id} from ServiceNow instance PROD. This cannot be undone. Proceed?")
        if isinstance(ok, InputRequiredResult):
            return ok
        if not ok:
            return {"status": "cancelled"}
    _DB.pop(ticket_id, None)
    return {"status": "deleted", "id": ticket_id}


# ---- Resources (static, read-only, application-controlled) -----------------
@mcp.resource("snow://runbook/on-call", mime_type="text/markdown")
def runbook() -> str:
    """On-call runbook."""
    return "# On-call runbook\n1. Check the dashboard..."


if __name__ == "__main__":
    if "--http" in sys.argv:
        mcp.run(transport="http", host="127.0.0.1", port=8766)
    else:
        mcp.run()
