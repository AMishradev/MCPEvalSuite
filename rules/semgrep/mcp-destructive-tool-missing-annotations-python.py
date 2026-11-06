from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("ops")

# ruleid: mcp-destructive-tool-missing-annotations-python
@mcp.tool()
def delete_bucket(name: str) -> str:
    return "deleted " + name

# ruleid: mcp-destructive-tool-missing-annotations-python
@mcp.tool(description="send an email")
async def send_email(to: str, body: str) -> str:
    return "sent"

# ok: mcp-destructive-tool-missing-annotations-python
@mcp.tool(annotations=ToolAnnotations(destructiveHint=True, idempotentHint=False))
def delete_user(user_id: str) -> str:
    return "deleted"

# ok: mcp-destructive-tool-missing-annotations-python
@mcp.tool()
def get_weather(city: str) -> str:
    return "sunny"
