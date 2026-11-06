from mcp.server.fastmcp import FastMCP
from mcp.server.auth.settings import AuthSettings

mcp = FastMCP("open")
# ruleid: mcp-http-server-without-auth-python
mcp.run(transport="streamable-http")

mcp2 = FastMCP("open-sse")
# ruleid: mcp-http-server-without-auth-python
mcp2.run(transport="sse", host="0.0.0.0", port=8000)

# ruleid: mcp-http-server-without-auth-python
mcp3 = FastMCP("bound-everywhere", host="0.0.0.0", port=9000)

mcp4 = FastMCP("secured", auth=AuthSettings(issuer_url="https://as.example.com", resource_server_url="https://mcp.example.com"), token_verifier=object())
# ok: mcp-http-server-without-auth-python
mcp4.run(transport="streamable-http")

mcp5 = FastMCP("local")
# ok: mcp-http-server-without-auth-python
mcp5.run(transport="stdio")

# python-sdk 2.x renamed FastMCP -> MCPServer (mcp.server.mcpserver)
from mcp.server.mcpserver import MCPServer
srv = MCPServer("v2-open")
# ruleid: mcp-http-server-without-auth-python
srv.run(transport="streamable-http", host="0.0.0.0")
