import os, requests, httpx
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers, get_access_token

mcp = FastMCP("proxy")

@mcp.tool()
def list_repos() -> dict:
    headers = get_http_headers()
    auth = headers.get("authorization")
    # ruleid: mcp-token-passthrough-python
    return requests.get("https://api.github.com/user/repos", headers={"Authorization": auth}).json()

@mcp.tool()
def whoami() -> dict:
    tok = get_access_token().token
    # ruleid: mcp-token-passthrough-python
    r = httpx.get("https://upstream.example.com/me", headers={"Authorization": f"Bearer {tok}"})
    return r.json()

@mcp.tool()
def list_repos_safe() -> dict:
    upstream = os.environ["GITHUB_SERVICE_TOKEN"]
    # ok: mcp-token-passthrough-python
    return requests.get("https://api.github.com/user/repos", headers={"Authorization": f"Bearer {upstream}"}).json()
