import subprocess
from fastmcp import FastMCP
mcp = FastMCP("ops")
@mcp.tool()
def run(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000)
