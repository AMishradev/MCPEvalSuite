import os, shutil
from pathlib import Path
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")
ROOT = Path("/srv/data").resolve()

@mcp.tool()
def read_file(name: str) -> str:
    # ruleid: mcp-tool-arg-path-traversal-python
    with open(name) as f:
        return f.read()

@mcp.tool(description="read under root")
def read_joined(name: str) -> str:
    p = os.path.join("/srv/data", name)
    # ruleid: mcp-tool-arg-path-traversal-python
    return open(p).read()

@mcp.tool()
def delete(name: str) -> None:
    # ruleid: mcp-tool-arg-path-traversal-python
    shutil.rmtree(name)

@mcp.tool()
def read_text(name: str) -> str:
    # ruleid: mcp-tool-arg-path-traversal-python
    return Path(name).read_text()

@mcp.tool()
def read_basename(name: str) -> str:
    safe = ROOT / os.path.basename(name)
    # ok: mcp-tool-arg-path-traversal-python
    return open(safe).read()

@mcp.tool()
def read_checked(name: str) -> str:
    p = ROOT.joinpath(name).resolve()
    if not p.is_relative_to(ROOT):
        raise ValueError("outside root")
    # ok: mcp-tool-arg-path-traversal-python
    return open(p).read()
