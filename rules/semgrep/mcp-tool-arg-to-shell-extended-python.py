import os, subprocess, asyncio, shlex
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool(description="Ping a host")
def ping(host: str) -> str:
    # ruleid: mcp-tool-arg-to-shell-extended-python
    return os.popen("ping -c1 " + host).read()

@mcp.tool
def bare_decorator(cmd: str) -> str:
    # ruleid: mcp-tool-arg-to-shell-extended-python
    return subprocess.getoutput(cmd)

@mcp.tool(name="dig")
async def dig(name: str) -> str:
    # ruleid: mcp-tool-arg-to-shell-extended-python
    proc = await asyncio.create_subprocess_shell(f"dig {name}")
    return str(proc)

@mcp.tool()
def checked(path: str) -> str:
    # ruleid: mcp-tool-arg-to-shell-extended-python
    return subprocess.check_output("ls " + path, shell=True).decode()

@mcp.tool()
def safe_list(host: str) -> str:
    # ok: mcp-tool-arg-to-shell-extended-python
    return subprocess.check_output(["ping", "-c1", host]).decode()

@mcp.tool()
def safe_quoted(host: str) -> str:
    # ok: mcp-tool-arg-to-shell-extended-python
    return os.popen("ping -c1 " + shlex.quote(host)).read()
