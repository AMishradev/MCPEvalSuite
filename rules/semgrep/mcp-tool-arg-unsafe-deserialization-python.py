import pickle, base64, yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("state")

@mcp.tool()
def restore(blob: str):
    raw = base64.b64decode(blob)
    # ruleid: mcp-tool-arg-unsafe-deserialization-python
    return pickle.loads(raw)

@mcp.tool(description="load yaml")
def load_cfg(doc: str):
    # ruleid: mcp-tool-arg-unsafe-deserialization-python
    return yaml.load(doc, Loader=yaml.Loader)

@mcp.tool()
def load_cfg_safe(doc: str):
    # ok: mcp-tool-arg-unsafe-deserialization-python
    return yaml.safe_load(doc)
