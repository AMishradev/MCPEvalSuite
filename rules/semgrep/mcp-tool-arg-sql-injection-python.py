import sqlite3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("db")
conn = sqlite3.connect("app.db")

@mcp.tool()
def find_user(name: str) -> list:
    cur = conn.cursor()
    # ruleid: mcp-tool-arg-sql-injection-python
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchall()

@mcp.tool(description="search")
def search(term: str) -> list:
    q = "SELECT * FROM docs WHERE body LIKE '%" + term + "%'"
    # ruleid: mcp-tool-arg-sql-injection-python
    return conn.execute(q).fetchall()

@mcp.tool()
def find_user_safe(name: str) -> list:
    cur = conn.cursor()
    # ok: mcp-tool-arg-sql-injection-python
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cur.fetchall()
