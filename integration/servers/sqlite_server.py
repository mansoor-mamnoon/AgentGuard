"""
SQLite MCP server for integration testing.

Tools:
  query(sql)            — execute a SELECT query
  list_tables()         — list all tables
  describe_table(name)  — show table schema

Usage::
    python -m integration.servers.sqlite_server /path/to/db.sqlite
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from typing import Any

from .base import MCPError, MCPServer


class SQLiteServer(MCPServer):
    SERVER_NAME = "sqlite-server"

    TOOLS = [
        {
            "name": "query",
            "description": "Execute a read-only SQL query and return results.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string", "description": "SELECT statement to execute"}
                },
                "required": ["sql"],
            },
        },
        {
            "name": "list_tables",
            "description": "List all tables in the database.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "describe_table",
            "description": "Show schema for a specific table.",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string", "description": "Table name"}},
                "required": ["name"],
            },
        },
    ]

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(str(db_path))
        # Read-only mode guard: disallow writes via PRAGMA
        self._conn.execute("PRAGMA query_only = 1")

    def handle_method(self, method: str, params: dict[str, Any], msg_id: Any) -> Any:
        if method == "tools/list":
            return {"tools": self.TOOLS}

        if method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments", {})
            return self._call_tool(name, args)

        if method == "resources/list":
            # Expose tables as resources
            cur = self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            resources = [
                {
                    "uri": f"sqlite://table/{row[0]}",
                    "name": row[0],
                    "description": f"Table: {row[0]}",
                }
                for row in cur.fetchall()
            ]
            return {"resources": resources}

        if method == "resources/read":
            uri = params.get("uri", "")
            if uri.startswith("sqlite://table/"):
                table = uri[len("sqlite://table/") :]
                return self._read_table(table, uri)
            raise MCPError(-32602, f"Unsupported URI: {uri}")

        if method == "prompts/list":
            return {"prompts": []}

        raise MCPError(-32601, f"Method not found: {method}")

    def _call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "query":
            sql = args.get("sql", "")
            if not sql.strip().upper().startswith("SELECT"):
                return {
                    "content": [{"type": "text", "text": "Error: only SELECT queries are allowed"}],
                    "isError": True,
                }
            try:
                cur = self._conn.execute(sql)
                rows = cur.fetchmany(100)  # limit to 100 rows
                cols = [d[0] for d in (cur.description or [])]
                lines = [", ".join(cols)] + [", ".join(str(v) for v in row) for row in rows]
                return {
                    "content": [{"type": "text", "text": "\n".join(lines)}],
                    "isError": False,
                }
            except sqlite3.Error as exc:
                return {
                    "content": [{"type": "text", "text": f"SQL error: {exc}"}],
                    "isError": True,
                }

        if name == "list_tables":
            cur = self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            tables = [row[0] for row in cur.fetchall()]
            return {
                "content": [{"type": "text", "text": "\n".join(tables)}],
                "isError": False,
            }

        if name == "describe_table":
            table = args.get("name", "")
            try:
                cur = self._conn.execute(f"PRAGMA table_info({table!r})")
                rows = cur.fetchall()
                if not rows:
                    return {
                        "content": [{"type": "text", "text": f"Table not found: {table}"}],
                        "isError": True,
                    }
                lines = [f"{r[1]} {r[2]}" for r in rows]
                return {
                    "content": [{"type": "text", "text": "\n".join(lines)}],
                    "isError": False,
                }
            except sqlite3.Error as exc:
                return {
                    "content": [{"type": "text", "text": f"Error: {exc}"}],
                    "isError": True,
                }

        raise MCPError(-32602, f"Unknown tool: {name}")

    def _read_table(self, table: str, uri: str) -> dict[str, Any]:
        try:
            cur = self._conn.execute(f"SELECT * FROM {table!r} LIMIT 100")
            rows = cur.fetchall()
            cols = [d[0] for d in (cur.description or [])]
            lines = [", ".join(cols)] + [", ".join(str(v) for v in row) for row in rows]
            return {"contents": [{"uri": uri, "mimeType": "text/plain", "text": "\n".join(lines)}]}
        except sqlite3.Error as exc:
            raise MCPError(-32602, f"Error reading table: {exc}") from exc


def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: sqlite_server <db-path>\n")
        sys.exit(1)
    db_path = Path(sys.argv[1])
    SQLiteServer(db_path).run()


if __name__ == "__main__":
    main()
