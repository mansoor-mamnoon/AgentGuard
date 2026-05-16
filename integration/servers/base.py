"""
Base class for test MCP servers.

Handles the JSON-RPC 2.0 stdio transport and MCP initialization handshake.
Subclasses implement ``handle_method(method, params, msg_id)`` → result dict.
"""

from __future__ import annotations

import json
import sys
from typing import Any


class MCPServer:
    """
    Minimal MCP server base class.

    Reads newline-delimited JSON from stdin, dispatches to ``handle_method``,
    and writes responses to stdout.
    """

    SERVER_NAME: str = "test-server"
    SERVER_VERSION: str = "1.0.0"
    PROTOCOL_VERSION: str = "2024-11-05"

    def capabilities(self) -> dict[str, Any]:
        return {"tools": {}, "resources": {}, "prompts": {}}

    def handle_method(self, method: str, params: dict[str, Any], msg_id: Any) -> Any:
        """Override in subclasses. Return result dict or raise MCPError."""
        raise MCPError(-32601, f"Method not found: {method}")

    def run(self) -> None:
        sys.stdin.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]

        for raw in sys.stdin:
            line = raw.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self._send_error(None, -32700, "Parse error")
                continue

            msg_id = msg.get("id")
            method = msg.get("method", "")
            params = msg.get("params") or {}
            is_notification = "method" in msg and "id" not in msg

            if is_notification:
                # Notifications get no response
                self._on_notification(method, params)
                continue

            if msg_id is None and "method" not in msg:
                # This is a response to a server-initiated request — ignore
                continue

            try:
                result = self._dispatch(method, params, msg_id)
                self._send_result(msg_id, result)
            except MCPError as exc:
                self._send_error(msg_id, exc.code, exc.message, exc.data)
            except Exception as exc:
                self._send_error(msg_id, -32603, f"Internal error: {exc}")

    def _dispatch(self, method: str, params: dict[str, Any], msg_id: Any) -> Any:
        if method == "initialize":
            return {
                "protocolVersion": self.PROTOCOL_VERSION,
                "capabilities": self.capabilities(),
                "serverInfo": {"name": self.SERVER_NAME, "version": self.SERVER_VERSION},
            }
        return self.handle_method(method, params, msg_id)

    def _on_notification(self, method: str, params: dict[str, Any]) -> None:
        pass  # subclasses may override

    def _send_result(self, msg_id: Any, result: Any) -> None:
        self._write({"jsonrpc": "2.0", "id": msg_id, "result": result})

    def _send_error(self, msg_id: Any, code: int, message: str, data: Any = None) -> None:
        err: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        self._write({"jsonrpc": "2.0", "id": msg_id, "error": err})

    def _write(self, obj: dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()


class MCPError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data
