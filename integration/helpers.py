"""
ProxyHarness — synchronous test client for the MCP proxy.

Starts ``python -m mcp_proxy --upstream <cmd> [flags]`` as a subprocess,
drives the MCP protocol over its stdin/stdout, and collects responses.

All reads use a background thread so they can be given a timeout without
blocking the test process forever on a hanging proxy.
"""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
import time
from typing import Any


class MCPError(Exception):
    """Raised when the proxy returns an error response."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class ProxyHarness:
    """
    Context-manager test harness.

    Usage::

        with ProxyHarness(
            upstream="python -m integration.servers.filesystem_server /tmp/sandbox",
            allow_tools="read_file,list_files",
        ) as h:
            h.initialize()
            resp = h.tools_list()
            assert "read_file" in {t["name"] for t in resp["tools"]}
    """

    def __init__(
        self,
        upstream: str,
        allow_tools: str | None = None,
        policy: str | None = None,
        threshold: float = 0.04,
        require_write_confirm: bool = False,
        quiet: bool = True,
    ) -> None:
        cmd = [sys.executable, "-m", "mcp_proxy", "--upstream", upstream]
        if allow_tools:
            cmd += ["--allow-tools", allow_tools]
        if policy:
            cmd += ["--policy", policy]
        if threshold != 0.04:
            cmd += ["--threshold", str(threshold)]
        if require_write_confirm:
            cmd += ["--require-write-confirm"]
        if quiet:
            cmd += ["--quiet"]

        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/Users/muneermamnoon/prompt-injection-lab",
        )
        self._id = 0
        self._notifications: list[dict] = []

        # Background reader thread puts lines into _q
        self._q: queue.Queue[bytes | None] = queue.Queue()
        self._reader_thread = threading.Thread(
            target=self._reader, daemon=True, name="proxy-reader"
        )
        self._reader_thread.start()

    def _reader(self) -> None:
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            self._q.put(line)
        self._q.put(None)  # sentinel — EOF

    def _readline(self, timeout: float = 5.0) -> bytes:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"No response within {timeout}s")
            try:
                item = self._q.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                continue
            if item is None:
                raise EOFError("Proxy stdout closed")
            return item

    def _recv(self, expected_id: Any, timeout: float = 5.0) -> dict:
        """Read messages until we find a response matching expected_id."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"No response for id={expected_id} within {timeout}s")
            line = self._readline(timeout=remaining)
            line = line.strip()
            if not line:
                continue
            msg = json.loads(line.decode("utf-8", errors="replace"))
            msg_id = msg.get("id")
            if msg_id is not None and msg_id == expected_id:
                return msg
            # Notification or response for a different id — save it
            self._notifications.append(msg)

    def _send(self, obj: dict) -> None:
        assert self._proc.stdin is not None
        data = (json.dumps(obj) + "\n").encode("utf-8")
        self._proc.stdin.write(data)
        self._proc.stdin.flush()

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    # ── MCP protocol helpers ────────────────────────────────────────────────────

    def initialize(self, timeout: float = 5.0) -> dict:
        req_id = self._next_id()
        self._send(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test-harness", "version": "1.0"},
                },
            }
        )
        resp = self._recv(req_id, timeout=timeout)
        # Send the initialized notification (no response expected)
        self._send({"jsonrpc": "2.0", "method": "initialized", "params": {}})
        return resp

    def tools_list(self, timeout: float = 5.0) -> dict:
        req_id = self._next_id()
        self._send({"jsonrpc": "2.0", "id": req_id, "method": "tools/list", "params": {}})
        resp = self._recv(req_id, timeout=timeout)
        return _unwrap(resp)

    def tools_call(
        self, name: str, arguments: dict[str, Any] | None = None, timeout: float = 5.0
    ) -> dict:
        req_id = self._next_id()
        self._send(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            }
        )
        resp = self._recv(req_id, timeout=timeout)
        return _unwrap(resp)

    def resources_list(self, timeout: float = 5.0) -> dict:
        req_id = self._next_id()
        self._send({"jsonrpc": "2.0", "id": req_id, "method": "resources/list", "params": {}})
        resp = self._recv(req_id, timeout=timeout)
        return _unwrap(resp)

    def resources_read(self, uri: str, timeout: float = 5.0) -> dict:
        req_id = self._next_id()
        self._send(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "resources/read",
                "params": {"uri": uri},
            }
        )
        resp = self._recv(req_id, timeout=timeout)
        return _unwrap(resp)

    def prompts_list(self, timeout: float = 5.0) -> dict:
        req_id = self._next_id()
        self._send({"jsonrpc": "2.0", "id": req_id, "method": "prompts/list", "params": {}})
        resp = self._recv(req_id, timeout=timeout)
        return _unwrap(resp)

    def prompts_get(self, name: str, arguments: dict | None = None, timeout: float = 5.0) -> dict:
        req_id = self._next_id()
        self._send(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "prompts/get",
                "params": {"name": name, "arguments": arguments or {}},
            }
        )
        resp = self._recv(req_id, timeout=timeout)
        return _unwrap(resp)

    def raw_request(self, method: str, params: dict | None = None, timeout: float = 5.0) -> dict:
        """Send any method and return the full response dict (including error field)."""
        req_id = self._next_id()
        self._send(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params or {},
            }
        )
        return self._recv(req_id, timeout=timeout)

    # ── Lifecycle ───────────────────────────────────────────────────────────────

    def close(self) -> None:
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
        except Exception:
            pass
        try:
            self._proc.terminate()
        except Exception:
            pass
        try:
            self._proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._proc.kill()

    def __enter__(self) -> ProxyHarness:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def _unwrap(resp: dict) -> dict:
    """Return resp['result'] or raise MCPError for resp['error']."""
    if "error" in resp:
        err = resp["error"]
        raise MCPError(err.get("code", -1), err.get("message", "unknown error"), err.get("data"))
    return resp.get("result", {})
