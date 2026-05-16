"""
Async stdio MCP proxy.

Spawns the upstream server as a subprocess and pipes JSON-RPC 2.0 messages
in both directions, applying the PolicyLayer to every interceptable message.

Transport: newline-delimited JSON over stdin/stdout (standard MCP stdio transport).

Design:
  Three concurrent asyncio tasks:
    1. _client_to_upstream  — reads our stdin, enforces outbound policy, writes to
                               upstream.stdin (or sends error back to client if blocked)
    2. _upstream_to_client  — reads upstream.stdout, transforms responses, writes to
                               our stdout
    3. _forward_stderr      — drains upstream.stderr → our stderr (never dropped)

  A single asyncio.Lock serializes all writes to sys.stdout.buffer so lines
  from the two tasks never interleave.

  Pending intercepts are tracked in a dict keyed by request id so each
  response is transformed with the context of its originating request.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

from .audit_log import AuditLog
from .config import ProxyConfig
from .jsonrpc import MCPMessage, MCPParseError, error_response, parse_line, serialize
from .policy import PolicyLayer
from .taint import SessionTaint


class _Pending:
    __slots__ = ("method", "extra")

    def __init__(self, method: str, extra: str = "") -> None:
        self.method = method
        self.extra = extra  # tool name, uri, prompt name, etc.


class AsyncStdioProxy:
    """
    Async MCP security proxy.

    Instantiate once and call ``await proxy.run()`` — it returns when either
    side closes the connection.
    """

    def __init__(
        self,
        config: ProxyConfig,
        audit: AuditLog | None = None,
    ) -> None:
        self._config = config
        self._policy = PolicyLayer(config)
        self._audit = audit or AuditLog(config.audit_log, to_stderr=True)
        self._taint = SessionTaint()
        self._pending: dict[Any, _Pending] = {}
        self._stdout_lock: asyncio.Lock | None = None

    # ── Public entry point ─────────────────────────────────────────────────────

    async def run(self) -> int:
        """Start the proxy. Returns upstream exit code (or 0 on client disconnect)."""
        self._stdout_lock = asyncio.Lock()

        try:
            proc = await asyncio.create_subprocess_exec(
                *self._config.upstream_cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            cmd_str = " ".join(self._config.upstream_cmd)
            sys.stderr.write(f"LLMFirewall: upstream command not found: {cmd_str!r}\n")
            sys.stderr.flush()
            return 127

        # Connect stdin as an asyncio StreamReader
        loop = asyncio.get_running_loop()
        client_reader = asyncio.StreamReader()
        stdin_protocol = asyncio.StreamReaderProtocol(client_reader)
        await loop.connect_read_pipe(lambda: stdin_protocol, sys.stdin.buffer)

        tasks = [
            asyncio.create_task(self._client_to_upstream(client_reader, proc), name="c2u"),
            asyncio.create_task(self._upstream_to_client(proc), name="u2c"),
            asyncio.create_task(self._forward_stderr(proc), name="stderr"),
        ]

        _done, pending_tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        for t in pending_tasks:
            t.cancel()
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass

        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=3.0)
        except TimeoutError:
            proc.kill()

        self._audit.close()
        return proc.returncode or 0

    # ── Stdout write (serialized) ───────────────────────────────────────────────

    async def _send(self, data: bytes) -> None:
        assert self._stdout_lock is not None
        async with self._stdout_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    # ── Task 1: client → upstream ──────────────────────────────────────────────

    async def _client_to_upstream(
        self,
        reader: asyncio.StreamReader,
        proc: asyncio.subprocess.Process,
    ) -> None:
        while True:
            try:
                line = await reader.readline()
            except Exception:
                break
            if not line:
                break
            stripped = line.strip()
            if not stripped:
                continue

            try:
                msg = parse_line(stripped)
            except MCPParseError as exc:
                self._audit.log_error("parse_client", str(exc))
                # Forward verbatim — let upstream reject it with a proper error
                await self._upstream_write(proc, stripped + b"\n")
                continue

            await self._handle_outbound(msg, proc)

        # Client disconnected — signal upstream
        if proc.stdin and not proc.stdin.is_closing():
            proc.stdin.close()

    async def _upstream_write(self, proc: asyncio.subprocess.Process, data: bytes) -> None:
        if proc.stdin and not proc.stdin.is_closing():
            proc.stdin.write(data)
            try:
                await proc.stdin.drain()
            except Exception:
                pass

    async def _handle_outbound(self, msg: MCPMessage, proc: asyncio.subprocess.Process) -> None:
        if msg.is_notification():
            # Notifications have no id and need no interception
            self._audit.log_allow(msg.method or "notification")
            await self._upstream_write(proc, serialize(msg))
            return

        decision = self._policy.check_outbound(msg)

        if decision.blocked:
            self._audit.log_block(msg.method or "?", decision.reason, id=msg.id)
            if msg.id is not None:
                await self._send(
                    serialize(
                        error_response(
                            msg.id,
                            -32001,
                            f"LLMFirewall blocked: {decision.reason}",
                        )
                    )
                )
            return

        self._audit.log_allow(msg.method or "?", id=msg.id)

        if decision.needs_response and msg.id is not None:
            # Determine the "extra" context for the response transformer
            extra = ""
            if msg.method == "tools/call":
                extra = msg.params.get("name", "")
            elif msg.method == "resources/read":
                extra = msg.params.get("uri") or ""
            elif msg.method == "prompts/get":
                extra = msg.params.get("name", "")
            self._pending[msg.id] = _Pending(msg.method or "", extra)

        fwd = decision.forward or msg
        await self._upstream_write(proc, serialize(fwd))

        for w in decision.warnings:
            self._audit.log("warning", {"method": msg.method, "warning": w})

    # ── Task 2: upstream → client ──────────────────────────────────────────────

    async def _upstream_to_client(self, proc: asyncio.subprocess.Process) -> None:
        assert proc.stdout is not None
        while True:
            try:
                line = await proc.stdout.readline()
            except Exception:
                break
            if not line:
                break
            stripped = line.strip()
            if not stripped:
                continue

            try:
                msg = parse_line(stripped)
            except MCPParseError:
                # Unparseable — forward as-is (could be a partial/chunked response)
                await self._send(stripped + b"\n")
                continue

            # Check if this response needs transformation
            if msg.is_response() and msg.id is not None and msg.id in self._pending:
                pending = self._pending.pop(msg.id)
                msg = self._policy.transform_response(
                    msg,
                    original_method=pending.method,
                    uri_or_tool=pending.extra,
                )
                self._audit.log(
                    "transform",
                    {"method": pending.method, "id": msg.id, "extra": pending.extra},
                )

            await self._send(serialize(msg))

    # ── Task 3: stderr drain ───────────────────────────────────────────────────

    async def _forward_stderr(self, proc: asyncio.subprocess.Process) -> None:
        assert proc.stderr is not None
        while True:
            line = await proc.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()
