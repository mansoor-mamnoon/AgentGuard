"""JSON-RPC 2.0 message types for MCP, re-exported from backend with helpers."""

from __future__ import annotations

import json
from typing import Any

# Re-export the canonical message type so consumers import from one place.
from backend.mcp_proxy import (
    FirewallDecision,
    MCPMessage,
    contains_secret,
    detect_lookalike,
    redact_secrets,
)

__all__ = [
    "MCPMessage",
    "FirewallDecision",
    "contains_secret",
    "redact_secrets",
    "detect_lookalike",
    "parse_line",
    "serialize",
    "error_response",
    "MCPParseError",
]


class MCPParseError(ValueError):
    """Raised when a line cannot be parsed as a valid JSON-RPC message."""


def parse_line(raw: str | bytes) -> MCPMessage:
    """Parse a single newline-stripped JSON-RPC line into an MCPMessage."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    raw = raw.strip()
    if not raw:
        raise MCPParseError("empty line")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MCPParseError(f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise MCPParseError("message must be a JSON object")
    return MCPMessage.from_dict(data)


def serialize(msg: MCPMessage) -> bytes:
    """Serialize an MCPMessage to a newline-terminated UTF-8 byte string."""
    return (msg.dumps() + "\n").encode("utf-8")


def error_response(req_id: Any, code: int, message: str, data: Any = None) -> MCPMessage:
    return MCPMessage.error_response(req_id, code, message, data)
