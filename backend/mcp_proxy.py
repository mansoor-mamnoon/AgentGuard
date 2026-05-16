"""
LLMFirewall MCP Security Proxy.

Sits between an LLM client (Claude, Cursor, custom agent) and upstream
MCP tool servers. Intercepts every JSON-RPC 2.0 message and applies:

  Inbound (client → upstream):
    tools/call   — allowlist, lookalike detection, taint policy, injection scan,
                   arg sanitization, secret-flow guard, write confirmation
    tools/list   — pass-through (response filtered on the way back)

  Outbound (upstream → client):
    tools/list   — strip non-allowlisted tools, flag lookalike names
    tools/call   — taint-label as TOOL_OUTPUT, injection scan on result content,
                   sanitize secret-bearing values before they reach the LLM

Transport
---------
The proxy reads newline-delimited JSON from stdin and writes to stdout —
identical to the MCP stdio transport.  An upstream MCP server is launched
as a subprocess; its stdin/stdout are the proxy's pipes.

In-process usage (tests / demo)
--------------------------------
    from backend.mcp_proxy import MCPFirewall, MCPMessage

    fw = MCPFirewall(allowed_tools={"search_docs", "read_email"})
    req = MCPMessage.call_request("tools/call", {"name": "post_slack", "arguments": {}})
    resp = fw.check_call_request(req, source_taint="user")
    # resp.blocked == True, resp.block_reason contains explanation

Stdio proxy usage
-----------------
    python -m backend.mcp_proxy --upstream "python -m my_mcp_server" \\
           --policy backend/policies/default.yaml \\
           --allow-tools search_docs,read_email,read_calendar

See ``proxy_main()`` for the full CLI.
"""

from __future__ import annotations

import difflib
import json
import logging
import re
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from typing import Any

from backend.context_classifier import classify_context
from backend.defense_v2 import DefenseV2
from backend.messages import MessageSegment, trust_for_source
from backend.taint import TaintedValue, TaintLabel, TaintPolicy

logger = logging.getLogger("llmfirewall.mcp")

# ── JSON-RPC helpers ──────────────────────────────────────────────────────────


@dataclass
class MCPMessage:
    """A single JSON-RPC 2.0 message (request, response, or notification)."""

    jsonrpc: str = "2.0"
    method: str | None = None  # present on requests & notifications
    id: Any = None  # present on requests & responses (not notifications)
    params: dict[str, Any] = field(default_factory=dict)
    result: Any = None  # present on success responses
    error: dict[str, Any] | None = None  # present on error responses

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MCPMessage:
        return cls(
            jsonrpc=d.get("jsonrpc", "2.0"),
            method=d.get("method"),
            id=d.get("id"),
            params=d.get("params") or {},
            result=d.get("result"),
            error=d.get("error"),
        )

    @classmethod
    def call_request(cls, method: str, params: dict[str, Any], req_id: Any = 1) -> MCPMessage:
        return cls(method=method, params=params, id=req_id)

    @classmethod
    def success(cls, req_id: Any, result: Any) -> MCPMessage:
        return cls(id=req_id, result=result)

    @classmethod
    def error_response(cls, req_id: Any, code: int, message: str, data: Any = None) -> MCPMessage:
        err: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return cls(id=req_id, error=err)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"jsonrpc": self.jsonrpc}
        if self.method is not None:
            d["method"] = self.method
        if self.id is not None:
            d["id"] = self.id
        if self.method is not None:
            d["params"] = self.params
        if self.result is not None:
            d["result"] = self.result
        if self.error is not None:
            d["error"] = self.error
        return d

    def is_request(self) -> bool:
        return self.method is not None and self.id is not None

    def is_notification(self) -> bool:
        return self.method is not None and self.id is None

    def is_response(self) -> bool:
        return self.method is None and self.id is not None

    def dumps(self) -> str:
        return json.dumps(self.to_dict())


# ── Firewall enforcement result ───────────────────────────────────────────────


@dataclass
class FirewallDecision:
    """The verdict + audit trail for one intercepted message."""

    blocked: bool
    block_reason: str = ""
    sanitized_message: MCPMessage | None = None  # modified message if rewritten
    warnings: list[str] = field(default_factory=list)
    audit: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def allow(
        cls,
        msg: MCPMessage | None = None,
        warnings: list[str] | None = None,
        audit: dict[str, Any] | None = None,
    ) -> FirewallDecision:
        return cls(
            blocked=False,
            sanitized_message=msg,
            warnings=warnings or [],
            audit=audit or {},
        )

    @classmethod
    def block(cls, reason: str, audit: dict[str, Any] | None = None) -> FirewallDecision:
        return cls(blocked=True, block_reason=reason, audit=audit or {})


# ── Lookalike tool detection ──────────────────────────────────────────────────

_HOMOGLYPH_MAP: dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "b",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
}
_LOOKALIKE_THRESHOLD = 0.80  # SequenceMatcher ratio


def _normalize(name: str) -> str:
    """Collapse homoglyphs and separators for comparison."""
    low = name.lower()
    out = []
    for ch in low:
        out.append(_HOMOGLYPH_MAP.get(ch, ch))
    return re.sub(r"[_\-\.]", "", "".join(out))


def detect_lookalike(candidate: str, trusted: set[str]) -> str | None:
    """
    Return the trusted tool name that `candidate` resembles if it is a likely
    lookalike but NOT an exact match. Returns None if clean.
    """
    if candidate in trusted:
        return None
    norm_c = _normalize(candidate)
    for t in trusted:
        norm_t = _normalize(t)
        ratio = difflib.SequenceMatcher(None, norm_c, norm_t).ratio()
        if ratio >= _LOOKALIKE_THRESHOLD:
            return t
    return None


# ── Secret pattern detector ───────────────────────────────────────────────────

_SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(r"sk-[A-Za-z0-9\-]{20,}", re.I),  # OpenAI / Anthropic keys (may have hyphens)
    re.compile(r"ghp_[A-Za-z0-9]{30,}", re.I),  # GitHub PAT
    re.compile(r"AKIA[0-9A-Z]{16}", re.I),  # AWS access key
    re.compile(r"[Bb]earer\s+[A-Za-z0-9\-_.]{20,}"),  # Bearer token
    re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----"),
    re.compile(r"(?i)password\s*[:=]\s*\S{8,}"),
    re.compile(r"(?i)api[_\-]?key\s*[:=]\s*\S{8,}"),
    re.compile(r"(?i)secret\s*[:=]\s*\S{8,}"),
    re.compile(r"tok-[A-Za-z0-9\-]{12,}"),  # internal token pattern
]


def contains_secret(text: str) -> bool:
    return any(p.search(text) for p in _SECRET_PATTERNS)


def redact_secrets(text: str) -> str:
    """Replace detected secret values with [REDACTED]."""
    for p in _SECRET_PATTERNS:
        text = p.sub("[REDACTED]", text)
    return text


# ── Injection detector for tool arguments / results ───────────────────────────

_DEFENSE = DefenseV2(threshold=0.04)
_TAINT_POLICY = TaintPolicy()


def _injection_score(text: str, source: str = "tool_output") -> float:
    """Return DefenseV2 combined score for a piece of text."""
    segs = [
        MessageSegment("system", trust_for_source("system"), "You are a helpful assistant."),
        MessageSegment(source, trust_for_source(source), text),
    ]
    sig = _DEFENSE.score(segs, text, [])
    return sig.combined


# ── Write-tool classification ─────────────────────────────────────────────────

_WRITE_KEYWORDS = re.compile(
    # No trailing \b — tool names like "post_slack" must still match "post"
    r"\b(?:send|post|create|write|delete|update|modify|transfer|publish|"
    r"upload|deploy|remove|patch|put|push)",
    re.I,
)


def _classify_tool_effect(tool_name: str, description: str = "") -> str:
    """Heuristically classify a tool as read-only or write."""
    combined = (tool_name + " " + description).lower()
    if _WRITE_KEYWORDS.search(combined):
        return "write"
    return "read"


# ── Core firewall ─────────────────────────────────────────────────────────────


class MCPFirewall:
    """
    Stateless enforcement layer applied to every intercepted MCP message.

    All checks are deterministic and sub-millisecond (no external calls).

    Parameters
    ----------
    allowed_tools : set[str] | None
        Explicit allowlist of tool names.  None means "allow all registered
        tools" (still subject to taint and injection checks).
    require_write_confirmation : bool
        When True, write-classified tools are blocked unless ``confirm=True``
        is present in the call params.  Useful for human-in-the-loop mode.
    injection_threshold : float
        DefenseV2 score above which a tool result is considered injected.
    policy_path : str | None
        Path to a policy YAML (uses backend.policy_dsl).  None = defaults only.
    """

    def __init__(
        self,
        allowed_tools: set[str] | None = None,
        require_write_confirmation: bool = False,
        injection_threshold: float = 0.04,
        policy_path: str | None = None,
    ) -> None:
        self.allowed_tools = allowed_tools  # None = allow all
        self.require_write_confirmation = require_write_confirmation
        self.injection_threshold = injection_threshold
        self._known_tools: dict[str, dict[str, Any]] = {}  # name → schema from tools/list
        self._taint: dict[str, TaintLabel] = {}  # call_id → taint for the request

        self._policy_checker = None
        if policy_path:
            try:
                from backend.policy_dsl import PolicyCompiler

                self._policy_checker = PolicyCompiler().compile(policy_path)
            except Exception as exc:
                logger.warning("Could not load policy %s: %s — using defaults", policy_path, exc)

    # ── tools/list response ───────────────────────────────────────────────────

    def filter_tools_list(self, tools: list[dict[str, Any]]) -> tuple[list[dict], list[str]]:
        """
        Given the raw tools/list result from upstream, return:
          (filtered_tools, warnings)

        Order of checks (both can produce warnings independently):
          1. Lookalike detection — block typosquatted names regardless of allowlist
          2. Allowlist — strip names not explicitly permitted
        """
        warnings: list[str] = []
        out: list[dict[str, Any]] = []

        # Trusted names are the allowlist if set, otherwise all tools in this response
        trusted_names = (
            self.allowed_tools
            if self.allowed_tools is not None
            else {t["name"] for t in tools if "name" in t}
        )

        for tool in tools:
            name = tool.get("name", "")
            # Register for later lookalike checks on call requests
            self._known_tools[name] = tool

            # 1. Lookalike detection (runs before allowlist so the reason is accurate)
            lookalike_of = detect_lookalike(name, trusted_names - {name})
            if lookalike_of:
                warnings.append(
                    f"Tool '{name}' blocked: lookalike of trusted tool '{lookalike_of}'"
                )
                continue

            # 2. Allowlist check
            if self.allowed_tools is not None and name not in self.allowed_tools:
                warnings.append(f"Tool '{name}' stripped: not in allowlist")
                continue

            out.append(tool)

        return out, warnings

    # ── tools/call request ────────────────────────────────────────────────────

    def check_call_request(
        self,
        msg: MCPMessage,
        source_taint: str | TaintLabel = "user",
        user_intent: str | None = None,
    ) -> FirewallDecision:
        """
        Validate an inbound tools/call request before forwarding to upstream.

        Checks (in order):
          1. Tool name in allowlist
          2. Lookalike detection
          3. Argument injection scan (user-supplied args)
          4. Arg sanitization (length, URL, control chars)
          5. Secret-bearing values in args
          6. Taint policy (RAG/TOOL_OUTPUT cannot authorize writes)
          7. Write confirmation gate (if require_write_confirmation)
        """
        label = (
            source_taint
            if isinstance(source_taint, TaintLabel)
            else TaintLabel.from_source(source_taint)
        )

        tool_name: str = msg.params.get("name", "")
        arguments: dict[str, Any] = msg.params.get("arguments") or {}
        audit: dict[str, Any] = {
            "tool": tool_name,
            "source_taint": label.name,
            "checks": [],
        }

        # 1. Lookalike detection (before allowlist — catches typosquatting even if name
        #    somehow appears in an allowlist the attacker influenced)
        trusted = (
            self.allowed_tools if self.allowed_tools is not None else set(self._known_tools.keys())
        )
        match = detect_lookalike(tool_name, trusted)
        if match:
            audit["checks"].append(f"lookalike:BLOCKED (resembles '{match}')")
            return FirewallDecision.block(
                f"Tool name '{tool_name}' resembles trusted tool '{match}' — possible typosquatting",
                audit=audit,
            )
        audit["checks"].append("lookalike:OK")

        # 2. Allowlist
        if self.allowed_tools is not None and tool_name not in self.allowed_tools:
            audit["checks"].append("allowlist:BLOCKED")
            return FirewallDecision.block(
                f"Tool '{tool_name}' is not in the allowed-tools list",
                audit=audit,
            )
        audit["checks"].append("allowlist:OK")

        # 3. Arg injection scan — check if any arg value looks like an injection payload.
        #    Skipped for SYSTEM_TRUSTED: system-originated args cannot be attacker-controlled.
        warnings: list[str] = []
        if label is not TaintLabel.SYSTEM_TRUSTED:
            for key, val in arguments.items():
                if not isinstance(val, str):
                    continue
                score = _injection_score(val, source="user")
                if score >= self.injection_threshold:
                    ctx = classify_context(val)
                    if not ctx.likely_hard_benign:
                        audit["checks"].append(f"arg_injection:BLOCKED key={key} score={score:.3f}")
                        return FirewallDecision.block(
                            f"Argument '{key}' contains injection payload (score={score:.3f})",
                            audit=audit,
                        )
                if score > self.injection_threshold * 0.5:
                    warnings.append(f"Arg '{key}' has elevated injection score ({score:.3f})")
        audit["checks"].append("arg_injection:OK")

        # 4. Arg sanitization
        san_violations: list[str] = []
        sanitized_args: dict[str, Any] = {}
        for key, val in arguments.items():
            if not isinstance(val, str):
                sanitized_args[key] = val
                continue
            # Strip control characters
            val = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", val)
            # Length cap
            if len(val) > 500:
                san_violations.append(f"arg '{key}' truncated to 500 chars")
                val = val[:500]
            # External URL block
            url_m = re.search(r"https?://([^/\s?#]+)", val)
            if url_m:
                domain = url_m.group(1).lower()
                if not domain.endswith((".internal", ".localhost")):
                    san_violations.append(f"external URL blocked in arg '{key}': {domain}")
                    audit["checks"].append(f"arg_sanitize:BLOCKED external_url={domain}")
                    return FirewallDecision.block(
                        f"External URL in argument '{key}' would exfiltrate data to '{domain}'",
                        audit=audit,
                    )
            sanitized_args[key] = val

        if san_violations:
            warnings.extend(san_violations)
        audit["checks"].append("arg_sanitize:OK")

        # 5. Secret detection in args
        for key, val in sanitized_args.items():
            if isinstance(val, str) and contains_secret(val):
                audit["checks"].append(f"secret_flow:BLOCKED key={key}")
                return FirewallDecision.block(
                    f"Argument '{key}' contains a secret-bearing value — exfiltration blocked",
                    audit=audit,
                )
        audit["checks"].append("secret_flow:OK")

        # 6. Taint policy
        tool_effect = _classify_tool_effect(
            tool_name,
            self._known_tools.get(tool_name, {}).get("description", ""),
        )
        if tool_effect == "write":
            violations = _TAINT_POLICY.check_tool_call(
                TaintedValue(json.dumps(sanitized_args), label),
                tool_name,
            )
            if violations:
                reasons = "; ".join(v.explanation for v in violations)
                audit["checks"].append(f"taint_policy:BLOCKED {reasons}")
                return FirewallDecision.block(
                    f"Taint policy violation for '{tool_name}': {reasons}",
                    audit=audit,
                )
        audit["checks"].append("taint_policy:OK")

        # 7. Write confirmation gate
        if self.require_write_confirmation and tool_effect == "write":
            if not msg.params.get("confirm", False):
                audit["checks"].append("write_confirm:BLOCKED")
                return FirewallDecision.block(
                    f"Tool '{tool_name}' is a write operation — set confirm=true to proceed",
                    audit=audit,
                )
        audit["checks"].append("write_confirm:OK")

        # Build (possibly sanitized) message to forward
        fwd_params = dict(msg.params)
        fwd_params["arguments"] = sanitized_args
        fwd_msg = MCPMessage(
            method=msg.method,
            id=msg.id,
            params=fwd_params,
        )
        return FirewallDecision.allow(msg=fwd_msg, warnings=warnings, audit=audit)

    # ── tools/call response ───────────────────────────────────────────────────

    def check_call_response(
        self,
        msg: MCPMessage,
        tool_name: str = "",
    ) -> FirewallDecision:
        """
        Scan an upstream tools/call response before returning it to the client.

        Checks:
          1. Injection in result content
          2. Secret-bearing values → redact
        """
        audit: dict[str, Any] = {"tool": tool_name, "checks": []}
        warnings: list[str] = []

        result_text = _extract_text(msg.result)

        # 1. Injection scan on tool output
        if result_text:
            score = _injection_score(result_text, source="tool_output")
            if score >= self.injection_threshold:
                audit["checks"].append(f"output_injection:BLOCKED score={score:.3f}")
                return FirewallDecision.block(
                    f"Tool output from '{tool_name}' contains injection payload (score={score:.3f})",
                    audit=audit,
                )
            if score > self.injection_threshold * 0.5:
                warnings.append(f"Tool output has elevated injection score ({score:.3f})")
        audit["checks"].append("output_injection:OK")

        # 2. Secret redaction
        redacted_result = _redact_result(msg.result)
        if redacted_result != msg.result:
            warnings.append(f"Secret values redacted from '{tool_name}' output")
        audit["checks"].append("secret_redact:OK")

        out_msg = MCPMessage(id=msg.id, result=redacted_result, error=msg.error)
        return FirewallDecision.allow(msg=out_msg, warnings=warnings, audit=audit)

    # ── resources/read response ───────────────────────────────────────────────

    def check_resource_response(self, msg: MCPMessage, uri: str = "") -> FirewallDecision:
        """Scan a resources/read result — treat as RAG_UNTRUSTED."""
        audit: dict[str, Any] = {"uri": uri, "checks": []}
        result_text = _extract_text(msg.result)

        if result_text:
            score = _injection_score(result_text, source="retrieved_doc")
            if score >= self.injection_threshold:
                audit["checks"].append(f"rag_injection:BLOCKED score={score:.3f}")
                return FirewallDecision.block(
                    f"Retrieved resource '{uri}' contains injection payload (score={score:.3f})",
                    audit=audit,
                )
        audit["checks"].append("rag_injection:OK")

        redacted_result = _redact_result(msg.result)
        warnings = ["Secret values redacted from resource"] if redacted_result != msg.result else []
        return FirewallDecision.allow(
            msg=MCPMessage(id=msg.id, result=redacted_result),
            warnings=warnings,
            audit=audit,
        )


# ── Result text extraction / redaction ────────────────────────────────────────


def _extract_text(result: Any) -> str:
    """Pull all string content out of a JSON-RPC result for scanning."""
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        parts = []
        for v in result.values():
            parts.append(_extract_text(v))
        return " ".join(parts)
    if isinstance(result, list):
        return " ".join(_extract_text(i) for i in result)
    return str(result) if result is not None else ""


def _redact_result(result: Any) -> Any:
    """Recursively redact secrets from a JSON-RPC result."""
    if isinstance(result, str):
        return redact_secrets(result)
    if isinstance(result, dict):
        return {k: _redact_result(v) for k, v in result.items()}
    if isinstance(result, list):
        return [_redact_result(i) for i in result]
    return result


# ── Stdio proxy ───────────────────────────────────────────────────────────────


class MCPStdioProxy:
    """
    Full stdio-transport MCP proxy.

    Spawns the upstream MCP server as a subprocess and pipes JSON-RPC
    messages through the MCPFirewall in both directions.

    Usage::

        proxy = MCPStdioProxy(
            upstream_cmd=["python", "-m", "my_mcp_server"],
            firewall=MCPFirewall(allowed_tools={"search_docs", "read_email"}),
        )
        proxy.run()   # blocks; reads stdin, writes stdout
    """

    def __init__(
        self,
        upstream_cmd: list[str],
        firewall: MCPFirewall,
        log_audit: bool = True,
    ) -> None:
        self.upstream_cmd = upstream_cmd
        self.firewall = firewall
        self.log_audit = log_audit
        self._pending: dict[Any, str] = {}  # id → tool_name for in-flight calls

    def run(self) -> None:
        """Start the proxy. Blocks until either side closes the pipe."""
        upstream = subprocess.Popen(
            self.upstream_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
        )

        # upstream → client (in a background thread)
        def _upstream_to_client():
            assert upstream.stdout
            for raw_line in upstream.stdout:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    msg = MCPMessage.from_dict(json.loads(line))
                    out = self._handle_outbound(msg)
                except Exception as exc:
                    logger.error("Error handling outbound message: %s", exc)
                    out = line
                sys.stdout.write(out + "\n")
                sys.stdout.flush()

        t = threading.Thread(target=_upstream_to_client, daemon=True)
        t.start()

        # client → upstream (main thread)
        assert upstream.stdin
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = MCPMessage.from_dict(json.loads(line))
                fwd = self._handle_inbound(msg)
            except Exception as exc:
                logger.error("Error handling inbound message: %s", exc)
                fwd = line

            if fwd:
                upstream.stdin.write((fwd + "\n").encode())
                upstream.stdin.flush()

        upstream.stdin.close()
        upstream.wait()

    # ── inbound (client → upstream) ───────────────────────────────────────────

    def _handle_inbound(self, msg: MCPMessage) -> str | None:
        """
        Process a client→upstream message.  Return the JSON string to forward,
        or None to drop/block the message.
        """
        if msg.method == "tools/call":
            decision = self.firewall.check_call_request(msg, source_taint="user")
            if self.log_audit:
                logger.info("tools/call [%s] → %s", msg.params.get("name"), decision.audit)
            if decision.blocked:
                err = MCPMessage.error_response(
                    msg.id, -32600, "LLMFirewall blocked", decision.block_reason
                )
                sys.stdout.write(err.dumps() + "\n")
                sys.stdout.flush()
                return None  # drop — already sent error to client
            # Track in-flight tool name for response matching
            if msg.id is not None:
                self._pending[msg.id] = msg.params.get("name", "")
            return decision.sanitized_message.dumps() if decision.sanitized_message else msg.dumps()

        if msg.method == "tools/list":
            # Pass through — we'll filter the response
            return msg.dumps()

        return msg.dumps()

    # ── outbound (upstream → client) ─────────────────────────────────────────

    def _handle_outbound(self, msg: MCPMessage) -> str:
        """Process an upstream→client message. Returns JSON string to send."""
        # tools/list response
        if msg.is_response() and msg.result and isinstance(msg.result, dict):
            if "tools" in msg.result:
                tools, warnings = self.firewall.filter_tools_list(msg.result["tools"])
                if warnings and self.log_audit:
                    for w in warnings:
                        logger.warning("tools/list filter: %s", w)
                new_result = dict(msg.result)
                new_result["tools"] = tools
                if warnings:
                    new_result["_firewall_warnings"] = warnings
                return MCPMessage.success(msg.id, new_result).dumps()

        # tools/call response
        if msg.is_response() and msg.id in self._pending:
            tool_name = self._pending.pop(msg.id)
            decision = self.firewall.check_call_response(msg, tool_name=tool_name)
            if self.log_audit:
                logger.info("tools/call result [%s] → %s", tool_name, decision.audit)
            if decision.blocked:
                err = MCPMessage.error_response(
                    msg.id, -32600, "LLMFirewall blocked output", decision.block_reason
                )
                return err.dumps()
            return decision.sanitized_message.dumps() if decision.sanitized_message else msg.dumps()

        return msg.dumps()


# ── CLI entry point ───────────────────────────────────────────────────────────


def proxy_main(argv: list[str] | None = None) -> None:
    import argparse

    ap = argparse.ArgumentParser(
        description="LLMFirewall MCP Security Proxy — enforces taint-aware least privilege"
    )
    ap.add_argument(
        "--upstream",
        required=True,
        help="Command to launch upstream MCP server, e.g. 'python -m my_server'",
    )
    ap.add_argument(
        "--allow-tools",
        default=None,
        help="Comma-separated allowlist of tool names (default: allow all)",
    )
    ap.add_argument(
        "--policy",
        default=None,
        help="Path to YAML policy file (e.g. backend/policies/default.yaml)",
    )
    ap.add_argument(
        "--require-write-confirm",
        action="store_true",
        help="Require confirm=true in params for any write-classified tool",
    )
    ap.add_argument(
        "--threshold",
        type=float,
        default=0.04,
        help="Injection detection threshold (default 0.04)",
    )
    ap.add_argument("--quiet", action="store_true", help="Suppress audit logs")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    allowed = (
        set(t.strip() for t in args.allow_tools.split(",") if t.strip())
        if args.allow_tools
        else None
    )

    firewall = MCPFirewall(
        allowed_tools=allowed,
        require_write_confirmation=args.require_write_confirm,
        injection_threshold=args.threshold,
        policy_path=args.policy,
    )

    import shlex

    cmd = shlex.split(args.upstream)
    proxy = MCPStdioProxy(upstream_cmd=cmd, firewall=firewall, log_audit=not args.quiet)
    proxy.run()


if __name__ == "__main__":
    proxy_main()
