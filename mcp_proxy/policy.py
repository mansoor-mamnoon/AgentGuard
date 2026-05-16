"""Policy layer — wraps MCPFirewall and extends it to resources and prompts."""

from __future__ import annotations

from typing import Any

from backend.mcp_proxy import (
    MCPFirewall,
    MCPMessage,
    _extract_text,  # type: ignore[attr-defined]
    _injection_score,  # type: ignore[attr-defined]
    _redact_result,  # type: ignore[attr-defined]
)

from .config import ProxyConfig


class PolicyLayer:
    """
    Full enforcement layer for all MCP message types.

    Wraps MCPFirewall (tools/list, tools/call, resources/read) and adds
    coverage for prompts/list, prompts/get, and resources/list.
    """

    def __init__(self, config: ProxyConfig) -> None:
        self._fw = MCPFirewall(
            allowed_tools=config.allowed_tools,
            require_write_confirmation=config.require_write_confirmation,
            injection_threshold=config.injection_threshold,
            policy_path=config.policy_path,
        )
        self._threshold = config.injection_threshold

    # ── Inbound (client → upstream) ────────────────────────────────────────────

    INTERCEPT_METHODS = frozenset(
        {
            "tools/list",
            "tools/call",
            "resources/list",
            "resources/read",
            "prompts/list",
            "prompts/get",
        }
    )

    def check_outbound(self, msg: MCPMessage) -> _OutboundDecision:
        """
        Decide what to do with an outbound (client → upstream) message.

        Returns an _OutboundDecision with:
          .blocked        — True if we should send an error back instead
          .reason         — human-readable block reason
          .needs_response — True if we need to intercept the upstream response
          .forward        — (possibly sanitized) message to send upstream
        """
        if msg.method == "tools/call":
            fw_decision = self._fw.check_call_request(msg, source_taint="user")
            if fw_decision.blocked:
                return _OutboundDecision(
                    blocked=True,
                    reason=fw_decision.block_reason,
                )
            fwd = fw_decision.sanitized_message or msg
            return _OutboundDecision(
                blocked=False,
                forward=fwd,
                needs_response=True,
                warnings=fw_decision.warnings,
            )

        if msg.method in self.INTERCEPT_METHODS:
            return _OutboundDecision(blocked=False, forward=msg, needs_response=True)

        # All other methods (initialize, initialized, ping, notifications…)
        return _OutboundDecision(blocked=False, forward=msg, needs_response=False)

    # ── Inbound (upstream → client) ────────────────────────────────────────────

    def transform_response(
        self,
        msg: MCPMessage,
        original_method: str,
        uri_or_tool: str = "",
    ) -> MCPMessage:
        """
        Inspect and possibly modify an upstream response before forwarding
        it to the client.  Returns the (possibly modified) MCPMessage.
        """
        if msg.error:
            return msg  # pass errors through untouched

        if original_method == "tools/list":
            return self._transform_tools_list(msg)
        if original_method == "tools/call":
            return self._transform_tools_call(msg, uri_or_tool)
        if original_method == "resources/list":
            return self._transform_resources_list(msg)
        if original_method == "resources/read":
            return self._transform_resources_read(msg, uri_or_tool)
        if original_method == "prompts/list":
            return self._transform_prompts_list(msg)
        if original_method == "prompts/get":
            return self._transform_prompts_get(msg, uri_or_tool)

        return msg

    # ── Per-method transformations ─────────────────────────────────────────────

    def _transform_tools_list(self, msg: MCPMessage) -> MCPMessage:
        if not isinstance(msg.result, dict) or "tools" not in msg.result:
            return msg
        filtered, warnings = self._fw.filter_tools_list(msg.result["tools"])
        new_result = dict(msg.result)
        new_result["tools"] = filtered
        if warnings:
            new_result.setdefault("_firewall_warnings", []).extend(warnings)
        return MCPMessage(id=msg.id, result=new_result)

    def _transform_tools_call(self, msg: MCPMessage, tool_name: str) -> MCPMessage:
        decision = self._fw.check_call_response(msg, tool_name=tool_name)
        if decision.blocked:
            return MCPMessage.error_response(
                msg.id,
                -32001,
                f"LLMFirewall blocked tool output: {decision.block_reason}",
            )
        return decision.sanitized_message or msg

    def _transform_resources_list(self, msg: MCPMessage) -> MCPMessage:
        if not isinstance(msg.result, dict) or "resources" not in msg.result:
            return msg
        resources = msg.result["resources"]
        warnings: list[str] = []
        cleaned: list[Any] = []
        for res in resources:
            desc = res.get("description", "") or ""
            if desc and _injection_score(desc, source="retrieved_doc") >= self._threshold:
                warnings.append(f"Resource '{res.get('uri', '?')}' description flagged — stripped")
                res = dict(res)
                res["description"] = "[description removed by LLMFirewall]"
            cleaned.append(res)
        new_result = dict(msg.result)
        new_result["resources"] = cleaned
        if warnings:
            new_result.setdefault("_firewall_warnings", []).extend(warnings)
        return MCPMessage(id=msg.id, result=new_result)

    def _transform_resources_read(self, msg: MCPMessage, uri: str) -> MCPMessage:
        decision = self._fw.check_resource_response(msg, uri=uri)
        if decision.blocked:
            return MCPMessage.error_response(
                msg.id,
                -32001,
                f"LLMFirewall blocked resource: {decision.block_reason}",
            )
        return decision.sanitized_message or msg

    def _transform_prompts_list(self, msg: MCPMessage) -> MCPMessage:
        if not isinstance(msg.result, dict) or "prompts" not in msg.result:
            return msg
        prompts = msg.result["prompts"]
        warnings: list[str] = []
        cleaned: list[Any] = []
        for prompt in prompts:
            desc = prompt.get("description", "") or ""
            if desc and _injection_score(desc, source="retrieved_doc") >= self._threshold:
                warnings.append(
                    f"Prompt '{prompt.get('name', '?')}' description flagged — stripped"
                )
                prompt = dict(prompt)
                prompt["description"] = "[description removed by LLMFirewall]"
            cleaned.append(prompt)
        new_result = dict(msg.result)
        new_result["prompts"] = cleaned
        if warnings:
            new_result.setdefault("_firewall_warnings", []).extend(warnings)
        return MCPMessage(id=msg.id, result=new_result)

    def _transform_prompts_get(self, msg: MCPMessage, prompt_name: str) -> MCPMessage:
        """Scan prompt messages for injection and redact secrets."""
        if not isinstance(msg.result, dict):
            return msg

        all_text = _extract_text(msg.result)
        if all_text and _injection_score(all_text, source="retrieved_doc") >= self._threshold:
            return MCPMessage.error_response(
                msg.id,
                -32001,
                f"LLMFirewall blocked prompt '{prompt_name}': contains injection payload",
            )

        redacted = _redact_result(msg.result)
        warnings: list[str] = []
        if redacted != msg.result:
            warnings.append(f"Secrets redacted from prompt '{prompt_name}'")

        result = redacted
        if warnings:
            if isinstance(result, dict):
                result = dict(result)
                result.setdefault("_firewall_warnings", []).extend(warnings)

        return MCPMessage(id=msg.id, result=result)


class _OutboundDecision:
    __slots__ = ("blocked", "reason", "forward", "needs_response", "warnings")

    def __init__(
        self,
        blocked: bool,
        reason: str = "",
        forward: MCPMessage | None = None,
        needs_response: bool = False,
        warnings: list[str] | None = None,
    ) -> None:
        self.blocked = blocked
        self.reason = reason
        self.forward = forward
        self.needs_response = needs_response
        self.warnings = warnings or []
