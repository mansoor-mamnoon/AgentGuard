"""
Policy DSL — YAML-configurable tool permission engine.

Compiles a YAML policy file into a runtime checker that enforces:
  - Which taint sources may invoke which tools
  - Which taint labels are forbidden in tool arguments
  - Which user intents may trigger which tools
  - Global rules (arg length, URL allowlist, FPR budget)

Usage::

    from backend.policy_dsl import PolicyCompiler, PolicyChecker

    compiler = PolicyCompiler()
    checker = compiler.compile("backend/policies/default.yaml")

    result = checker.check_call(
        tool_name="send_email",
        source_label=TaintLabel.RAG_UNTRUSTED,
        user_intent="summarize",
        args={"to": "attacker@evil.com", "body": "secrets"},
    )
    print(result.allowed)   # False
    print(result.reason)    # "UNTRUSTED_CANNOT_AUTHORIZE_WRITE_EXTERNAL"

Pipeline::

    natural language input
      → segments (taint labels)
      → intent classification
      → policy check (PolicyChecker.check_call)
      → tool permission set
      → execution guard (gate + arg sanitizer)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from backend.taint import TaintLabel

# ── Policy types ──────────────────────────────────────────────────────────────


@dataclass
class ToolPolicy:
    name: str
    effect: str  # read_private | write_external | write_internal | read_sensitive
    allowed_sources: list[str] = field(default_factory=list)
    forbidden_inputs: list[str] = field(default_factory=list)
    allowed_intents: list[str] | None = None
    requires: list[str] = field(default_factory=list)


@dataclass
class GlobalRules:
    max_arg_length: int = 500
    allowed_external_domains: list[str] = field(default_factory=list)
    block_on_external_url_in_args: bool = True
    fpr_budget: float = 0.10


@dataclass
class CompiledPolicy:
    tools: dict[str, ToolPolicy] = field(default_factory=dict)
    global_rules: GlobalRules = field(default_factory=GlobalRules)
    source_path: str = ""


# ── Check result ──────────────────────────────────────────────────────────────


@dataclass
class PolicyCheckResult:
    allowed: bool
    tool_name: str
    source_label: TaintLabel
    user_intent: str | None
    violations: list[str]
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "tool": self.tool_name,
            "source": self.source_label.name,
            "intent": self.user_intent,
            "violations": self.violations,
            "reason": self.reason,
        }


_URL_RE = re.compile(r"https?://([^/\s?#]+)")


# ── Compiler ──────────────────────────────────────────────────────────────────


class PolicyCompiler:
    """Loads and compiles a YAML policy file into a PolicyChecker."""

    def compile(self, policy_path: str | Path) -> PolicyChecker:
        path = Path(policy_path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        if yaml is None:
            raise ImportError("PyYAML is required for policy loading. Run: uv add pyyaml")

        raw = yaml.safe_load(path.read_text())
        tools = {}
        for tool_name, cfg in (raw.get("tools") or {}).items():
            tools[tool_name] = ToolPolicy(
                name=tool_name,
                effect=cfg.get("effect", "read_private"),
                allowed_sources=cfg.get("allowed_sources", []),
                forbidden_inputs=cfg.get("forbidden_inputs", []),
                allowed_intents=cfg.get("allowed_intents"),
                requires=cfg.get("requires", []),
            )

        gr_raw = raw.get("global_rules", {})
        global_rules = GlobalRules(
            max_arg_length=gr_raw.get("max_arg_length", 500),
            allowed_external_domains=gr_raw.get("allowed_external_domains", []),
            block_on_external_url_in_args=gr_raw.get("block_on_external_url_in_args", True),
            fpr_budget=gr_raw.get("fpr_budget", 0.10),
        )

        policy = CompiledPolicy(tools=tools, global_rules=global_rules, source_path=str(path))
        return PolicyChecker(policy)

    def compile_from_dict(self, raw: dict) -> PolicyChecker:
        """Compile from a dict (for testing without a YAML file)."""
        tools = {}
        for tool_name, cfg in (raw.get("tools") or {}).items():
            tools[tool_name] = ToolPolicy(
                name=tool_name,
                effect=cfg.get("effect", "read_private"),
                allowed_sources=cfg.get("allowed_sources", []),
                forbidden_inputs=cfg.get("forbidden_inputs", []),
                allowed_intents=cfg.get("allowed_intents"),
                requires=cfg.get("requires", []),
            )
        gr_raw = raw.get("global_rules", {})
        global_rules = GlobalRules(
            max_arg_length=gr_raw.get("max_arg_length", 500),
            allowed_external_domains=gr_raw.get("allowed_external_domains", []),
            block_on_external_url_in_args=gr_raw.get("block_on_external_url_in_args", True),
            fpr_budget=gr_raw.get("fpr_budget", 0.10),
        )
        policy = CompiledPolicy(tools=tools, global_rules=global_rules)
        return PolicyChecker(policy)


# ── Runtime checker ───────────────────────────────────────────────────────────


class PolicyChecker:
    """
    Runtime enforcement of a compiled policy.

    For each tool call, checks:
      1. Source label is in allowed_sources
      2. Source label is not in forbidden_inputs
      3. User intent is in allowed_intents (if specified)
      4. No external URLs in args (if block_on_external_url_in_args)
      5. Arg lengths within global max
    """

    def __init__(self, policy: CompiledPolicy) -> None:
        self.policy = policy

    def check_call(
        self,
        tool_name: str,
        source_label: TaintLabel,
        user_intent: str | None = None,
        args: dict[str, Any] | None = None,
    ) -> PolicyCheckResult:
        violations: list[str] = []
        tool_cfg = self.policy.tools.get(tool_name)

        if tool_cfg is None:
            # Unknown tool — deny by default
            return PolicyCheckResult(
                allowed=False,
                tool_name=tool_name,
                source_label=source_label,
                user_intent=user_intent,
                violations=["UNKNOWN_TOOL"],
                reason=f"Tool '{tool_name}' is not defined in the policy.",
            )

        # 1. Source must be in allowed_sources
        if source_label.name not in tool_cfg.allowed_sources:
            violations.append(f"SOURCE_NOT_ALLOWED:{source_label.name}")

        # 2. Source must not be in forbidden_inputs
        if source_label.name in tool_cfg.forbidden_inputs:
            violations.append(f"SOURCE_FORBIDDEN:{source_label.name}")

        # 3. Intent must be in allowed_intents (if list is specified)
        if tool_cfg.allowed_intents is not None and user_intent not in tool_cfg.allowed_intents:
            violations.append(f"INTENT_NOT_PERMITTED:{user_intent}")

        # 4 & 5. Arg validation
        if args:
            for key, val in args.items():
                if not isinstance(val, str):
                    continue
                if len(val) > self.policy.global_rules.max_arg_length:
                    violations.append(f"ARG_TOO_LONG:{key}")
                if self.policy.global_rules.block_on_external_url_in_args:
                    m = _URL_RE.search(val)
                    if m:
                        domain = m.group(1).lower()
                        if domain not in self.policy.global_rules.allowed_external_domains:
                            violations.append(f"EXTERNAL_URL_BLOCKED:{domain}")

        allowed = len(violations) == 0
        reason = "; ".join(violations) if violations else "PERMITTED"

        return PolicyCheckResult(
            allowed=allowed,
            tool_name=tool_name,
            source_label=source_label,
            user_intent=user_intent,
            violations=violations,
            reason=reason,
        )

    def permitted_tools(
        self,
        source_label: TaintLabel,
        user_intent: str | None = None,
        available_tools: list[str] | None = None,
    ) -> list[str]:
        """Return the subset of available_tools permitted under this source and intent."""
        candidate = list(self.policy.tools.keys()) if available_tools is None else available_tools
        return [t for t in candidate if self.check_call(t, source_label, user_intent).allowed]

    def explain(self, tool_name: str) -> str:
        """Return a human-readable explanation of the policy for a tool."""
        cfg = self.policy.tools.get(tool_name)
        if cfg is None:
            return f"Tool '{tool_name}': not defined (deny all)."
        lines = [
            f"Tool: {tool_name}",
            f"  Effect:           {cfg.effect}",
            f"  Allowed sources:  {', '.join(cfg.allowed_sources) or 'none'}",
            f"  Forbidden inputs: {', '.join(cfg.forbidden_inputs) or 'none'}",
            f"  Allowed intents:  {', '.join(cfg.allowed_intents) if cfg.allowed_intents else 'any'}",
            f"  Requires:         {', '.join(cfg.requires) or 'none'}",
        ]
        return "\n".join(lines)
