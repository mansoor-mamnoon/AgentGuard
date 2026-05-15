"""
Day 10 — Tool misuse guardrails: capability gating.

Three protection layers:

1. Intent-to-tool gate
   Classifies user intent (keyword rules) and permits only the tools that
   serve that intent.  post_message is absent from every intent mapping:
   it is a write-side-effect tool that must be explicitly granted by the
   system, never triggered by user text alone.

2. Argument sanitization
   - Length caps per argument (prevents oversized payloads)
   - Channel allowlist (post_message locked to approved channels)
   - URL domain allowlist (blocks exfiltration via webhooks / external URLs)
   - Control-character stripping

3. Downgrade-to-read-only
   When a suspicion score (e.g. semantic drift from Day 9) exceeds a threshold,
   all tools except search_docs are stripped before the agent runs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# ── Intent classification ─────────────────────────────────────────────────────

INTENT_PATTERNS: dict[str, list[str]] = {
    # Check more specific intents first to prevent generic keywords (e.g. "what is")
    # from shadowing them.
    "email": ["email", "mail", "inbox", "message from"],
    "summarize": [
        "summarize",
        "summary",
        "read",
        "review",
        "explain",
        "analyze",
        "analysis",
    ],
    "search": [
        "search",
        "find",
        "look up",
        "what is",
        "tell me about",
        "describe",
        "where is",
        "locate",
    ],
}

# Permitted tools per intent.
# post_message is deliberately absent from every entry: write side-effects
# require explicit system authorization, not user intent.
INTENT_TOOL_PERMISSIONS: dict[str, frozenset[str]] = {
    "search": frozenset({"search_docs"}),
    "email": frozenset({"get_email", "search_docs"}),
    "summarize": frozenset({"get_email", "search_docs"}),
    "unknown": frozenset({"search_docs"}),  # safe read-only fallback
}

# ── Argument sanitization constants ───────────────────────────────────────────

MAX_ARG_LENGTH: int = 200
ALLOWED_CHANNELS: frozenset[str] = frozenset({"general", "announcements", "random"})
ALLOWED_DOMAINS: frozenset[str] = frozenset({"docs.internal", "api.internal"})

_URL_RE = re.compile(r"https?://([^/\s?#]+)")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _extract_domain(text: str) -> str | None:
    m = _URL_RE.search(text)
    return m.group(1).lower() if m else None


# ── Result types ──────────────────────────────────────────────────────────────


@dataclass
class SanitizeResult:
    sanitized_args: dict[str, Any]
    violations: list[str]
    blocked: bool  # True when a hard violation was found (don't execute the call)


@dataclass
class GateDecision:
    intent: str
    allowed_tools: list[str]
    blocked: bool  # True when no tools remain (request cannot proceed usefully)
    downgraded: bool  # True when tools were stripped due to suspicion score
    reason: str


# ── Components ────────────────────────────────────────────────────────────────


class IntentClassifier:
    """Keyword-based intent classifier. Returns one of: search, email, summarize, unknown."""

    def classify(self, text: str) -> str:
        low = text.lower()
        for intent, keywords in INTENT_PATTERNS.items():
            if any(kw in low for kw in keywords):
                return intent
        return "unknown"


class ArgSanitizer:
    """
    Argument sanitizer for tool calls.

    Soft violations (sanitize and note, do not block):
      - arg value > MAX_ARG_LENGTH  → truncate to MAX_ARG_LENGTH
      - control characters in value → strip

    Hard violations (set blocked=True):
      - channel arg not in ALLOWED_CHANNELS
      - URL whose domain is not in ALLOWED_DOMAINS
    """

    def sanitize(self, tool_name: str, args: dict[str, Any]) -> SanitizeResult:
        sanitized: dict[str, Any] = {}
        violations: list[str] = []
        blocked = False

        for key, val in args.items():
            if not isinstance(val, str):
                sanitized[key] = val
                continue

            # Strip control characters (soft)
            val = _CTRL_RE.sub("", val)

            # Length cap (soft)
            if len(val) > MAX_ARG_LENGTH:
                violations.append(
                    f"arg '{key}' truncated from {len(val)} to {MAX_ARG_LENGTH} chars"
                )
                val = val[:MAX_ARG_LENGTH]

            # Channel allowlist (hard)
            if key == "channel" and val.lower() not in ALLOWED_CHANNELS:
                violations.append(f"channel '{val}' not in allowlist {sorted(ALLOWED_CHANNELS)}")
                blocked = True

            # URL domain allowlist (hard)
            domain = _extract_domain(val)
            if domain is not None and domain not in ALLOWED_DOMAINS:
                violations.append(
                    f"URL domain '{domain}' not in allowlist {sorted(ALLOWED_DOMAINS)}"
                )
                blocked = True

            sanitized[key] = val

        return SanitizeResult(sanitized_args=sanitized, violations=violations, blocked=blocked)


# ── Gate ──────────────────────────────────────────────────────────────────────


class ToolGate:
    """
    Intent-to-tool gate with argument sanitization and suspicion-based downgrade.

    Primary guarantee: post_message is never added to allowed_tools by user
    intent alone, regardless of what tools the system has made available.

    Usage::

        gate = ToolGate()
        decision = gate.check(user_text, available_tools, suspicion_score=drift)
        if decision.blocked:
            return  # no safe tools remain
        tools = [t for t in tools if t.name in set(decision.allowed_tools)]

        # Later, before executing a tool call:
        sanitize = gate.sanitize_call(tool_name, args)
        if sanitize.blocked:
            return  # hard arg violation
        use sanitize.sanitized_args
    """

    READ_ONLY_TOOLS: frozenset[str] = frozenset({"search_docs"})
    DOWNGRADE_THRESHOLD: float = 0.3

    def __init__(self, downgrade_threshold: float = DOWNGRADE_THRESHOLD) -> None:
        self.downgrade_threshold = downgrade_threshold
        self._classifier = IntentClassifier()
        self._sanitizer = ArgSanitizer()

    def check(
        self,
        user_text: str,
        available_tools: list[str],
        suspicion_score: float = 0.0,
    ) -> GateDecision:
        """
        Determine which tools from available_tools are permitted for this request.

        Steps:
          1. Classify intent from user_text.
          2. Intersect available_tools with INTENT_TOOL_PERMISSIONS[intent].
          3. If suspicion_score >= downgrade_threshold, further restrict to READ_ONLY_TOOLS.
          4. If all available_tools were removed, set blocked=True.
        """
        intent = self._classifier.classify(user_text)
        permitted = INTENT_TOOL_PERMISSIONS.get(intent, INTENT_TOOL_PERMISSIONS["unknown"])

        allowed = [t for t in available_tools if t in permitted]

        downgraded = False
        if suspicion_score >= self.downgrade_threshold:
            allowed = [t for t in allowed if t in self.READ_ONLY_TOOLS]
            downgraded = True

        removed = sorted(set(available_tools) - set(allowed))
        blocked = bool(available_tools) and not allowed

        if downgraded:
            reason = (
                f"Downgraded to read-only (suspicion_score={suspicion_score:.3f} "
                f">= threshold={self.downgrade_threshold}); removed: {removed}"
            )
        elif removed:
            reason = f"Intent '{intent}': removed tools not needed for this task: {removed}"
        else:
            reason = f"Intent '{intent}': all available tools permitted."

        return GateDecision(
            intent=intent,
            allowed_tools=allowed,
            blocked=blocked,
            downgraded=downgraded,
            reason=reason,
        )

    def sanitize_call(self, tool_name: str, args: dict[str, Any]) -> SanitizeResult:
        """Sanitize concrete tool-call arguments before execution."""
        return self._sanitizer.sanitize(tool_name, args)
