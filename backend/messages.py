from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

SourceType = Literal["system", "user", "tool_output", "retrieved_doc"]
TrustLevel = Literal["trusted", "untrusted"]


@dataclass
class MessageSegment:
    """
    A segment of content that will be included in the agent's prompt.

    Key security idea:
    - We must never lose where content came from (source),
      because source determines trust_level.
    """

    source: SourceType
    trust_level: TrustLevel
    content: str

    # Optional metadata for debugging / eval (e.g., tool name, doc id)
    meta: dict[str, Any] | None = None


def trust_for_source(source: SourceType) -> TrustLevel:
    """
    First-principles rule:
    - Only the system prompt is trusted.
    - Everything else is untrusted because it may be attacker-controlled.
    """
    return "trusted" if source == "system" else "untrusted"
