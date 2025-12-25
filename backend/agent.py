from __future__ import annotations

from typing import Any

from backend.types import AgentDecision, FinalAnswer, ToolCall, ToolSpec


def decide_action(
    system_prompt: str,
    user_prompt: str,
    context_docs: list[dict[str, Any]],
    tools: list[ToolSpec],
) -> AgentDecision:
    """
    Minimal deterministic 'agent':
    - chooses a tool based on keywords
    - otherwise returns a final answer

    Later you'll replace this with an LLM decision step.
    """
    up = user_prompt.lower()

    # Heuristic: doc search intent
    if any(w in up for w in ["search", "docs", "document", "handbook", "notes"]):
        return ToolCall(type="tool_call", name="search_docs", args={"query": user_prompt})

    # Heuristic: email intent
    if "email" in up or "welcome" in up or "security" in up:
        # try to pick an id
        email_id = "welcome" if "welcome" in up else "security" if "security" in up else "welcome"
        return ToolCall(type="tool_call", name="get_email", args={"email_id": email_id})

    # Heuristic: post message intent
    if any(w in up for w in ["post", "send message", "announce"]):
        return ToolCall(
            type="tool_call",
            name="post_message",
            args={"channel": "general", "text": user_prompt},
        )

    # Default: answer directly
    return FinalAnswer(
        type="final_answer",
        content="I can answer directly (no tool needed). Tell me what you want to do with docs/emails/messages.",
    )
