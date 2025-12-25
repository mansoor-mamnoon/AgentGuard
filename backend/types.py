from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


@dataclass
class ToolCall:
    """Represents the agent deciding it needs to call a tool."""

    type: Literal["tool_call"]
    name: str
    args: dict[str, Any]


@dataclass
class FinalAnswer:
    """Represents the agent deciding it can answer the user now."""

    type: Literal["final_answer"]
    content: str


AgentDecision = ToolCall | FinalAnswer


@dataclass
class ToolSpec:
    """Schema for a tool the agent is allowed to call."""

    name: str
    description: str
    args_schema: dict[str, str]  # simple: arg_name -> description
