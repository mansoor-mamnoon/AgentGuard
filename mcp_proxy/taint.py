"""Per-session taint context.

Tracks taint labels for in-flight requests so the response handler knows
what taint level the original request carried.
"""

from __future__ import annotations

from typing import Any

from backend.taint import TaintLabel


class SessionTaint:
    """Maps request IDs to the TaintLabel of their originating source."""

    def __init__(self) -> None:
        self._labels: dict[Any, TaintLabel] = {}
        self._methods: dict[Any, str] = {}

    def record(self, req_id: Any, method: str, label: TaintLabel) -> None:
        self._labels[req_id] = label
        self._methods[req_id] = method

    def pop(self, req_id: Any) -> tuple[str, TaintLabel] | tuple[None, None]:
        label = self._labels.pop(req_id, None)
        method = self._methods.pop(req_id, None)
        return method, label

    def label_for(self, req_id: Any) -> TaintLabel:
        return self._labels.get(req_id, TaintLabel.USER_UNTRUSTED)
