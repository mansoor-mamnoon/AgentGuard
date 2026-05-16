"""Structured audit log — writes JSONL to a file and/or stderr."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuditLog:
    """Thread-safe structured audit logger.

    Each event is a JSON object written to the audit file (if configured) and
    optionally to stderr. In the async proxy, all writes happen from the event
    loop so no extra locking is needed.
    """

    def __init__(self, path: Path | None = None, to_stderr: bool = True) -> None:
        self._path = path
        self._to_stderr = to_stderr
        self._fh = open(path, "a", encoding="utf-8") if path else None  # noqa: SIM115

    def log(self, event: str, data: dict[str, Any]) -> None:
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
            **data,
        }
        line = json.dumps(record, default=str)
        if self._fh:
            self._fh.write(line + "\n")
            self._fh.flush()
        if self._to_stderr:
            sys.stderr.write(f"[audit] {line}\n")
            sys.stderr.flush()

    def log_block(self, method: str, reason: str, **extra: Any) -> None:
        self.log("block", {"method": method, "reason": reason, **extra})

    def log_allow(self, method: str, **extra: Any) -> None:
        self.log("allow", {"method": method, **extra})

    def log_sanitize(self, method: str, what: str, **extra: Any) -> None:
        self.log("sanitize", {"method": method, "what": what, **extra})

    def log_error(self, context: str, error: str, **extra: Any) -> None:
        self.log("error", {"context": context, "error": error, **extra})

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
