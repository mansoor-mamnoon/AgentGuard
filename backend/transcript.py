from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any


def new_run_id() -> str:
    # short unique ID that's human-readable
    return uuid.uuid4().hex[:12]


class TranscriptLogger:
    def __init__(self, run_id: str, base_dir: str = "runs") -> None:
        self.run_id = run_id
        self.path = Path(base_dir) / f"{run_id}.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event_type: str, payload: dict[str, Any]) -> None:
        record = {
            "ts": time.time(),
            "run_id": self.run_id,
            "event_type": event_type,
            "payload": payload,
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
