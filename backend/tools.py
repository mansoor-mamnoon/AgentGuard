from __future__ import annotations

import json
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
DOCS_DIR = DATA_DIR / "docs"
EMAILS_PATH = DATA_DIR / "emails.json"
POSTS_LOG = Path("runs") / "posted_messages.log"


def search_docs(query: str, k: int = 3) -> list[dict[str, str]]:
    """
    Naive local search: return up to k snippets from text files containing the query.
    """
    query_l = query.lower().strip()
    results = []
    for p in sorted(DOCS_DIR.glob("*.txt")):
        text = p.read_text(encoding="utf-8")
        if query_l in text.lower():
            # simple snippet: first 200 chars
            results.append({"doc": p.name, "snippet": text[:200]})
    return results[:k]


def get_email(email_id: str) -> dict[str, str]:
    """
    Return an email by id from a local JSON list.
    """
    emails = json.loads(EMAILS_PATH.read_text(encoding="utf-8"))
    for e in emails:
        if e["id"] == email_id:
            return e
    raise KeyError(f"email_id not found: {email_id}")


def post_message(channel: str, text: str) -> dict[str, str]:
    """
    Simulate a side-effect tool by appending to a local log file.
    """
    POSTS_LOG.parent.mkdir(parents=True, exist_ok=True)
    line = f"[channel={channel}] {text}\n"
    with POSTS_LOG.open("a", encoding="utf-8") as f:
        f.write(line)
    return {"status": "ok", "channel": channel, "chars_written": str(len(text))}
