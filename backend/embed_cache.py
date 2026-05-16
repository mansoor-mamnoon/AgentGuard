"""
Day 16 — SQLite-backed embedding cache.

Caches _stable_embed() results to avoid re-computing SHA-256 feature hashes
for repeated texts. Significant speedup when the same document snippets or
archetype strings are scored multiple times across an eval run.

Design
------
  - Thread-safe: each thread gets its own sqlite3.Connection.
  - Cache key: SHA-256(f"{dim}:{text}") — keeps DB rows small regardless of
    text length.
  - Embeddings stored as JSON arrays — portable and human-readable.
  - In-memory mode (path=":memory:") supported for tests and ephemeral runs.

Usage::

    from backend.embed_cache import EmbedCache
    from backend.semantic_detector import _stable_embed

    cache = EmbedCache("data/embed_cache.db")
    vec   = cache.get_or_compute("hello world", dim=512, compute_fn=_stable_embed)
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path

_INIT_SQL = """
CREATE TABLE IF NOT EXISTS embed_cache (
    cache_key TEXT PRIMARY KEY,
    embedding  TEXT NOT NULL
);
"""

EmbedFn = Callable[[str, int], list[float]]


def _cache_key(text: str, dim: int) -> str:
    return hashlib.sha256(f"{dim}:{text}".encode()).hexdigest()


class EmbedCache:
    """
    Thread-safe SQLite embedding cache.

    Each thread maintains its own connection; the underlying DB file is shared
    across threads (SQLite WAL mode handles concurrent reads safely).
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        self._local = threading.local()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        # Initialise schema on the calling thread's connection.
        self._conn().commit()

    # ── connection management ─────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(_INIT_SQL)
            conn.commit()
            self._local.conn = conn
        return self._local.conn

    # ── public API ────────────────────────────────────────────────────────────

    def get(self, text: str, dim: int) -> list[float] | None:
        """Return cached embedding or None on cache miss."""
        key = _cache_key(text, dim)
        row = (
            self._conn()
            .execute("SELECT embedding FROM embed_cache WHERE cache_key = ?", (key,))
            .fetchone()
        )
        with self._lock:
            if row is None:
                self._misses += 1
                return None
            self._hits += 1
        return json.loads(row[0])

    def put(self, text: str, dim: int, embedding: list[float]) -> None:
        """Store an embedding. Silently overwrites on collision."""
        key = _cache_key(text, dim)
        conn = self._conn()
        conn.execute(
            "INSERT OR REPLACE INTO embed_cache (cache_key, embedding) VALUES (?, ?)",
            (key, json.dumps(embedding)),
        )
        conn.commit()

    def get_or_compute(
        self,
        text: str,
        dim: int,
        compute_fn: EmbedFn,
    ) -> list[float]:
        """Return cached embedding, computing and storing it on a miss."""
        cached = self.get(text, dim)
        if cached is not None:
            return cached
        result = compute_fn(text, dim)
        self.put(text, dim, result)
        return result

    def batch_get_or_compute(
        self,
        texts: list[str],
        dim: int,
        compute_fn: EmbedFn,
    ) -> list[list[float]]:
        """
        Return embeddings for all texts in order.

        Cache hits are served without calling compute_fn; misses are computed
        individually and stored. For CPU-bound compute_fn the main speedup comes
        from avoiding recomputation across repeated calls, not from batching
        at the compute level.
        """
        return [self.get_or_compute(t, dim, compute_fn) for t in texts]

    # ── statistics & maintenance ──────────────────────────────────────────────

    @property
    def stats(self) -> dict[str, int]:
        return {"hits": self._hits, "misses": self._misses, "size": len(self)}

    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def clear(self) -> None:
        self._conn().execute("DELETE FROM embed_cache")
        self._conn().commit()
        with self._lock:
            self._hits = 0
            self._misses = 0

    def __len__(self) -> int:
        row = self._conn().execute("SELECT COUNT(*) FROM embed_cache").fetchone()
        return int(row[0]) if row else 0
