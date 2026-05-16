"""
Day 16 — Parallel eval runner with latency budget reporting.

Scores a JSONL dataset using DefenseV2, parallelized across worker processes.
Each worker maintains its own in-process embedding cache so repeated texts
are not re-hashed within a worker's lifetime.

Reports per-item latency statistics (p50, p95, p99) and throughput.

CLI::

    uv run python -m eval.run_eval_parallel \\
        --dataset data/attacks_v2.jsonl \\
        --workers 4 \\
        --budget_ms 200

Exit code 0 if p95 latency ≤ budget, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

# ── Worker (runs in child process) ───────────────────────────────────────────
# Must be a top-level function so ProcessPoolExecutor can pickle it.


def _score_one(case: dict[str, Any]) -> dict[str, Any]:
    """
    Score a single case with DefenseV2 and return timing + result.

    Imports are inside the function so each worker process gets its own
    module-level state (including the module-level _SEMANTIC singleton).
    """
    from backend.defense_v2 import DefenseV2  # noqa: PLC0415

    payload = case.get("payload", "")
    doc_content = case.get("doc_content")
    if isinstance(payload, list):
        user_text = " ".join(str(p) for p in payload)
    else:
        user_text = str(payload)

    scorer = DefenseV2()
    t0 = time.perf_counter()
    signals = scorer.score_text(user_text, doc_content=doc_content)
    elapsed = time.perf_counter() - t0

    return {
        "case_id": str(case.get("attack_id", case.get("case_id", "unknown"))),
        "combined": round(signals.combined, 4),
        "latency_s": elapsed,
        "attack_type": case.get("attack_type", "unknown"),
    }


# ── Latency stats ─────────────────────────────────────────────────────────────


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    sorted_v = sorted(values)
    idx = min(int(pct * len(sorted_v)), len(sorted_v) - 1)
    return sorted_v[idx]


def _latency_stats(latencies_s: list[float]) -> dict[str, float]:
    return {
        "p50_ms": round(_percentile(latencies_s, 0.50) * 1000, 2),
        "p95_ms": round(_percentile(latencies_s, 0.95) * 1000, 2),
        "p99_ms": round(_percentile(latencies_s, 0.99) * 1000, 2),
        "mean_ms": round(sum(latencies_s) / len(latencies_s) * 1000, 2) if latencies_s else 0.0,
        "max_ms": round(max(latencies_s) * 1000, 2) if latencies_s else 0.0,
    }


# ── Core eval function (importable by tests) ──────────────────────────────────


def run_parallel_eval(
    cases: list[dict[str, Any]],
    max_workers: int = 4,
) -> dict[str, Any]:
    """
    Score all cases using a process pool; return results and latency stats.

    Returns a dict with keys:
      results   — list of per-case dicts (case_id, combined, latency_s, attack_type)
      latency   — latency stats dict (p50_ms, p95_ms, p99_ms, mean_ms, max_ms)
      n_scored  — total cases scored
      n_workers — workers used
      wall_s    — total wall-clock seconds
    """
    if not cases:
        return {
            "results": [],
            "latency": _latency_stats([]),
            "n_scored": 0,
            "n_workers": max_workers,
            "wall_s": 0.0,
        }

    results: list[dict[str, Any]] = []
    wall_start = time.perf_counter()

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_score_one, case): i for i, case in enumerate(cases)}
        for future in as_completed(futures):
            results.append(future.result())

    wall_s = time.perf_counter() - wall_start
    latencies = [r["latency_s"] for r in results]

    return {
        "results": results,
        "latency": _latency_stats(latencies),
        "n_scored": len(results),
        "n_workers": max_workers,
        "wall_s": round(wall_s, 3),
    }


def run_sequential_eval(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Single-process baseline for comparison."""
    results = []
    wall_start = time.perf_counter()
    for case in cases:
        results.append(_score_one(case))
    wall_s = time.perf_counter() - wall_start
    latencies = [r["latency_s"] for r in results]
    return {
        "results": results,
        "latency": _latency_stats(latencies),
        "n_scored": len(results),
        "n_workers": 1,
        "wall_s": round(wall_s, 3),
    }


# ── CLI ───────────────────────────────────────────────────────────────────────


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="Parallel eval runner (Day 16)")
    ap.add_argument("--dataset", required=True, help="JSONL dataset path")
    ap.add_argument("--workers", type=int, default=4, help="Worker processes")
    ap.add_argument("--budget_ms", type=float, default=200.0, help="p95 latency budget (ms)")
    ap.add_argument("--limit", type=int, default=None, help="Max cases to score")
    args = ap.parse_args()

    cases = _load_jsonl(Path(args.dataset))
    if args.limit:
        cases = cases[: args.limit]

    print(f"Scoring {len(cases)} cases with {args.workers} workers …")
    report = run_parallel_eval(cases, max_workers=args.workers)

    lat = report["latency"]
    print(f"\nLatency (per item, n={report['n_scored']})")
    print(f"  p50  : {lat['p50_ms']:7.1f} ms")
    print(f"  p95  : {lat['p95_ms']:7.1f} ms  (budget: {args.budget_ms:.0f} ms)")
    print(f"  p99  : {lat['p99_ms']:7.1f} ms")
    print(f"  mean : {lat['mean_ms']:7.1f} ms")
    print(f"  max  : {lat['max_ms']:7.1f} ms")
    print(f"\nWall time : {report['wall_s']:.2f} s")
    print(f"Throughput: {report['n_scored'] / report['wall_s']:.1f} cases/s")

    within_budget = lat["p95_ms"] <= args.budget_ms
    status = "PASS" if within_budget else "FAIL"
    print(f"\nLatency budget ({args.budget_ms:.0f} ms p95): {status}")

    import sys

    sys.exit(0 if within_budget else 1)


if __name__ == "__main__":
    main()
