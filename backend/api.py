"""
Day 15 — Evaluation dashboard API.

Endpoints
---------
  GET /health              — liveness check
  GET /runs                — list all run files with summary stats
  GET /runs/{run_id}       — single run with turns, segments, detector flags
  GET /metrics             — aggregate metrics across all runs
  GET /report              — self-contained HTML dashboard
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from backend.html_report import generate_html_report

app = FastAPI(title="LLMFirewall Dashboard", version="1.0.0")

# Default locations — override via environment or direct instantiation
_DEFAULT_RUNS_DIR = Path("data/runs")
_DEFAULT_CALIBRATION = Path("data/calibration_report.json")


# ── helpers ───────────────────────────────────────────────────────────────────


def _runs_dir() -> Path:
    return _DEFAULT_RUNS_DIR


def _calibration_path() -> Path | None:
    p = _DEFAULT_CALIBRATION
    return p if p.exists() else None


def _load_runs() -> list[dict[str, Any]]:
    """Load all JSONL run files from the runs directory."""
    d = _runs_dir()
    if not d.exists():
        return []
    runs: list[dict[str, Any]] = []
    for path in sorted(d.glob("*.jsonl")):
        rows = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        if rows:
            runs.append({"run_id": path.stem, "path": str(path), "rows": rows})
    return runs


def _summarise_run(run: dict[str, Any]) -> dict[str, Any]:
    """Return a lightweight summary dict for the /runs list."""
    rows = run["rows"]
    total = len(rows)
    blocked = sum(1 for r in rows if r.get("any_blocked") or r.get("blocked"))
    asr = 1.0 - (blocked / total) if total else 0.0
    modes = list({r.get("mode", "unknown") for r in rows})
    return {
        "run_id": run["run_id"],
        "total_cases": total,
        "blocked": blocked,
        "asr": round(asr, 4),
        "modes": modes,
    }


def _turn_detail(turn: dict[str, Any]) -> dict[str, Any]:
    """Format a single turn for the detail response."""
    signals = turn.get("signals", {})
    return {
        "turn_idx": turn.get("turn_idx", 0),
        "user_text": turn.get("user_text", ""),
        "restriction_level": turn.get("restriction_level", "unknown"),
        "suspicion_score": turn.get("suspicion_score", 0.0),
        "blocked": turn.get("blocked", False),
        "rewritten_text": turn.get("rewritten_text"),
        "allowed_tools": turn.get("allowed_tools", []),
        "detector_flags": {
            "semantic_drift": signals.get("semantic_drift", 0.0),
            "regex_triggered": signals.get("regex_triggered", False),
            "gate_downgraded": signals.get("gate_downgraded", False),
        },
    }


def _find_run(run_id: str, runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    for run in runs:
        if run["run_id"] == run_id:
            return run
    return None


# ── endpoints ─────────────────────────────────────────────────────────────────


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/runs")
def list_runs() -> list[dict[str, Any]]:
    """List all evaluation runs with summary statistics."""
    runs = _load_runs()
    return [_summarise_run(r) for r in runs]


@app.get("/runs/{run_id}")
def get_run(run_id: str) -> dict[str, Any]:
    """
    Return full detail for a single run: all cases with per-turn detector
    flags, prompt segments, and policy actions.
    """
    runs = _load_runs()
    run = _find_run(run_id, runs)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

    cases = []
    for row in run["rows"]:
        turns_raw = row.get("turns", [])
        cases.append(
            {
                "case_id": row.get("case_id", "unknown"),
                "mode": row.get("mode", "unknown"),
                "final_suspicion": row.get("final_suspicion", 0.0),
                "any_blocked": row.get("any_blocked", False),
                "turns": [_turn_detail(t) for t in turns_raw],
            }
        )

    blocked = sum(1 for c in cases if c["any_blocked"])
    total = len(cases)
    return {
        "run_id": run_id,
        "total_cases": total,
        "blocked": blocked,
        "asr": round(1.0 - (blocked / total), 4) if total else 0.0,
        "cases": cases,
    }


@app.get("/metrics")
def get_metrics() -> dict[str, Any]:
    """Aggregate metrics across all runs."""
    runs = _load_runs()
    if not runs:
        return {"total_runs": 0, "total_cases": 0, "overall_asr": None}

    total_cases = 0
    total_blocked = 0
    run_summaries = []

    for run in runs:
        s = _summarise_run(run)
        total_cases += s["total_cases"]
        total_blocked += s["blocked"]
        run_summaries.append(s)

    overall_asr = round(1.0 - (total_blocked / total_cases), 4) if total_cases else None

    cal_path = _calibration_path()
    calibration: dict[str, Any] | None = None
    if cal_path:
        try:
            calibration = json.loads(cal_path.read_text(encoding="utf-8"))
            # Keep only the summary fields, not the full curve
            calibration = {k: v for k, v in calibration.items() if k != "validation_curve"}
        except Exception:
            calibration = None

    return {
        "total_runs": len(runs),
        "total_cases": total_cases,
        "total_blocked": total_blocked,
        "overall_asr": overall_asr,
        "per_run": run_summaries,
        "calibration": calibration,
    }


@app.get("/report", response_class=HTMLResponse)
def html_report() -> HTMLResponse:
    """Serve the self-contained HTML evaluation dashboard."""
    html = generate_html_report(
        runs_dir=_runs_dir(),
        calibration_path=_calibration_path(),
    )
    return HTMLResponse(content=html)
