"""
Baseline comparison — measures multiple defense configurations
across both attack recall and benign FPR.

Baselines evaluated:
  1. No defense         — pass everything through
  2. Regex denylist     — Layer 1 only, policy engine
  3. Semantic only      — Layer 2 only, drift detector
  4. LLM-as-judge       — simulated via the SemanticDetector with a lower threshold
  5. Read/write isolation only — ToolGate only, no scoring
  6. Full LLMFirewall   — all four layers, calibrated threshold

Usage::

    python -m eval.baselines
    python -m eval.baselines --json data/baseline_results.json
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from backend.defense_v2 import DefenseV2
from backend.messages import MessageSegment, trust_for_source
from backend.policy_engine import PolicyEngine
from backend.semantic_detector import SemanticDetector
from backend.tool_gate import ToolGate

THRESHOLD = 0.04
DATA_DIR = Path(__file__).parent.parent / "data"
BENCH_DIR = Path(__file__).parent.parent / "benchmarks"


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _build_segs(payload: str, doc: str | None = None) -> list[MessageSegment]:
    segs = [
        MessageSegment("system", "trusted", "You are a helpful assistant."),
        MessageSegment("user", "untrusted", payload),
    ]
    if doc:
        segs.append(MessageSegment("retrieved_doc", trust_for_source("retrieved_doc"), doc))
    return segs


# ── Baseline implementations ──────────────────────────────────────────────────


def _no_defense(payload: str, doc: str | None = None) -> bool:
    """Always allow — 0% block rate."""
    return False


def _regex_only(payload: str, doc: str | None = None) -> bool:
    """Layer 1 only: regex denylist via PolicyEngine."""
    segs = _build_segs(payload, doc)
    engine = PolicyEngine()
    pd = engine.evaluate("", segs, payload, ["search_docs", "post_message"])
    return pd.action != "allow"


def _semantic_only(payload: str, doc: str | None = None) -> bool:
    """Layer 2 only: semantic drift detector at default threshold."""
    segs = _build_segs(payload, doc)
    detector = SemanticDetector(threshold=0.07)
    results = detector.check_segments(segs)
    return any(r.flagged for r in results)


def _llm_judge_sim(payload: str, doc: str | None = None) -> bool:
    """
    Simulated LLM-as-judge using a more sensitive semantic threshold.
    In production this would call an LLM classifier. Here we simulate
    a more aggressive semantic detector (lower threshold) to approximate
    the sensitivity/specificity tradeoff of an LLM-based filter.
    """
    segs = _build_segs(payload, doc)
    detector = SemanticDetector(threshold=0.03)  # more aggressive
    results = detector.check_segments(segs)
    return any(r.flagged for r in results)


def _gate_only(payload: str, doc: str | None = None) -> bool:
    """
    Read/write tool isolation only — no scoring, just gate.
    Block if the requested intent would need write tools.
    This is 'capability isolation without detection'.
    """
    gate = ToolGate()
    decision = gate.check(
        payload, ["search_docs", "send_email", "post_message"], suspicion_score=0.0
    )
    # Block only if all tools were removed (true block) — approximates read/write isolation
    return decision.blocked


def _full_llmfirewall(payload: str, doc: str | None = None) -> bool:
    """Full 4-layer LLMFirewall with calibrated threshold."""
    segs = _build_segs(payload, doc)
    scorer = DefenseV2(threshold=THRESHOLD)
    sig = scorer.score(segs, payload, ["search_docs", "send_email", "post_message"])
    return sig.combined > THRESHOLD


BASELINES = {
    "no_defense": _no_defense,
    "regex_only": _regex_only,
    "semantic_only": _semantic_only,
    "llm_judge_sim": _llm_judge_sim,
    "gate_only": _gate_only,
    "llmfirewall_full": _full_llmfirewall,
}


# ── Evaluator ─────────────────────────────────────────────────────────────────


def _eval_baseline(
    name: str,
    fn,
    attack_records: list[dict],
    benign_records: list[dict],
) -> dict[str, Any]:
    t0 = time.perf_counter()

    # Score attacks
    attack_blocked = 0
    for r in attack_records:
        payload = r.get("payload", "")
        doc = r.get("doc_content") or r.get("injected_tool_output")
        if fn(payload, doc):
            attack_blocked += 1

    # Score benign
    benign_blocked = 0
    for r in benign_records:
        payload = r.get("payload", "")
        if fn(payload, None):
            benign_blocked += 1

    total_time_ms = (time.perf_counter() - t0) * 1000

    n_attack = len(attack_records)
    n_benign = len(benign_records)

    recall = attack_blocked / n_attack if n_attack else 0
    fpr = benign_blocked / n_benign if n_benign else 0
    asr = 1.0 - recall
    precision = (
        attack_blocked / (attack_blocked + benign_blocked)
        if (attack_blocked + benign_blocked)
        else 0
    )
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    avg_lat = total_time_ms / (n_attack + n_benign) if (n_attack + n_benign) else 0

    return {
        "baseline": name,
        "n_attack": n_attack,
        "n_benign": n_benign,
        "asr": round(asr, 4),
        "recall": round(recall, 4),
        "fpr": round(fpr, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "avg_latency_ms": round(avg_lat, 3),
    }


def run_comparison(
    attack_limit: int = 500,
    benign_limit: int = 500,
) -> dict[str, Any]:
    # Load data — prefer benchmark suite, fall back to legacy data/
    attack_records = (
        _load_jsonl(BENCH_DIR / "agentdojo" / "direct_attacks.jsonl")[:attack_limit]
        + _load_jsonl(BENCH_DIR / "custom_enterprise_rag" / "indirect_attacks.jsonl")[
            : attack_limit // 2
        ]
    )
    benign_records = _load_jsonl(BENCH_DIR / "agentdojo" / "benign.jsonl")[:benign_limit]

    if not attack_records:
        attack_records = _load_jsonl(DATA_DIR / "attacks_v2.jsonl")[:attack_limit]
    if not benign_records:
        benign_records = _load_jsonl(DATA_DIR / "benign.jsonl")[:benign_limit]

    print("\nBaseline Comparison")
    print(f"Attacks: {len(attack_records)} | Benign: {len(benign_records)}")
    print("=" * 88)
    print(
        f"{'Baseline':<22} {'ASR':>6} {'Recall':>8} {'FPR':>6} "
        f"{'Precision':>10} {'F1':>6} {'Lat(ms)':>9}"
    )
    print("-" * 88)

    all_results = []
    for name, fn in BASELINES.items():
        r = _eval_baseline(name, fn, attack_records, benign_records)
        all_results.append(r)
        print(
            f"  {name:<20} {r['asr']:>6.1%} {r['recall']:>8.1%} {r['fpr']:>6.1%} "
            f"{r['precision']:>10.1%} {r['f1']:>6.3f} {r['avg_latency_ms']:>9.3f}"
        )

    print("=" * 88)
    print("\nKey takeaways:")
    no_def = next(r for r in all_results if r["baseline"] == "no_defense")
    full = next(r for r in all_results if r["baseline"] == "llmfirewall_full")
    regex = next(r for r in all_results if r["baseline"] == "regex_only")
    print(f"  LLMFirewall vs no defense:  ASR {no_def['asr']:.0%} → {full['asr']:.0%}")
    print(f"  LLMFirewall vs regex only:  ASR {regex['asr']:.0%} → {full['asr']:.0%}")
    print(f"  LLMFirewall FPR:            {full['fpr']:.1%} (regex FPR: {regex['fpr']:.1%})")
    print(f"  LLMFirewall avg latency:    {full['avg_latency_ms']:.3f} ms (no LLM dependency)")

    return {"baselines": all_results}


def main() -> None:
    parser = argparse.ArgumentParser(description="LLMFirewall baseline comparison")
    parser.add_argument("--attack_limit", type=int, default=500)
    parser.add_argument("--benign_limit", type=int, default=500)
    parser.add_argument("--json", help="Write results to JSON file")
    args = parser.parse_args()

    results = run_comparison(
        attack_limit=args.attack_limit,
        benign_limit=args.benign_limit,
    )

    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2))
        print(f"\nResults written to {args.json}")


if __name__ == "__main__":
    main()
