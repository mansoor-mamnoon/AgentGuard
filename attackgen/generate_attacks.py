from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any

from attackgen.mutate import MutateConfig, dedup_texts, mutate_payload


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def extract_seed_payload(case: dict[str, Any]) -> str | None:
    """
    Return the string payload to mutate, or None if the case should be skipped.

    Handles two payload shapes:
    - str  : used directly (direct / indirect_doc / tool_output)
    - list : multiturn turns; we mutate the last string turn (the action turn)
    """
    if case.get("is_benign") is True:
        return None

    payload = case.get("payload")

    if isinstance(payload, str):
        return payload.strip() or None

    if isinstance(payload, list):
        # find the last non-empty string turn
        for turn in reversed(payload):
            if isinstance(turn, str) and turn.strip():
                return turn.strip()

    return None


def is_attack_seed(case: dict[str, Any]) -> bool:
    return extract_seed_payload(case) is not None


def expand_seed(
    case: dict[str, Any],
    cfg: MutateConfig,
    rng: random.Random,
) -> list[dict[str, Any]]:
    """
    Generate up to cfg.variants_per_seed unique mutated rows from a single seed case.
    Returns deduplicated rows (per-seed dedup applied).
    """
    seed_payload = extract_seed_payload(case)
    if seed_payload is None:
        return []

    attack_id = str(case.get("attack_id", "X"))
    original_type = str(case.get("attack_type", "direct"))
    # Multiturn seeds are mutated from their last string turn, producing a standalone
    # string payload -- represent those as "direct" so the eval harness can run them.
    attack_type = "direct" if original_type == "multiturn" else original_type

    candidates: list[str] = [
        mutate_payload(seed_payload, rng) for _ in range(cfg.variants_per_seed)
    ]

    unique_payloads = dedup_texts(
        candidates,
        dim=cfg.embed_dim,
        cosine_threshold=cfg.dedup_cosine_threshold,
    )

    rows: list[dict[str, Any]] = []
    for j, mp in enumerate(unique_payloads):
        row = dict(case)
        row["attack_id"] = f"{attack_id}_m{j:02d}"
        row["attack_type"] = attack_type
        row["payload"] = mp
        row["is_benign"] = False
        row.setdefault("policy", {})
        rows.append(row)

    return rows


def generate(
    seeds: list[dict[str, Any]],
    cfg: MutateConfig,
    rng: random.Random,
) -> list[dict[str, Any]]:
    """
    Core generation logic (pure function, no file I/O -- easy to test).

    Steps:
    1. Per-seed: generate variants_per_seed candidates, dedup within the seed.
    2. Global dedup across all surviving rows.
    """
    all_rows: list[dict[str, Any]] = []
    for case in seeds:
        if not is_attack_seed(case):
            continue
        all_rows.extend(expand_seed(case, cfg, rng))

    if not all_rows:
        return []

    all_payloads = [r["payload"] for r in all_rows]
    kept_set = set(
        dedup_texts(
            all_payloads,
            dim=cfg.embed_dim,
            cosine_threshold=cfg.dedup_cosine_threshold,
        )
    )
    return [r for r in all_rows if r["payload"] in kept_set]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", required=True, help="Path to seed dataset JSONL")
    ap.add_argument(
        "--out",
        default="data/attacks_mutated.jsonl",
        help="Output JSONL path (mutated attacks)",
    )
    ap.add_argument(
        "--variants",
        type=int,
        default=15,
        help="Variants generated per seed attack (before dedup). Default 15 ensures "
        "800-1500 unique attacks after dedup with 90 seeds.",
    )
    ap.add_argument("--seed", type=int, default=1337, help="RNG seed")
    ap.add_argument(
        "--dedup-threshold",
        type=float,
        default=0.92,
        help="Cosine similarity threshold above which a candidate is dropped as a near-duplicate",
    )
    args = ap.parse_args()

    seeds_path = Path(args.seeds)
    out_path = Path(args.out)

    cfg = MutateConfig(
        variants_per_seed=args.variants,
        rng_seed=args.seed,
        dedup_cosine_threshold=args.dedup_threshold,
        embed_dim=512,
    )
    rng = random.Random(cfg.rng_seed)

    seeds = load_jsonl(seeds_path)
    attack_seeds = [c for c in seeds if is_attack_seed(c)]

    final_rows = generate(attack_seeds, cfg, rng)

    write_jsonl(out_path, final_rows)

    candidates_total = len(attack_seeds) * cfg.variants_per_seed
    print(f"Seeds (attacks):          {len(attack_seeds)}")
    print(f"Candidates generated:     {candidates_total}")
    print(f"Unique after dedup:       {len(final_rows)}")
    print(f"Wrote:                    {out_path}")


if __name__ == "__main__":
    main()
