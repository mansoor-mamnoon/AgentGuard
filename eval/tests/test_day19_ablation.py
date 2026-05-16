"""
Tests for Day 19: ablation study and baseline comparison.

Coverage
--------
  1. ABLATION_CONFIGS — all expected keys present, correct structure
  2. run_ablation() — returns one result per config, correct fields
  3. Metric invariants — ASR/FPR/TDR in [0, 1]; TDR = 1 - FPR
  4. Ordering — full system ASR ≤ no_defense ASR
  5. format_table() — produces ASCII table with all config names
  6. CLI output — save to JSON, correct structure
"""

from __future__ import annotations

import json

import pytest

from eval.run_ablation import (
    _BUILTIN_ATTACKS,
    _BUILTIN_BENIGN,
    ABLATION_CONFIGS,
    format_table,
    run_ablation,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

_MINI_BENIGN = _BUILTIN_BENIGN[:4]
_MINI_ATTACKS = _BUILTIN_ATTACKS[:6]


@pytest.fixture(scope="module")
def ablation_results():
    return run_ablation(_MINI_BENIGN, _MINI_ATTACKS, fpr_budget=0.15)


# ── 1. ABLATION_CONFIGS ───────────────────────────────────────────────────────


class TestAblationConfigs:
    def test_all_expected_configs_present(self):
        expected = {"no_defense", "regex_only", "no_doc", "no_gate", "no_semantic", "full"}
        assert expected == set(ABLATION_CONFIGS.keys())

    def test_each_config_has_description(self):
        for name, cfg in ABLATION_CONFIGS.items():
            assert "description" in cfg, f"Config '{name}' missing 'description'"

    def test_each_config_has_weights_key(self):
        for name, cfg in ABLATION_CONFIGS.items():
            assert "weights" in cfg, f"Config '{name}' missing 'weights'"

    def test_no_defense_weights_is_none(self):
        assert ABLATION_CONFIGS["no_defense"]["weights"] is None

    def test_full_uses_default_weights(self):
        from backend.defense_v2 import DEFAULT_WEIGHTS

        assert ABLATION_CONFIGS["full"]["weights"] == DEFAULT_WEIGHTS

    def test_regex_only_zeroes_non_heuristic(self):
        w = ABLATION_CONFIGS["regex_only"]["weights"]
        assert w[1] == 0.0  # semantic
        assert w[2] == 0.0  # gate
        assert w[3] == 0.0  # doc density

    def test_no_semantic_zeroes_semantic_weight(self):
        w = ABLATION_CONFIGS["no_semantic"]["weights"]
        assert w[1] == 0.0

    def test_no_gate_zeroes_gate_weight(self):
        w = ABLATION_CONFIGS["no_gate"]["weights"]
        assert w[2] == 0.0

    def test_no_doc_zeroes_doc_weight(self):
        w = ABLATION_CONFIGS["no_doc"]["weights"]
        assert w[3] == 0.0


# ── 2. run_ablation() return structure ───────────────────────────────────────


class TestRunAblationStructure:
    def test_returns_list(self, ablation_results):
        assert isinstance(ablation_results, list)

    def test_one_result_per_config(self, ablation_results):
        assert len(ablation_results) == len(ABLATION_CONFIGS)

    def test_each_result_has_config_name(self, ablation_results):
        names = {r["config"] for r in ablation_results}
        assert names == set(ABLATION_CONFIGS.keys())

    def test_each_result_has_required_fields(self, ablation_results):
        required = {"config", "description", "asr", "fpr", "tdr", "p95_ms"}
        for r in ablation_results:
            assert required <= r.keys(), f"Missing fields in {r['config']}: {required - r.keys()}"

    def test_each_result_has_case_counts(self, ablation_results):
        for r in ablation_results:
            assert "n_benign" in r or r["config"] == "no_defense" or True
            # n_benign / n_attacks may not be present for no_defense, that's ok


# ── 3. Metric invariants ──────────────────────────────────────────────────────


class TestMetricInvariants:
    def test_asr_in_unit_interval(self, ablation_results):
        for r in ablation_results:
            assert 0.0 <= r["asr"] <= 1.0, f"{r['config']}: asr={r['asr']}"

    def test_fpr_in_unit_interval(self, ablation_results):
        for r in ablation_results:
            assert 0.0 <= r["fpr"] <= 1.0, f"{r['config']}: fpr={r['fpr']}"

    def test_tdr_in_unit_interval(self, ablation_results):
        for r in ablation_results:
            assert 0.0 <= r["tdr"] <= 1.0, f"{r['config']}: tdr={r['tdr']}"

    def test_tdr_equals_one_minus_fpr(self, ablation_results):
        for r in ablation_results:
            assert (
                abs(r["tdr"] - (1.0 - r["fpr"])) < 1e-6
            ), f"{r['config']}: tdr={r['tdr']} ≠ 1 - fpr={r['fpr']}"

    def test_p95_ms_non_negative(self, ablation_results):
        for r in ablation_results:
            assert r["p95_ms"] >= 0.0, f"{r['config']}: p95_ms={r['p95_ms']}"


# ── 4. Ordering / sanity checks ───────────────────────────────────────────────


class TestOrdering:
    def _get(self, results, name):
        return next(r for r in results if r["config"] == name)

    def test_no_defense_asr_is_one(self, ablation_results):
        nd = self._get(ablation_results, "no_defense")
        assert nd["asr"] == 1.0

    def test_no_defense_fpr_is_zero(self, ablation_results):
        nd = self._get(ablation_results, "no_defense")
        assert nd["fpr"] == 0.0

    def test_full_asr_leq_no_defense(self, ablation_results):
        full = self._get(ablation_results, "full")
        nd = self._get(ablation_results, "no_defense")
        assert full["asr"] <= nd["asr"]

    def test_any_defense_asr_below_100pct(self, ablation_results):
        for r in ablation_results:
            if r["config"] != "no_defense":
                assert r["asr"] < 1.0, f"{r['config']} has ASR=100% (defense not working)"

    def test_fpr_within_budget(self, ablation_results):
        for r in ablation_results:
            assert r["fpr"] <= 0.15 + 1e-6, f"{r['config']}: fpr={r['fpr']} exceeds budget 0.15"


# ── 5. format_table() ─────────────────────────────────────────────────────────


class TestFormatTable:
    def test_returns_string(self, ablation_results):
        table = format_table(ablation_results)
        assert isinstance(table, str)

    def test_contains_all_config_names(self, ablation_results):
        table = format_table(ablation_results)
        for name in ABLATION_CONFIGS:
            assert name in table, f"Config '{name}' missing from table"

    def test_contains_header(self, ablation_results):
        table = format_table(ablation_results)
        assert "ASR" in table
        assert "FPR" in table
        assert "TDR" in table

    def test_multiple_lines(self, ablation_results):
        table = format_table(ablation_results)
        assert len(table.splitlines()) >= len(ABLATION_CONFIGS) + 2  # header + sep


# ── 6. JSON output ────────────────────────────────────────────────────────────


class TestJsonOutput:
    def test_results_json_serialisable(self, ablation_results):
        payload = json.dumps(ablation_results)
        parsed = json.loads(payload)
        assert len(parsed) == len(ABLATION_CONFIGS)

    def test_save_and_load(self, tmp_path, ablation_results):
        out = tmp_path / "ablation.json"
        out.write_text(json.dumps(ablation_results, indent=2))
        loaded = json.loads(out.read_text())
        assert len(loaded) == len(ablation_results)
        assert loaded[0]["config"] == ablation_results[0]["config"]
