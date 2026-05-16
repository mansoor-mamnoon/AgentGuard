"""
Day 17 — Property-based tests for AttackMutator and dataset schemas.

Uses Hypothesis to verify invariants that hold over arbitrary inputs:
  - No mutation strategy crashes on any short ASCII string.
  - Mutated output is always a non-empty string.
  - Output length stays within sane bounds relative to input.
  - Strategy enum values are exhaustive and stable.
  - EvalCase schema rejects empty payloads.
  - AttackCaseInput rejects invalid attack_type values.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from eval.attack_generator_v2 import AttackMutator, MutationStrategy

# ── helpers ───────────────────────────────────────────────────────────────────

_SHORT_TEXT = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "Zs", "Po")),
    min_size=1,
    max_size=120,
)

_MEDIUM_TEXT = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "Zs", "Po")),
    min_size=5,
    max_size=300,
)


# ── 1. Mutation strategy properties ──────────────────────────────────────────


class TestMutationProperties:
    @given(text=_SHORT_TEXT)
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_synonym_swap_never_crashes(self, text):
        m = AttackMutator()
        result = m.synonym_swap(text)
        assert isinstance(result, str)

    @given(text=_SHORT_TEXT)
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_sentence_split_never_crashes(self, text):
        m = AttackMutator()
        result = m.sentence_split(text)
        assert isinstance(result, str)

    @given(text=_SHORT_TEXT)
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_persona_wrap_never_crashes(self, text):
        m = AttackMutator()
        result = m.persona_wrap(text)
        assert isinstance(result, str)

    @given(text=_SHORT_TEXT)
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_indirect_phrasing_never_crashes(self, text):
        m = AttackMutator()
        result = m.indirect_phrasing(text)
        assert isinstance(result, str)

    @given(text=_SHORT_TEXT)
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_authority_escalation_never_crashes(self, text):
        m = AttackMutator()
        result = m.authority_escalation(text)
        assert isinstance(result, str)

    @given(text=_SHORT_TEXT)
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_all_strategies_return_nonempty(self, text):
        m = AttackMutator()
        for strategy in MutationStrategy:
            result = m.mutate(text, strategy)
            assert len(result) > 0, f"Strategy {strategy} returned empty string for '{text!r}'"

    @given(text=_MEDIUM_TEXT)
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_output_length_bounded(self, text):
        """Output should not exceed 10× the input length (no runaway expansion)."""
        m = AttackMutator()
        for strategy in MutationStrategy:
            result = m.mutate(text, strategy)
            limit = max(len(text) * 10, 500)
            msg = f"Strategy {strategy} output too long: {len(result)} chars for input {len(text)} chars"
            assert len(result) <= limit, msg

    @given(text=_SHORT_TEXT, strategy=st.sampled_from(list(MutationStrategy)))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_mutate_all_strategies_no_crash(self, text, strategy):
        m = AttackMutator()
        result = m.mutate(text, strategy)
        assert isinstance(result, str)
        assert len(result) > 0

    @given(text=_SHORT_TEXT)
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_mutate_all_returns_list(self, text):
        m = AttackMutator()
        results = m.mutate_all(text)
        assert isinstance(results, list)
        # mutate_all skips ENCODE_KEYWORDS (not applied standalone)
        assert len(results) == len(MutationStrategy) - 1

    @given(text=_SHORT_TEXT)
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_mutate_all_all_nonempty(self, text):
        m = AttackMutator()
        for result in m.mutate_all(text):
            assert len(result) > 0


# ── 2. Strategy enum invariants ───────────────────────────────────────────────


class TestMutationStrategyEnum:
    def test_all_strategy_values_unique(self):
        values = [s.value for s in MutationStrategy]
        assert len(values) == len(set(values))

    def test_strategy_count_stable(self):
        # Document the expected count so additions require a conscious test update.
        assert len(MutationStrategy) == 6

    def test_synonym_swap_in_enum(self):
        assert MutationStrategy.SYNONYM_SWAP in MutationStrategy

    def test_persona_wrap_in_enum(self):
        assert MutationStrategy.PERSONA_WRAP in MutationStrategy

    def test_authority_escalation_in_enum(self):
        assert MutationStrategy.AUTHORITY_ESCALATION in MutationStrategy


# ── 3. Schema property tests ──────────────────────────────────────────────────


class TestEvalCaseSchema:
    def test_valid_string_payload(self):
        from backend.schemas import EvalCase

        case = EvalCase(payload="Find the policy.")
        assert case.user_text == "Find the policy."

    def test_valid_list_payload(self):
        from backend.schemas import EvalCase

        case = EvalCase(payload=["Find", "the", "policy."])
        assert "Find" in case.user_text

    def test_empty_string_payload_rejected(self):
        from pydantic import ValidationError

        from backend.schemas import EvalCase

        with pytest.raises(ValidationError):
            EvalCase(payload="   ")

    def test_empty_list_payload_rejected(self):
        from pydantic import ValidationError

        from backend.schemas import EvalCase

        with pytest.raises(ValidationError):
            EvalCase(payload=[])

    def test_default_is_benign_false(self):
        from backend.schemas import EvalCase

        case = EvalCase(payload="test")
        assert case.is_benign is False

    def test_default_attack_type_direct(self):
        from backend.schemas import EvalCase

        case = EvalCase(payload="test")
        assert case.attack_type == "direct"

    @given(text=_SHORT_TEXT)
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_nonempty_string_always_valid(self, text):
        from backend.schemas import EvalCase

        if text.strip():
            case = EvalCase(payload=text)
            assert case.user_text == text


class TestAttackCaseInputSchema:
    def test_valid_attack_type_direct(self):
        from backend.schemas import AttackCaseInput

        case = AttackCaseInput(payload="test", attack_type="direct")
        assert case.attack_type == "direct"

    def test_valid_attack_type_indirect_doc(self):
        from backend.schemas import AttackCaseInput

        case = AttackCaseInput(payload="test", attack_type="indirect_doc")
        assert case.attack_type == "indirect_doc"

    def test_valid_attack_type_multiturn(self):
        from backend.schemas import AttackCaseInput

        case = AttackCaseInput(payload=["t1", "t2"], attack_type="multiturn")
        assert case.attack_type == "multiturn"

    def test_invalid_attack_type_rejected(self):
        from pydantic import ValidationError

        from backend.schemas import AttackCaseInput

        with pytest.raises(ValidationError):
            AttackCaseInput(payload="test", attack_type="unknown_type")

    @given(attack_type=st.sampled_from(["direct", "indirect_doc", "multiturn"]))
    @settings(max_examples=10)
    def test_all_valid_attack_types_accepted(self, attack_type):
        from backend.schemas import AttackCaseInput

        case = AttackCaseInput(payload="test", attack_type=attack_type)
        assert case.attack_type == attack_type


class TestCalibrationCurvePointSchema:
    def test_valid_point(self):
        from backend.schemas import CalibrationCurvePoint

        p = CalibrationCurvePoint(threshold=0.5, fpr=0.1, tpr=0.8, asr=0.2)
        assert p.asr == 0.2

    def test_asr_tpr_invariant_enforced(self):
        from pydantic import ValidationError

        from backend.schemas import CalibrationCurvePoint

        with pytest.raises(ValidationError):
            CalibrationCurvePoint(threshold=0.5, fpr=0.1, tpr=0.8, asr=0.5)  # asr != 1-tpr

    def test_boundary_values_accepted(self):
        from backend.schemas import CalibrationCurvePoint

        p = CalibrationCurvePoint(threshold=0.0, fpr=1.0, tpr=1.0, asr=0.0)
        assert p.threshold == 0.0

    @given(
        threshold=st.floats(min_value=0.0, max_value=1.0),
        fpr=st.floats(min_value=0.0, max_value=1.0),
        tpr=st.floats(min_value=0.0, max_value=1.0),
    )
    @settings(max_examples=30)
    def test_asr_always_one_minus_tpr(self, threshold, fpr, tpr):
        from backend.schemas import CalibrationCurvePoint

        asr = round(1.0 - tpr, 6)
        p = CalibrationCurvePoint(threshold=threshold, fpr=fpr, tpr=tpr, asr=asr)
        assert abs(p.asr - (1.0 - p.tpr)) < 1e-5
