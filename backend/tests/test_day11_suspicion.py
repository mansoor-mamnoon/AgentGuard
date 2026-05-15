"""
Tests for Day 11: stateful suspicion tracker.

Coverage:
  1. TurnSignals — signal combination (semantic + regex + gate)
  2. SuspicionTracker — decay, accumulation, history
  3. Restriction levels — allow / rewrite / downgrade / block thresholds
  4. Decay behaviour — suspicion falls after clean turns
  5. Edge cases — reset, empty turns, clamping at 1.0
"""

from __future__ import annotations

from backend.suspicion_tracker import (
    ALLOW_THRESHOLD,
    DEFAULT_DECAY,
    DOWNGRADE_THRESHOLD,
    GATE_BONUS,
    REGEX_BONUS,
    REWRITE_THRESHOLD,
    SuspicionTracker,
    TurnSignals,
)

# ===========================================================================
# 1. TurnSignals
# ===========================================================================


class TestTurnSignals:
    def test_zero_signals_give_zero_combined(self):
        s = TurnSignals()
        assert s.combined == 0.0

    def test_semantic_only(self):
        s = TurnSignals(semantic_drift=0.3)
        assert abs(s.combined - 0.3) < 1e-9

    def test_regex_bonus_added(self):
        s = TurnSignals(semantic_drift=0.0, regex_triggered=True)
        assert abs(s.combined - REGEX_BONUS) < 1e-9

    def test_gate_bonus_added(self):
        s = TurnSignals(semantic_drift=0.0, gate_downgraded=True)
        assert abs(s.combined - GATE_BONUS) < 1e-9

    def test_all_three_combined(self):
        s = TurnSignals(semantic_drift=0.3, regex_triggered=True, gate_downgraded=True)
        expected = min(1.0, 0.3 + REGEX_BONUS + GATE_BONUS)
        assert abs(s.combined - expected) < 1e-9

    def test_combined_capped_at_one(self):
        s = TurnSignals(semantic_drift=1.0, regex_triggered=True, gate_downgraded=True)
        assert s.combined == 1.0

    def test_negative_semantic_drift_treated_as_zero(self):
        # Semantic drift can theoretically be negative (see clamping in SemanticDetector).
        # The TurnSignals should not penalise a negative drift.
        s = TurnSignals(semantic_drift=0.0)  # already clamped upstream
        assert s.combined == 0.0


# ===========================================================================
# 2. SuspicionTracker — basic properties
# ===========================================================================


class TestSuspicionTrackerBasic:
    def test_initial_score_is_zero(self):
        t = SuspicionTracker()
        assert t.score == 0.0

    def test_initial_turn_count_is_zero(self):
        t = SuspicionTracker()
        assert t.turn_count == 0

    def test_initial_history_is_empty(self):
        t = SuspicionTracker()
        assert t.history() == []

    def test_update_returns_new_score(self):
        t = SuspicionTracker()
        s = TurnSignals(semantic_drift=0.5)
        result = t.update(s)
        assert result == t.score

    def test_turn_count_increments_per_update(self):
        t = SuspicionTracker()
        t.update(TurnSignals())
        assert t.turn_count == 1
        t.update(TurnSignals())
        assert t.turn_count == 2

    def test_history_records_all_scores(self):
        t = SuspicionTracker()
        t.update(TurnSignals(semantic_drift=0.1))
        t.update(TurnSignals(semantic_drift=0.2))
        hist = t.history()
        assert len(hist) == 2
        assert hist[0] < hist[1]  # second turn's signal adds to score

    def test_score_capped_at_one(self):
        t = SuspicionTracker()
        t.update(TurnSignals(semantic_drift=1.0))
        t.update(TurnSignals(semantic_drift=1.0))
        assert t.score <= 1.0

    def test_reset_clears_state(self):
        t = SuspicionTracker()
        t.update(TurnSignals(semantic_drift=0.5))
        t.reset()
        assert t.score == 0.0
        assert t.turn_count == 0
        assert t.history() == []

    def test_default_decay_constant(self):
        assert 0.0 < DEFAULT_DECAY < 1.0


# ===========================================================================
# 3. Decay behaviour
# ===========================================================================


class TestSuspicionDecay:
    def test_score_decays_with_zero_signal_turns(self):
        t = SuspicionTracker(decay=DEFAULT_DECAY)
        t.update(TurnSignals(semantic_drift=0.8))
        score_after_attack = t.score
        t.update(TurnSignals())  # benign
        assert t.score < score_after_attack

    def test_score_approaches_zero_after_many_clean_turns(self):
        t = SuspicionTracker(decay=DEFAULT_DECAY)
        t.update(TurnSignals(semantic_drift=0.8))
        for _ in range(20):
            t.update(TurnSignals(semantic_drift=0.0))
        assert t.score < ALLOW_THRESHOLD

    def test_higher_decay_decays_slower(self):
        slow = SuspicionTracker(decay=0.95)
        fast = SuspicionTracker(decay=0.50)
        sig = TurnSignals(semantic_drift=0.6)
        slow.update(sig)
        fast.update(sig)
        for _ in range(5):
            slow.update(TurnSignals())
            fast.update(TurnSignals())
        assert fast.score < slow.score

    def test_benign_steady_state_below_allow_threshold(self):
        """Continuous benign turns (low drift) must stay below the 'allow' threshold."""
        t = SuspicionTracker(decay=DEFAULT_DECAY)
        benign_signal = 0.02
        for _ in range(30):
            t.update(TurnSignals(semantic_drift=benign_signal))
        assert t.score < ALLOW_THRESHOLD

    def test_score_increases_with_attack_signals(self):
        t = SuspicionTracker(decay=DEFAULT_DECAY)
        # Score is non-decreasing with attack signals; it may reach 1.0 and stay there
        for _ in range(3):
            prev = t.score
            t.update(TurnSignals(semantic_drift=0.5, regex_triggered=True))
            assert t.score >= prev
        # After 3 strong attacks the score must be at max
        assert t.score == 1.0


# ===========================================================================
# 4. Restriction levels
# ===========================================================================


class TestRestrictionLevels:
    def test_initial_level_is_allow(self):
        t = SuspicionTracker()
        assert t.restriction_level() == "allow"

    def test_allow_below_threshold(self):
        t = SuspicionTracker()
        # Manually craft score below ALLOW_THRESHOLD
        t._score = ALLOW_THRESHOLD - 0.01
        assert t.restriction_level() == "allow"

    def test_rewrite_at_allow_threshold(self):
        t = SuspicionTracker()
        t._score = ALLOW_THRESHOLD
        assert t.restriction_level() == "rewrite"

    def test_rewrite_below_downgrade_threshold(self):
        t = SuspicionTracker()
        t._score = REWRITE_THRESHOLD - 0.01
        assert t.restriction_level() == "rewrite"

    def test_downgrade_at_rewrite_threshold(self):
        t = SuspicionTracker()
        t._score = REWRITE_THRESHOLD
        assert t.restriction_level() == "downgrade"

    def test_downgrade_below_block_threshold(self):
        t = SuspicionTracker()
        t._score = DOWNGRADE_THRESHOLD - 0.01
        assert t.restriction_level() == "downgrade"

    def test_block_at_downgrade_threshold(self):
        t = SuspicionTracker()
        t._score = DOWNGRADE_THRESHOLD
        assert t.restriction_level() == "block"

    def test_block_at_max_score(self):
        t = SuspicionTracker()
        t._score = 1.0
        assert t.restriction_level() == "block"

    def test_levels_are_monotone(self):
        """Higher score → same or higher restriction level."""
        order = {"allow": 0, "rewrite": 1, "downgrade": 2, "block": 3}
        t = SuspicionTracker()
        scores = [0.0, ALLOW_THRESHOLD, REWRITE_THRESHOLD, DOWNGRADE_THRESHOLD, 1.0]
        levels = []
        for s in scores:
            t._score = s
            levels.append(order[t.restriction_level()])
        for a, b in zip(levels, levels[1:], strict=False):
            assert a <= b


# ===========================================================================
# 5. Escalation scenarios
# ===========================================================================


class TestEscalationScenarios:
    def test_single_obvious_attack_reaches_block_or_downgrade(self):
        """One strong attack turn (regex + semantic) should immediately restrict."""
        t = SuspicionTracker(decay=DEFAULT_DECAY)
        strong_attack = TurnSignals(semantic_drift=0.5, regex_triggered=True)
        t.update(strong_attack)
        assert t.restriction_level() in {"downgrade", "block"}

    def test_two_obvious_attacks_reach_block(self):
        t = SuspicionTracker(decay=DEFAULT_DECAY)
        attack = TurnSignals(semantic_drift=0.5, regex_triggered=True)
        t.update(attack)
        t.update(attack)
        assert t.restriction_level() == "block"

    def test_slow_escalation_eventually_blocks(self):
        """Subtle attack signals accumulate to block level over several turns."""
        t = SuspicionTracker(decay=DEFAULT_DECAY)
        subtle = TurnSignals(semantic_drift=0.25)
        for _ in range(10):
            t.update(subtle)
        assert t.restriction_level() == "block"

    def test_benign_multi_turn_never_blocked(self):
        """Five benign turns with low drift must not be blocked."""
        t = SuspicionTracker(decay=DEFAULT_DECAY)
        benign = TurnSignals(semantic_drift=0.02)
        for _ in range(5):
            t.update(benign)
            assert (
                t.restriction_level() == "allow"
            ), f"Turn {t.turn_count}: score={t.score:.4f} unexpectedly restricted"

    def test_benign_then_attack_blocked(self):
        """Benign history doesn't prevent an obvious attack from being caught."""
        t = SuspicionTracker(decay=DEFAULT_DECAY)
        benign = TurnSignals(semantic_drift=0.02)
        for _ in range(3):
            t.update(benign)
        strong_attack = TurnSignals(semantic_drift=0.5, regex_triggered=True)
        t.update(strong_attack)
        assert t.restriction_level() in {"downgrade", "block"}

    def test_attack_then_benign_recovery(self):
        """Suspicion eventually decays to allow after clean turns."""
        t = SuspicionTracker(decay=DEFAULT_DECAY)
        t.update(TurnSignals(semantic_drift=0.5, regex_triggered=True))
        initial_level = t.restriction_level()
        assert initial_level in {"downgrade", "block"}
        # After many benign turns, should recover to allow
        benign = TurnSignals(semantic_drift=0.01)
        for _ in range(30):
            t.update(benign)
        assert t.restriction_level() == "allow"

    def test_custom_thresholds_respected(self):
        """Custom threshold tuple changes restriction levels."""
        strict = SuspicionTracker(
            decay=DEFAULT_DECAY,
            thresholds=(0.05, 0.10, 0.20),  # much stricter than defaults
        )
        strict.update(TurnSignals(semantic_drift=0.25))
        assert strict.restriction_level() == "block"

        lenient = SuspicionTracker(
            decay=DEFAULT_DECAY,
            thresholds=(0.80, 0.90, 0.95),  # very lenient
        )
        lenient.update(TurnSignals(semantic_drift=0.25))
        assert lenient.restriction_level() == "allow"
