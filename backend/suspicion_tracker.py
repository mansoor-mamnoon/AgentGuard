"""
Day 11 — Stateful suspicion tracking with decay.

The tracker accumulates evidence of injection attempts across conversation turns
and maps the running score to a restriction level.  Signals from multiple
detection layers (semantic drift, regex policy, tool gate) are summed and fed
into an exponential-decay accumulator:

    score_t = min(1.0, score_{t-1} * decay + signal_t)

Restriction levels (thresholds are configurable; defaults designed for decay=0.70):

    score < 0.20          → allow       (normal operation)
    0.20 <= score < 0.40  → rewrite     (strip injection vocabulary from prompt)
    0.40 <= score < 0.65  → downgrade   (remove write/side-effect tools)
    score >= 0.65         → block       (refuse the turn entirely)

With the default decay of 0.70 the system has two useful properties:
  - Benign steady-state (signal ≈ 0.02/turn) converges to ≈ 0.067, well below allow.
  - A single strong attack (signal ≈ 0.90) immediately reaches downgrade/block.
  - Suspicion decays back to allow within ~6 clean turns after an attack.
"""

from __future__ import annotations

from dataclasses import dataclass

# ── Signal bonuses (added on top of raw semantic drift) ───────────────────────

REGEX_BONUS: float = 0.40  # PolicyEngine regex/role-redef match
GATE_BONUS: float = 0.20  # ToolGate suspicion-based downgrade triggered

# ── Restriction thresholds ────────────────────────────────────────────────────

ALLOW_THRESHOLD: float = 0.20
REWRITE_THRESHOLD: float = 0.40
DOWNGRADE_THRESHOLD: float = 0.45
# score >= DOWNGRADE_THRESHOLD → "block"

DEFAULT_DECAY: float = 0.70

# Default threshold tuple: (allow_threshold, rewrite_threshold, downgrade_threshold)
DEFAULT_THRESHOLDS: tuple[float, float, float] = (
    ALLOW_THRESHOLD,
    REWRITE_THRESHOLD,
    DOWNGRADE_THRESHOLD,
)


# ── Signal container ──────────────────────────────────────────────────────────


@dataclass
class TurnSignals:
    """
    Evidence collected from all detection layers for a single turn.

    semantic_drift  — raw drift_score from SemanticDetector (already clamped to [0,1])
    regex_triggered — True if PolicyEngine fired (suspicious/role-redef match)
    gate_downgraded — True if ToolGate stripped tools due to per-turn drift
    """

    semantic_drift: float = 0.0
    regex_triggered: bool = False
    gate_downgraded: bool = False

    @property
    def combined(self) -> float:
        """Sum all signal components, capped at 1.0."""
        return min(
            1.0,
            self.semantic_drift
            + (REGEX_BONUS if self.regex_triggered else 0.0)
            + (GATE_BONUS if self.gate_downgraded else 0.0),
        )


# ── Tracker ───────────────────────────────────────────────────────────────────


class SuspicionTracker:
    """
    Stateful accumulator for multi-turn suspicion.

    Usage::

        tracker = SuspicionTracker()
        for turn_text in conversation:
            signals = TurnSignals(
                semantic_drift=detector.check(turn_text).drift_score,
                regex_triggered=policy_engine.evaluate(...).action != "allow",
                gate_downgraded=gate.check(...).downgraded,
            )
            score = tracker.update(signals)
            level = tracker.restriction_level()
            # apply level: allow | rewrite | downgrade | block
    """

    def __init__(
        self,
        decay: float = DEFAULT_DECAY,
        thresholds: tuple[float, float, float] = DEFAULT_THRESHOLDS,
    ) -> None:
        self.decay = decay
        self._allow_t, self._rewrite_t, self._downgrade_t = thresholds
        self._score: float = 0.0
        self._history: list[float] = []

    # ── public API ────────────────────────────────────────────────────────────

    @property
    def score(self) -> float:
        return self._score

    @property
    def turn_count(self) -> int:
        return len(self._history)

    def update(self, signals: TurnSignals) -> float:
        """
        Apply decay to the current score and add the turn's combined signal.
        Returns the new cumulative score.
        """
        self._score = min(1.0, self._score * self.decay + signals.combined)
        self._history.append(self._score)
        return self._score

    def restriction_level(self) -> str:
        """Map the current score to a restriction level string."""
        if self._score < self._allow_t:
            return "allow"
        if self._score < self._rewrite_t:
            return "rewrite"
        if self._score < self._downgrade_t:
            return "downgrade"
        return "block"

    def history(self) -> list[float]:
        """Return a copy of the per-turn score history."""
        return list(self._history)

    def reset(self) -> None:
        """Clear accumulated state (start a new conversation)."""
        self._score = 0.0
        self._history.clear()
