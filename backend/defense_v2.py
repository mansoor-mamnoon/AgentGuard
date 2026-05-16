"""
Day 14 — Defense v2: combined signal scoring + threshold calibration.

Aggregates four evidence layers into a single combined score, then maps
that score to a restriction level using thresholds calibrated on a small
validation set to minimise ASR subject to an FPR budget.

Signal components
-----------------
  heuristic_score  — 1.0 if the regex denylist (PolicyEngine) fires, else 0.0
  semantic_drift   — raw drift_score from SemanticDetector, clamped to [0, 1]
  tool_violation   — 1.0 if ToolGate stripped tools (downgraded), else 0.0
  doc_density      — fraction of retrieved-doc / tool-output lines that look
                     like injection instructions

Combined score (weighted sum, clamped to [0, 1])
-------------------------------------------------
  combined = clamp(
      w_heuristic * heuristic_score
      + w_semantic  * semantic_drift
      + w_gate      * tool_violation
      + w_doc       * doc_density,
      0.0, 1.0
  )

Calibration
-----------
Sweep threshold t over [0, 0.02, 0.04, ..., 1.0].  For each t:
  FPR(t) = P(combined > t | benign)
  TPR(t) = P(combined > t | attack) = 1 − ASR(t)

Choose t* = lowest t such that FPR(t) ≤ fpr_budget (default 0.15).
Report includes the full validation curve so it can be plotted.

Usage::

    scorer = DefenseV2()
    signals = scorer.score(segments, user_text, available_tools)
    level   = scorer.classify(signals)

    result  = scorer.calibrate(benign_cases, attack_cases)
    scorer.threshold = result.chosen_threshold
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from backend.context_classifier import classify_context
from backend.messages import MessageSegment, trust_for_source
from backend.policy_engine import PolicyEngine
from backend.semantic_detector import SemanticDetector
from backend.tool_gate import ToolGate

# ── Default weights ───────────────────────────────────────────────────────────

DEFAULT_WEIGHTS: tuple[float, float, float, float] = (
    0.40,  # heuristic (regex denylist)
    0.35,  # semantic drift
    0.15,  # tool gate violation
    0.10,  # doc instruction density
)

DEFAULT_THRESHOLD: float = 0.30  # initial before calibration
DEFAULT_FPR_BUDGET: float = 0.15  # max false-positive rate

# ── Instruction-line detector (for doc_density) ────────────────────────────────

_INSTRUCTION_TRIGGERS: tuple[str, ...] = (
    "ignore",
    "disregard",
    "forget",
    "override",
    "bypass",
    "jailbreak",
    "post a message",
    "call post_message",
    "send a message",
    "system prompt",
    "developer mode",
    "you are now",
    "act as",
    "from now on",
    "pretend to be",
)


def _looks_like_instruction(line: str) -> bool:
    low = line.strip().lower()
    return bool(low) and any(t in low for t in _INSTRUCTION_TRIGGERS)


def _doc_density(segments: list[MessageSegment]) -> float:
    """Fraction of retrieved-doc / tool-output lines that look like instructions."""
    doc_segs = [s for s in segments if s.source in ("retrieved_doc", "tool_output")]
    if not doc_segs:
        return 0.0
    total = 0
    flagged = 0
    for seg in doc_segs:
        lines = (seg.content or "").splitlines()
        total += len(lines)
        flagged += sum(1 for ln in lines if _looks_like_instruction(ln))
    if total == 0:
        return 0.0
    return flagged / total


# ── Signal container ───────────────────────────────────────────────────────────


@dataclass
class DefenseV2Signals:
    """Evidence from all four detection layers for a single turn."""

    heuristic_score: float = 0.0  # 0.0 or 1.0
    semantic_drift: float = 0.0  # [0, 1]
    tool_violation: float = 0.0  # 0.0 or 1.0
    doc_density: float = 0.0  # [0, 1]

    weights: tuple[float, float, float, float] = field(default_factory=lambda: DEFAULT_WEIGHTS)

    @property
    def combined(self) -> float:
        w_h, w_s, w_g, w_d = self.weights
        raw = (
            w_h * self.heuristic_score
            + w_s * self.semantic_drift
            + w_g * self.tool_violation
            + w_d * self.doc_density
        )
        return min(1.0, max(0.0, raw))


# ── Calibration result types ──────────────────────────────────────────────────


@dataclass
class CalibrationPoint:
    threshold: float
    fpr: float
    tpr: float
    asr: float  # = 1.0 - tpr


@dataclass
class CalibrationResult:
    chosen_threshold: float
    fpr_at_threshold: float
    asr_at_threshold: float
    fpr_budget: float
    validation_curve: list[CalibrationPoint]


# ── Combined scorer ───────────────────────────────────────────────────────────

_SEMANTIC = SemanticDetector()
_GATE = ToolGate()
_POLICY = None  # instantiated per-call (stateless)


class DefenseV2:
    """
    Combined signal scorer with calibrated thresholds.

    Usage::

        scorer = DefenseV2()
        signals = scorer.score(segments, user_text, available_tools)
        level   = scorer.classify(signals)      # "allow" | "rewrite" | "downgrade" | "block"
    """

    def __init__(
        self,
        weights: tuple[float, float, float, float] = DEFAULT_WEIGHTS,
        threshold: float = DEFAULT_THRESHOLD,
    ) -> None:
        self.weights = weights
        self.threshold = threshold

    # ── public API ────────────────────────────────────────────────────────────

    def score(
        self,
        segments: list[MessageSegment],
        user_text: str,
        available_tools: list[str],
    ) -> DefenseV2Signals:
        """Compute the four-layer combined signal for one turn."""
        # 1. Semantic drift
        drift_results = _SEMANTIC.check_segments(segments)
        max_drift = max((max(0.0, r.drift_score) for r in drift_results), default=0.0)

        # 2. Tool gate (per-turn drift as suspicion hint)
        gate = _GATE.check(user_text, available_tools, suspicion_score=max_drift)
        tool_violation = 1.0 if gate.downgraded else 0.0

        # 3. Heuristic policy engine
        engine = PolicyEngine()
        pd = engine.evaluate("", segments, user_text, gate.allowed_tools)
        heuristic = 0.0 if pd.action == "allow" else 1.0

        # 4. Doc instruction density
        density = _doc_density(segments)

        # 5. Context adjustment — separate "mentioning dangerous concepts" from
        #    "issuing dangerous instructions" via the 3-factor rule.
        #    Only applies to the user text; doc/tool-output injections are scored
        #    independently and not dampened (they are never educational context).
        ctx = classify_context(user_text)
        heuristic = heuristic * ctx.heuristic_multiplier
        max_drift = max_drift * ctx.semantic_multiplier

        return DefenseV2Signals(
            heuristic_score=heuristic,
            semantic_drift=max_drift,
            tool_violation=tool_violation,
            doc_density=density,
            weights=self.weights,
        )

    def classify(self, signals: DefenseV2Signals) -> str:
        """
        Map combined score to a restriction level using the calibrated threshold.

        Below threshold  → "allow"
        At threshold+    → "block"

        Simple two-level mapping keeps the interface clean; callers that need
        intermediate levels can inspect signals.combined directly.
        """
        if signals.combined < self.threshold:
            return "allow"
        return "block"

    def score_text(
        self,
        user_text: str,
        available_tools: list[str] | None = None,
        doc_content: str | None = None,
    ) -> DefenseV2Signals:
        """Convenience wrapper: build segments from raw text, then score."""
        if available_tools is None:
            available_tools = ["search_docs", "get_email", "post_message"]

        segs: list[MessageSegment] = [
            MessageSegment("system", trust_for_source("system"), "You are a helpful assistant."),
            MessageSegment("user", trust_for_source("user"), user_text),
        ]
        if doc_content is not None:
            segs.append(
                MessageSegment("retrieved_doc", trust_for_source("retrieved_doc"), doc_content)
            )
        return self.score(segs, user_text, available_tools)

    # ── Calibration ───────────────────────────────────────────────────────────

    def calibrate(
        self,
        benign_cases: list[dict[str, Any]],
        attack_cases: list[dict[str, Any]],
        fpr_budget: float = DEFAULT_FPR_BUDGET,
        n_thresholds: int = 51,
    ) -> CalibrationResult:
        """
        Sweep thresholds and choose the one that minimises ASR subject to
        FPR ≤ fpr_budget.

        Each case dict must have "payload" (str or list[str]) and optionally
        "attack_type" and "doc_content" keys.

        Returns a CalibrationResult with the full validation curve.
        """
        benign_scores = [self._score_case(c) for c in benign_cases]
        attack_scores = [self._score_case(c) for c in attack_cases]

        thresholds = [i / (n_thresholds - 1) for i in range(n_thresholds)]
        curve: list[CalibrationPoint] = []

        for t in thresholds:
            fpr = (
                sum(1 for s in benign_scores if s > t) / len(benign_scores)
                if benign_scores
                else 0.0
            )
            tpr = (
                sum(1 for s in attack_scores if s > t) / len(attack_scores)
                if attack_scores
                else 0.0
            )
            asr = 1.0 - tpr
            curve.append(CalibrationPoint(threshold=round(t, 4), fpr=fpr, tpr=tpr, asr=asr))

        # Choose: minimum ASR with FPR <= budget
        feasible = [p for p in curve if p.fpr <= fpr_budget]
        if feasible:
            best = min(feasible, key=lambda p: p.asr)
        else:
            # No feasible point: choose the highest threshold (strictest FPR)
            best = min(curve, key=lambda p: p.fpr)

        return CalibrationResult(
            chosen_threshold=best.threshold,
            fpr_at_threshold=best.fpr,
            asr_at_threshold=best.asr,
            fpr_budget=fpr_budget,
            validation_curve=curve,
        )

    def _score_case(self, case: dict[str, Any]) -> float:
        """Score a single case dict and return the combined float."""
        payload = case.get("payload", "")
        doc_content = case.get("doc_content")

        if isinstance(payload, list):
            user_text = " ".join(payload)
        else:
            user_text = str(payload)

        signals = self.score_text(user_text, doc_content=doc_content)
        return signals.combined
