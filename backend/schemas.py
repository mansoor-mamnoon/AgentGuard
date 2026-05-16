"""
Day 17 — Pydantic typed schemas.

Covers two domains:
  1. API response models  — used as FastAPI response_model annotations so that
     FastAPI validates and serialises the output automatically.
  2. Eval pipeline models — typed inputs for dataset cases, scoring, and
     calibration so that bad data is caught at ingestion rather than deep in
     the scorer.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator, model_validator

# ── API response schemas ──────────────────────────────────────────────────────


class DetectorFlags(BaseModel):
    semantic_drift: float = Field(ge=0.0, le=10.0)
    regex_triggered: bool
    gate_downgraded: bool


class TurnDetail(BaseModel):
    turn_idx: int = Field(ge=0)
    user_text: str
    restriction_level: str
    suspicion_score: float
    blocked: bool
    rewritten_text: str | None = None
    allowed_tools: list[str]
    detector_flags: DetectorFlags


class CaseDetail(BaseModel):
    case_id: str
    mode: str
    final_suspicion: float
    any_blocked: bool
    turns: list[TurnDetail]


class RunSummary(BaseModel):
    run_id: str
    total_cases: int = Field(ge=0)
    blocked: int = Field(ge=0)
    asr: float = Field(ge=0.0, le=1.0)
    modes: list[str]


class RunDetail(BaseModel):
    run_id: str
    total_cases: int = Field(ge=0)
    blocked: int = Field(ge=0)
    asr: float = Field(ge=0.0, le=1.0)
    cases: list[CaseDetail]


class CalibrationSummary(BaseModel):
    chosen_threshold: float = Field(ge=0.0, le=1.0)
    fpr_at_threshold: float = Field(ge=0.0, le=1.0)
    asr_at_threshold: float = Field(ge=0.0, le=1.0)
    fpr_budget: float = Field(ge=0.0, le=1.0)


class MetricsResponse(BaseModel):
    total_runs: int = Field(ge=0)
    total_cases: int = Field(ge=0)
    total_blocked: int = Field(ge=0)
    overall_asr: float | None = Field(default=None)
    per_run: list[RunSummary]
    calibration: CalibrationSummary | None = None

    @field_validator("overall_asr")
    @classmethod
    def asr_in_range(cls, v: float | None) -> float | None:
        if v is not None and not (0.0 <= v <= 1.0):
            raise ValueError(f"overall_asr must be in [0, 1], got {v}")
        return v


# ── Eval pipeline schemas ─────────────────────────────────────────────────────


class EvalCase(BaseModel):
    """A single case in an evaluation dataset (benign or attack)."""

    payload: str | list[str]
    is_benign: bool = False
    attack_type: str = "direct"
    doc_content: str | None = None

    @field_validator("payload")
    @classmethod
    def payload_not_empty(cls, v: str | list[str]) -> str | list[str]:
        if isinstance(v, str) and not v.strip():
            raise ValueError("payload must not be an empty string")
        if isinstance(v, list) and len(v) == 0:
            raise ValueError("payload list must not be empty")
        return v

    @property
    def user_text(self) -> str:
        if isinstance(self.payload, list):
            return " ".join(str(p) for p in self.payload)
        return self.payload


class AttackCaseInput(BaseModel):
    """Input schema for a generated attack case."""

    payload: str | list[str]
    attack_type: str = "direct"
    doc_content: str | None = None
    strategy: str | None = None  # e.g. "synonym_swap", "template"

    @field_validator("attack_type")
    @classmethod
    def valid_attack_type(cls, v: str) -> str:
        allowed = {"direct", "indirect_doc", "multiturn"}
        if v not in allowed:
            raise ValueError(f"attack_type must be one of {allowed}, got '{v}'")
        return v


class CalibrationCurvePoint(BaseModel):
    threshold: float = Field(ge=0.0, le=1.0)
    fpr: float = Field(ge=0.0, le=1.0)
    tpr: float = Field(ge=0.0, le=1.0)
    asr: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def asr_equals_one_minus_tpr(self) -> CalibrationCurvePoint:
        if abs(self.asr - (1.0 - self.tpr)) > 1e-6:
            raise ValueError(f"asr ({self.asr}) must equal 1 - tpr ({1.0 - self.tpr})")
        return self


class CalibrationReport(BaseModel):
    chosen_threshold: float = Field(ge=0.0, le=1.0)
    fpr_at_threshold: float = Field(ge=0.0, le=1.0)
    asr_at_threshold: float = Field(ge=0.0, le=1.0)
    fpr_budget: float = Field(ge=0.0, le=1.0)
    validation_curve: list[CalibrationCurvePoint]

    @field_validator("validation_curve")
    @classmethod
    def curve_not_empty(cls, v: list) -> list:
        if not v:
            raise ValueError("validation_curve must not be empty")
        return v


class ScoringResult(BaseModel):
    """Result of scoring one case through DefenseV2."""

    case_id: str
    combined: float = Field(ge=0.0, le=1.0)
    heuristic_score: float = Field(ge=0.0, le=1.0)
    semantic_drift: float
    tool_violation: float = Field(ge=0.0, le=1.0)
    doc_density: float = Field(ge=0.0, le=1.0)
    latency_s: float = Field(ge=0.0)
