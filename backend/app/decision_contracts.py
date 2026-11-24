"""Strict API contracts for deterministic finding decisions (`oaw.decision.v1`)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from .finding_contracts import FINDING_ID_PATTERN, RULE_ID_PATTERN
from .hub_contracts import SITE_ID_PATTERN


REASON_CODE_PATTERN = r"^[A-Z][A-Z0-9_]{1,63}$"
DIGEST_PATTERN = r"^[0-9a-f]{64}$"
ReasonCode = Annotated[str, Field(pattern=REASON_CODE_PATTERN)]
EvidenceReference = Annotated[str, Field(min_length=1, max_length=80)]

ActionBandValue = Literal["monitor", "plan", "prioritize", "act-now"]
UrgencyValue = Literal["immediate", "expedited", "scheduled", "monitor", "verification-required"]
DecisionStateValue = Literal["current", "not-current"]
ProjectionState = Literal["current", "stale", "inconsistent"]
SeverityValue = Literal["critical", "high", "medium", "low", "informational"]
ConfidenceBandValue = Literal["high", "medium", "low", "insufficient", "conflicted"]
FreshnessValue = Literal["fresh", "aging", "stale", "unknown"]
ExploitationValue = Literal[
    "known-exploited",
    "public-exploit-evidence",
    "no-known-exploitation",
    "unknown",
    "not-applicable",
]
ExposureValue = Literal[
    "internet-reachable",
    "externally-reachable",
    "internally-reachable",
    "segmented",
    "not-reachable",
    "unknown",
    "not-applicable",
]
ImportanceValue = Literal["critical", "high", "standard", "low", "unknown", "not-applicable"]
TransitionCause = Literal["initial", "inputs-changed", "ruleset-changed", "finding-resolved", "finding-reopened"]


class StrictDecisionContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DecisionReasonResponse(StrictDecisionContract):
    code: str = Field(..., pattern=REASON_CODE_PATTERN)
    explanation: str = Field(..., min_length=1, max_length=300)


class DecisionAttentionResponse(StrictDecisionContract):
    """Operational Attention Score context. Shown only; it never selects a band."""

    asset_score: int | None = Field(default=None, ge=0, le=100)
    formula_version: str | None = Field(default=None, max_length=64)
    finding_contribution: float | None = Field(default=None, ge=0.0, le=100.0)


class FindingDecisionResponse(StrictDecisionContract):
    schema_version: Literal["oaw.decision.v1"]
    ruleset_version: str = Field(..., pattern=r"^oaw[.]decision[.]rules[.]v[0-9]+$")
    finding_id: str = Field(..., pattern=FINDING_ID_PATTERN)
    site_id: str = Field(..., pattern=SITE_ID_PATTERN)
    asset_id: str | None = Field(default=None, max_length=160)
    sensor_id: str | None = Field(default=None, max_length=160)
    finding_rule_id: str = Field(..., pattern=RULE_ID_PATTERN)
    finding_status: Literal["active", "acknowledged", "resolved", "suppressed"]
    decision_state: DecisionStateValue
    decision_rule_id: str = Field(..., pattern=r"^[a-z][a-z0-9-]{0,63}$")
    action_band: ActionBandValue | None = None
    urgency: UrgencyValue | None = None
    severity: SeverityValue
    evidence_confidence: ConfidenceBandValue
    evidence_confidence_value: float = Field(..., ge=0.0, le=1.0)
    evidence_freshness: FreshnessValue
    exploitation_status: ExploitationValue
    exposure_state: ExposureValue
    asset_importance: ImportanceValue
    uncertainty_present: bool
    verification_required: bool
    prioritization_excluded: bool
    reason_codes: list[ReasonCode] = Field(..., min_length=1, max_length=32)
    reasons: list[DecisionReasonResponse] = Field(..., max_length=32)
    evidence_references: list[EvidenceReference] = Field(default_factory=list, max_length=8)
    input_digest: str = Field(..., pattern=DIGEST_PATTERN)
    finding_evaluated_at: datetime
    evaluated_at: datetime
    evaluation_run_id: str = Field(..., min_length=1, max_length=80)
    revision: int = Field(..., ge=1)
    projection_state: ProjectionState
    attention: DecisionAttentionResponse


class FindingDecisionListResponse(StrictDecisionContract):
    items: list[FindingDecisionResponse] = Field(max_length=200)
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1, le=200)
    offset: int = Field(..., ge=0, le=10_000)
    truncated: bool


class FindingDecisionTransitionResponse(StrictDecisionContract):
    finding_id: str = Field(..., pattern=FINDING_ID_PATTERN)
    site_id: str = Field(..., pattern=SITE_ID_PATTERN)
    revision: int = Field(..., ge=1)
    transition_cause: TransitionCause
    ruleset_version: str = Field(..., pattern=r"^oaw[.]decision[.]rules[.]v[0-9]+$")
    previous_decision_state: DecisionStateValue | None = None
    decision_state: DecisionStateValue
    previous_action_band: ActionBandValue | None = None
    action_band: ActionBandValue | None = None
    previous_urgency: UrgencyValue | None = None
    urgency: UrgencyValue | None = None
    previous_reason_codes: list[ReasonCode] | None = Field(default=None, max_length=32)
    reason_codes: list[ReasonCode] = Field(..., min_length=1, max_length=32)
    input_digest: str = Field(..., pattern=DIGEST_PATTERN)
    finding_evaluated_at: datetime
    evaluated_at: datetime
    evaluation_run_id: str = Field(..., min_length=1, max_length=80)


class FindingDecisionHistoryResponse(StrictDecisionContract):
    items: list[FindingDecisionTransitionResponse] = Field(max_length=200)
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1, le=200)
    offset: int = Field(..., ge=0, le=10_000)
    truncated: bool


class DecisionBandResponse(StrictDecisionContract):
    band: ActionBandValue
    label: str = Field(..., max_length=32)
    urgency: UrgencyValue


class DecisionRuleResponse(StrictDecisionContract):
    rule_id: str = Field(..., pattern=r"^[a-z][a-z0-9-]{0,63}$")
    order: int = Field(..., ge=1)
    condition: str = Field(..., max_length=300)
    action_band: ActionBandValue | None = None
    verification_required: bool


class DecisionReasonCodeResponse(StrictDecisionContract):
    code: str = Field(..., pattern=REASON_CODE_PATTERN)
    source: str = Field(..., max_length=80)
    explanation: str = Field(..., max_length=300)


class DecisionConfidenceThresholds(StrictDecisionContract):
    high_min: float = Field(..., ge=0.0, le=1.0)
    medium_min: float = Field(..., ge=0.0, le=1.0)
    low_min: float = Field(..., ge=0.0, le=1.0)


class DecisionRulesetResponse(StrictDecisionContract):
    schema_version: Literal["oaw.decision.v1"]
    ruleset_version: str = Field(..., pattern=r"^oaw[.]decision[.]rules[.]v[0-9]+$")
    action_bands: list[DecisionBandResponse] = Field(max_length=4)
    rules: list[DecisionRuleResponse] = Field(max_length=32)
    reason_codes: list[DecisionReasonCodeResponse] = Field(max_length=64)
    confidence_bands: DecisionConfidenceThresholds
    limitations: list[str] = Field(max_length=8)
