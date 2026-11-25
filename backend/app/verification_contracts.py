"""Strict API contracts for remediation verification (`oaw.verification.v1`).

All verification routes are read-only. No request can set a verification
outcome: outcomes come only from deterministic rules over collected evidence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from .finding_contracts import FINDING_ID_PATTERN, RULE_ID_PATTERN
from .hub_contracts import SITE_ID_PATTERN


REASON_CODE_PATTERN = r"^[A-Z][A-Z0-9_]{1,63}$"
ReasonCode = Annotated[str, Field(pattern=REASON_CODE_PATTERN)]
VerificationStateValue = Literal[
    "not-reported",
    "awaiting-evidence",
    "insufficient-evidence",
    "evidence-stale",
    "still-present",
    "conflicting-evidence",
    "manual-review-required",
    "verified",
    "resolved-before-report",
    "resolved-by-advisory-change",
    "report-withdrawn",
]
RecordedStateValue = Literal[
    "awaiting-evidence",
    "insufficient-evidence",
    "evidence-stale",
    "still-present",
    "conflicting-evidence",
    "manual-review-required",
    "verified",
    "resolved-before-report",
    "resolved-by-advisory-change",
    "report-withdrawn",
]
ResolutionBasisValue = Literal[
    "component-removed",
    "component-version-fixed",
    "component-version-available",
    "sensor-check-in",
    "fresh-observation",
    "classification-recognized",
    "classification-consistent",
    "managed-evidence",
    "healthy-coverage",
    "applicability-not-affected",
    "advisory-withdrawn",
    "advisory-identity-reviewed",
    "match-fixed-unattributed",
]
CompletenessValue = Literal["complete", "incomplete", "none-since-report", "not-recorded", "not-applicable"]
CollectionStatusValue = Literal["complete", "partial", "unsupported", "failed"]
FreshnessValue = Literal["fresh", "aging", "stale", "unknown"]
FindingStatusValue = Literal["active", "acknowledged", "resolved", "suppressed"]


class StrictVerificationContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VerificationReasonResponse(StrictVerificationContract):
    code: str = Field(..., pattern=REASON_CODE_PATTERN)
    explanation: str = Field(..., min_length=1, max_length=300)


class VerificationEvidenceReference(StrictVerificationContract):
    evidence_ref: str = Field(..., min_length=1, max_length=200)
    evidence_type: str = Field(..., min_length=1, max_length=64)
    freshness: FreshnessValue
    observed_at: datetime | None = None


class ResolutionEvidenceReference(StrictVerificationContract):
    """Affirmative evidence the finding lifecycle recorded when it resolved."""

    resolution_basis: ResolutionBasisValue
    technical: bool = Field(
        ..., description="True for a change observed on the asset; false for an advisory or applicability change."
    )
    evidence_ref: str = Field(..., min_length=1, max_length=200)
    evidence_type: str = Field(..., min_length=1, max_length=64)
    source: str = Field(..., min_length=1, max_length=120)
    observed_at: datetime | None = Field(default=None, description="Collection time, not evaluation time.")
    freshness: FreshnessValue
    installed_version: str | None = Field(default=None, max_length=160)
    fixed_version: str | None = Field(default=None, max_length=160)
    supporting_snapshot_id: str | None = Field(default=None, pattern=r"^css_[0-9a-f]{32}$")


class VerificationCollection(StrictVerificationContract):
    snapshot_id: str = Field(..., pattern=r"^css_[0-9a-f]{32}$")
    collection_status: CollectionStatusValue
    observed_at: datetime


class VerificationComponent(StrictVerificationContract):
    match_id: str = Field(..., min_length=1, max_length=80)
    match_status: str = Field(..., max_length=32)
    installed_version: str | None = Field(default=None, max_length=160)
    fixed_version: str | None = Field(default=None, max_length=160)


class VerificationGuidance(StrictVerificationContract):
    condition: str = Field(..., max_length=500)
    recommendation: str = Field(..., max_length=1000)
    method_id: str = Field(..., pattern=r"^[a-z][a-z0-9-]{0,63}$")
    automated: bool
    evidence_source: str = Field(..., max_length=200)
    comparable_evidence: str = Field(..., max_length=500)
    collection_check: Literal["component-source-snapshot", "finding-freshness"]
    required_evidence: list[str] = Field(default_factory=list, max_length=16)
    resolution_behavior: str | None = Field(default=None, max_length=500)
    components: list[VerificationComponent] = Field(default_factory=list, max_length=8)


class VerificationLastRecorded(StrictVerificationContract):
    verification_state: RecordedStateValue
    reason_codes: list[ReasonCode] = Field(..., max_length=32)
    evaluated_at: datetime
    sequence: int = Field(..., ge=1)


class FindingVerificationSummary(StrictVerificationContract):
    schema_version: Literal["oaw.verification.v1"]
    ruleset_version: str = Field(..., pattern=r"^oaw[.]verification[.]rules[.]v[0-9]+$")
    finding_id: str = Field(..., pattern=FINDING_ID_PATTERN)
    site_id: str = Field(..., pattern=SITE_ID_PATTERN)
    asset_id: str | None = Field(default=None, max_length=160)
    sensor_id: str | None = Field(default=None, max_length=160)
    finding_rule_id: str = Field(..., pattern=RULE_ID_PATTERN)
    finding_status: FindingStatusValue = Field(
        ..., description="Owned by deterministic evaluation; verification never changes it."
    )
    finding_resolved_at: datetime | None = None
    finding_evidence_observed_at: datetime | None = None
    finding_evidence_freshness: FreshnessValue
    verification_state: VerificationStateValue
    verified: bool
    method_id: str = Field(..., pattern=r"^[a-z][a-z0-9-]{0,63}$")
    automated: bool
    collection_completeness: CompletenessValue
    collection_since_report: VerificationCollection | None = None
    reason_codes: list[ReasonCode] = Field(..., min_length=1, max_length=32)
    reasons: list[VerificationReasonResponse] = Field(..., max_length=32)
    work_item_id: str | None = Field(default=None, pattern=r"^fwi_[0-9a-f]{32}$")
    work_status: Literal["open", "in_progress", "blocked", "done", "cancelled"] | None = None
    report_revision: int | None = Field(default=None, ge=1)
    reported_at: datetime | None = None
    before_evidence_references: list[VerificationEvidenceReference] = Field(default_factory=list, max_length=8)
    before_collection: VerificationCollection | None = None
    after_evidence_references: list[VerificationEvidenceReference] = Field(default_factory=list, max_length=8)
    resolution_evidence: list[ResolutionEvidenceReference] = Field(default_factory=list, max_length=8)
    collection_at_resolution: VerificationCollection | None = None
    collection_after_resolution: VerificationCollection | None = None
    input_digest: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class FindingVerificationResponse(FindingVerificationSummary):
    guidance: VerificationGuidance
    last_recorded: VerificationLastRecorded | None = None
    record_state: Literal["current", "stale", "not-recorded"]


class UnverifiedWorkListResponse(StrictVerificationContract):
    items: list[FindingVerificationSummary] = Field(max_length=200)
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1, le=200)
    offset: int = Field(..., ge=0, le=10_000)
    truncated: bool


class VerificationTransitionResponse(StrictVerificationContract):
    work_item_id: str = Field(..., pattern=r"^fwi_[0-9a-f]{32}$")
    finding_id: str = Field(..., pattern=FINDING_ID_PATTERN)
    site_id: str = Field(..., pattern=SITE_ID_PATTERN)
    report_revision: int = Field(..., ge=1)
    sequence: int = Field(..., ge=1)
    ruleset_version: str = Field(..., pattern=r"^oaw[.]verification[.]rules[.]v[0-9]+$")
    previous_state: RecordedStateValue | None = None
    verification_state: RecordedStateValue
    reason_codes: list[ReasonCode] = Field(..., min_length=1, max_length=32)
    after_evidence_references: list[VerificationEvidenceReference] = Field(default_factory=list, max_length=8)
    finding_status: FindingStatusValue
    finding_evidence_observed_at: datetime | None = None
    collection_status: CollectionStatusValue | None = None
    input_digest: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    evaluated_at: datetime
    evaluation_run_id: str = Field(..., min_length=1, max_length=80)


class VerificationHistoryResponse(StrictVerificationContract):
    items: list[VerificationTransitionResponse] = Field(max_length=200)
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1, le=200)
    offset: int = Field(..., ge=0, le=10_000)
    truncated: bool


class VerificationMethodResponse(StrictVerificationContract):
    finding_rule_id: str = Field(..., pattern=RULE_ID_PATTERN)
    method_id: str = Field(..., pattern=r"^[a-z][a-z0-9-]{0,63}$")
    evidence_source: str = Field(..., max_length=200)
    comparable_evidence: str = Field(..., max_length=500)
    collection_check: Literal["component-source-snapshot", "finding-freshness"]
    automated: bool
    resolution_behavior: str | None = Field(default=None, max_length=500)


class VerificationRulesetResponse(StrictVerificationContract):
    schema_version: Literal["oaw.verification.v1"]
    ruleset_version: str = Field(..., pattern=r"^oaw[.]verification[.]rules[.]v[0-9]+$")
    states: list[VerificationStateValue] = Field(max_length=16)
    unverified_states: list[VerificationStateValue] = Field(max_length=16)
    not_attributable_states: list[VerificationStateValue] = Field(max_length=16)
    methods: list[VerificationMethodResponse] = Field(max_length=32)
    reason_codes: list[VerificationReasonResponse] = Field(max_length=64)
    limitations: list[str] = Field(max_length=8)
