"""Bounded API contracts for deterministic findings and risk."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .hub_contracts import SENSOR_ID_PATTERN, SITE_ID_PATTERN


FINDING_ID_PATTERN = r"^fnd_[0-9a-f]{32}$"
RULE_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,63}$"
ASSET_ID_PATTERN = r"^[^\x00-\x1f]{1,160}$"


class StrictFindingContract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class FindingEvidenceResponse(StrictFindingContract):
    evidence_ref: str = Field(..., min_length=4, max_length=80)
    evidence_type: str = Field(..., min_length=1, max_length=64)
    source: str = Field(..., min_length=1, max_length=120)
    observed_at: datetime | None = None
    freshness: Literal["fresh", "aging", "stale", "unknown"]
    confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str = Field(..., min_length=1, max_length=240)


class FindingResponse(StrictFindingContract):
    finding_id: str = Field(..., pattern=FINDING_ID_PATTERN)
    dedupe_key: str = Field(..., min_length=68, max_length=68)
    rule_id: str = Field(..., pattern=RULE_ID_PATTERN)
    rule_version: int = Field(..., ge=1)
    previous_rule_version: int | None = Field(default=None, ge=1)
    rule_version_changed_at: datetime | None = None
    engine_version: str = Field(..., min_length=1, max_length=64)
    category: str = Field(..., min_length=1, max_length=64)
    subject_type: Literal["asset", "sensor", "site"]
    site_id: str = Field(..., pattern=SITE_ID_PATTERN)
    asset_id: str | None = Field(default=None, max_length=160)
    sensor_id: str | None = Field(default=None, pattern=SENSOR_ID_PATTERN)
    title: str = Field(..., min_length=1, max_length=240)
    description: str = Field(..., min_length=1, max_length=1000)
    recommendation: str = Field(..., min_length=1, max_length=1000)
    severity: Literal["critical", "high", "medium", "low", "informational"]
    confidence: float = Field(..., ge=0.0, le=1.0)
    status: Literal["active", "acknowledged", "resolved", "suppressed"]
    evidence_observed_at: datetime | None = None
    evidence_freshness: Literal["fresh", "aging", "stale", "unknown"]
    first_seen_at: datetime
    last_seen_at: datetime
    evaluated_at: datetime
    resolved_at: datetime | None = None
    resolution_basis: str | None = None
    acknowledged_at: datetime | None = None
    acknowledged_by: str | None = None
    suppressed_at: datetime | None = None
    suppressed_by: str | None = None
    suppressed_until: datetime | None = None
    suppression_reason: str | None = None
    reopen_count: int = Field(default=0, ge=0)
    last_evaluation_run_id: str
    created_at: datetime | None = None
    updated_at: datetime | None = None
    evidence: list[FindingEvidenceResponse] = Field(default_factory=list, max_length=8)


class FindingListResponse(StrictFindingContract):
    items: list[FindingResponse] = Field(max_length=200)
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1, le=200)
    offset: int = Field(..., ge=0, le=10_000)
    truncated: bool


class FindingEvaluateRequest(StrictFindingContract):
    site_id: str | None = Field(default=None, pattern=SITE_ID_PATTERN)
    asset_id: str | None = Field(default=None, pattern=ASSET_ID_PATTERN)
    sensor_id: str | None = Field(default=None, pattern=SENSOR_ID_PATTERN)
    rule_ids: list[str] | None = Field(default=None, max_length=20)
    requested_by: str = Field(default="admin", min_length=1, max_length=120)

    @field_validator("rule_ids")
    @classmethod
    def validate_rule_ids(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        if len(value) != len(set(value)):
            raise ValueError("rule_ids must not contain duplicates")
        for rule_id in value:
            if not rule_id or len(rule_id) > 64 or not all(character.islower() or character.isdigit() or character == "-" for character in rule_id):
                raise ValueError("invalid rule id")
        return value

    @model_validator(mode="after")
    def require_valid_scope(self) -> "FindingEvaluateRequest":
        if (self.asset_id or self.sensor_id) and not self.site_id:
            raise ValueError("asset- and sensor-scoped evaluation require site_id")
        if self.asset_id and self.sensor_id:
            raise ValueError("asset_id and sensor_id scopes are mutually exclusive")
        if self.sensor_id and self.rule_ids is not None and set(self.rule_ids) - {"sensor-stale"}:
            raise ValueError("sensor-scoped evaluation supports only sensor-stale")
        return self


class FindingEvaluationResponse(StrictFindingContract):
    run_id: str
    trigger_type: str
    scope_site_id: str | None = None
    scope_asset_id: str | None = None
    scope_sensor_id: str | None = None
    ruleset_version: str
    evaluated_rule_ids: list[str]
    candidate_count: int = Field(..., ge=0)
    opened_count: int = Field(..., ge=0)
    updated_count: int = Field(..., ge=0)
    reopened_count: int = Field(..., ge=0)
    resolved_count: int = Field(..., ge=0)
    asset_risk_count: int = Field(..., ge=0)
    site_risk_count: int = Field(..., ge=0)
    data_as_of: datetime | None = None
    started_at: datetime
    completed_at: datetime


class FindingAcknowledgeRequest(StrictFindingContract):
    actor: str = Field(default="admin", min_length=1, max_length=120)


class FindingSuppressRequest(StrictFindingContract):
    actor: str = Field(default="admin", min_length=1, max_length=120)
    reason: str = Field(..., min_length=1, max_length=500)
    until: datetime | None = None

    @field_validator("until")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("suppression expiry must include a timezone")
        return value


class RuleDefinitionResponse(StrictFindingContract):
    rule_id: str
    version: int
    category: str
    title: str
    rationale: str
    severity: Literal["critical", "high", "medium", "low", "informational"]
    scope: Literal["asset", "sensor", "site"]
    required_evidence: list[str] = Field(max_length=8)
    freshness_requirement: str = Field(max_length=500)
    remediation_guidance: str = Field(max_length=1000)
    resolution_behavior: str = Field(max_length=500)


class RuleRegistryResponse(StrictFindingContract):
    ruleset_version: str
    rules: list[RuleDefinitionResponse] = Field(max_length=20)
    deferred_rules: list[str] = Field(max_length=20)


class RiskFactorResponse(StrictFindingContract):
    factor_type: str
    finding_id: str | None = None
    category: str
    label: str
    severity: str | None = None
    confidence: float
    freshness: str
    base_weight: float
    adjusted_weight: float
    ordinal: int


class AssetRiskResponse(StrictFindingContract):
    site_id: str
    asset_id: str
    score: int = Field(..., ge=0, le=100)
    band: str
    formula_version: str
    finding_count: int = Field(..., ge=0)
    data_as_of: datetime | None = None
    calculated_at: datetime
    evaluation_run_id: str
    factors: list[RiskFactorResponse] = Field(default_factory=list, max_length=100)


class SiteRiskResponse(StrictFindingContract):
    site_id: str
    score: int = Field(..., ge=0, le=100)
    band: str
    formula_version: str
    asset_count: int = Field(..., ge=0)
    finding_count: int = Field(..., ge=0)
    data_as_of: datetime | None = None
    calculated_at: datetime
    evaluation_run_id: str
    factors: list[RiskFactorResponse] = Field(default_factory=list, max_length=100)


class RiskSummaryResponse(StrictFindingContract):
    sites: list[SiteRiskResponse] = Field(max_length=200)
    assets: list[AssetRiskResponse] = Field(max_length=200)
    active_findings_by_severity: dict[str, int]
    formula_version: str
