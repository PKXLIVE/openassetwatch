"""Bounded API contracts for deterministic asset classifications."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .classification import CLASSIFIER_VERSION
from .hub_contracts import SITE_ID_PATTERN


CLASSIFICATION_ID_PATTERN = r"^cls_[0-9a-f]{32}$"
CLASSIFICATION_RUN_ID_PATTERN = r"^crun_[0-9a-f]{32}$"
CLASSIFICATION_EVIDENCE_ID_PATTERN = r"^cev_[0-9a-f]{40}$"


class StrictClassificationContract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ManagedCapabilityResponse(StrictClassificationContract):
    endpoint_collector: Literal["expected", "not-expected", "unknown"]
    endpoint_security: Literal["expected", "not-expected", "unknown"]
    software_inventory: Literal["expected", "not-expected", "unknown"]
    patch_management: Literal["expected", "not-expected", "unknown"]


class ClassificationConflictResponse(StrictClassificationContract):
    conflict_id: str | None = Field(default=None, max_length=80)
    conflict_type: str = Field(..., min_length=1, max_length=64)
    selected_value: str = Field(..., min_length=1, max_length=160)
    conflicting_value: str = Field(..., min_length=1, max_length=160)
    supporting_evidence_ids: list[str] = Field(default_factory=list, max_length=32)
    conflicting_evidence_ids: list[str] = Field(default_factory=list, max_length=32)
    reason_code: str = Field(..., min_length=1, max_length=64)
    status: Literal["open", "resolved"] = "open"
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    resolved_at: datetime | None = None


class ClassificationResponse(StrictClassificationContract):
    classification_id: str = Field(..., pattern=CLASSIFICATION_ID_PATTERN)
    asset_id: str = Field(..., min_length=1, max_length=160)
    site_id: str = Field(..., min_length=1, max_length=128, pattern=SITE_ID_PATTERN)
    classifier_version: str = Field(default=CLASSIFIER_VERSION, max_length=80)
    category: Literal[
        "workstation",
        "server",
        "mobile",
        "network-device",
        "printer",
        "camera",
        "media-device",
        "storage",
        "iot",
        "ot-industrial",
        "virtual-machine",
        "unknown",
    ]
    subtype: str | None = Field(default=None, max_length=160)
    manufacturer: str | None = Field(default=None, max_length=160)
    product_hint: str | None = Field(default=None, max_length=160)
    os_family: str | None = Field(default=None, max_length=80)
    os_version_hint: str | None = Field(default=None, max_length=160)
    managed_capability: ManagedCapabilityResponse
    confidence: float = Field(..., ge=0.0, le=1.0)
    status: Literal[
        "classified",
        "partially-classified",
        "unknown",
        "conflicting",
        "insufficient-evidence",
    ]
    supporting_evidence_ids: list[str] = Field(default_factory=list, max_length=32)
    conflicting_evidence_ids: list[str] = Field(default_factory=list, max_length=32)
    independent_source_count: int = Field(..., ge=0, le=256)
    evidence_count: int = Field(..., ge=0, le=256)
    first_classified_at: datetime
    last_classified_at: datetime
    evaluated_at: datetime
    superseded_at: datetime | None = None
    freshness: Literal["fresh", "aging", "stale", "unknown"]
    reason_codes: list[str] = Field(default_factory=list, max_length=12)
    conflicts: list[ClassificationConflictResponse] = Field(default_factory=list, max_length=16)


class ClassificationEvidenceResponse(StrictClassificationContract):
    evidence_id: str = Field(..., pattern=CLASSIFICATION_EVIDENCE_ID_PATTERN)
    site_id: str = Field(..., min_length=1, max_length=128, pattern=SITE_ID_PATTERN)
    asset_id: str = Field(..., min_length=1, max_length=160)
    source_id: str = Field(..., min_length=1, max_length=160)
    source_type: str = Field(..., min_length=1, max_length=64)
    collection_method: str = Field(..., min_length=1, max_length=64)
    kind: str = Field(..., min_length=1, max_length=80)
    value: str = Field(..., min_length=1, max_length=512)
    observed_at: datetime
    first_seen_at: datetime
    last_seen_at: datetime
    direct: bool
    strength: Literal["direct", "medium", "weak"]
    source_confidence: float = Field(..., ge=0.0, le=1.0)
    observation_count: int = Field(..., ge=1)
    agreement_state: Literal["unassessed", "supporting", "conflicting", "unused"]
    classifier_used: bool
    source_revoked: bool = False


class ClassificationListResponse(StrictClassificationContract):
    items: list[ClassificationResponse]
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1, le=200)
    offset: int = Field(..., ge=0, le=10_000)
    truncated: bool


class ClassificationEvidenceListResponse(StrictClassificationContract):
    items: list[ClassificationEvidenceResponse]
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1, le=200)
    offset: int = Field(..., ge=0, le=10_000)
    truncated: bool


class ClassificationSummaryResponse(StrictClassificationContract):
    site_id: str | None = Field(default=None, max_length=128)
    classification_count: int = Field(..., ge=0)
    conflict_count: int = Field(..., ge=0)
    unknown_count: int = Field(..., ge=0)
    categories: dict[str, int]
    statuses: dict[str, int]
    endpoint_collector_expectations: dict[str, int]
    data_as_of: datetime | None = None
    classifier_version: str = CLASSIFIER_VERSION


class VendorCatalogStatusResponse(StrictClassificationContract):
    available: bool
    schema_version: str | None = None
    catalog_version: str | None = None
    source_name: str | None = None
    source_license: str | None = None
    source_url: str | None = None
    checksum: str | None = None
    entry_count: int = Field(default=0, ge=0)
    network_lookup: Literal[False] = False
    status: Literal["ready", "not-configured", "invalid"]
    error_code: str | None = Field(default=None, max_length=80)


class ClassificationEvaluateRequest(StrictClassificationContract):
    requested_by: str = Field(default="admin", min_length=1, max_length=120)
    site_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=SITE_ID_PATTERN)
    asset_id: str | None = Field(default=None, min_length=1, max_length=160)
    asset_ids: list[Annotated[str, Field(min_length=1, max_length=160)]] | None = Field(
        default=None,
        min_length=1,
        max_length=500,
    )

    @model_validator(mode="after")
    def validate_scope(self) -> "ClassificationEvaluateRequest":
        if (self.asset_id or self.asset_ids) and not self.site_id:
            raise ValueError("asset-scoped classification requires site_id")
        if self.asset_id and self.asset_ids:
            raise ValueError("asset_id and asset_ids are mutually exclusive")
        if self.asset_ids and len(set(self.asset_ids)) != len(self.asset_ids):
            raise ValueError("asset_ids must be unique")
        return self


class ClassificationEvaluationResponse(StrictClassificationContract):
    run_id: str = Field(..., pattern=CLASSIFICATION_RUN_ID_PATTERN)
    trigger_type: str = Field(..., min_length=1, max_length=64)
    scope_site_id: str | None = None
    scope_asset_ids: list[str] = Field(default_factory=list, max_length=500)
    classifier_version: str
    status: Literal["completed"]
    assets_evaluated: int = Field(..., ge=0)
    assets_changed: int = Field(..., ge=0)
    conflicts_found: int = Field(..., ge=0)
    finding_evaluations: int = Field(..., ge=0)
    started_at: datetime
    completed_at: datetime
    bounded_errors: list[str] = Field(default_factory=list, max_length=20)
