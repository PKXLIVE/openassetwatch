"""Strict API contracts for audited asset importance (CTEM-GAP-02).

Importance is an operator assertion, not discovered evidence. Actor labels are
unverified text under the shared administrative token, not authenticated
identities. The contracts accept no reviewer or approver identity: the platform
cannot verify one, so it never pretends to record independent approval.
Unknown fields are rejected.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .hub_contracts import SITE_ID_PATTERN


# Asset identifiers are accepted by ingestion as any 1-160 character text, so
# they may contain `/`. The routes use a path converter and fixed suffixes, so
# such identifiers stay addressable. Control characters are rejected.
ASSET_ID_PATH_PATTERN = r"^[^\x00-\x1f\x7f]{1,160}$"
ACTOR_LABEL_PATTERN = r"^[^\x00-\x1f\x7f]{1,120}$"
# Reasons may span lines but may not contain other control characters.
IMPORTANCE_REASON_PATTERN = r"^[^\x00-\x08\x0b-\x1f\x7f]{1,500}$"

AssignableImportance = Literal["critical", "high", "standard", "low"]
EffectiveImportance = Literal["critical", "high", "standard", "low", "unknown"]
ImportanceSource = Literal["operator-assigned", "unassigned"]
AssignmentState = Literal["assigned", "withdrawn", "none"]
IntegrityState = Literal["consistent", "inconsistent", "not-applicable"]
ReviewState = Literal["current", "review-due", "not-applicable"]
ImportanceEventType = Literal["assigned", "changed", "reviewed", "withdrawn"]
ImportanceDirection = Literal["initial", "raised", "lowered", "unchanged", "withdrawn", "reassigned"]
IndependentReview = Literal["not-required", "recommended-not-enforced"]
DecisionReevaluation = Literal["completed", "failed"]


class StrictImportanceContract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AssetImportanceAssignRequest(StrictImportanceContract):
    actor: str = Field(..., pattern=ACTOR_LABEL_PATTERN)
    importance: AssignableImportance
    reason: str = Field(..., pattern=IMPORTANCE_REASON_PATTERN)
    # Omit for the first assignment of an asset; otherwise the current revision.
    expected_revision: int | None = Field(default=None, ge=1, le=2_000_000_000)


class AssetImportanceWithdrawRequest(StrictImportanceContract):
    actor: str = Field(..., pattern=ACTOR_LABEL_PATTERN)
    reason: str = Field(..., pattern=IMPORTANCE_REASON_PATTERN)
    expected_revision: int = Field(..., ge=1, le=2_000_000_000)


class AssetImportanceResponse(StrictImportanceContract):
    site_id: str = Field(..., pattern=SITE_ID_PATTERN)
    asset_id: str = Field(..., min_length=1, max_length=160)
    importance: EffectiveImportance = Field(
        ...,
        description="Effective importance. `unknown` when no consistent operator assignment exists.",
    )
    importance_source: ImportanceSource
    assignment_state: AssignmentState
    integrity_state: IntegrityState = Field(
        ...,
        description="`inconsistent` when the current record disagrees with its history; "
        "importance is then reported and decided as unknown.",
    )
    recorded_importance: EffectiveImportance | None = None
    revision: int | None = Field(default=None, ge=1)
    reason: str | None = Field(default=None, max_length=500)
    principal: Literal["api-admin-token"] | None = None
    actor_label: str | None = Field(default=None, max_length=120)
    actor_verification: Literal["unverified"] | None = None
    created_at: datetime | None = None
    reviewed_at: datetime | None = None
    updated_at: datetime | None = None
    review_state: ReviewState


class AssetImportanceListResponse(StrictImportanceContract):
    items: list[AssetImportanceResponse] = Field(max_length=200)
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1, le=200)
    offset: int = Field(..., ge=0, le=10_000)
    truncated: bool


class AssetImportanceEventResponse(StrictImportanceContract):
    event_id: int = Field(..., ge=1)
    site_id: str = Field(..., pattern=SITE_ID_PATTERN)
    asset_id: str = Field(..., min_length=1, max_length=160)
    revision: int = Field(..., ge=1)
    event_type: ImportanceEventType
    previous_importance: EffectiveImportance | None = None
    importance: EffectiveImportance
    direction: ImportanceDirection
    security_sensitive: bool = Field(
        ...,
        description="True for lowering and withdrawal, which can reduce attention.",
    )
    independent_review: IndependentReview = Field(
        ...,
        description="Second-person review of security-sensitive changes is recommended but "
        "not enforceable until per-user identity exists.",
    )
    reason: str = Field(..., max_length=500)
    principal: Literal["api-admin-token"]
    actor_label: str = Field(..., max_length=120)
    actor_verification: Literal["unverified"]
    occurred_at: datetime


class AssetImportanceHistoryResponse(StrictImportanceContract):
    items: list[AssetImportanceEventResponse] = Field(max_length=200)
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1, le=200)
    offset: int = Field(..., ge=0, le=10_000)
    truncated: bool


class AssetImportanceMutationResponse(StrictImportanceContract):
    importance: AssetImportanceResponse
    event: AssetImportanceEventResponse
    decision_reevaluation: DecisionReevaluation = Field(
        ...,
        description="`failed` leaves decisions stale until the next evaluation; reads report "
        "them as stale rather than current.",
    )
