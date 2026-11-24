"""Strict API contracts for manual finding work tracking.

Work tracking is operator-supplied coordination metadata. Every label here is
untrusted, unverified text: owner labels are not identities, actor labels are
not authenticated principals, and reference labels are opaque strings rather
than links. None of these contracts can change finding status, evidence, or
risk.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .finding_contracts import FINDING_ID_PATTERN
from .hub_contracts import SITE_ID_PATTERN


WORK_ITEM_ID_PATTERN = r"^fwi_[0-9a-f]{32}$"
WORK_REFERENCE_ID_PATTERN = r"^fwr_[0-9a-f]{32}$"
# Printable single-line labels: no ASCII control characters.
LABEL_PATTERN = r"^[^\x00-\x1f\x7f]{1,120}$"
# Notes may span lines but may not contain other control characters.
NOTE_PATTERN = r"^[^\x00-\x08\x0b-\x1f\x7f]{1,1000}$"
REFERENCE_SYSTEM_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,39}$"
# Opaque ticket/change keys only. Excluding ':' and '/' means a scheme-bearing
# URL or path can never be stored as a reference label.
REFERENCE_LABEL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 ._#-]{0,119}$"
WORK_ACTOR_PRINCIPAL = "api-admin-token"
MAX_ACTIVE_WORK_REFERENCES = 20

WorkStatus = Literal["open", "in_progress", "blocked", "done", "cancelled"]
OwnerKind = Literal["person", "team"]
ReferenceType = Literal["ticket", "change", "other"]
WorkEventType = Literal[
    "created",
    "status_changed",
    "owner_changed",
    "reference_added",
    "reference_removed",
    "note_added",
]
FindingStatus = Literal["active", "acknowledged", "resolved", "suppressed"]

WORK_STATUS_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"in_progress", "blocked", "done", "cancelled"}),
    "in_progress": frozenset({"open", "blocked", "done", "cancelled"}),
    "blocked": frozenset({"open", "in_progress", "done", "cancelled"}),
    "done": frozenset({"open"}),
    "cancelled": frozenset({"open"}),
}


class StrictWorkContract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _require_owner_pair(owner_kind: str | None, owner_label: str | None) -> None:
    if (owner_kind is None) != (owner_label is None):
        raise ValueError("owner_kind and owner_label must be supplied together")


class FindingWorkItemCreateRequest(StrictWorkContract):
    actor: str = Field(..., pattern=LABEL_PATTERN)
    owner_kind: OwnerKind | None = None
    owner_label: str | None = Field(default=None, pattern=LABEL_PATTERN)
    note: str | None = Field(default=None, pattern=NOTE_PATTERN)

    @model_validator(mode="after")
    def require_owner_pair(self) -> "FindingWorkItemCreateRequest":
        _require_owner_pair(self.owner_kind, self.owner_label)
        return self


class FindingWorkStatusRequest(StrictWorkContract):
    actor: str = Field(..., pattern=LABEL_PATTERN)
    status: WorkStatus
    expected_revision: int = Field(..., ge=1, le=2_000_000_000)
    note: str | None = Field(default=None, pattern=NOTE_PATTERN)


class FindingWorkOwnerRequest(StrictWorkContract):
    actor: str = Field(..., pattern=LABEL_PATTERN)
    owner_kind: OwnerKind | None = None
    owner_label: str | None = Field(default=None, pattern=LABEL_PATTERN)
    expected_revision: int = Field(..., ge=1, le=2_000_000_000)

    @model_validator(mode="after")
    def require_owner_pair(self) -> "FindingWorkOwnerRequest":
        _require_owner_pair(self.owner_kind, self.owner_label)
        return self


class FindingWorkReferenceRequest(StrictWorkContract):
    actor: str = Field(..., pattern=LABEL_PATTERN)
    reference_type: ReferenceType
    reference_system: str = Field(..., pattern=REFERENCE_SYSTEM_PATTERN)
    reference_label: str = Field(..., pattern=REFERENCE_LABEL_PATTERN)
    expected_revision: int = Field(..., ge=1, le=2_000_000_000)


class FindingWorkReferenceRemoveRequest(StrictWorkContract):
    actor: str = Field(..., pattern=LABEL_PATTERN)
    expected_revision: int = Field(..., ge=1, le=2_000_000_000)


class FindingWorkNoteRequest(StrictWorkContract):
    actor: str = Field(..., pattern=LABEL_PATTERN)
    note: str = Field(..., pattern=NOTE_PATTERN)
    expected_revision: int = Field(..., ge=1, le=2_000_000_000)


class FindingWorkOwnerResponse(StrictWorkContract):
    kind: OwnerKind
    label: str = Field(..., max_length=120)
    verification: Literal["unverified"]


class FindingWorkReferenceResponse(StrictWorkContract):
    reference_id: str = Field(..., pattern=WORK_REFERENCE_ID_PATTERN)
    reference_type: ReferenceType
    reference_system: str = Field(..., max_length=40)
    reference_label: str = Field(..., max_length=120)
    verification: Literal["unverified"]
    added_actor_label: str = Field(..., max_length=120)
    added_at: datetime


class FindingWorkItemResponse(StrictWorkContract):
    work_item_id: str = Field(..., pattern=WORK_ITEM_ID_PATTERN)
    finding_id: str = Field(..., pattern=FINDING_ID_PATTERN)
    site_id: str = Field(..., pattern=SITE_ID_PATTERN)
    work_status: WorkStatus
    owner: FindingWorkOwnerResponse | None = None
    revision: int = Field(..., ge=1)
    finding_status: FindingStatus = Field(
        ...,
        description="Read-only; owned by deterministic evidence evaluation.",
    )
    created_principal: Literal["api-admin-token"]
    created_actor_label: str = Field(..., max_length=120)
    actor_verification: Literal["unverified"]
    created_at: datetime
    updated_at: datetime
    references: list[FindingWorkReferenceResponse] = Field(
        default_factory=list,
        max_length=MAX_ACTIVE_WORK_REFERENCES,
    )


class FindingWorkItemListResponse(StrictWorkContract):
    items: list[FindingWorkItemResponse] = Field(max_length=200)
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1, le=200)
    offset: int = Field(..., ge=0, le=10_000)
    truncated: bool


class FindingWorkEventResponse(StrictWorkContract):
    event_id: int = Field(..., ge=1)
    work_item_id: str = Field(..., pattern=WORK_ITEM_ID_PATTERN)
    finding_id: str = Field(..., pattern=FINDING_ID_PATTERN)
    site_id: str = Field(..., pattern=SITE_ID_PATTERN)
    revision: int = Field(..., ge=1)
    event_type: WorkEventType
    from_status: WorkStatus | None = None
    to_status: WorkStatus | None = None
    owner_kind: OwnerKind | None = None
    owner_label: str | None = Field(default=None, max_length=120)
    reference_id: str | None = Field(default=None, pattern=WORK_REFERENCE_ID_PATTERN)
    note: str | None = Field(default=None, max_length=1000)
    finding_status: FindingStatus
    principal: Literal["api-admin-token"]
    actor_label: str = Field(..., max_length=120)
    actor_verification: Literal["unverified"]
    occurred_at: datetime


class FindingWorkEventListResponse(StrictWorkContract):
    items: list[FindingWorkEventResponse] = Field(max_length=200)
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1, le=200)
    offset: int = Field(..., ge=0, le=10_000)
    truncated: bool
