"""Strict bounded administrative contracts for advisory synchronization."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class StrictSyncModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AdvisorySyncRequest(StrictSyncModel):
    pass


class AdvisoryApprovalRequest(StrictSyncModel):
    pass


class AdvisoryRejectionRequest(StrictSyncModel):
    reason: str = Field(..., min_length=1, max_length=240)


class AdvisoryRollbackRequest(StrictSyncModel):
    catalog_id: str = Field(..., pattern=r"^afcat_[0-9a-f]{32}$")


class AdvisoryReevaluationRetryRequest(StrictSyncModel):
    pass
