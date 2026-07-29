from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


MAX_OBSERVATIONS_PER_BATCH = 500


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ObservationEvidence(StrictContract):
    """Bounded, vendor-neutral evidence attached to a normalized asset."""

    protocol: str = Field(..., min_length=1, max_length=32, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    kind: str = Field(..., min_length=1, max_length=64)
    value: str = Field(..., min_length=1, max_length=512)
    confidence: float = Field(..., ge=0.0, le=1.0)


class ObservationAsset(StrictContract):
    asset_id: str = Field(..., min_length=1, max_length=160)
    hostname: str | None = Field(default=None, max_length=255)
    primary_ip: str | None = Field(default=None, max_length=64)
    mac: str | None = Field(default=None, max_length=64)
    os: str | None = Field(default=None, max_length=160)
    platform: str | None = Field(default=None, max_length=160)
    category: str | None = Field(default=None, max_length=80)
    evidence: list[ObservationEvidence] = Field(default_factory=list, max_length=32)


class ObservationBatchRequest(StrictContract):
    schema_version: Literal["oaw.observation-batch.v1"]
    observation_batch_id: str = Field(..., min_length=8, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$")
    site_id: str = Field(..., min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    sensor_id: str = Field(..., min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$")
    sensor_name: str = Field(..., min_length=1, max_length=160)
    sensor_type: Literal["passive-network-sensor", "endpoint-collector", "connector"]
    sensor_version: str | None = Field(default=None, max_length=80)
    observed_at: datetime
    observation_source: Literal["passive-network", "endpoint-inventory", "connector"]
    delivery_state: Literal["live", "cached-retry"] = "live"
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    assets: list[ObservationAsset] = Field(default_factory=list, max_length=MAX_OBSERVATIONS_PER_BATCH)

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value


class ObservationBatchResponse(StrictContract):
    status: Literal["accepted", "duplicate"]
    observation_batch_id: str
    storage_id: int
    site_id: str
    sensor_id: str
    received_at: datetime
    observed_asset_count: int
    normalized_asset_count: int
    message: str


class SensorSummary(StrictContract):
    sensor_id: str
    site_id: str
    sensor_name: str
    sensor_type: str
    sensor_version: str | None = None
    sensor_status: Literal["healthy", "delayed", "stale", "never-seen"]
    identity_status: Literal["enrolled"]
    last_seen_at: datetime | None = None
    data_freshness: Literal["fresh", "aging", "stale", "unknown"]
    observation_source: str


class SensorSummaryResponse(StrictContract):
    sensors: list[SensorSummary]
    data_as_of: datetime | None = None


class SiteIntelligenceSummary(StrictContract):
    site_id: str
    name: str
    description: str | None = None
    sensor_count: int
    stale_sensor_count: int
    asset_count: int
    unmanaged_asset_count: int
    finding_count: int
    highest_risk_score: int
    data_freshness: Literal["fresh", "aging", "stale", "unknown"]


class SiteIntelligenceSummaryResponse(StrictContract):
    sites: list[SiteIntelligenceSummary]
    data_as_of: datetime | None = None
