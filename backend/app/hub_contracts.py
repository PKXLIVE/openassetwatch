from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)


MAX_OBSERVATIONS_PER_BATCH = 500
MAX_COMPONENTS_PER_BATCH = 32_000
MAX_OBSERVATION_FUTURE_SKEW = timedelta(minutes=5)
SITE_ID_PATTERN = r"^[A-Za-z0-9._-]+$"
SENSOR_ID_PATTERN = r"^[A-Za-z0-9._:-]+$"
SENSOR_ENROLLMENT_ID_PATTERN = r"^senr_[0-9a-f]{32}$"
SENSOR_CREDENTIAL_ID_PATTERN = r"^scred_[0-9a-f]{32}$"


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ObservationEvidence(StrictContract):
    """Bounded, vendor-neutral evidence attached to a normalized asset."""

    protocol: str = Field(..., min_length=1, max_length=32, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    kind: str = Field(..., min_length=1, max_length=64)
    value: str = Field(..., min_length=1, max_length=512)
    confidence: float = Field(..., ge=0.0, le=1.0)


class ComponentObservation(StrictContract):
    """Bounded passive component evidence; collected values remain data."""

    component_type: Literal[
        "application",
        "operating-system-package",
        "library",
        "runtime",
        "driver",
        "firmware",
        "operating-system",
        "security-tool",
        "unknown",
    ]
    ecosystem: str = Field(..., min_length=1, max_length=40)
    name: str = Field(..., min_length=1, max_length=240)
    version: str | None = Field(default=None, max_length=160)
    namespace: str | None = Field(default=None, max_length=160)
    vendor: str | None = Field(default=None, max_length=160)
    architecture: str | None = Field(default=None, max_length=40)
    package_manager: str | None = Field(default=None, max_length=48)
    purl: str | None = Field(default=None, max_length=600)
    install_scope: str = Field(default="system", min_length=1, max_length=40)
    observed_at: datetime | None = None
    firmware_evidence_type: Literal[
        "direct",
        "vendor-reported",
        "collector-reported",
        "inferred",
        "unknown",
    ] = "unknown"
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list, max_length=16)
    collection_source_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
    )
    source_record_id: str | None = Field(default=None, min_length=1, max_length=240)
    evidence_method: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
    )
    metadata: dict[str, str] = Field(default_factory=dict, max_length=4)

    @field_validator("metadata")
    @classmethod
    def bound_component_metadata(cls, value: dict[str, str]) -> dict[str, str]:
        if any(
            not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", key)
            or len(item) > 240
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            for key, item in value.items()
        ):
            raise ValueError("component metadata must contain bounded safe strings")
        return value

    @field_validator("observed_at")
    @classmethod
    def require_component_timezone(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if value is None:
            return value
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("component observed_at must include a timezone")
        if (
            value.astimezone(timezone.utc)
            > datetime.now(timezone.utc) + MAX_OBSERVATION_FUTURE_SKEW
        ):
            raise ValueError(
                "component observed_at exceeds the allowed future clock skew"
            )
        return value

    @model_validator(mode="after")
    def require_complete_native_source_reference(self) -> "ComponentObservation":
        fields = (
            self.collection_source_id,
            self.source_record_id,
            self.evidence_method,
        )
        if any(fields) and not all(fields):
            raise ValueError(
                "native component source fields must be supplied together"
            )
        return self


class ObservationAsset(StrictContract):
    asset_id: str = Field(..., min_length=1, max_length=160)
    hostname: str | None = Field(default=None, max_length=255)
    primary_ip: str | None = Field(default=None, max_length=64)
    mac: str | None = Field(default=None, max_length=64)
    os: str | None = Field(default=None, max_length=160)
    platform: str | None = Field(default=None, max_length=160)
    category: str | None = Field(default=None, max_length=80)
    evidence: list[ObservationEvidence] = Field(default_factory=list, max_length=32)
    components: list[ComponentObservation] = Field(
        default_factory=list,
        max_length=1_000,
    )
    component_inventory_complete: bool = False


class ObservationBatchRequest(StrictContract):
    schema_version: Literal["oaw.observation-batch.v1"]
    observation_batch_id: str = Field(..., min_length=8, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$")
    site_id: str = Field(..., min_length=1, max_length=128, pattern=SITE_ID_PATTERN)
    sensor_id: str = Field(..., min_length=1, max_length=160, pattern=SENSOR_ID_PATTERN)
    sensor_name: str = Field(..., min_length=1, max_length=160)
    sensor_type: Literal["passive-network-sensor", "endpoint-collector", "connector"]
    sensor_version: str | None = Field(default=None, max_length=80)
    observed_at: datetime
    observation_source: Literal["passive-network", "endpoint-inventory", "connector"]
    delivery_state: Literal["live", "cached-retry"] = "live"
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    component_inventory_complete: bool = False
    assets: list[ObservationAsset] = Field(default_factory=list, max_length=MAX_OBSERVATIONS_PER_BATCH)

    @model_validator(mode="before")
    @classmethod
    def bound_aggregate_components(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        assets = value.get("assets")
        if not isinstance(assets, list):
            return value
        component_count = 0
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            components = asset.get("components")
            if isinstance(components, list):
                component_count += len(components)
                if component_count > MAX_COMPONENTS_PER_BATCH:
                    raise ValueError("observation component limit exceeded")
        return value

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        if value.astimezone(timezone.utc) > datetime.now(timezone.utc) + MAX_OBSERVATION_FUTURE_SKEW:
            raise ValueError("observed_at exceeds the allowed future clock skew")
        return value

    @model_validator(mode="after")
    def require_bound_source_kind(self) -> "ObservationBatchRequest":
        expected = {
            "passive-network-sensor": "passive-network",
            "endpoint-collector": "endpoint-inventory",
            "connector": "connector",
        }[self.sensor_type]
        if self.observation_source != expected:
            raise ValueError(
                "observation_source must match the authenticated sensor_type"
            )
        component_limit = (
            self.observed_at.astimezone(timezone.utc)
            + MAX_OBSERVATION_FUTURE_SKEW
        )
        if any(
            component.observed_at is not None
            and component.observed_at.astimezone(timezone.utc) > component_limit
            for asset in self.assets
            for component in asset.components
        ):
            raise ValueError(
                "component observed_at exceeds the batch observation time"
            )
        return self


class ObservationBatchResponse(StrictContract):
    status: Literal["accepted", "duplicate"]
    observation_batch_id: str
    storage_id: int
    canonical_collection_id: str = Field(..., pattern=r"^col_[0-9a-f]{32}$")
    site_id: str
    sensor_id: str
    received_at: datetime
    observed_asset_count: int
    normalized_asset_count: int
    source_authority: Literal[
        "authenticated-passive-sensor", "untrusted-transitional"
    ]
    adapter_type: Literal["passive-sensor"] = "passive-sensor"
    compatibility_status: Literal["canonical", "deprecated"]
    evaluation_state: Literal[
        "queued", "running", "completed", "retryable-failure", "not-required"
    ]
    warnings: list[str] = Field(default_factory=list, max_length=16)
    message: str


class SensorSummary(StrictContract):
    sensor_id: str
    site_id: str
    sensor_name: str
    sensor_type: str
    sensor_version: str | None = None
    sensor_status: Literal["healthy", "delayed", "stale", "never-seen", "revoked"]
    identity_status: Literal["enrolled", "development-shared", "revoked"]
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


class SensorEnrollmentCreateRequest(StrictContract):
    site_id: str = Field(..., min_length=1, max_length=128, pattern=SITE_ID_PATTERN)
    requested_sensor_id: str | None = Field(default=None, min_length=1, max_length=160, pattern=SENSOR_ID_PATTERN)
    requested_sensor_name: str | None = Field(default=None, min_length=1, max_length=160)
    sensor_type: Literal["passive-network-sensor"] = "passive-network-sensor"
    expires_in_minutes: int = Field(default=60, ge=5, le=1440)


class SensorEnrollmentPublic(StrictContract):
    enrollment_id: str = Field(..., pattern=SENSOR_ENROLLMENT_ID_PATTERN)
    site_id: str
    requested_sensor_id: str | None = None
    requested_sensor_name: str | None = None
    sensor_type: Literal["passive-network-sensor"]
    status: Literal["pending", "used", "expired", "revoked"]
    failed_attempts: int = Field(..., ge=0, le=100)
    max_attempts: int = Field(..., ge=1, le=100)
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None = None
    revoked_at: datetime | None = None
    issued_sensor_id: str | None = None


class SensorEnrollmentCreateResponse(SensorEnrollmentPublic):
    enrollment_token: str = Field(..., min_length=64, max_length=256)


class SensorEnrollmentListResponse(StrictContract):
    enrollments: list[SensorEnrollmentPublic]


class SensorEnrollmentExchangeRequest(StrictContract):
    enrollment_token: SecretStr = Field(...)
    sensor_id: str = Field(..., min_length=1, max_length=160, pattern=SENSOR_ID_PATTERN)
    sensor_name: str = Field(..., min_length=1, max_length=160)
    sensor_type: Literal["passive-network-sensor"] = "passive-network-sensor"
    sensor_version: str | None = Field(default=None, max_length=80)
    platform: str | None = Field(default=None, max_length=80)


class SensorEnrollmentExchangeResponse(StrictContract):
    status: Literal["enrolled"]
    site_id: str
    sensor_id: str
    sensor_type: Literal["passive-network-sensor"]
    credential_id: str = Field(..., pattern=SENSOR_CREDENTIAL_ID_PATTERN)
    sensor_credential: str = Field(..., min_length=64, max_length=256)
    issued_at: datetime


class SensorCredentialStatus(StrictContract):
    credential_id: str = Field(..., pattern=SENSOR_CREDENTIAL_ID_PATTERN)
    sensor_id: str
    site_id: str
    sensor_type: Literal["passive-network-sensor"]
    status: Literal["active", "revoked", "rotated", "expired"]
    created_at: datetime
    last_used_at: datetime | None = None
    rotated_at: datetime | None = None
    revoked_at: datetime | None = None
    expires_at: datetime | None = None
    predecessor_credential_id: str | None = None
    replacement_credential_id: str | None = None
    sensor_name: str | None = None
    identity_status: Literal["active", "revoked", "legacy"]


class SensorCredentialListResponse(StrictContract):
    credentials: list[SensorCredentialStatus]


class SensorCredentialIssueResponse(StrictContract):
    status: Literal["rotated"]
    credential_id: str = Field(..., pattern=SENSOR_CREDENTIAL_ID_PATTERN)
    sensor_id: str
    site_id: str
    sensor_type: Literal["passive-network-sensor"]
    sensor_credential: str = Field(..., min_length=64, max_length=256)
    issued_at: datetime


class SensorCheckInRequest(StrictContract):
    site_id: str = Field(..., min_length=1, max_length=128, pattern=SITE_ID_PATTERN)
    sensor_id: str = Field(..., min_length=1, max_length=160, pattern=SENSOR_ID_PATTERN)
    sensor_name: str = Field(..., min_length=1, max_length=160)
    sensor_type: Literal["passive-network-sensor"] = "passive-network-sensor"
    sensor_version: str | None = Field(default=None, max_length=80)
    status: Literal["healthy", "degraded"] = "healthy"


class SensorCheckInResponse(StrictContract):
    status: Literal["accepted"]
    site_id: str
    sensor_id: str
    received_at: datetime
    message: str
