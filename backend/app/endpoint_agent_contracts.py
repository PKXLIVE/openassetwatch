"""Strict public contracts for authenticated endpoint-agent identity and inventory."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from .hub_contracts import ComponentObservation


AGENT_ID_PATTERN = r"^agent_[0-9a-f]{32}$"
ENROLLMENT_ID_PATTERN = r"^aenr_[0-9a-f]{32}$"
CREDENTIAL_ID_PATTERN = r"^acred_[0-9a-f]{32}$"
SITE_ID_PATTERN = r"^[A-Za-z0-9._-]+$"
DEPLOYMENT_ID_PATTERN = r"^[A-Za-z0-9._:-]+$"
MAX_FUTURE_SKEW = timedelta(minutes=5)
MAX_INVENTORY_AGE = timedelta(days=30)
MAX_ASSETS = 16
MAX_COMPONENTS_PER_ASSET = 2_000
NATIVE_SOFTWARE_SOURCES = {
    "windows": {"windows-uninstall-32", "windows-uninstall-64"},
    "linux": {"linux-dpkg", "linux-rpm"},
    "darwin": {"macos-pkgutil"},
}
NATIVE_COMPONENT_CONTRACTS = {
    "windows-uninstall-32": ("generic", "windows-registry", "windows-uninstall-registry", ""),
    "windows-uninstall-64": ("generic", "windows-registry", "windows-uninstall-registry", ""),
    "linux-dpkg": ("deb", "dpkg", "dpkg-native-query", None),
    "linux-rpm": ("rpm", "rpm", "rpm-native-query", None),
    "macos-pkgutil": ("generic", "pkgutil", "pkgutil-native-query", None),
}


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _timezone_aware(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return value.astimezone(timezone.utc)


class AgentEnrollmentCreateRequest(StrictContract):
    site_id: str = Field(..., min_length=1, max_length=128, pattern=SITE_ID_PATTERN)
    requested_deployment_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
        pattern=DEPLOYMENT_ID_PATTERN,
    )
    requested_display_name: str | None = Field(default=None, min_length=1, max_length=160)
    requested_agent_type: Literal["endpoint-agent"] = "endpoint-agent"
    expires_in_minutes: int = Field(default=60, ge=5, le=1440)


class AgentEnrollmentPublic(StrictContract):
    enrollment_id: str = Field(..., pattern=ENROLLMENT_ID_PATTERN)
    site_id: str
    requested_deployment_id: str | None = None
    requested_display_name: str | None = None
    requested_agent_type: Literal["endpoint-agent"]
    status: Literal["pending", "consumed", "expired", "revoked"]
    failed_attempts: int = Field(..., ge=0, le=100)
    max_attempts: int = Field(..., ge=1, le=100)
    created_by: str
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None
    revoked_at: datetime | None = None
    issued_agent_id: str | None = None


class AgentEnrollmentCreateResponse(AgentEnrollmentPublic):
    enrollment_token: str = Field(..., min_length=64, max_length=256)


class AgentEnrollmentListResponse(StrictContract):
    enrollments: list[AgentEnrollmentPublic]


class AgentEnrollmentExchangeRequest(StrictContract):
    enrollment_token: SecretStr
    installation_id: str | None = Field(default=None, min_length=1, max_length=160, pattern=DEPLOYMENT_ID_PATTERN)
    display_name: str | None = Field(default=None, min_length=1, max_length=160)
    agent_version: str | None = Field(default=None, min_length=1, max_length=80)
    platform: str | None = Field(default=None, min_length=1, max_length=80)
    architecture: str | None = Field(default=None, min_length=1, max_length=40)
    agent_type: Literal["endpoint-agent"] = "endpoint-agent"


class AgentEnrollmentExchangeResponse(StrictContract):
    status: Literal["enrolled"]
    site_id: str
    agent_id: str = Field(..., pattern=AGENT_ID_PATTERN)
    deployment_id: str | None = None
    agent_type: Literal["endpoint-agent"]
    credential_id: str = Field(..., pattern=CREDENTIAL_ID_PATTERN)
    agent_credential: str = Field(..., min_length=64, max_length=256)
    issued_at: datetime


class AgentCredentialStatus(StrictContract):
    credential_id: str = Field(..., pattern=CREDENTIAL_ID_PATTERN)
    agent_id: str = Field(..., pattern=AGENT_ID_PATTERN)
    site_id: str
    deployment_id: str | None = None
    agent_type: Literal["endpoint-agent"]
    status: Literal["active", "rotated", "revoked", "expired"]
    created_at: datetime
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    rotated_at: datetime | None = None
    revoked_at: datetime | None = None
    predecessor_credential_id: str | None = None
    replacement_credential_id: str | None = None
    identity_status: Literal["active", "revoked", "legacy"]


class AgentCredentialListResponse(StrictContract):
    credentials: list[AgentCredentialStatus]


class AgentCredentialIssueResponse(StrictContract):
    status: Literal["rotated"]
    credential_id: str = Field(..., pattern=CREDENTIAL_ID_PATTERN)
    agent_id: str = Field(..., pattern=AGENT_ID_PATTERN)
    site_id: str
    deployment_id: str | None = None
    agent_type: Literal["endpoint-agent"]
    agent_credential: str = Field(..., min_length=64, max_length=256)
    issued_at: datetime


class AgentCheckInRequest(StrictContract):
    site_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=SITE_ID_PATTERN)
    agent_id: str | None = Field(default=None, pattern=AGENT_ID_PATTERN)
    deployment_id: str | None = Field(default=None, min_length=1, max_length=160, pattern=DEPLOYMENT_ID_PATTERN)
    agent_type: Literal["endpoint-agent"] | None = None
    agent_version: str | None = Field(default=None, min_length=1, max_length=80)
    platform: str | None = Field(default=None, min_length=1, max_length=80)
    architecture: str | None = Field(default=None, min_length=1, max_length=40)
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    supported_capabilities: list[str] = Field(default_factory=list, max_length=64)
    inventory_schema_version: str | None = Field(default=None, min_length=1, max_length=80)
    health: Literal["healthy", "degraded"] = "healthy"
    observed_at: datetime | None = None

    @field_validator("supported_capabilities")
    @classmethod
    def bound_capabilities(cls, values: list[str]) -> list[str]:
        if any(not value or len(value) > 80 for value in values):
            raise ValueError("capabilities must contain bounded non-empty strings")
        if len(set(values)) != len(values):
            raise ValueError("capabilities must not contain duplicates")
        return values

    @field_validator("observed_at")
    @classmethod
    def bound_observed_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        current = datetime.now(timezone.utc)
        parsed = _timezone_aware(value, label="observed_at")
        if parsed > current + MAX_FUTURE_SKEW or parsed < current - MAX_INVENTORY_AGE:
            raise ValueError("observed_at is outside the accepted window")
        return parsed


class AgentCheckInResponse(StrictContract):
    status: Literal["accepted"]
    site_id: str
    agent_id: str | None = None
    agent_type: Literal["endpoint-agent"]
    credential_id: str | None = None
    identity_status: Literal["active", "legacy"]
    source_authority: Literal["authenticated-endpoint", "untrusted-legacy"]
    received_at: datetime
    message: str


class EndpointEvidence(StrictContract):
    kind: str = Field(..., min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    value: str = Field(..., min_length=1, max_length=512)
    method: str = Field(default="endpoint-inventory", min_length=1, max_length=64)
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)


class EndpointIPAddress(StrictContract):
    address: str = Field(..., min_length=2, max_length=64)
    family: Literal["ipv4", "ipv6"] | None = None

    @field_validator("address")
    @classmethod
    def valid_address(cls, value: str) -> str:
        parsed = ip_address(value)
        return str(parsed)


class EndpointInterface(StrictContract):
    name: str = Field(..., min_length=1, max_length=128)
    mac_address: str | None = Field(default=None, min_length=11, max_length=64)
    ip_addresses: list[EndpointIPAddress] = Field(default_factory=list, max_length=64)


class EndpointAsset(StrictContract):
    asset_id: str | None = Field(default=None, min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$")
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    fqdn: str | None = Field(default=None, min_length=1, max_length=255)
    os: str | None = Field(default=None, min_length=1, max_length=160)
    platform: str | None = Field(default=None, min_length=1, max_length=160)
    architecture: str | None = Field(default=None, min_length=1, max_length=40)
    category: str | None = Field(default=None, min_length=1, max_length=80)
    interfaces: list[EndpointInterface] = Field(default_factory=list, max_length=128)
    evidence: list[EndpointEvidence] = Field(default_factory=list, max_length=256)
    components: list[ComponentObservation] = Field(default_factory=list, max_length=MAX_COMPONENTS_PER_ASSET)
    management_capabilities: list[str] = Field(default_factory=list, max_length=64)

    @field_validator("management_capabilities")
    @classmethod
    def bound_management_capabilities(cls, values: list[str]) -> list[str]:
        if any(not value or len(value) > 80 for value in values):
            raise ValueError("management capabilities must be bounded strings")
        return values

    @field_validator("components")
    @classmethod
    def reject_client_evidence_ids(
        cls, values: list[ComponentObservation]
    ) -> list[ComponentObservation]:
        if any(component.evidence_ids for component in values):
            raise ValueError("component evidence identifiers are server-issued")
        return values


class NativeSoftwareSourceResult(StrictContract):
    source_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
    )
    platform: Literal["windows", "linux", "darwin"]
    status: Literal["complete", "partial", "unsupported", "failed"]
    observed_at: datetime
    record_count: int = Field(..., ge=0, le=MAX_COMPONENTS_PER_ASSET)
    truncated: bool = False
    error_code: str | None = Field(
        default=None,
        min_length=1,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
    )
    limitations: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("observed_at")
    @classmethod
    def bound_source_observed_at(cls, value: datetime) -> datetime:
        return _timezone_aware(value, label="software source observed_at")

    @field_validator("limitations")
    @classmethod
    def bound_source_limitations(cls, values: list[str]) -> list[str]:
        if any(not value or len(value) > 120 for value in values):
            raise ValueError("software source limitations must be bounded strings")
        return list(dict.fromkeys(values))

    @model_validator(mode="after")
    def require_reviewed_source(self) -> "NativeSoftwareSourceResult":
        if self.source_id not in NATIVE_SOFTWARE_SOURCES[self.platform]:
            raise ValueError("software source is not reviewed for the reported platform")
        if self.status == "complete" and (self.truncated or self.error_code):
            raise ValueError("complete software source cannot be truncated or failed")
        if self.status in {"failed", "unsupported"} and self.record_count:
            raise ValueError("unsuccessful software source cannot report components")
        if self.status in {"failed", "unsupported"} and not self.error_code:
            raise ValueError("unsuccessful software source requires an error code")
        if self.status == "partial" and not (
            self.truncated or self.error_code or self.limitations
        ):
            raise ValueError("partial software source requires bounded diagnostics")
        return self

class EndpointInventoryRequest(StrictContract):
    schema_version: Literal["oaw.endpoint-inventory.v1"]
    inventory_batch_id: str = Field(..., min_length=8, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$")
    observed_at: datetime
    inventory_mode: Literal["complete", "partial"]
    site_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=SITE_ID_PATTERN)
    agent_id: str | None = Field(default=None, pattern=AGENT_ID_PATTERN)
    deployment_id: str | None = Field(default=None, min_length=1, max_length=160, pattern=DEPLOYMENT_ID_PATTERN)
    agent_type: Literal["endpoint-agent"] | None = None
    agent_version: str | None = Field(default=None, min_length=1, max_length=80)
    platform: str | None = Field(default=None, min_length=1, max_length=80)
    architecture: str | None = Field(default=None, min_length=1, max_length=40)
    supported_capabilities: list[str] = Field(default_factory=list, max_length=64)
    collection_limitations: list[str] = Field(default_factory=list, max_length=64)
    software_sources: list[NativeSoftwareSourceResult] = Field(
        default_factory=list,
        max_length=8,
    )
    assets: list[EndpointAsset] = Field(..., min_length=1, max_length=MAX_ASSETS)

    @field_validator("observed_at")
    @classmethod
    def bound_observation_time(cls, value: datetime) -> datetime:
        current = datetime.now(timezone.utc)
        parsed = _timezone_aware(value, label="observed_at")
        if parsed > current + MAX_FUTURE_SKEW or parsed < current - MAX_INVENTORY_AGE:
            raise ValueError("observed_at is outside the accepted window")
        return parsed

    @field_validator("supported_capabilities", "collection_limitations")
    @classmethod
    def bound_string_lists(cls, values: list[str]) -> list[str]:
        if any(not value or len(value) > 240 for value in values):
            raise ValueError("inventory string lists must contain bounded strings")
        return values

    @model_validator(mode="after")
    def bound_aggregate_counts(self) -> "EndpointInventoryRequest":
        components = sum(len(asset.components) for asset in self.assets)
        evidence = sum(len(asset.evidence) for asset in self.assets)
        interfaces = sum(len(asset.interfaces) for asset in self.assets)
        addresses = sum(len(interface.ip_addresses) for asset in self.assets for interface in asset.interfaces)
        if components > 8_000:
            raise ValueError("inventory component limit exceeded")
        if evidence > 1_024:
            raise ValueError("inventory evidence limit exceeded")
        if interfaces > 256 or addresses > 1_024:
            raise ValueError("inventory network evidence limit exceeded")
        source_ids = [source.source_id for source in self.software_sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("software source identifiers must be unique")
        if self.software_sources and len(self.assets) != 1:
            raise ValueError(
                "native software source results must describe exactly one endpoint asset"
            )
        component_counts: dict[str, int] = {}
        for asset in self.assets:
            for component in asset.components:
                if component.collection_source_id is None:
                    continue
                component_counts[component.collection_source_id] = (
                    component_counts.get(component.collection_source_id, 0) + 1
                )
        reported = {source.source_id: source for source in self.software_sources}
        if any(source_id not in reported for source_id in component_counts):
            raise ValueError("native component source must have a source-level result")
        if any(
            source.record_count != component_counts.get(source.source_id, 0)
            for source in self.software_sources
        ):
            raise ValueError("software source record count does not match components")
        native_records: set[tuple[str, str]] = set()
        for asset in self.assets:
            for component in asset.components:
                source_id = component.collection_source_id
                if source_id is None:
                    continue
                source = reported[source_id]
                expected = NATIVE_COMPONENT_CONTRACTS[source_id]
                actual = (
                    component.ecosystem.casefold(),
                    (component.package_manager or "").casefold(),
                    component.evidence_method or "",
                    component.architecture.casefold()
                    if component.architecture
                    else None,
                )
                architecture_mismatch = (
                    actual[3] is not None
                    if expected[3] == ""
                    else expected[3] is not None and actual[3] != expected[3]
                )
                if actual[:3] != expected[:3] or architecture_mismatch:
                    raise ValueError(
                        "native component fields do not match the reviewed source contract"
                    )
                if component.install_scope != "system":
                    raise ValueError("native software collection is machine scoped")
                if (
                    component.observed_at is not None
                    and component.observed_at > source.observed_at
                ):
                    raise ValueError(
                        "native component time exceeds its source snapshot time"
                    )
                record_key = (source_id, component.source_record_id or "")
                if record_key in native_records:
                    raise ValueError("native source record identifiers must be unique")
                native_records.add(record_key)
        if any(
            source.observed_at > self.observed_at + MAX_FUTURE_SKEW
            for source in self.software_sources
        ):
            raise ValueError("software source time exceeds inventory observation time")
        if self.platform in NATIVE_SOFTWARE_SOURCES and any(
            source.platform != self.platform for source in self.software_sources
        ):
            raise ValueError("software source platform does not match the endpoint")
        return self


class EndpointInventoryResponse(StrictContract):
    status: Literal["accepted", "duplicate"]
    inventory_batch_id: str
    storage_id: int = Field(..., ge=1)
    collection_id: int = Field(..., ge=1)
    canonical_collection_id: str = Field(..., pattern=r"^col_[0-9a-f]{32}$")
    site_id: str
    agent_id: str
    credential_id: str
    received_at: datetime
    observed_asset_count: int = Field(..., ge=0, le=MAX_ASSETS)
    normalized_asset_count: int = Field(..., ge=0, le=MAX_ASSETS)
    component_count: int = Field(..., ge=0, le=32_000)
    reevaluation_state: Literal[
        "queued", "running", "completed", "retryable-failure", "not-required"
    ]
    source_authority: Literal["authenticated-endpoint"] = "authenticated-endpoint"
    adapter_type: Literal["endpoint-agent"] = "endpoint-agent"
    compatibility_status: Literal["canonical"] = "canonical"
    warnings: list[str] = Field(default_factory=list, max_length=16)
    message: str
