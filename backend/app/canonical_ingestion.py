"""Canonical inventory-ingestion contracts and compatibility adapters.

Public request models are translated here into a server-owned envelope.  The
envelope deliberately has no public API binding: authority, identity, site,
trust, and adapter fields are supplied only by authenticated server context or
by an explicitly lower-trust compatibility adapter.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .hub_contracts import ComponentObservation


CANONICAL_SCHEMA_VERSION = "oaw.canonical-inventory.v1"
MAX_CANONICAL_ASSETS = 1_000
MAX_CANONICAL_COMPONENTS = 32_000
MAX_CANONICAL_EVIDENCE = 64_000
MAX_JSON_DEPTH = 10
MAX_JSON_NODES = 50_000
MAX_JSON_STRING = 2_048
MAX_METADATA_FIELDS = 32
MAX_PROVENANCE_FIELDS = 16
MAX_LIMITATIONS = 64
MAX_WARNINGS = 16
MAX_FUTURE_SKEW = timedelta(minutes=5)
SITE_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
AUTHORITY_FIELD_NAMES = frozenset(
    {
        "agent_authority",
        "authoritative",
        "credential_id",
        "management_state",
        "risk",
        "risk_score",
        "severity_override",
        "site_authority",
        "source_authenticated",
        "source_authority",
        "tenant_authority",
        "trust_rank",
    }
)


class CanonicalIngestionRejected(ValueError):
    """A compatibility payload cannot be safely normalized."""


class CanonicalReplayConflict(Exception):
    """An idempotency key was reused with different canonical content."""


class CanonicalAuthorizationRejected(Exception):
    """A bound identity became inactive before persistence completed."""


class CanonicalAdmissionRejected(Exception):
    """A source exceeded a bounded persistent admission window."""


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, frozen=True)


class CanonicalEvidence(StrictModel):
    protocol: str = Field(default="inventory", min_length=1, max_length=64)
    kind: str = Field(..., min_length=1, max_length=80)
    value: str = Field(..., min_length=1, max_length=512)
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)


class CanonicalAsset(StrictModel):
    asset_id: str = Field(..., min_length=1, max_length=160)
    hostname: str | None = Field(default=None, max_length=255)
    primary_ip: str | None = Field(default=None, max_length=64)
    mac: str | None = Field(default=None, max_length=64)
    os: str | None = Field(default=None, max_length=160)
    platform: str | None = Field(default=None, max_length=160)
    category: str | None = Field(default=None, max_length=80)
    evidence: tuple[CanonicalEvidence, ...] = Field(default=(), max_length=64)
    components: tuple[ComponentObservation, ...] = Field(default=(), max_length=2_000)
    component_inventory_complete: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def bound_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        bounded = _bounded_json(value)
        if not isinstance(bounded, dict):
            raise ValueError("asset metadata must be an object")
        return bounded


class CanonicalInventoryEnvelope(StrictModel):
    schema_version: Literal["oaw.canonical-inventory.v1"]
    route_name: str = Field(..., min_length=1, max_length=96)
    site_id: str = Field(..., min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    source_id: str = Field(..., pattern=r"^src_[0-9a-f]{32}$")
    source_identity: str = Field(..., min_length=1, max_length=160)
    source_type: Literal["endpoint-agent", "passive-sensor", "legacy-collector", "transitional"]
    adapter_type: Literal["endpoint-agent", "passive-sensor", "python-collector", "transitional-local"]
    authentication_class: Literal["bound-credential", "development-shared", "legacy-shared", "unauthenticated"]
    source_authority: Literal[
        "authenticated-endpoint",
        "authenticated-passive-sensor",
        "legacy-collector",
        "untrusted-transitional",
    ]
    trust_rank: int = Field(..., ge=0, le=100)
    compatibility_status: Literal["canonical", "compatibility", "deprecated"]
    observed_at: datetime
    ingested_at: datetime
    inventory_mode: Literal["complete", "partial", "passive", "legacy", "transitional"]
    idempotency_key: str = Field(..., min_length=1, max_length=200)
    canonical_collection_id: str = Field(..., pattern=r"^col_[0-9a-f]{32}$")
    payload_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    original_identifier: str | None = Field(default=None, max_length=160)
    assets: tuple[CanonicalAsset, ...] = Field(default=(), max_length=MAX_CANONICAL_ASSETS)
    collection_limitations: tuple[str, ...] = Field(default=(), max_length=MAX_LIMITATIONS)
    provenance: dict[str, str] = Field(default_factory=dict)
    credential_id: str | None = Field(default=None, max_length=80)
    bound_identity_id: str | None = Field(default=None, max_length=160)
    legacy_submission: dict[str, Any] | None = None

    @field_validator("observed_at", "ingested_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical ingestion timestamps must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("collection_limitations")
    @classmethod
    def bound_limitations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item or len(item) > 240 for item in value):
            raise ValueError("collection limitations must be bounded strings")
        return tuple(dict.fromkeys(value))

    @field_validator("provenance")
    @classmethod
    def bound_provenance(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > MAX_PROVENANCE_FIELDS:
            raise ValueError("provenance field limit exceeded")
        bounded: dict[str, str] = {}
        for key, item in sorted(value.items()):
            if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", key):
                raise ValueError("invalid provenance key")
            if not isinstance(item, str) or not item or len(item) > 240:
                raise ValueError("invalid provenance value")
            bounded[key] = item
        return bounded

    @field_validator("legacy_submission")
    @classmethod
    def bound_legacy_submission(
        cls, value: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        if value is None:
            return None
        bounded = _bounded_json(value)
        if not isinstance(bounded, dict):
            raise ValueError("legacy submission projection must be an object")
        return bounded

    @model_validator(mode="after")
    def enforce_authority_contract(self) -> "CanonicalInventoryEnvelope":
        expected = {
            "authenticated-endpoint": ("endpoint-agent", "endpoint-agent", "bound-credential", 90, "canonical"),
            "authenticated-passive-sensor": ("passive-sensor", "passive-sensor", "bound-credential", 75, "canonical"),
            "legacy-collector": ("legacy-collector", "python-collector", None, 25, "compatibility"),
            "untrusted-transitional": ("transitional", None, None, 10, "deprecated"),
        }[self.source_authority]
        if self.source_type != expected[0] or self.trust_rank != expected[3] or self.compatibility_status != expected[4]:
            raise ValueError("canonical authority fields are inconsistent")
        if expected[1] is not None and self.adapter_type != expected[1]:
            raise ValueError("canonical adapter authority is inconsistent")
        if expected[2] is not None and self.authentication_class != expected[2]:
            raise ValueError("canonical authentication authority is inconsistent")
        if self.source_authority.startswith("authenticated-") and (
            not self.credential_id or not self.bound_identity_id
        ):
            raise ValueError("authenticated envelopes require a bound identity and credential")
        if self.observed_at > self.ingested_at + MAX_FUTURE_SKEW:
            raise ValueError("observation time exceeds the allowed future skew")
        component_count = sum(len(asset.components) for asset in self.assets)
        evidence_count = sum(len(asset.evidence) for asset in self.assets)
        if component_count > MAX_CANONICAL_COMPONENTS:
            raise ValueError("canonical component limit exceeded")
        if evidence_count > MAX_CANONICAL_EVIDENCE:
            raise ValueError("canonical evidence limit exceeded")
        return self

    @property
    def source_authenticated(self) -> bool:
        return self.source_authority in {
            "authenticated-endpoint",
            "authenticated-passive-sensor",
        }

    @property
    def evidence_count(self) -> int:
        return sum(len(asset.evidence) for asset in self.assets)

    @property
    def component_count(self) -> int:
        return sum(len(asset.components) for asset in self.assets)

    def persistence_payload(self) -> dict[str, Any]:
        assets: list[dict[str, Any]] = []
        for asset in self.assets:
            item = asset.model_dump(mode="json")
            metadata = dict(item.pop("metadata", {}))
            item = {**metadata, **item}
            item["source_agent_id"] = self.source_id
            item["observed_at"] = self.observed_at.isoformat()
            assets.append(item)
        return {
            "schema_version": self.schema_version,
            "site_id": self.site_id,
            "agent_id": self.source_id,
            "sensor_id": self.source_id,
            "sensor_type": (
                "endpoint-agent"
                if self.source_authority == "authenticated-endpoint"
                else "passive-network-sensor"
                if self.source_authority == "authenticated-passive-sensor"
                else "connector"
            ),
            "observation_source": {
                "endpoint-agent": "endpoint-inventory",
                "passive-sensor": "passive-network",
                "python-collector": "legacy-collector",
                "transitional-local": "local-inventory",
            }[self.adapter_type],
            "observation_batch_id": self.original_identifier,
            "inventory_mode": self.inventory_mode,
            "component_inventory_complete": self.inventory_mode == "complete",
            "observed_at": self.observed_at.isoformat(),
            "collected_at": self.observed_at.isoformat(),
            "ingested_at": self.ingested_at.isoformat(),
            "source_authenticated": self.source_authenticated,
            "source_authority": self.source_authority,
            "canonical_collection_id": self.canonical_collection_id,
            "collection_limitations": list(self.collection_limitations),
            "provenance": self.provenance,
            "confidence": 0.9 if self.source_authority == "authenticated-endpoint" else 0.8 if self.source_authority == "authenticated-passive-sensor" else 0.35,
            "assets": assets,
        }


class CanonicalIngestionAcknowledgement(StrictModel):
    status: Literal["accepted", "duplicate"]
    canonical_collection_id: str = Field(..., pattern=r"^col_[0-9a-f]{32}$")
    canonical_asset_ids: tuple[str, ...] = Field(default=(), max_length=MAX_CANONICAL_ASSETS)
    replay_state: Literal["new", "identical-replay"]
    evidence_count: int = Field(..., ge=0, le=MAX_CANONICAL_EVIDENCE)
    component_count: int = Field(..., ge=0, le=MAX_CANONICAL_COMPONENTS)
    evaluation_state: Literal["queued", "running", "completed", "retryable-failure", "not-required"]
    warnings: tuple[str, ...] = Field(default=(), max_length=MAX_WARNINGS)
    adapter_type: Literal["endpoint-agent", "passive-sensor", "python-collector", "transitional-local"]
    compatibility_status: Literal["canonical", "compatibility", "deprecated"]
    source_authority: str = Field(..., max_length=40)
    compatibility_collection_id: int = Field(..., ge=1)
    legacy_submission_id: int | None = Field(default=None, ge=1)
    endpoint_storage_id: int | None = Field(default=None, ge=1)
    received_at: datetime
    observed_asset_count: int = Field(..., ge=0, le=MAX_CANONICAL_ASSETS)
    normalized_asset_count: int = Field(..., ge=0, le=MAX_CANONICAL_ASSETS)


def _bounded_json(value: Any) -> Any:
    nodes = [0]

    def visit(item: Any, depth: int) -> Any:
        nodes[0] += 1
        if nodes[0] > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise CanonicalIngestionRejected("compatibility payload structure limit exceeded")
        if item is None or isinstance(item, (bool, int)):
            return item
        if isinstance(item, float):
            if not math.isfinite(item):
                raise CanonicalIngestionRejected(
                    "compatibility payload number must be finite"
                )
            return item
        if isinstance(item, str):
            if len(item) > MAX_JSON_STRING:
                raise CanonicalIngestionRejected("compatibility payload string limit exceeded")
            return item
        if isinstance(item, Mapping):
            if len(item) > 256:
                raise CanonicalIngestionRejected("compatibility payload object limit exceeded")
            result: dict[str, Any] = {}
            for raw_key, raw_value in item.items():
                if not isinstance(raw_key, str) or not raw_key or len(raw_key) > 128:
                    raise CanonicalIngestionRejected("compatibility payload key is invalid")
                if raw_key.casefold() in AUTHORITY_FIELD_NAMES:
                    continue
                result[raw_key] = visit(raw_value, depth + 1)
            return result
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            if len(item) > 8_000:
                raise CanonicalIngestionRejected("compatibility payload list limit exceeded")
            return [visit(entry, depth + 1) for entry in item]
        raise CanonicalIngestionRejected("compatibility payload contains an unsupported value")

    return visit(value, 0)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _source_id(*, site_id: str, adapter: str, auth_class: str, identity: str) -> str:
    value = "\x00".join((site_id, adapter, auth_class, identity)).encode("utf-8")
    return f"src_{hashlib.sha256(value).hexdigest()[:32]}"


def _collection_id(*, source_id: str, adapter: str, idempotency_key: str) -> str:
    value = "\x00".join((source_id, adapter, idempotency_key)).encode("utf-8")
    return f"col_{hashlib.sha256(value).hexdigest()[:32]}"


def _text(value: Any, *, limit: int) -> str | None:
    if value is None:
        return None
    result = str(value).strip()
    return result[:limit] if result else None


def _component(entry: Mapping[str, Any], *, default_type: str = "application") -> ComponentObservation | None:
    name = _text(entry.get("name") or entry.get("package") or entry.get("product"), limit=240)
    if not name:
        return None
    raw_type = _text(entry.get("component_type"), limit=40) or default_type
    if raw_type not in {
        "application", "operating-system-package", "library", "runtime", "driver",
        "firmware", "operating-system", "security-tool", "unknown",
    }:
        raw_type = default_type
    ecosystem = _text(entry.get("ecosystem") or entry.get("package_manager"), limit=40) or "generic"
    candidate = {
        "component_type": raw_type,
        "ecosystem": ecosystem,
        "name": name,
        "version": _text(entry.get("version"), limit=160),
        "namespace": _text(entry.get("namespace"), limit=160),
        "vendor": _text(entry.get("vendor") or entry.get("publisher"), limit=160),
        "architecture": _text(entry.get("architecture"), limit=40),
        "package_manager": _text(entry.get("package_manager"), limit=48),
        "purl": _text(entry.get("purl"), limit=600),
        "install_scope": _text(entry.get("install_scope"), limit=40) or "system",
        "firmware_evidence_type": _text(entry.get("firmware_evidence_type"), limit=32) or "unknown",
        "confidence": entry.get("confidence") if isinstance(entry.get("confidence"), (int, float)) else 0.7,
    }
    return ComponentObservation.model_validate(candidate)


def _asset_from_mapping(value: Mapping[str, Any], *, index: int) -> CanonicalAsset:
    safe = _bounded_json(value)
    if not isinstance(safe, dict):
        raise CanonicalIngestionRejected("asset must be an object")
    host = safe.get("host") if isinstance(safe.get("host"), dict) else {}
    platform_info = safe.get("platform_info") if isinstance(safe.get("platform_info"), dict) else {}
    hostname = _text(safe.get("hostname") or host.get("hostname"), limit=255)
    primary_ip = _text(safe.get("primary_ip"), limit=64)
    mac = _text(safe.get("mac") or safe.get("mac_address"), limit=64)
    for interface in safe.get("primary_interfaces", []) if isinstance(safe.get("primary_interfaces"), list) else []:
        if not isinstance(interface, dict):
            continue
        mac = mac or _text(interface.get("mac_address"), limit=64)
        addresses = interface.get("ip_addresses")
        if isinstance(addresses, list):
            for address in addresses:
                if isinstance(address, dict):
                    primary_ip = primary_ip or _text(address.get("address"), limit=64)
    asset_id = _text(safe.get("asset_id") or hostname or mac or primary_ip, limit=160) or f"observed-{index + 1}"
    evidence: list[CanonicalEvidence] = []
    raw_evidence = safe.get("evidence")
    if isinstance(raw_evidence, list):
        for item in raw_evidence[:64]:
            if not isinstance(item, Mapping):
                continue
            kind = _text(item.get("kind"), limit=80)
            observed = _text(item.get("value"), limit=512)
            if kind and observed:
                evidence.append(
                    CanonicalEvidence(
                        protocol=_text(item.get("protocol") or item.get("method"), limit=64) or "inventory",
                        kind=kind,
                        value=observed,
                        confidence=float(item.get("confidence")) if isinstance(item.get("confidence"), (int, float)) else 0.7,
                    )
                )
    components: list[ComponentObservation] = []
    for field_name, default_type in (("components", "application"), ("software", "application"), ("packages", "operating-system-package")):
        entries = safe.get(field_name)
        if not isinstance(entries, list):
            continue
        for entry in entries[:2_000]:
            if isinstance(entry, str):
                entry = {"name": entry}
            if isinstance(entry, Mapping):
                normalized = _component(entry, default_type=default_type)
                if normalized is not None:
                    components.append(normalized)
    return CanonicalAsset(
        asset_id=asset_id,
        hostname=hostname,
        primary_ip=primary_ip,
        mac=mac,
        os=_text(safe.get("os") or platform_info.get("os"), limit=160),
        platform=_text(safe.get("platform") or platform_info.get("platform"), limit=160),
        category=_text(safe.get("category"), limit=80),
        evidence=tuple(evidence),
        components=tuple(components),
        component_inventory_complete=bool(safe.get("component_inventory_complete")),
        metadata=safe,
    )


def _envelope(
    *,
    route_name: str,
    site_id: str,
    source_identity: str,
    source_type: str,
    adapter_type: str,
    authentication_class: str,
    source_authority: str,
    trust_rank: int,
    compatibility_status: str,
    observed_at: datetime,
    ingested_at: datetime,
    inventory_mode: str,
    idempotency_key: str,
    payload_digest: str,
    original_identifier: str | None,
    assets: Sequence[CanonicalAsset],
    limitations: Sequence[str] = (),
    provenance: Mapping[str, str] | None = None,
    credential_id: str | None = None,
    bound_identity_id: str | None = None,
    legacy_submission: dict[str, Any] | None = None,
) -> CanonicalInventoryEnvelope:
    source = _source_id(
        site_id=site_id,
        adapter=adapter_type,
        auth_class=authentication_class,
        identity=source_identity,
    )
    return CanonicalInventoryEnvelope(
        schema_version=CANONICAL_SCHEMA_VERSION,
        route_name=route_name,
        site_id=site_id,
        source_id=source,
        source_identity=source_identity,
        source_type=source_type,
        adapter_type=adapter_type,
        authentication_class=authentication_class,
        source_authority=source_authority,
        trust_rank=trust_rank,
        compatibility_status=compatibility_status,
        observed_at=observed_at,
        ingested_at=ingested_at,
        inventory_mode=inventory_mode,
        idempotency_key=idempotency_key,
        canonical_collection_id=_collection_id(
            source_id=source,
            adapter=adapter_type,
            idempotency_key=idempotency_key,
        ),
        payload_sha256=payload_digest,
        original_identifier=original_identifier,
        assets=tuple(assets),
        collection_limitations=tuple(limitations),
        provenance=dict(provenance or {}),
        credential_id=credential_id,
        bound_identity_id=bound_identity_id,
        legacy_submission=legacy_submission,
    )


def endpoint_envelope(*, payload: Any, context: Any, received_at: datetime) -> CanonicalInventoryEnvelope:
    client = payload.model_dump(mode="json", exclude_none=True)
    assets: list[CanonicalAsset] = []
    for index, raw in enumerate(client["assets"]):
        interfaces = raw.pop("interfaces", [])
        raw["primary_interfaces"] = interfaces
        raw["ip_addresses"] = [address for interface in interfaces for address in interface.get("ip_addresses", [])]
        raw["mac_addresses"] = [
            {"address": interface["mac_address"]}
            for interface in interfaces
            if interface.get("mac_address")
        ]
        raw["component_inventory_complete"] = payload.inventory_mode == "complete"
        assets.append(_asset_from_mapping(raw, index=index))
    return _envelope(
        route_name="/api/v1/agents/inventory",
        site_id=str(context.site_id),
        source_identity=str(context.agent_id),
        source_type="endpoint-agent",
        adapter_type="endpoint-agent",
        authentication_class="bound-credential",
        source_authority="authenticated-endpoint",
        trust_rank=90,
        compatibility_status="canonical",
        observed_at=payload.observed_at,
        ingested_at=received_at,
        inventory_mode=payload.inventory_mode,
        idempotency_key=payload.inventory_batch_id,
        payload_digest=_digest(payload.model_dump(mode="json", exclude_none=True)),
        original_identifier=payload.inventory_batch_id,
        assets=assets,
        limitations=payload.collection_limitations,
        provenance={
            key: value
            for key, value in {
                "agent_version": payload.agent_version,
                "architecture": payload.architecture,
                "deployment_id": context.deployment_id,
                "platform": payload.platform,
            }.items()
            if value
        },
        credential_id=str(context.credential_id),
        bound_identity_id=str(context.agent_id),
    )


def sensor_envelope(*, payload: Any, context: Any, received_at: datetime) -> CanonicalInventoryEnvelope:
    client = payload.model_dump(mode="json")
    bound = context.mode == "bound-sensor"
    site_id = str(context.site_id) if bound else payload.site_id
    claimed_identity = payload.sensor_id
    source_identity = (
        str(context.sensor_id)
        if bound
        else f"transitional_{hashlib.sha256((site_id + chr(0) + claimed_identity).encode()).hexdigest()[:32]}"
    )
    assets = [_asset_from_mapping(item, index=index) for index, item in enumerate(client["assets"])]
    return _envelope(
        route_name="/api/v1/observations/batches",
        site_id=site_id,
        source_identity=source_identity,
        source_type="passive-sensor" if bound else "transitional",
        adapter_type="passive-sensor",
        authentication_class="bound-credential" if bound else "development-shared",
        source_authority="authenticated-passive-sensor" if bound else "untrusted-transitional",
        trust_rank=75 if bound else 10,
        compatibility_status="canonical" if bound else "deprecated",
        observed_at=payload.observed_at,
        ingested_at=received_at,
        inventory_mode="passive" if bound else "transitional",
        idempotency_key=payload.observation_batch_id,
        payload_digest=_digest(client),
        original_identifier=payload.observation_batch_id,
        assets=assets,
        limitations=(() if bound else ("development-shared sensor identity is untrusted",)),
        provenance={
            "claimed_sensor_id": claimed_identity,
            "sensor_name": payload.sensor_name,
            "sensor_type": payload.sensor_type,
            **({"sensor_version": payload.sensor_version} if payload.sensor_version else {}),
        },
        credential_id=str(context.credential_id) if bound else None,
        bound_identity_id=str(context.sensor_id) if bound else None,
    )


def transitional_envelope(*, payload: Mapping[str, Any], received_at: datetime) -> CanonicalInventoryEnvelope:
    safe = _bounded_json(payload)
    if not isinstance(safe, dict):
        raise CanonicalIngestionRejected("local inventory payload must be an object")
    site_id = _text(safe.get("site_id"), limit=128)
    if not site_id or not SITE_PATTERN.fullmatch(site_id):
        raise CanonicalIngestionRejected("local inventory site_id is invalid")
    raw_assets = safe.get("assets") or []
    if not isinstance(raw_assets, list) or len(raw_assets) > MAX_CANONICAL_ASSETS:
        raise CanonicalIngestionRejected("local inventory asset limit exceeded")
    assets = [_asset_from_mapping(item, index=index) for index, item in enumerate(raw_assets) if isinstance(item, Mapping)]
    observed = safe.get("observed_at") or safe.get("collected_at")
    try:
        parsed = datetime.fromisoformat(str(observed).replace("Z", "+00:00")) if observed else received_at
    except ValueError:
        parsed = received_at
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed > received_at + MAX_FUTURE_SKEW:
        parsed = received_at
    digest = _digest(safe)
    supplied_identifier = _text(safe.get("observation_batch_id"), limit=160)
    source_identity = f"transitional_{hashlib.sha256(site_id.encode()).hexdigest()[:32]}"
    return _envelope(
        route_name="/api/v1/collections/local-inventory",
        site_id=site_id,
        source_identity=source_identity,
        source_type="transitional",
        adapter_type="transitional-local",
        authentication_class="unauthenticated",
        source_authority="untrusted-transitional",
        trust_rank=10,
        compatibility_status="deprecated",
        observed_at=parsed,
        ingested_at=received_at,
        inventory_mode="transitional",
        idempotency_key=supplied_identifier or f"digest-{digest}",
        payload_digest=digest,
        original_identifier=supplied_identifier,
        assets=assets,
        limitations=("unauthenticated compatibility input", "not authoritative evidence"),
        provenance={"legacy_schema_version": _text(safe.get("schema_version"), limit=80) or "unknown"},
    )


def legacy_collector_envelope(
    *,
    payload: Any,
    received_at: datetime,
    authentication_class: Literal["legacy-shared", "unauthenticated"],
) -> CanonicalInventoryEnvelope:
    known = payload.model_dump(mode="json", exclude_none=True)
    known = {key: known[key] for key in (
        "schema_version", "collector", "collector_guid", "collector_id", "collector_name",
        "collector_version", "mode", "collected_at", "platform", "deployment", "labels",
        "supported_capabilities", "enabled_capabilities", "device", "network", "software",
    ) if key in known}
    safe = _bounded_json(known)
    assert isinstance(safe, dict)
    deployment = safe.get("deployment") if isinstance(safe.get("deployment"), dict) else {}
    site_candidate = _text(deployment.get("site_id") or deployment.get("deployment_id"), limit=128)
    site_id = site_candidate if site_candidate and SITE_PATTERN.fullmatch(site_candidate) else "legacy-collector-default"
    collector_value = safe.get("collector")
    collector_object = collector_value if isinstance(collector_value, dict) else {}
    identity_claim = _text(
        safe.get("collector_guid") or safe.get("collector_id") or collector_object.get("id") or collector_value,
        limit=160,
    ) or "anonymous-collector"
    source_identity = f"legacy_{hashlib.sha256(identity_claim.encode()).hexdigest()[:32]}"
    assets: list[CanonicalAsset] = []
    device = safe.get("device")
    software = safe.get("software") if isinstance(safe.get("software"), list) else []
    if isinstance(device, Mapping) or software:
        device_value = dict(device) if isinstance(device, Mapping) else {}
        device_value.setdefault("asset_id", _text(device_value.get("hostname"), limit=160) or source_identity)
        device_value["software"] = software
        assets.append(_asset_from_mapping(device_value, index=0))
    network = safe.get("network")
    network_items = list(network.values()) if isinstance(network, Mapping) else network if isinstance(network, list) else []
    if len(network_items) > MAX_CANONICAL_ASSETS - len(assets):
        raise CanonicalIngestionRejected("legacy collector network asset limit exceeded")
    for entry in network_items:
        if isinstance(entry, Mapping):
            mapped = {
                "asset_id": entry.get("asset_id") or entry.get("mac_address") or entry.get("mac") or entry.get("ip_address") or entry.get("ip"),
                "primary_ip": entry.get("ip_address") or entry.get("ip"),
                "mac": entry.get("mac_address") or entry.get("mac"),
                **dict(entry),
            }
            assets.append(_asset_from_mapping(mapped, index=len(assets)))
    observed = payload.collected_at or received_at
    if observed.tzinfo is None or observed.utcoffset() is None or observed > received_at + MAX_FUTURE_SKEW:
        observed = received_at
    digest = _digest(safe)
    collector_id = _text(safe.get("collector_id") or collector_object.get("id") or collector_value, limit=160)
    collector_name = _text(safe.get("collector_name") or collector_object.get("name"), limit=160)
    legacy_submission = {
        "collector_guid": _text(safe.get("collector_guid"), limit=160),
        "collector_id": collector_id,
        "collector_name": collector_name,
        "collector_version": _text(safe.get("collector_version"), limit=80),
        "mode": _text(safe.get("mode"), limit=40),
        "schema_version": _text(safe.get("schema_version"), limit=80),
        "collected_at": observed.isoformat(),
        "device_count": 1 if isinstance(device, Mapping) else 0,
        "network_observation_count": len(network_items),
        "software_count": len(software),
        "payload": safe,
        "deployment": deployment,
        "labels": safe.get("labels") if isinstance(safe.get("labels"), dict) else {},
        "supported_capabilities": safe.get("supported_capabilities") if isinstance(safe.get("supported_capabilities"), list) else [],
        "enabled_capabilities": safe.get("enabled_capabilities") if isinstance(safe.get("enabled_capabilities"), list) else [],
    }
    return _envelope(
        route_name="/api/v1/collectors/inventory",
        site_id=site_id,
        source_identity=source_identity,
        source_type="legacy-collector",
        adapter_type="python-collector",
        authentication_class=authentication_class,
        source_authority="legacy-collector",
        trust_rank=25,
        compatibility_status="compatibility",
        observed_at=observed,
        ingested_at=received_at,
        inventory_mode="legacy",
        idempotency_key=f"digest-{digest}",
        payload_digest=digest,
        original_identifier=identity_claim,
        assets=assets,
        limitations=("legacy shared identity", "reported facts are lower trust"),
        provenance={
            "collector_id": collector_id or "unknown",
            "collector_name": collector_name or "unknown",
        },
        legacy_submission=legacy_submission,
    )


def ingest(envelope: CanonicalInventoryEnvelope) -> CanonicalIngestionAcknowledgement:
    """Persist one canonical envelope through the sole inventory write service."""

    from .canonical_ingestion_store import persist_canonical_inventory

    result = persist_canonical_inventory(envelope=envelope)
    warnings = {
        "authenticated-endpoint": (
            "authenticated identity does not prove every reported fact",
        ),
        "authenticated-passive-sensor": (
            "passive observations do not prove endpoint ownership",
        ),
        "legacy-collector": (
            "legacy collector compatibility input is lower trust",
        ),
        "untrusted-transitional": (
            "transitional compatibility input is untrusted and deprecated",
        ),
    }[envelope.source_authority]
    return CanonicalIngestionAcknowledgement(
        status="duplicate" if result["duplicate"] else "accepted",
        canonical_collection_id=envelope.canonical_collection_id,
        canonical_asset_ids=tuple(result.get("asset_ids") or ()),
        replay_state="identical-replay" if result["duplicate"] else "new",
        evidence_count=int(result["evidence_count"]),
        component_count=int(result["component_count"]),
        evaluation_state=str(result["evaluation_state"]),
        warnings=warnings,
        adapter_type=envelope.adapter_type,
        compatibility_status=envelope.compatibility_status,
        source_authority=envelope.source_authority,
        compatibility_collection_id=int(result["compatibility_collection_id"]),
        legacy_submission_id=result.get("legacy_submission_id"),
        endpoint_storage_id=result.get("endpoint_storage_id"),
        received_at=envelope.ingested_at,
        observed_asset_count=len(envelope.assets),
        normalized_asset_count=int(result["normalized_asset_count"]),
    )
