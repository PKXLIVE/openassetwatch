"""Reviewed advisory feed-source and publisher-key registries.

The files loaded here are application configuration, not feed-controlled data.
They are deliberately rooted next to the backend package and cannot be
overridden by a synchronization request.
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


REGISTRY_SCHEMA_VERSION = "oaw.advisory-feed-registry.v1"
KEYRING_SCHEMA_VERSION = "oaw.advisory-publisher-keyring.v1"
MAX_REGISTRY_BYTES = 256 << 10
MAX_FEED_PAYLOAD_BYTES = 8 << 20
MAX_FEED_ADVISORIES = 20_000
MAX_FEED_ALIASES = 640_000
MAX_FEED_REFERENCES = 320_000
SOURCE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,95}$")


class RegistryError(ValueError):
    """Raised when reviewed registry data or a source selection is invalid."""

    def __init__(self, code: str, summary: str) -> None:
        super().__init__(summary)
        self.code = code
        self.summary = summary[:240]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class FeedEndpoint(_StrictModel):
    host: str = Field(..., min_length=1, max_length=253)
    manifest_path: str = Field(..., min_length=1, max_length=500)
    signature_path: str = Field(..., min_length=1, max_length=500)
    payload_path: str = Field(..., min_length=1, max_length=500)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        if value != value.casefold() or not value.isascii():
            raise ValueError("feed host must be lower-case ASCII")
        parsed = urlsplit(f"https://{value}")
        if parsed.hostname != value or parsed.port is not None:
            raise ValueError("feed host must be an exact DNS hostname without a port")
        if value.startswith(".") or value.endswith(".") or "*" in value:
            raise ValueError("feed host must not be a wildcard or relative name")
        return value

    @field_validator("manifest_path", "signature_path", "payload_path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            not value.isascii()
            or any(ord(character) < 0x21 or ord(character) == 0x7F for character in value)
            or not value.startswith("/")
            or value.startswith("//")
            or parsed.scheme
            or parsed.netloc
            or parsed.query
            or parsed.fragment
            or "\\" in value
            or "%" in value
            or any(segment in {".", ".."} for segment in value.split("/"))
        ):
            raise ValueError("feed paths must be exact absolute URL paths")
        return value


class FeedLimits(_StrictModel):
    maximum_manifest_bytes: int = Field(default=64 << 10, ge=1, le=64 << 10)
    maximum_signature_bytes: int = Field(default=256, ge=64, le=4096)
    maximum_compressed_bytes: int = Field(..., ge=1, le=MAX_FEED_PAYLOAD_BYTES)
    maximum_uncompressed_bytes: int = Field(..., ge=1, le=MAX_FEED_PAYLOAD_BYTES)
    maximum_expansion_ratio: int = Field(default=20, ge=1, le=100)
    maximum_advisories: int = Field(..., ge=1, le=MAX_FEED_ADVISORIES)
    maximum_aliases: int = Field(..., ge=0, le=MAX_FEED_ALIASES)
    maximum_references: int = Field(..., ge=0, le=MAX_FEED_REFERENCES)
    maximum_response_header_bytes: int = Field(default=16 << 10, ge=1024, le=64 << 10)
    connection_timeout_seconds: float = Field(default=5.0, ge=0.5, le=30.0)
    read_timeout_seconds: float = Field(default=10.0, ge=0.5, le=60.0)
    total_timeout_seconds: float = Field(default=30.0, ge=1.0, le=300.0)
    minimum_sync_interval_seconds: int = Field(default=60, ge=0, le=86_400)
    control_action_cooldown_seconds: int = Field(default=30, ge=0, le=3600)

    @model_validator(mode="after")
    def validate_payload_limits(self) -> "FeedLimits":
        if self.maximum_compressed_bytes > self.maximum_uncompressed_bytes:
            raise ValueError("compressed-byte limit cannot exceed uncompressed-byte limit")
        if self.total_timeout_seconds < max(
            self.connection_timeout_seconds,
            self.read_timeout_seconds,
        ):
            raise ValueError("total timeout must cover connection and read timeouts")
        return self


class FeedSource(_StrictModel):
    source_id: str = Field(..., min_length=3, max_length=64)
    display_name: str = Field(..., min_length=1, max_length=120)
    enabled: bool
    adapter_type: Literal["oaw-catalog-v1"]
    adapter_version: str = Field(..., min_length=1, max_length=40)
    endpoint: FeedEndpoint
    expected_manifest_schema: Literal["oaw.advisory-bundle.manifest.v1"]
    expected_payload_schema: Literal["oaw.advisory-catalog.v1"]
    expected_payload_name: str = Field(..., pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$")
    expected_catalog_source: str = Field(..., min_length=1, max_length=120)
    trusted_publisher_key_ids: list[str] = Field(..., min_length=1, max_length=16)
    accepted_licenses: list[str] = Field(..., min_length=1, max_length=16)
    required_attribution: str = Field(..., min_length=1, max_length=500)
    downgrade_policy: Literal["forbid"] = "forbid"
    approval_policy: Literal["explicit-admin"] = "explicit-admin"
    expected_content_types: dict[str, list[str]]
    limits: FeedLimits
    documentation_url: str = Field(..., min_length=8, max_length=500)
    documentation_note: str = Field(..., min_length=1, max_length=500)

    @field_validator("source_id")
    @classmethod
    def validate_source_id(cls, value: str) -> str:
        if not SOURCE_ID_PATTERN.fullmatch(value):
            raise ValueError("invalid source_id")
        return value

    @field_validator("trusted_publisher_key_ids")
    @classmethod
    def validate_key_ids(cls, values: list[str]) -> list[str]:
        if any(not KEY_ID_PATTERN.fullmatch(value) for value in values):
            raise ValueError("invalid publisher key ID")
        if len(values) != len(set(values)):
            raise ValueError("duplicate publisher key ID")
        return values

    @field_validator("accepted_licenses")
    @classmethod
    def validate_licenses(cls, values: list[str]) -> list[str]:
        if any(not value or len(value) > 120 for value in values):
            raise ValueError("invalid license identifier")
        if len(values) != len(set(values)):
            raise ValueError("duplicate license identifier")
        return values

    @field_validator("expected_content_types")
    @classmethod
    def validate_content_types(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        if set(value) != {"manifest", "signature", "payload"}:
            raise ValueError("content types must cover manifest, signature, and payload")
        for types in value.values():
            if not types or len(types) > 8:
                raise ValueError("each artifact requires bounded content types")
            if any(not item or len(item) > 120 or item != item.casefold() for item in types):
                raise ValueError("content types must be lower-case media types")
        return value

    @field_validator("documentation_url")
    @classmethod
    def validate_documentation_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("source documentation URL must be credential-free HTTPS")
        return value


class FeedRegistryDocument(_StrictModel):
    schema_version: Literal["oaw.advisory-feed-registry.v1"]
    registry_version: str = Field(..., min_length=1, max_length=80)
    sources: list[FeedSource] = Field(..., max_length=64)

    @model_validator(mode="after")
    def validate_uniqueness(self) -> "FeedRegistryDocument":
        ids = [source.source_id for source in self.sources]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate advisory source ID")
        return self


class PublisherKey(_StrictModel):
    key_id: str = Field(..., min_length=3, max_length=96)
    publisher_id: str = Field(..., min_length=3, max_length=96)
    publisher_name: str = Field(..., min_length=1, max_length=120)
    algorithm: Literal["ed25519"]
    public_key_base64: str = Field(..., min_length=44, max_length=44)
    status: Literal["active", "retired", "revoked"]
    not_before: datetime | None = None
    not_after: datetime | None = None

    @field_validator("key_id")
    @classmethod
    def validate_key_id(cls, value: str) -> str:
        if not KEY_ID_PATTERN.fullmatch(value):
            raise ValueError("invalid key ID")
        return value

    @field_validator("public_key_base64")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("publisher public key must use canonical base64") from exc
        if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("publisher Ed25519 public key must be exactly 32 bytes")
        return value

    @field_validator("not_before", "not_after")
    @classmethod
    def validate_key_time(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("key validity timestamps require a timezone")
        return value

    @model_validator(mode="after")
    def validate_validity(self) -> "PublisherKey":
        if self.not_before and self.not_after and self.not_after <= self.not_before:
            raise ValueError("publisher key validity interval is empty")
        return self

    def public_key_bytes(self) -> bytes:
        return base64.b64decode(self.public_key_base64, validate=True)


class PublisherKeyringDocument(_StrictModel):
    schema_version: Literal["oaw.advisory-publisher-keyring.v1"]
    keyring_version: str = Field(..., min_length=1, max_length=80)
    keys: list[PublisherKey] = Field(..., max_length=128)

    @model_validator(mode="after")
    def validate_uniqueness(self) -> "PublisherKeyringDocument":
        ids = [key.key_id for key in self.keys]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate publisher key ID")
        return self


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError("registry-json-duplicate-key", "reviewed registry JSON contains a duplicate key")
        result[key] = value
    return result


def _load_json(path: Path) -> object:
    data = path.read_bytes()
    if len(data) > MAX_REGISTRY_BYTES:
        raise RegistryError("registry-too-large", "reviewed registry exceeds its size limit")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegistryError("registry-invalid-json", "reviewed registry must be UTF-8 JSON") from exc


class ReviewedFeedRegistry:
    """Immutable view of the source and publisher configuration in the tree."""

    def __init__(
        self,
        source_document: FeedRegistryDocument,
        keyring_document: PublisherKeyringDocument,
    ) -> None:
        self.source_document = source_document
        self.keyring_document = keyring_document
        self._sources = {source.source_id: source for source in source_document.sources}
        self._keys = {key.key_id: key for key in keyring_document.keys}
        for source in source_document.sources:
            missing = [key_id for key_id in source.trusted_publisher_key_ids if key_id not in self._keys]
            if missing:
                raise RegistryError("registry-key-missing", "reviewed source references an unknown publisher key")

    def source(self, source_id: str, *, require_enabled: bool = True) -> FeedSource:
        source = self._sources.get(source_id)
        if source is None:
            raise RegistryError("source-unknown", "advisory feed source is not configured")
        if require_enabled and not source.enabled:
            raise RegistryError("source-disabled", "advisory feed source is disabled")
        return source

    def publisher_key(self, key_id: str) -> PublisherKey:
        key = self._keys.get(key_id)
        if key is None:
            raise RegistryError("publisher-key-unknown", "publisher key is not trusted")
        return key

    def sources_public(self) -> list[dict[str, object]]:
        key_statuses = {key.key_id: key.status for key in self._keys.values()}
        return [
            {
                "source_id": source.source_id,
                "display_name": source.display_name,
                "enabled": source.enabled,
                "adapter_type": source.adapter_type,
                "adapter_version": source.adapter_version,
                "trusted_publishers": [
                    {"key_id": key_id, "status": key_statuses[key_id]}
                    for key_id in source.trusted_publisher_key_ids
                ],
                "accepted_licenses": list(source.accepted_licenses),
                "approval_policy": source.approval_policy,
                "documentation_url": source.documentation_url,
                "documentation_note": source.documentation_note,
            }
            for source in sorted(self._sources.values(), key=lambda item: item.source_id)
        ]


def load_reviewed_feed_registry(base_path: Path | None = None) -> ReviewedFeedRegistry:
    root = base_path or (Path(__file__).resolve().parents[1] / "advisory_feeds")
    try:
        sources = FeedRegistryDocument.model_validate(_load_json(root / "sources.json"))
        keyring = PublisherKeyringDocument.model_validate(_load_json(root / "publishers.json"))
    except (OSError, ValidationError) as exc:
        raise RegistryError("registry-invalid", "reviewed advisory feed registry is invalid") from exc
    return ReviewedFeedRegistry(sources, keyring)
