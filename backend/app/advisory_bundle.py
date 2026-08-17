"""Signed OpenAssetWatch advisory-bundle verification and preview logic."""

from __future__ import annotations

import base64
import hashlib
import json
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .advisory_catalog import AdvisoryCatalog, CatalogValidationError, parse_catalog_bytes
from .advisory_feed_registry import FeedSource, PublisherKey, RegistryError, ReviewedFeedRegistry


MANIFEST_SCHEMA_VERSION = "oaw.advisory-bundle.manifest.v1"
SUPPORTED_CATALOG_FORMAT_VERSION = 1
MAX_MANIFEST_FUTURE_SKEW = timedelta(minutes=5)
MAX_MANIFEST_VALIDITY = timedelta(days=366)
MAX_PREVIEW_IDENTIFIERS = 100


class BundleVerificationError(ValueError):
    """A bounded, API-safe signed-bundle rejection."""

    def __init__(self, code: str, summary: str) -> None:
        super().__init__(summary)
        self.code = code[:80]
        self.summary = summary[:240]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class UpstreamProvenance(_StrictModel):
    source_name: str = Field(..., min_length=1, max_length=120)
    source_version: str = Field(..., min_length=1, max_length=80)
    dataset_id: str = Field(..., min_length=1, max_length=160)
    retrieved_at: datetime

    @field_validator("retrieved_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("provenance retrieval time requires a timezone")
        return value.astimezone(timezone.utc)


class AdvisoryBundleManifest(_StrictModel):
    schema_id: Literal["oaw.advisory-bundle.manifest.v1"]
    schema_version: Literal[1]
    source_id: str = Field(..., min_length=3, max_length=64)
    publisher_key_id: str = Field(..., min_length=3, max_length=96)
    catalog_version: str = Field(..., min_length=1, max_length=120)
    catalog_sequence: int = Field(..., ge=1, le=9_223_372_036_854_775_807)
    created_at: datetime
    expires_at: datetime
    payload_name: str = Field(..., pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$")
    payload_media_type: Literal[
        "application/vnd.openassetwatch.advisory-catalog+json",
        "application/vnd.openassetwatch.advisory-catalog+gzip",
    ]
    payload_compression: Literal["none", "gzip"]
    payload_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    compressed_bytes: int = Field(..., ge=1)
    uncompressed_bytes: int = Field(..., ge=1)
    advisory_count: int = Field(..., ge=0)
    alias_count: int = Field(..., ge=0)
    reference_count: int = Field(..., ge=0)
    license_identifier: str = Field(..., min_length=1, max_length=120)
    attribution: str = Field(..., min_length=1, max_length=500)
    upstream_provenance: UpstreamProvenance
    adapter_version: str = Field(..., min_length=1, max_length=40)
    minimum_supported_catalog_version: int = Field(..., ge=1, le=1_000_000)

    @field_validator("created_at", "expires_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("manifest timestamps require a timezone")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "AdvisoryBundleManifest":
        if self.expires_at <= self.created_at:
            raise ValueError("manifest expiry must follow creation")
        if self.expires_at - self.created_at > MAX_MANIFEST_VALIDITY:
            raise ValueError("manifest validity interval exceeds one year")
        expected_media = (
            "application/vnd.openassetwatch.advisory-catalog+gzip"
            if self.payload_compression == "gzip"
            else "application/vnd.openassetwatch.advisory-catalog+json"
        )
        if self.payload_media_type != expected_media:
            raise ValueError("payload media type and compression disagree")
        if self.payload_compression == "none" and self.compressed_bytes != self.uncompressed_bytes:
            raise ValueError("plain payload byte counts must agree")
        return self


@dataclass(frozen=True)
class VerifiedBundle:
    manifest: AdvisoryBundleManifest
    manifest_bytes: bytes
    manifest_digest: str
    signature: bytes
    publisher: PublisherKey
    payload_bytes: bytes
    payload_digest: str
    catalog_bytes: bytes
    catalog: AdvisoryCatalog
    catalog_checksum: str


@dataclass(frozen=True)
class VerifiedManifest:
    manifest: AdvisoryBundleManifest
    manifest_bytes: bytes
    manifest_digest: str
    signature: bytes
    publisher: PublisherKey


@dataclass(frozen=True)
class CatalogPreview:
    source_id: str
    publisher_key_id: str
    signature_status: str
    catalog_version: str
    catalog_sequence: int
    created_at: datetime
    expires_at: datetime
    license_identifier: str
    license_status: str
    attribution_status: str
    payload_digest: str
    total_advisories: int
    added_advisories: int
    updated_advisories: int
    withdrawn_advisories: int
    aliases_added: int
    aliases_removed: int
    affected_ecosystems: tuple[str, ...]
    known_exploited_count: int
    incompatible_records: int
    rejected_records: int
    validation_warnings: tuple[str, ...]
    changed_advisory_ids: tuple[str, ...]
    withdrawn_advisory_ids: tuple[str, ...]
    expected_match_impact: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "publisher_key_id": self.publisher_key_id,
            "signature_status": self.signature_status,
            "catalog_version": self.catalog_version,
            "catalog_sequence": self.catalog_sequence,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "license_identifier": self.license_identifier,
            "license_status": self.license_status,
            "attribution_status": self.attribution_status,
            "payload_digest": self.payload_digest,
            "total_advisories": self.total_advisories,
            "added_advisories": self.added_advisories,
            "updated_advisories": self.updated_advisories,
            "withdrawn_advisories": self.withdrawn_advisories,
            "aliases_added": self.aliases_added,
            "aliases_removed": self.aliases_removed,
            "affected_ecosystems": list(self.affected_ecosystems),
            "known_exploited_count": self.known_exploited_count,
            "incompatible_records": self.incompatible_records,
            "rejected_records": self.rejected_records,
            "validation_warnings": list(self.validation_warnings),
            "changed_advisory_ids": list(self.changed_advisory_ids),
            "withdrawn_advisory_ids": list(self.withdrawn_advisory_ids),
            "expected_match_impact": dict(self.expected_match_impact),
        }


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BundleVerificationError("manifest-duplicate-key", "signed manifest JSON contains a duplicate key")
        result[key] = value
    return result


def parse_manifest_bytes(data: bytes, *, maximum_bytes: int) -> AdvisoryBundleManifest:
    if not data or len(data) > maximum_bytes:
        raise BundleVerificationError("manifest-size-invalid", "signed manifest size is outside the configured limit")
    if data.startswith(b"\xef\xbb\xbf"):
        raise BundleVerificationError("manifest-encoding-invalid", "signed manifest must be UTF-8 without a byte-order mark")
    try:
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except BundleVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleVerificationError("manifest-invalid-json", "signed manifest must be valid UTF-8 JSON") from exc
    if not isinstance(raw, dict):
        raise BundleVerificationError("manifest-root-invalid", "signed manifest root must be an object")
    try:
        return AdvisoryBundleManifest.model_validate(raw)
    except ValidationError as exc:
        raise BundleVerificationError("manifest-schema-invalid", "signed manifest violates the supported schema") from exc


def decode_signature(data: bytes, *, maximum_bytes: int) -> bytes:
    if not data or len(data) > maximum_bytes:
        raise BundleVerificationError("signature-size-invalid", "detached signature size is outside the configured limit")
    encoded = data[:-2] if data.endswith(b"\r\n") else data[:-1] if data.endswith(b"\n") else data
    if not encoded or any(character in b" \t\r\n" for character in encoded):
        raise BundleVerificationError("signature-malformed", "detached signature must use canonical base64")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise BundleVerificationError("signature-malformed", "detached signature must use canonical base64") from exc
    if len(signature) != 64 or base64.b64encode(signature) != encoded:
        raise BundleVerificationError("signature-length-invalid", "Ed25519 signature must be exactly 64 bytes")
    return signature


def _validate_manifest_policy(
    manifest: AdvisoryBundleManifest,
    *,
    source: FeedSource,
    publisher: PublisherKey,
    now: datetime,
) -> None:
    if manifest.source_id != source.source_id:
        raise BundleVerificationError("source-mismatch", "signed manifest source does not match the reviewed source")
    if manifest.publisher_key_id not in source.trusted_publisher_key_ids:
        raise BundleVerificationError("publisher-substitution", "signed manifest publisher key is not approved for this source")
    if publisher.status == "revoked":
        raise BundleVerificationError("publisher-key-revoked", "publisher key has been revoked")
    if publisher.status != "active":
        raise BundleVerificationError("publisher-key-retired", "retired publisher keys cannot sign new feed bundles")
    if publisher.not_before and now < publisher.not_before:
        raise BundleVerificationError("publisher-key-not-yet-valid", "publisher key is not yet valid")
    if publisher.not_after and now >= publisher.not_after:
        raise BundleVerificationError("publisher-key-expired", "publisher key has expired")
    if publisher.not_before and manifest.created_at < publisher.not_before:
        raise BundleVerificationError("publisher-key-time-invalid", "manifest predates publisher key validity")
    if publisher.not_after and manifest.created_at >= publisher.not_after:
        raise BundleVerificationError("publisher-key-time-invalid", "manifest was created after publisher key expiry")
    if manifest.created_at > now + MAX_MANIFEST_FUTURE_SKEW:
        raise BundleVerificationError("manifest-future-dated", "signed manifest creation time is too far in the future")
    if (
        manifest.upstream_provenance.retrieved_at > now + MAX_MANIFEST_FUTURE_SKEW
        or manifest.upstream_provenance.retrieved_at > manifest.created_at + MAX_MANIFEST_FUTURE_SKEW
    ):
        raise BundleVerificationError("provenance-future-dated", "signed upstream retrieval time is inconsistent")
    if manifest.expires_at <= now:
        raise BundleVerificationError("manifest-expired", "signed manifest has expired")
    if manifest.payload_name != source.expected_payload_name:
        raise BundleVerificationError("payload-name-mismatch", "signed payload name does not match reviewed source configuration")
    if manifest.adapter_version != source.adapter_version:
        raise BundleVerificationError("adapter-version-mismatch", "signed adapter version is not supported for this source")
    if manifest.minimum_supported_catalog_version > SUPPORTED_CATALOG_FORMAT_VERSION:
        raise BundleVerificationError("catalog-version-incompatible", "bundle requires a newer OpenAssetWatch catalog format")
    if manifest.license_identifier not in source.accepted_licenses:
        raise BundleVerificationError("license-mismatch", "signed license is not approved for this source")
    if manifest.attribution != source.required_attribution:
        raise BundleVerificationError("attribution-missing", "signed attribution does not match the reviewed source policy")
    if manifest.compressed_bytes > source.limits.maximum_compressed_bytes:
        raise BundleVerificationError("payload-claim-too-large", "signed compressed byte count exceeds source limits")
    if manifest.uncompressed_bytes > source.limits.maximum_uncompressed_bytes:
        raise BundleVerificationError("payload-claim-too-large", "signed uncompressed byte count exceeds source limits")
    if manifest.advisory_count > source.limits.maximum_advisories:
        raise BundleVerificationError("advisory-count-too-large", "signed advisory count exceeds source limits")
    if manifest.alias_count > source.limits.maximum_aliases:
        raise BundleVerificationError("alias-count-too-large", "signed alias count exceeds source limits")
    if manifest.reference_count > source.limits.maximum_references:
        raise BundleVerificationError("reference-count-too-large", "signed reference count exceeds source limits")


def _decompress_gzip(data: bytes, *, maximum_bytes: int, maximum_ratio: int) -> bytes:
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    output = bytearray()
    pending = data
    try:
        while pending:
            remaining = maximum_bytes - len(output) + 1
            chunk = decompressor.decompress(pending, remaining)
            output.extend(chunk)
            if len(output) > maximum_bytes:
                raise BundleVerificationError("payload-decompressed-too-large", "gzip payload exceeds the uncompressed-byte limit")
            pending = decompressor.unconsumed_tail
            if pending and not chunk and remaining > 0:
                raise BundleVerificationError("payload-gzip-invalid", "gzip payload could not be consumed safely")
        output.extend(decompressor.flush(maximum_bytes - len(output) + 1))
    except zlib.error as exc:
        raise BundleVerificationError("payload-gzip-invalid", "payload is not a valid single gzip stream") from exc
    if len(output) > maximum_bytes:
        raise BundleVerificationError("payload-decompressed-too-large", "gzip payload exceeds the uncompressed-byte limit")
    if not decompressor.eof or decompressor.unused_data or decompressor.unconsumed_tail:
        raise BundleVerificationError("payload-gzip-trailing-data", "concatenated or trailing gzip data is not supported")
    if len(output) > max(len(data), 1) * maximum_ratio:
        raise BundleVerificationError("payload-expansion-ratio", "gzip payload exceeds the configured expansion ratio")
    return bytes(output)


def _verify_catalog_metadata(
    catalog: AdvisoryCatalog,
    manifest: AdvisoryBundleManifest,
    source: FeedSource,
) -> None:
    aliases = sum(len(record.aliases) for record in catalog.advisories)
    references = sum(len(record.references) for record in catalog.advisories)
    if catalog.catalog_version != manifest.catalog_version:
        raise BundleVerificationError("catalog-version-mismatch", "catalog version does not match the signed manifest")
    if catalog.source.name != source.expected_catalog_source:
        raise BundleVerificationError("catalog-source-mismatch", "catalog source name does not match reviewed configuration")
    if catalog.source.name != manifest.upstream_provenance.source_name:
        raise BundleVerificationError("provenance-source-mismatch", "catalog source does not match signed provenance")
    if catalog.source.version != manifest.upstream_provenance.source_version:
        raise BundleVerificationError("provenance-version-mismatch", "catalog source version does not match signed provenance")
    if catalog.source.license != manifest.license_identifier:
        raise BundleVerificationError("license-mismatch", "catalog license does not match the signed manifest")
    if len(catalog.advisories) != manifest.advisory_count:
        raise BundleVerificationError("advisory-count-mismatch", "catalog advisory count does not match the signed manifest")
    if aliases != manifest.alias_count:
        raise BundleVerificationError("alias-count-mismatch", "catalog alias count does not match the signed manifest")
    if references != manifest.reference_count:
        raise BundleVerificationError("reference-count-mismatch", "catalog reference count does not match the signed manifest")


def verify_bundle(
    *,
    manifest_bytes: bytes,
    signature_bytes: bytes,
    payload_bytes: bytes,
    source: FeedSource,
    registry: ReviewedFeedRegistry,
    now: datetime | None = None,
) -> VerifiedBundle:
    """Verify exact manifest bytes and every signed payload invariant."""

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    verified_manifest = verify_manifest(
        manifest_bytes=manifest_bytes,
        signature_bytes=signature_bytes,
        source=source,
        registry=registry,
        now=current,
    )
    manifest = verified_manifest.manifest
    publisher = verified_manifest.publisher
    signature = verified_manifest.signature
    manifest_digest = verified_manifest.manifest_digest
    if len(payload_bytes) != manifest.compressed_bytes:
        raise BundleVerificationError("compressed-size-mismatch", "payload byte count does not match the signed manifest")
    digest = hashlib.sha256(payload_bytes).hexdigest()
    if digest != manifest.payload_sha256:
        raise BundleVerificationError("payload-digest-mismatch", "payload digest does not match the signed manifest")
    decoded_catalog_bytes = (
        _decompress_gzip(
            payload_bytes,
            maximum_bytes=source.limits.maximum_uncompressed_bytes,
            maximum_ratio=source.limits.maximum_expansion_ratio,
        )
        if manifest.payload_compression == "gzip"
        else payload_bytes
    )
    if len(decoded_catalog_bytes) != manifest.uncompressed_bytes:
        raise BundleVerificationError("uncompressed-size-mismatch", "uncompressed byte count does not match the signed manifest")
    try:
        catalog, checksum = parse_catalog_bytes(decoded_catalog_bytes)
    except CatalogValidationError as exc:
        raise BundleVerificationError("catalog-invalid", "signed payload is not a valid advisory catalog") from exc
    _verify_catalog_metadata(catalog, manifest, source)
    canonical_catalog_bytes = json.dumps(
        catalog.model_dump(mode="json"),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if hashlib.sha256(canonical_catalog_bytes).hexdigest() != checksum:
        raise BundleVerificationError("catalog-canonicalization-failed", "catalog canonical digest could not be verified")
    return VerifiedBundle(
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_digest=manifest_digest,
        signature=signature,
        publisher=publisher,
        payload_bytes=payload_bytes,
        payload_digest=digest,
        catalog_bytes=canonical_catalog_bytes,
        catalog=catalog,
        catalog_checksum=checksum,
    )


def verify_manifest(
    *,
    manifest_bytes: bytes,
    signature_bytes: bytes,
    source: FeedSource,
    registry: ReviewedFeedRegistry,
    now: datetime | None = None,
) -> VerifiedManifest:
    """Authenticate exact manifest bytes before a payload is downloaded."""

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    manifest = parse_manifest_bytes(manifest_bytes, maximum_bytes=source.limits.maximum_manifest_bytes)
    try:
        publisher = registry.publisher_key(manifest.publisher_key_id)
    except RegistryError as exc:
        raise BundleVerificationError(exc.code, exc.summary) from exc
    _validate_manifest_policy(manifest, source=source, publisher=publisher, now=current)
    signature = decode_signature(signature_bytes, maximum_bytes=source.limits.maximum_signature_bytes)
    try:
        Ed25519PublicKey.from_public_bytes(publisher.public_key_bytes()).verify(signature, manifest_bytes)
    except (InvalidSignature, ValueError) as exc:
        raise BundleVerificationError("signature-invalid", "detached manifest signature is invalid") from exc
    return VerifiedManifest(
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_digest=hashlib.sha256(manifest_bytes).hexdigest(),
        signature=signature,
        publisher=publisher,
    )


def _record_digest(record: Any) -> str:
    encoded = json.dumps(
        record.model_dump(mode="json"),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def preview_bundle(
    bundle: VerifiedBundle,
    *,
    previous_catalog: AdvisoryCatalog | None,
    now: datetime | None = None,
) -> CatalogPreview:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    previous_records = {
        record.id.casefold(): record for record in (previous_catalog.advisories if previous_catalog else [])
    }
    new_records = {record.id.casefold(): record for record in bundle.catalog.advisories}
    added = sorted(set(new_records) - set(previous_records))
    updated = sorted(
        key
        for key in set(new_records) & set(previous_records)
        if _record_digest(new_records[key]) != _record_digest(previous_records[key])
    )
    removed = sorted(set(previous_records) - set(new_records))
    explicit_withdrawals = sorted(
        key
        for key, record in new_records.items()
        if record.withdrawn_at is not None
        and (key not in previous_records or previous_records[key].withdrawn_at is None)
    )
    previous_aliases = {
        alias for record in previous_records.values() for alias in record.aliases
    }
    current_aliases = {alias for record in new_records.values() for alias in record.aliases}
    ecosystems = sorted(
        {affected.ecosystem for record in new_records.values() for affected in record.affected}
    )
    changed = sorted(set(added) | set(updated) | set(removed) | set(explicit_withdrawals))
    warnings: list[str] = []
    if bundle.manifest.expires_at - current <= timedelta(days=7):
        warnings.append("manifest-expires-within-seven-days")
    return CatalogPreview(
        source_id=bundle.manifest.source_id,
        publisher_key_id=bundle.manifest.publisher_key_id,
        signature_status="verified",
        catalog_version=bundle.manifest.catalog_version,
        catalog_sequence=bundle.manifest.catalog_sequence,
        created_at=bundle.manifest.created_at,
        expires_at=bundle.manifest.expires_at,
        license_identifier=bundle.manifest.license_identifier,
        license_status="approved",
        attribution_status="present",
        payload_digest=bundle.payload_digest,
        total_advisories=len(new_records),
        added_advisories=len(added),
        updated_advisories=len(updated),
        withdrawn_advisories=len(set(removed) | set(explicit_withdrawals)),
        aliases_added=len(current_aliases - previous_aliases),
        aliases_removed=len(previous_aliases - current_aliases),
        affected_ecosystems=tuple(ecosystems),
        known_exploited_count=sum(record.known_exploited for record in new_records.values()),
        incompatible_records=0,
        rejected_records=0,
        validation_warnings=tuple(warnings),
        changed_advisory_ids=tuple(changed[:MAX_PREVIEW_IDENTIFIERS]),
        withdrawn_advisory_ids=tuple(sorted(set(removed) | set(explicit_withdrawals))[:MAX_PREVIEW_IDENTIFIERS]),
        expected_match_impact={
            "mode": "bounded-advisory-diff",
            "exact": False,
            "changed_advisory_count": len(changed),
            "identifier_list_truncated": len(changed) > MAX_PREVIEW_IDENTIFIERS,
        },
    )
