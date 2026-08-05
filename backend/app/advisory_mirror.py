"""Strict signed advisory-mirror index, local builder, and verification helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .advisory_bundle import (
    MAX_MANIFEST_FUTURE_SKEW,
    SUPPORTED_CATALOG_FORMAT_VERSION,
    AdvisoryBundleManifest,
    UpstreamProvenance,
    VerifiedBundle,
    decode_signature,
    parse_manifest_bytes,
    verify_bundle,
)
from .advisory_feed_registry import FeedSource, RegistryError, ReviewedFeedRegistry
from .advisory_transport import (
    AdvisoryDownloader,
    StagingSecurityError,
    _fsync_directory,
    _validate_parent_chain,
    _valid_mirror_relative_path,
    read_single_link_file,
)


MIRROR_INDEX_SCHEMA = "oaw.advisory-mirror-index.v1"
MIRROR_INDEX_VERSION = 1
DEFAULT_RETAIN_PRIOR = 3
MAX_RETAIN_PRIOR = 31
MAX_MIRROR_PATH_BYTES = 500
PUBLIC_FILE_MODE = 0o644
PUBLIC_DIRECTORY_MODE = 0o755


class MirrorSecurityError(ValueError):
    """A bounded advisory-mirror validation or publication rejection."""

    def __init__(self, code: str, summary: str) -> None:
        super().__init__(summary)
        self.code = code[:80]
        self.summary = summary[:240]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def canonical_json_bytes(value: BaseModel | dict[str, object]) -> bytes:
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class MirrorCatalogEntry(_StrictModel):
    catalog_version: str = Field(..., min_length=1, max_length=120)
    catalog_sequence: int = Field(..., ge=1, le=9_223_372_036_854_775_807)
    created_at: datetime
    expires_at: datetime
    publisher_key_id: str = Field(..., min_length=3, max_length=96)
    manifest_path: str = Field(..., min_length=1, max_length=MAX_MIRROR_PATH_BYTES)
    signature_path: str = Field(..., min_length=1, max_length=MAX_MIRROR_PATH_BYTES)
    payload_path: str = Field(..., min_length=1, max_length=MAX_MIRROR_PATH_BYTES)
    manifest_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    signature_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    payload_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    manifest_bytes: int = Field(..., ge=1, le=64 << 10)
    signature_bytes: int = Field(..., ge=1, le=4096)
    payload_bytes: int = Field(..., ge=1, le=8 << 20)
    license_identifier: str = Field(..., min_length=1, max_length=120)
    attribution: str = Field(..., min_length=1, max_length=500)
    source_provenance: UpstreamProvenance
    adapter_version: str = Field(..., min_length=1, max_length=40)
    minimum_supported_catalog_version: int = Field(..., ge=1, le=1_000_000)
    minimum_supported_openassetwatch_version: str = Field(..., min_length=1, max_length=80)

    @field_validator("created_at", "expires_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("mirror catalog timestamps require a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("manifest_path", "signature_path", "payload_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        if not _valid_mirror_relative_path(value):
            raise ValueError("mirror catalog paths must be safe relative paths")
        return value

    @model_validator(mode="after")
    def validate_entry(self) -> "MirrorCatalogEntry":
        if self.expires_at <= self.created_at:
            raise ValueError("mirror catalog expiry must follow creation")
        paths = (self.manifest_path, self.signature_path, self.payload_path)
        if len(set(paths)) != 3:
            raise ValueError("mirror catalog artifact paths must be distinct")
        parents = {value.rsplit("/", 1)[0] for value in paths}
        if len(parents) != 1 or not next(iter(parents)).startswith("catalogs/"):
            raise ValueError("mirror catalog artifacts must share one immutable catalog directory")
        if self.manifest_path.rsplit("/", 1)[1] != "manifest.json":
            raise ValueError("mirror manifest path has an unexpected file name")
        if self.signature_path.rsplit("/", 1)[1] != "manifest.ed25519":
            raise ValueError("mirror signature path has an unexpected file name")
        return self


class AdvisoryMirrorIndex(_StrictModel):
    schema_id: Literal["oaw.advisory-mirror-index.v1"]
    schema_version: Literal[1]
    source_id: str = Field(..., min_length=3, max_length=64)
    index_signing_key_id: str = Field(..., min_length=3, max_length=96)
    published_at: datetime
    latest_catalog_version: str = Field(..., min_length=1, max_length=120)
    latest_catalog_sequence: int = Field(..., ge=1, le=9_223_372_036_854_775_807)
    license_identifier: str = Field(..., min_length=1, max_length=120)
    attribution: str = Field(..., min_length=1, max_length=500)
    source_provenance: UpstreamProvenance
    adapter_version: str = Field(..., min_length=1, max_length=40)
    minimum_supported_catalog_version: int = Field(..., ge=1, le=1_000_000)
    minimum_supported_openassetwatch_version: str = Field(..., min_length=1, max_length=80)
    catalogs: list[MirrorCatalogEntry] = Field(..., min_length=1, max_length=32)

    @field_validator("published_at")
    @classmethod
    def validate_published_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("mirror publication time requires a timezone")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_catalogs(self) -> "AdvisoryMirrorIndex":
        sequences = [entry.catalog_sequence for entry in self.catalogs]
        versions = [entry.catalog_version for entry in self.catalogs]
        if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
            raise ValueError("mirror catalogs must have unique increasing sequences")
        if len(versions) != len(set(versions)):
            raise ValueError("mirror catalogs must have unique versions")
        all_paths = [
            path
            for entry in self.catalogs
            for path in (entry.manifest_path, entry.signature_path, entry.payload_path)
        ]
        if len(all_paths) != len(set(all_paths)):
            raise ValueError("mirror artifact paths must be unique")
        latest = self.catalogs[-1]
        if (
            latest.catalog_version != self.latest_catalog_version
            or latest.catalog_sequence != self.latest_catalog_sequence
        ):
            raise ValueError("mirror latest pointer must select the highest retained sequence")
        if self.published_at < latest.created_at:
            raise ValueError("mirror publication cannot predate the latest catalog")
        if latest.source_provenance != self.source_provenance:
            raise ValueError("mirror top-level provenance must describe the latest catalog")
        if (
            latest.adapter_version != self.adapter_version
            or latest.minimum_supported_catalog_version != self.minimum_supported_catalog_version
            or latest.minimum_supported_openassetwatch_version
            != self.minimum_supported_openassetwatch_version
        ):
            raise ValueError("mirror top-level compatibility metadata must describe the latest catalog")
        if any(
            entry.license_identifier != self.license_identifier
            or entry.attribution != self.attribution
            or entry.source_provenance.source_name != self.source_provenance.source_name
            or entry.adapter_version != self.adapter_version
            or entry.minimum_supported_catalog_version != self.minimum_supported_catalog_version
            or entry.minimum_supported_openassetwatch_version
            != self.minimum_supported_openassetwatch_version
            for entry in self.catalogs
        ):
            raise ValueError("mirror catalog policy metadata must agree with the index")
        return self

    @property
    def latest(self) -> MirrorCatalogEntry:
        return self.catalogs[-1]


@dataclass(frozen=True)
class VerifiedMirrorIndex:
    index: AdvisoryMirrorIndex
    index_bytes: bytes
    index_digest: str
    signature: bytes


@dataclass(frozen=True)
class LocalMirrorBundle:
    bundle: VerifiedBundle
    manifest_bytes: bytes
    signature_bytes: bytes
    payload_bytes: bytes


@dataclass(frozen=True)
class MirrorBuildResult:
    index: AdvisoryMirrorIndex
    index_digest: str
    output_directory: Path
    retained_prior_catalogs: int
    retained_catalog_sequences: tuple[int, ...]
    removed_catalog_sequences: tuple[int, ...]

    def report(self) -> dict[str, object]:
        return {
            "schema_version": "oaw.advisory-mirror-publication-report.v1",
            "status": "mirror-complete",
            "source_id": self.index.source_id,
            "index_schema": self.index.schema_id,
            "index_sha256": self.index_digest,
            "index_signing_key_id": self.index.index_signing_key_id,
            "latest_catalog_version": self.index.latest_catalog_version,
            "latest_catalog_sequence": self.index.latest_catalog_sequence,
            "catalog_count": len(self.index.catalogs),
            "retained_prior_catalogs": self.retained_prior_catalogs,
            "retained_catalog_sequences": list(self.retained_catalog_sequences),
            "removed_catalog_count": len(self.removed_catalog_sequences),
            "removed_catalog_sequences": list(self.removed_catalog_sequences),
            "license_identifier": self.index.license_identifier,
            "output_directory_name": self.output_directory.name,
            "signing_key_persisted": False,
        }


@dataclass(frozen=True)
class MirrorSnapshotResult:
    index: AdvisoryMirrorIndex
    index_digest: str
    output_directory: Path

    def report(self) -> dict[str, object]:
        return {
            "schema_version": "oaw.advisory-mirror-snapshot-report.v1",
            "status": "snapshot-complete",
            "source_id": self.index.source_id,
            "index_sha256": self.index_digest,
            "catalog_count": len(self.index.catalogs),
            "latest_catalog_version": self.index.latest_catalog_version,
            "latest_catalog_sequence": self.index.latest_catalog_sequence,
            "output_directory_name": self.output_directory.name,
        }


class PublicationCheckpoint(_StrictModel):
    schema_version: Literal["oaw.advisory-mirror-publication-checkpoint.v1"]
    source_id: str = Field(..., min_length=3, max_length=64)
    latest_catalog_sequence: int = Field(..., ge=1, le=9_223_372_036_854_775_807)
    index_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class MirrorSnapshotReport(_StrictModel):
    schema_version: Literal["oaw.advisory-mirror-snapshot-report.v1"]
    status: Literal["snapshot-complete"]
    source_id: str = Field(..., min_length=3, max_length=64)
    index_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    catalog_count: int = Field(..., ge=1, le=32)
    latest_catalog_version: str = Field(..., min_length=1, max_length=120)
    latest_catalog_sequence: int = Field(..., ge=1, le=9_223_372_036_854_775_807)
    output_directory_name: str = Field(..., min_length=1, max_length=255)


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise MirrorSecurityError("mirror-index-duplicate-key", "mirror index JSON contains a duplicate key")
        result[key] = value
    return result


def _parse_bounded_report(data: bytes, model: type[_StrictModel]) -> _StrictModel:
    if not data or len(data) > 64 << 10:
        raise MirrorSecurityError("mirror-report-size-invalid", "mirror report size is outside the reviewed limit")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
        return model.model_validate(value)
    except MirrorSecurityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise MirrorSecurityError("mirror-report-invalid", "mirror report violates its strict schema") from exc


def verify_publication_continuity(
    *,
    checkpoint_bytes: bytes,
    snapshot_report_bytes: bytes,
    time_floor: int,
) -> dict[str, object]:
    """Reject a static-host replay before a newly signed publication is built."""

    if not 0 < time_floor < 9_223_372_036_854_775_807:
        raise MirrorSecurityError("mirror-sequence-floor-invalid", "publication sequence floor is outside its bound")
    checkpoint = _parse_bounded_report(checkpoint_bytes, PublicationCheckpoint)
    snapshot = _parse_bounded_report(snapshot_report_bytes, MirrorSnapshotReport)
    if checkpoint.source_id != snapshot.source_id:
        raise MirrorSecurityError("mirror-checkpoint-source-mismatch", "publication checkpoint source does not match")
    if snapshot.latest_catalog_sequence < checkpoint.latest_catalog_sequence:
        raise MirrorSecurityError("mirror-checkpoint-downgrade", "mirror sequence is older than trusted checkpoint")
    if (
        snapshot.latest_catalog_sequence == checkpoint.latest_catalog_sequence
        and snapshot.index_sha256 != checkpoint.index_sha256
    ):
        raise MirrorSecurityError("mirror-checkpoint-conflict", "mirror digest conflicts with trusted checkpoint")
    return {
        "schema_version": "oaw.advisory-mirror-continuity-report.v1",
        "status": "continuity-verified",
        "source_id": snapshot.source_id,
        "checkpoint_sequence": checkpoint.latest_catalog_sequence,
        "snapshot_sequence": snapshot.latest_catalog_sequence,
        "sequence_floor": max(snapshot.latest_catalog_sequence, time_floor),
    }


def parse_mirror_index(data: bytes, *, maximum_bytes: int) -> AdvisoryMirrorIndex:
    if not data or len(data) > maximum_bytes:
        raise MirrorSecurityError("mirror-index-size-invalid", "mirror index size is outside the reviewed limit")
    if data.startswith(b"\xef\xbb\xbf"):
        raise MirrorSecurityError("mirror-index-encoding-invalid", "mirror index must be UTF-8 without a byte-order mark")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except MirrorSecurityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MirrorSecurityError("mirror-index-invalid-json", "mirror index must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise MirrorSecurityError("mirror-index-root-invalid", "mirror index root must be an object")
    try:
        index = AdvisoryMirrorIndex.model_validate(value)
    except ValidationError as exc:
        raise MirrorSecurityError("mirror-index-schema-invalid", "mirror index violates the supported schema") from exc
    if canonical_json_bytes(index) != data:
        raise MirrorSecurityError("mirror-index-noncanonical", "mirror index must use exact canonical JSON bytes")
    return index


def _validate_index_key(
    index: AdvisoryMirrorIndex,
    *,
    source: FeedSource,
    registry: ReviewedFeedRegistry,
    now: datetime,
) -> Ed25519PublicKey:
    if source.retrieval_mode != "signed-mirror-index" or source.mirror is None:
        raise MirrorSecurityError("mirror-source-mode-invalid", "reviewed source does not use a signed mirror index")
    if index.source_id != source.source_id:
        raise MirrorSecurityError("mirror-source-mismatch", "mirror index source does not match reviewed configuration")
    if index.schema_id != source.expected_index_schema:
        raise MirrorSecurityError("mirror-index-schema-mismatch", "mirror index schema does not match reviewed policy")
    if index.index_signing_key_id not in source.mirror.trusted_index_key_ids:
        raise MirrorSecurityError("mirror-index-key-substitution", "mirror index key is not approved for this source")
    try:
        key = registry.publisher_key(index.index_signing_key_id)
    except RegistryError as exc:
        raise MirrorSecurityError(exc.code, exc.summary) from exc
    if key.status == "revoked":
        raise MirrorSecurityError("mirror-index-key-revoked", "mirror index key has been revoked")
    if key.status != "active":
        raise MirrorSecurityError("mirror-index-key-retired", "retired keys cannot sign a new mirror index")
    if key.not_before and (now < key.not_before or index.published_at < key.not_before):
        raise MirrorSecurityError("mirror-index-key-not-yet-valid", "mirror index key is not yet valid")
    if key.not_after and (now >= key.not_after or index.published_at >= key.not_after):
        raise MirrorSecurityError("mirror-index-key-expired", "mirror index key has expired")
    return Ed25519PublicKey.from_public_bytes(key.public_key_bytes())


def verify_mirror_index(
    *,
    index_bytes: bytes,
    signature_bytes: bytes,
    source: FeedSource,
    registry: ReviewedFeedRegistry,
    now: datetime | None = None,
) -> VerifiedMirrorIndex:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    index = parse_mirror_index(index_bytes, maximum_bytes=source.limits.maximum_mirror_index_bytes)
    public_key = _validate_index_key(index, source=source, registry=registry, now=current)
    signature = decode_signature(signature_bytes, maximum_bytes=source.limits.maximum_signature_bytes)
    try:
        public_key.verify(signature, index_bytes)
    except (InvalidSignature, ValueError) as exc:
        raise MirrorSecurityError("mirror-index-signature-invalid", "mirror index signature is invalid") from exc
    if index.published_at > current + MAX_MANIFEST_FUTURE_SKEW:
        raise MirrorSecurityError("mirror-index-future-dated", "mirror index publication time is in the future")
    if current - index.published_at > timedelta(seconds=source.limits.maximum_mirror_index_age_seconds):
        raise MirrorSecurityError("mirror-index-stale", "mirror index is stale and older than the reviewed freshness limit")
    if len(index.catalogs) > source.limits.maximum_mirror_catalogs:
        raise MirrorSecurityError("mirror-index-catalog-limit", "mirror index exceeds the reviewed catalog-retention limit")
    if index.latest.expires_at <= current:
        raise MirrorSecurityError("mirror-latest-expired", "mirror latest catalog has expired")
    if index.license_identifier not in source.accepted_licenses:
        raise MirrorSecurityError("mirror-license-mismatch", "mirror license is not approved for this source")
    if index.attribution != source.required_attribution:
        raise MirrorSecurityError("mirror-attribution-mismatch", "mirror attribution does not match reviewed policy")
    if index.source_provenance.source_name != source.expected_catalog_source:
        raise MirrorSecurityError("mirror-provenance-mismatch", "mirror provenance does not match the reviewed source")
    if index.adapter_version != source.adapter_version:
        raise MirrorSecurityError("mirror-adapter-version-mismatch", "mirror adapter version does not match reviewed policy")
    if index.minimum_supported_catalog_version > SUPPORTED_CATALOG_FORMAT_VERSION:
        raise MirrorSecurityError(
            "mirror-catalog-version-unsupported",
            "mirror requires an unsupported advisory catalog format",
        )
    if index.minimum_supported_openassetwatch_version != source.minimum_supported_openassetwatch_version:
        raise MirrorSecurityError(
            "mirror-openassetwatch-version-mismatch",
            "mirror OpenAssetWatch compatibility metadata does not match reviewed policy",
        )
    for entry in index.catalogs:
        if entry.publisher_key_id not in source.trusted_publisher_key_ids:
            raise MirrorSecurityError("mirror-publisher-substitution", "mirror catalog publisher is not approved")
        if entry.payload_bytes > source.limits.maximum_compressed_bytes:
            raise MirrorSecurityError("mirror-payload-claim-too-large", "mirror catalog exceeds the payload limit")
        if entry.payload_path.rsplit("/", 1)[1] != source.expected_payload_name:
            raise MirrorSecurityError("mirror-payload-name-mismatch", "mirror payload name does not match reviewed policy")
    return VerifiedMirrorIndex(
        index=index,
        index_bytes=index_bytes,
        index_digest=hashlib.sha256(index_bytes).hexdigest(),
        signature=signature,
    )


def verify_mirror_artifact(entry: MirrorCatalogEntry, kind: Literal["manifest", "signature", "payload"], data: bytes) -> None:
    expected_bytes = {
        "manifest": entry.manifest_bytes,
        "signature": entry.signature_bytes,
        "payload": entry.payload_bytes,
    }[kind]
    expected_digest = {
        "manifest": entry.manifest_sha256,
        "signature": entry.signature_sha256,
        "payload": entry.payload_sha256,
    }[kind]
    if len(data) != expected_bytes:
        raise MirrorSecurityError("mirror-artifact-size-mismatch", "mirror artifact size does not match the signed index")
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise MirrorSecurityError("mirror-artifact-digest-mismatch", "mirror artifact digest does not match the signed index")


def verify_bundle_against_mirror_entry(bundle: VerifiedBundle, entry: MirrorCatalogEntry) -> None:
    manifest = bundle.manifest
    if (
        manifest.catalog_version != entry.catalog_version
        or manifest.catalog_sequence != entry.catalog_sequence
        or manifest.created_at != entry.created_at
        or manifest.expires_at != entry.expires_at
        or manifest.publisher_key_id != entry.publisher_key_id
        or manifest.license_identifier != entry.license_identifier
        or manifest.attribution != entry.attribution
        or manifest.upstream_provenance != entry.source_provenance
        or manifest.adapter_version != entry.adapter_version
        or manifest.minimum_supported_catalog_version != entry.minimum_supported_catalog_version
        or bundle.manifest_digest != entry.manifest_sha256
        or bundle.payload_digest != entry.payload_sha256
    ):
        raise MirrorSecurityError("mirror-bundle-metadata-mismatch", "verified bundle does not match signed mirror metadata")


def _inspect_bundle_directory(path: Path) -> None:
    if not path.is_absolute():
        raise MirrorSecurityError("mirror-bundle-path-relative", "mirror bundle directory must be absolute")
    try:
        info = path.lstat()
    except OSError as exc:
        raise MirrorSecurityError("mirror-bundle-directory-invalid", "mirror bundle directory could not be inspected") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise MirrorSecurityError("mirror-bundle-directory-invalid", "mirror bundle input must be a directory")


def load_local_bundle(
    path: Path,
    *,
    source: FeedSource,
    registry: ReviewedFeedRegistry,
    now: datetime,
) -> LocalMirrorBundle:
    _inspect_bundle_directory(path)
    manifest_bytes = read_single_link_file(path / "manifest.json", maximum_bytes=source.limits.maximum_manifest_bytes)
    signature_bytes = read_single_link_file(path / "manifest.ed25519", maximum_bytes=source.limits.maximum_signature_bytes)
    manifest = parse_manifest_bytes(manifest_bytes, maximum_bytes=source.limits.maximum_manifest_bytes)
    payload_bytes = read_single_link_file(path / manifest.payload_name, maximum_bytes=source.limits.maximum_compressed_bytes)
    bundle = verify_bundle(
        manifest_bytes=manifest_bytes,
        signature_bytes=signature_bytes,
        payload_bytes=payload_bytes,
        source=source,
        registry=registry,
        now=now,
    )
    return LocalMirrorBundle(bundle, manifest_bytes, signature_bytes, payload_bytes)


def _entry_for_bundle(bundle: LocalMirrorBundle, *, source: FeedSource) -> MirrorCatalogEntry:
    manifest = bundle.bundle.manifest
    directory = f"catalogs/{manifest.catalog_sequence:020d}-{bundle.bundle.manifest_digest[:16]}"
    return MirrorCatalogEntry(
        catalog_version=manifest.catalog_version,
        catalog_sequence=manifest.catalog_sequence,
        created_at=manifest.created_at,
        expires_at=manifest.expires_at,
        publisher_key_id=manifest.publisher_key_id,
        manifest_path=f"{directory}/manifest.json",
        signature_path=f"{directory}/manifest.ed25519",
        payload_path=f"{directory}/{manifest.payload_name}",
        manifest_sha256=bundle.bundle.manifest_digest,
        signature_sha256=hashlib.sha256(bundle.signature_bytes).hexdigest(),
        payload_sha256=bundle.bundle.payload_digest,
        manifest_bytes=len(bundle.manifest_bytes),
        signature_bytes=len(bundle.signature_bytes),
        payload_bytes=len(bundle.payload_bytes),
        license_identifier=manifest.license_identifier,
        attribution=manifest.attribution,
        source_provenance=manifest.upstream_provenance,
        adapter_version=manifest.adapter_version,
        minimum_supported_catalog_version=manifest.minimum_supported_catalog_version,
        minimum_supported_openassetwatch_version=source.minimum_supported_openassetwatch_version,
    )


def _safe_local_artifact(root: Path, relative_path: str) -> Path:
    if not root.is_absolute() or not _valid_mirror_relative_path(relative_path):
        raise MirrorSecurityError("mirror-local-path-invalid", "local mirror artifact path is invalid")
    current = root
    for segment in relative_path.split("/")[:-1]:
        current = current / segment
        try:
            info = current.lstat()
        except OSError as exc:
            raise MirrorSecurityError("mirror-local-directory-invalid", "local mirror directory is unavailable") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise MirrorSecurityError("mirror-local-directory-unsafe", "local mirror path traverses a non-directory")
    return root / Path(*relative_path.split("/"))


def load_existing_mirror(
    root: Path,
    *,
    source: FeedSource,
    registry: ReviewedFeedRegistry,
    now: datetime,
) -> list[LocalMirrorBundle]:
    _inspect_bundle_directory(root)
    index_bytes = read_single_link_file(root / "index.json", maximum_bytes=source.limits.maximum_mirror_index_bytes)
    signature_bytes = read_single_link_file(root / "index.ed25519", maximum_bytes=source.limits.maximum_signature_bytes)
    verified = verify_mirror_index(
        index_bytes=index_bytes,
        signature_bytes=signature_bytes,
        source=source,
        registry=registry,
        now=now,
    )
    bundles: list[LocalMirrorBundle] = []
    for entry in verified.index.catalogs:
        manifest_bytes = read_single_link_file(
            _safe_local_artifact(root, entry.manifest_path),
            maximum_bytes=source.limits.maximum_manifest_bytes,
        )
        signature = read_single_link_file(
            _safe_local_artifact(root, entry.signature_path),
            maximum_bytes=source.limits.maximum_signature_bytes,
        )
        payload = read_single_link_file(
            _safe_local_artifact(root, entry.payload_path),
            maximum_bytes=source.limits.maximum_compressed_bytes,
        )
        for kind, data in (("manifest", manifest_bytes), ("signature", signature), ("payload", payload)):
            verify_mirror_artifact(entry, kind, data)
        bundle = verify_bundle(
            manifest_bytes=manifest_bytes,
            signature_bytes=signature,
            payload_bytes=payload,
            source=source,
            registry=registry,
            now=entry.created_at,
        )
        verify_bundle_against_mirror_entry(bundle, entry)
        bundles.append(LocalMirrorBundle(bundle, manifest_bytes, signature, payload))
    return bundles


def _validate_output_parent(output: Path) -> os.stat_result:
    if not output.is_absolute() or len(str(output)) > 4096:
        raise MirrorSecurityError("mirror-output-path-invalid", "mirror output path must be absolute and bounded")
    try:
        parent = output.parent.lstat()
    except OSError as exc:
        raise MirrorSecurityError("mirror-output-parent-invalid", "mirror output parent is unavailable") from exc
    if not stat.S_ISDIR(parent.st_mode):
        raise MirrorSecurityError("mirror-output-parent-invalid", "mirror output parent must be a directory")
    try:
        _validate_parent_chain(output.parent)
    except StagingSecurityError as exc:
        raise MirrorSecurityError("mirror-output-parent-unsafe", "mirror output parent chain is unsafe") from exc
    if hasattr(os, "getuid") and parent.st_uid != os.getuid():
        raise MirrorSecurityError("mirror-output-owner-unsafe", "mirror output parent has the wrong owner")
    if os.name != "nt" and parent.st_mode & 0o022:
        raise MirrorSecurityError("mirror-output-parent-unsafe", "mirror output parent is writable by another account")
    if output.exists() or output.is_symlink():
        raise MirrorSecurityError("mirror-output-exists", "mirror output target already exists")
    return parent


def _revalidate_output_parent(output: Path, expected: os.stat_result) -> None:
    try:
        current = output.parent.lstat()
    except OSError as exc:
        raise MirrorSecurityError("mirror-output-parent-invalid", "mirror output parent disappeared") from exc
    if (
        not stat.S_ISDIR(current.st_mode)
        or current.st_dev != expected.st_dev
        or current.st_ino != expected.st_ino
    ):
        raise MirrorSecurityError("mirror-output-parent-replaced", "mirror output parent was replaced")


def _write_public_file(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise MirrorSecurityError("mirror-output-write-failed", "mirror artifact could not be written safely")
            view = view[written:]
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise MirrorSecurityError("mirror-output-file-unsafe", "mirror artifact is not a single-link regular file")
        if os.name != "nt":
            os.fchmod(descriptor, PUBLIC_FILE_MODE)
    finally:
        os.close(descriptor)


def build_advisory_mirror(
    *,
    bundle_directories: list[Path],
    output_directory: Path,
    source: FeedSource,
    registry: ReviewedFeedRegistry,
    index_signing_key_id: str,
    index_signing_key: Ed25519PrivateKey,
    published_at: datetime | None = None,
    retain_prior: int = DEFAULT_RETAIN_PRIOR,
    existing_mirror_root: Path | None = None,
) -> MirrorBuildResult:
    """Build one complete static mirror snapshot without making network requests."""

    if not bundle_directories:
        raise MirrorSecurityError("mirror-input-empty", "at least one complete signed bundle is required")
    if not 0 <= retain_prior <= MAX_RETAIN_PRIOR:
        raise MirrorSecurityError("mirror-retention-invalid", "mirror retention is outside the reviewed bound")
    if retain_prior + 1 > source.limits.maximum_mirror_catalogs:
        raise MirrorSecurityError("mirror-retention-too-large", "mirror retention exceeds the source catalog limit")
    current = (published_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    output_parent_info = _validate_output_parent(output_directory)
    if source.retrieval_mode != "signed-mirror-index" or source.mirror is None:
        raise MirrorSecurityError("mirror-source-mode-invalid", "mirror builder requires a reviewed mirror source")
    if index_signing_key_id not in source.mirror.trusted_index_key_ids:
        raise MirrorSecurityError("mirror-index-key-substitution", "mirror index key is not approved for this source")

    existing_bundles = (
        load_existing_mirror(existing_mirror_root, source=source, registry=registry, now=current)
        if existing_mirror_root is not None
        else []
    )
    input_bundles = [
        load_local_bundle(path, source=source, registry=registry, now=current)
        for path in bundle_directories
    ]
    if existing_bundles and max(
        item.bundle.manifest.catalog_sequence for item in input_bundles
    ) <= max(item.bundle.manifest.catalog_sequence for item in existing_bundles):
        raise MirrorSecurityError("mirror-catalog-not-advanced", "new bundle does not advance the verified mirror sequence")
    bundles = [*existing_bundles, *input_bundles]
    by_sequence: dict[int, LocalMirrorBundle] = {}
    by_version: dict[str, int] = {}
    for item in bundles:
        manifest = item.bundle.manifest
        previous = by_sequence.get(manifest.catalog_sequence)
        if previous is not None:
            if previous.bundle.manifest_digest != item.bundle.manifest_digest:
                raise MirrorSecurityError("mirror-sequence-conflict", "catalog sequence maps to conflicting signed manifests")
            raise MirrorSecurityError("mirror-bundle-duplicate", "signed bundle appears more than once in mirror input")
        previous_sequence = by_version.get(manifest.catalog_version)
        if previous_sequence is not None and previous_sequence != manifest.catalog_sequence:
            raise MirrorSecurityError("mirror-version-conflict", "catalog version maps to conflicting sequences")
        by_sequence[manifest.catalog_sequence] = item
        by_version[manifest.catalog_version] = manifest.catalog_sequence
    all_sequences = sorted(by_sequence)
    retained_sequences = all_sequences[-(retain_prior + 1) :]
    retained = [by_sequence[key] for key in retained_sequences]
    removed_sequences = tuple(key for key in all_sequences if key not in set(retained_sequences))
    latest_bundle = retained[-1]
    if latest_bundle.bundle.manifest.expires_at <= current:
        raise MirrorSecurityError("mirror-latest-expired", "latest catalog expires before publication")
    entries = [_entry_for_bundle(item, source=source) for item in retained]
    latest = entries[-1]
    index = AdvisoryMirrorIndex(
        schema_id=MIRROR_INDEX_SCHEMA,
        schema_version=MIRROR_INDEX_VERSION,
        source_id=source.source_id,
        index_signing_key_id=index_signing_key_id,
        published_at=current,
        latest_catalog_version=latest.catalog_version,
        latest_catalog_sequence=latest.catalog_sequence,
        license_identifier=latest.license_identifier,
        attribution=latest.attribution,
        source_provenance=latest.source_provenance,
        adapter_version=latest.adapter_version,
        minimum_supported_catalog_version=latest.minimum_supported_catalog_version,
        minimum_supported_openassetwatch_version=latest.minimum_supported_openassetwatch_version,
        catalogs=entries,
    )
    index_bytes = canonical_json_bytes(index)
    if len(index_bytes) > source.limits.maximum_mirror_index_bytes:
        raise MirrorSecurityError("mirror-index-size-invalid", "generated mirror index exceeds the reviewed limit")
    index_signature_bytes = base64.b64encode(index_signing_key.sign(index_bytes)) + b"\n"
    verified_index = verify_mirror_index(
        index_bytes=index_bytes,
        signature_bytes=index_signature_bytes,
        source=source,
        registry=registry,
        now=current,
    )

    staging = Path(tempfile.mkdtemp(prefix=f".{output_directory.name}.", dir=output_directory.parent)).absolute()
    staging_info = staging.lstat()
    try:
        _revalidate_output_parent(output_directory, output_parent_info)
        for entry, item in zip(entries, retained, strict=True):
            target_directory = staging / Path(*entry.manifest_path.split("/")[:-1])
            target_directory.mkdir(parents=True, mode=PUBLIC_DIRECTORY_MODE, exist_ok=False)
            if os.name != "nt":
                os.chmod(target_directory.parent, PUBLIC_DIRECTORY_MODE)
                os.chmod(target_directory, PUBLIC_DIRECTORY_MODE)
            _write_public_file(target_directory / "manifest.json", item.manifest_bytes)
            _write_public_file(target_directory / "manifest.ed25519", item.signature_bytes)
            _write_public_file(target_directory / item.bundle.manifest.payload_name, item.payload_bytes)
        _write_public_file(staging / "index.json", index_bytes)
        _write_public_file(staging / "index.ed25519", index_signature_bytes)
        if os.name != "nt":
            os.chmod(staging, PUBLIC_DIRECTORY_MODE)

        reverified = load_existing_mirror(staging, source=source, registry=registry, now=current)
        if [item.bundle.manifest_digest for item in reverified] != [
            item.bundle.manifest_digest for item in retained
        ]:
            raise MirrorSecurityError("mirror-output-verification-failed", "generated mirror contents changed during verification")
        linked = staging.lstat()
        if (
            not stat.S_ISDIR(linked.st_mode)
            or linked.st_dev != staging_info.st_dev
            or linked.st_ino != staging_info.st_ino
        ):
            raise MirrorSecurityError("mirror-output-replaced", "mirror staging directory was replaced")
        if output_directory.exists() or output_directory.is_symlink():
            raise MirrorSecurityError("mirror-output-exists", "mirror output target appeared during publication")
        _revalidate_output_parent(output_directory, output_parent_info)
        os.replace(staging, output_directory)
        _fsync_directory(output_directory.parent)
    except Exception:
        try:
            linked = staging.lstat()
        except OSError:
            linked = None
        if linked is not None and linked.st_dev == staging_info.st_dev and linked.st_ino == staging_info.st_ino:
            shutil.rmtree(staging)
        raise
    return MirrorBuildResult(
        index=verified_index.index,
        index_digest=verified_index.index_digest,
        output_directory=output_directory,
        retained_prior_catalogs=max(0, len(entries) - 1),
        retained_catalog_sequences=tuple(entry.catalog_sequence for entry in entries),
        removed_catalog_sequences=removed_sequences,
    )


def snapshot_advisory_mirror(
    *,
    output_directory: Path,
    source: FeedSource,
    registry: ReviewedFeedRegistry,
    downloader: AdvisoryDownloader | None = None,
    now: datetime | None = None,
) -> MirrorSnapshotResult:
    """Download and authenticate a complete bounded mirror for retention input."""

    output_parent_info = _validate_output_parent(output_directory)
    if source.retrieval_mode != "signed-mirror-index":
        raise MirrorSecurityError("mirror-source-mode-invalid", "snapshot requires a reviewed mirror source")
    client = downloader or AdvisoryDownloader()
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    started = time.monotonic()

    def remaining() -> float:
        value = source.limits.total_timeout_seconds - (time.monotonic() - started)
        if value <= 0:
            raise MirrorSecurityError("mirror-snapshot-timeout", "mirror snapshot exceeded the total timeout")
        return value

    index_artifact = client.fetch(source, "index", total_timeout_seconds=remaining())
    signature_artifact = client.fetch(source, "index_signature", total_timeout_seconds=remaining())
    verified = verify_mirror_index(
        index_bytes=index_artifact.body,
        signature_bytes=signature_artifact.body,
        source=source,
        registry=registry,
        now=current,
    )
    staging = Path(tempfile.mkdtemp(prefix=f".{output_directory.name}.", dir=output_directory.parent)).absolute()
    staging_info = staging.lstat()
    try:
        _revalidate_output_parent(output_directory, output_parent_info)
        total_bytes = len(verified.index_bytes) + len(signature_artifact.body)
        _write_public_file(staging / "index.json", verified.index_bytes)
        _write_public_file(staging / "index.ed25519", signature_artifact.body)
        for entry in verified.index.catalogs:
            claimed = entry.manifest_bytes + entry.signature_bytes + entry.payload_bytes
            if total_bytes + claimed > source.limits.maximum_mirror_snapshot_bytes:
                raise MirrorSecurityError("mirror-snapshot-too-large", "mirror snapshot exceeds the total byte limit")
            manifest = client.fetch_mirror_artifact(
                source,
                "manifest",
                entry.manifest_path,
                total_timeout_seconds=remaining(),
            ).body
            signature = client.fetch_mirror_artifact(
                source,
                "signature",
                entry.signature_path,
                total_timeout_seconds=remaining(),
            ).body
            payload = client.fetch_mirror_artifact(
                source,
                "payload",
                entry.payload_path,
                total_timeout_seconds=remaining(),
            ).body
            for kind, data in (("manifest", manifest), ("signature", signature), ("payload", payload)):
                verify_mirror_artifact(entry, kind, data)
            bundle = verify_bundle(
                manifest_bytes=manifest,
                signature_bytes=signature,
                payload_bytes=payload,
                source=source,
                registry=registry,
                now=entry.created_at,
            )
            verify_bundle_against_mirror_entry(bundle, entry)
            target_directory = staging / Path(*entry.manifest_path.split("/")[:-1])
            target_directory.mkdir(parents=True, mode=PUBLIC_DIRECTORY_MODE, exist_ok=False)
            if os.name != "nt":
                os.chmod(target_directory.parent, PUBLIC_DIRECTORY_MODE)
                os.chmod(target_directory, PUBLIC_DIRECTORY_MODE)
            _write_public_file(target_directory / "manifest.json", manifest)
            _write_public_file(target_directory / "manifest.ed25519", signature)
            _write_public_file(target_directory / entry.payload_path.rsplit("/", 1)[1], payload)
            total_bytes += len(manifest) + len(signature) + len(payload)
        if os.name != "nt":
            os.chmod(staging, PUBLIC_DIRECTORY_MODE)
        load_existing_mirror(staging, source=source, registry=registry, now=current)
        linked = staging.lstat()
        if (
            not stat.S_ISDIR(linked.st_mode)
            or linked.st_dev != staging_info.st_dev
            or linked.st_ino != staging_info.st_ino
        ):
            raise MirrorSecurityError("mirror-output-replaced", "mirror snapshot staging directory was replaced")
        if output_directory.exists() or output_directory.is_symlink():
            raise MirrorSecurityError("mirror-output-exists", "mirror snapshot target appeared during download")
        _revalidate_output_parent(output_directory, output_parent_info)
        os.replace(staging, output_directory)
        _fsync_directory(output_directory.parent)
    except Exception:
        try:
            linked = staging.lstat()
        except OSError:
            linked = None
        if linked is not None and linked.st_dev == staging_info.st_dev and linked.st_ino == staging_info.st_ino:
            shutil.rmtree(staging)
        raise
    return MirrorSnapshotResult(verified.index, verified.index_digest, output_directory)
