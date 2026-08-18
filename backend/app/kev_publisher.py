"""One-shot official CISA KEV publisher using the shared signed-feed envelope."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import secrets
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .advisory_bundle import AdvisoryBundleManifest, UpstreamProvenance, VerifiedBundle, verify_bundle
from .advisory_feed_registry import (
    FeedEndpoint,
    FeedLimits,
    FeedRegistryDocument,
    FeedSource,
    PublisherKey,
    PublisherKeyringDocument,
    ReviewedFeedRegistry,
)
from .advisory_transport import (
    AdvisoryDownloader,
    PrivateStagingArea,
    StagingSecurityError,
    _fsync_directory,
    read_single_link_file,
)
from .kev_catalog import (
    CISA_KEV_ATTRIBUTION,
    CISA_KEV_DOCUMENTATION_URL,
    CISA_KEV_LICENSE,
    CISA_KEV_SOURCE_ID,
    CISA_KEV_SOURCE_NAME,
    KEV_ADAPTER_VERSION,
    MAX_CISA_KEV_BYTES,
    MAX_KEV_RECORDS,
    KevCatalog,
    canonical_kev_bytes,
    normalize_cisa_kev_catalog,
    parse_cisa_kev_bytes,
)
from .osv_pypi_publisher import load_signing_key


CISA_KEV_HOST = "raw.githubusercontent.com"
CISA_KEV_PATH = "/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
PUBLISHER_STATE_SCHEMA = "oaw.cisa-kev-publisher-state.v1"
PUBLISHER_REPORT_SCHEMA = "oaw.cisa-kev-publisher-report.v1"
MAX_STATE_BYTES = 64 << 10
MAX_REPORT_BYTES = 256 << 10
DEFAULT_TIMEOUT_SECONDS = 60.0


class KevPublisherError(ValueError):
    def __init__(self, code: str, summary: str) -> None:
        super().__init__(summary)
        self.code = code[:80]
        self.summary = summary[:240]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class KevPublisherState(_StrictModel):
    schema_version: str = Field(pattern=r"^oaw\.cisa-kev-publisher-state\.v1$")
    source_id: str = Field(pattern=r"^cisa-kev-official$")
    adapter_version: str = Field(pattern=r"^1$")
    run_sequence: int = Field(ge=1)
    catalog_version: str = Field(min_length=1, max_length=120)
    catalog_date_released: datetime
    source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    payload_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    last_successful_run_at: datetime
    publication_status: str = Field(default="published", pattern=r"^(reserved|published)$")


@dataclass(frozen=True)
class PublishRequest:
    state_path: Path
    output_root: Path | None = None
    dry_run: bool = False
    key_id: str | None = None
    signing_key_file: Path | None = None
    sequence_floor: int = 0
    manifest_validity_days: int = 30


@dataclass(frozen=True)
class PublishResult:
    status: str
    report: dict[str, Any]
    bundle_directory: Path | None = None
    verified_bundle: VerifiedBundle | None = None


class KevSource(Protocol):
    def fetch(self, *, total_timeout_seconds: float) -> bytes: ...


def _source_download_policy() -> FeedSource:
    endpoint = FeedEndpoint(
        host=CISA_KEV_HOST,
        manifest_path=CISA_KEV_PATH,
        signature_path=CISA_KEV_PATH,
        payload_path=CISA_KEV_PATH,
    )
    return FeedSource(
        source_id=CISA_KEV_SOURCE_ID,
        display_name=CISA_KEV_SOURCE_NAME,
        enabled=True,
        adapter_type="cisa-kev-v1",
        adapter_version=KEV_ADAPTER_VERSION,
        endpoint=endpoint,
        expected_manifest_schema="oaw.advisory-bundle.manifest.v1",
        expected_payload_schema="oaw.kev-catalog.v1",
        expected_payload_name="catalog.json",
        expected_catalog_source=CISA_KEV_SOURCE_NAME,
        trusted_publisher_key_ids=["local-cisa-kev-publisher"],
        accepted_licenses=[CISA_KEV_LICENSE],
        required_attribution=CISA_KEV_ATTRIBUTION,
        expected_content_types={
            "manifest": ["application/json", "text/plain"],
            "signature": ["application/json", "text/plain"],
            "payload": ["application/json", "text/plain"],
        },
        limits=FeedLimits(
            maximum_compressed_bytes=8 << 20,
            maximum_uncompressed_bytes=8 << 20,
            maximum_advisories=MAX_KEV_RECORDS,
            maximum_aliases=0,
            maximum_references=0,
            total_timeout_seconds=300,
            minimum_sync_interval_seconds=0,
            control_action_cooldown_seconds=0,
        ),
        documentation_url=CISA_KEV_DOCUMENTATION_URL,
        documentation_note="Exact official CISA-controlled machine-readable mirror path; no caller URL is accepted.",
    )


class CisaKevHttpSource:
    def __init__(self, *, downloader: AdvisoryDownloader | None = None) -> None:
        self.downloader = downloader or AdvisoryDownloader()
        self.policy = _source_download_policy()

    def fetch(self, *, total_timeout_seconds: float) -> bytes:
        return self.downloader.fetch(
            self.policy,
            "payload",
            total_timeout_seconds=total_timeout_seconds,
        ).body


class FileKevSource:
    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise KevPublisherError("fixture-path-relative", "KEV fixture path must be absolute")
        self.path = path

    def fetch(self, *, total_timeout_seconds: float) -> bytes:
        if total_timeout_seconds <= 0:
            raise KevPublisherError("publisher-timeout", "KEV publisher exceeded its absolute run deadline")
        try:
            return read_single_link_file(self.path, maximum_bytes=MAX_CISA_KEV_BYTES)
        except StagingSecurityError as exc:
            raise KevPublisherError("fixture-file-unsafe", "KEV fixture file failed safe-open validation") from exc


def _canonical(value: BaseModel | dict[str, Any]) -> bytes:
    def json_ready(item: Any) -> Any:
        if isinstance(item, BaseModel):
            return json_ready(item.model_dump(mode="json"))
        if isinstance(item, dict):
            return {str(key): json_ready(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [json_ready(child) for child in item]
        if isinstance(item, datetime):
            return item.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        if isinstance(item, date):
            return item.isoformat()
        if item is None or isinstance(item, (str, int, float, bool)):
            return item
        raise TypeError("KEV publisher JSON contains an unsupported value")

    item = json_ready(value)
    return json.dumps(item, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _state_bytes(state: KevPublisherState) -> bytes:
    data = _canonical(state) + b"\n"
    if len(data) > MAX_STATE_BYTES:
        raise KevPublisherError("state-size-invalid", "KEV publisher state exceeds its bounded size")
    return data


def load_state(path: Path) -> KevPublisherState | None:
    if not path.is_absolute():
        raise KevPublisherError("state-path-relative", "KEV publisher state path must be absolute")
    _validate_private_parent(path)
    if not path.exists() and not path.is_symlink():
        return None
    try:
        data = read_single_link_file(path, maximum_bytes=MAX_STATE_BYTES)
        raw = json.loads(data.decode("utf-8"))
        return KevPublisherState.model_validate(raw)
    except (StagingSecurityError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise KevPublisherError("state-invalid", "KEV publisher state is invalid or unsafe") from exc


def _validate_private_parent(path: Path) -> os.stat_result:
    parent = path.parent
    if not parent.is_absolute():
        raise KevPublisherError("state-path-relative", "KEV publisher state parent must be absolute")
    try:
        area = PrivateStagingArea(parent)
        area.ensure_root()
        return parent.lstat()
    except (OSError, StagingSecurityError) as exc:
        raise KevPublisherError(
            "state-parent-unsafe",
            "KEV publisher state parent must be a private owned directory with a safe parent chain",
        ) from exc


def write_state(path: Path, state: KevPublisherState) -> None:
    parent_info = _validate_private_parent(path)
    if path.exists() or path.is_symlink():
        try:
            current = path.lstat()
        except OSError as exc:
            raise KevPublisherError("state-file-unsafe", "KEV publisher state file cannot be inspected") from exc
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
            raise KevPublisherError("state-file-unsafe", "KEV publisher state must be a single-link regular file")
    temporary = path.parent / f".{path.name}.{secrets.token_hex(12)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(_state_bytes(state))
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise KevPublisherError("state-file-write-failed", "KEV publisher state write failed")
            view = view[written:]
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise KevPublisherError("state-file-unsafe", "KEV publisher state became unsafe while open")
    finally:
        os.close(descriptor)
    try:
        latest_parent = path.parent.lstat()
        if (latest_parent.st_dev, latest_parent.st_ino) != (parent_info.st_dev, parent_info.st_ino):
            raise KevPublisherError("state-parent-replaced", "KEV publisher state parent changed during write")
        if path.exists() or path.is_symlink():
            current = path.lstat()
            if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
                raise KevPublisherError("state-file-unsafe", "KEV publisher state was replaced unsafely")
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if temporary.exists() or temporary.is_symlink():
            current = temporary.lstat()
            if stat.S_ISREG(current.st_mode) and current.st_nlink == 1:
                temporary.unlink()
    read_single_link_file(path, maximum_bytes=MAX_STATE_BYTES)
    _validate_private_parent(path)


@contextmanager
def _publisher_state_lock(path: Path):
    """Hold a crash-releasing inter-process lock across sequence issuance."""

    parent_info = _validate_private_parent(path)
    lock_path = path.parent / f".{path.name}.lock"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise KevPublisherError("state-lock-unsafe", "KEV publisher state lock could not be opened safely") from exc
    locked = False
    try:
        opened = os.fstat(descriptor)
        current = lock_path.lstat()
        latest_parent = path.parent.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or (latest_parent.st_dev, latest_parent.st_ino) != (parent_info.st_dev, parent_info.st_ino)
        ):
            raise KevPublisherError("state-lock-unsafe", "KEV publisher state lock is not a stable single-link file")
        if os.name != "nt" and opened.st_uid != os.getuid():
            raise KevPublisherError("state-lock-owner-invalid", "KEV publisher state lock has the wrong owner")
        if opened.st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as exc:
            raise KevPublisherError("publisher-already-running", "another KEV publisher run already holds the state lock") from exc
        yield
    finally:
        if locked:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(descriptor)


def _verification_registry(
    *, key_id: str, private_key: Ed25519PrivateKey
) -> tuple[ReviewedFeedRegistry, FeedSource]:
    source = _source_download_policy().model_copy(
        update={
            "trusted_publisher_key_ids": [key_id],
            "endpoint": FeedEndpoint(
                host="cisa-kev-publisher.openassetwatch.invalid",
                manifest_path="/v1/cisa-kev/manifest.json",
                signature_path="/v1/cisa-kev/manifest.ed25519",
                payload_path="/v1/cisa-kev/catalog.json",
            ),
        }
    )
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    registry = ReviewedFeedRegistry(
        FeedRegistryDocument(
            schema_version="oaw.advisory-feed-registry.v1",
            registry_version="local-cisa-kev-verification",
            sources=[source],
        ),
        PublisherKeyringDocument(
            schema_version="oaw.advisory-publisher-keyring.v1",
            keyring_version="local-cisa-kev-verification",
            keys=[
                PublisherKey(
                    key_id=key_id,
                    publisher_id="openassetwatch-cisa-kev-publisher",
                    publisher_name="OpenAssetWatch CISA KEV Publisher",
                    algorithm="ed25519",
                    public_key_base64=base64.b64encode(public).decode("ascii"),
                    status="active",
                )
            ],
        ),
    )
    return registry, source


def sign_kev_bundle(
    catalog: KevCatalog,
    *,
    source_digest: str,
    key_id: str,
    private_key: Ed25519PrivateKey,
    sequence: int,
    created_at: datetime,
    validity_days: int,
) -> tuple[bytes, bytes, bytes, VerifiedBundle]:
    payload = canonical_kev_bytes(catalog)
    manifest = AdvisoryBundleManifest(
        schema_id="oaw.advisory-bundle.manifest.v1",
        schema_version=1,
        source_id=CISA_KEV_SOURCE_ID,
        publisher_key_id=key_id,
        catalog_version=catalog.catalog_version,
        catalog_sequence=sequence,
        created_at=created_at,
        expires_at=created_at + timedelta(days=validity_days),
        payload_name="catalog.json",
        payload_kind="kev-prioritization",
        payload_media_type="application/vnd.openassetwatch.kev-catalog+json",
        payload_compression="none",
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        compressed_bytes=len(payload),
        uncompressed_bytes=len(payload),
        advisory_count=len(catalog.records),
        alias_count=0,
        reference_count=0,
        license_identifier=CISA_KEV_LICENSE,
        attribution=CISA_KEV_ATTRIBUTION,
        upstream_provenance=UpstreamProvenance(
            source_name=CISA_KEV_SOURCE_NAME,
            source_version=catalog.catalog_version,
            dataset_id=f"cisa-kev-official-mirror:{source_digest}",
            retrieved_at=created_at,
        ),
        adapter_version=KEV_ADAPTER_VERSION,
        minimum_supported_catalog_version=1,
    )
    manifest_bytes = _canonical(manifest)
    signature = base64.b64encode(private_key.sign(manifest_bytes)) + b"\n"
    registry, source = _verification_registry(key_id=key_id, private_key=private_key)
    verified = verify_bundle(
        manifest_bytes=manifest_bytes,
        signature_bytes=signature,
        payload_bytes=payload,
        source=source,
        registry=registry,
        now=created_at,
    )
    return payload, manifest_bytes, signature, verified


def _publish_output(
    *,
    output_root: Path,
    payload: bytes,
    manifest: bytes,
    signature: bytes,
    report: bytes,
    sequence: int,
    verified: VerifiedBundle,
) -> Path:
    area = PrivateStagingArea(output_root)
    run_directory = area.create_run_directory("afrun_" + secrets.token_hex(16))
    try:
        area.write_artifact(run_directory, "catalog.json", payload)
        area.write_artifact(run_directory, "manifest.json", manifest)
        area.write_artifact(run_directory, "manifest.ed25519", signature)
        area.write_artifact(run_directory, "publisher-report.json", report)
        final = output_root / f"cisa-kev-{sequence:08d}-{verified.manifest_digest[:16]}"
        if final.exists() or final.is_symlink():
            raise KevPublisherError("output-conflict", "KEV publisher output already exists")
        os.replace(run_directory, final)
        _fsync_directory(output_root)
        return final
    except Exception:
        if run_directory.exists():
            try:
                area.cleanup(run_directory)
            except StagingSecurityError:
                pass
        raise


def publisher_report_bytes(report: dict[str, Any]) -> bytes:
    data = _canonical(report) + b"\n"
    if len(data) > MAX_REPORT_BYTES:
        raise KevPublisherError("report-too-large", "KEV publisher report exceeds its bounded size")
    return data


def publish_once(
    source: KevSource,
    request: PublishRequest,
    *,
    now: Callable[[], datetime] | None = None,
    total_timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> PublishResult:
    if not request.state_path.is_absolute():
        raise KevPublisherError("state-path-relative", "KEV publisher state path must be absolute")
    if request.dry_run:
        return _publish_once_locked(
            source,
            request,
            now=now,
            total_timeout_seconds=total_timeout_seconds,
            clock=clock,
        )
    with _publisher_state_lock(request.state_path):
        return _publish_once_locked(
            source,
            request,
            now=now,
            total_timeout_seconds=total_timeout_seconds,
            clock=clock,
        )


def _publish_once_locked(
    source: KevSource,
    request: PublishRequest,
    *,
    now: Callable[[], datetime] | None,
    total_timeout_seconds: float,
    clock: Callable[[], float],
) -> PublishResult:
    if not request.state_path.is_absolute():
        raise KevPublisherError("state-path-relative", "KEV publisher state path must be absolute")
    if request.output_root is not None and not request.output_root.is_absolute():
        raise KevPublisherError("output-path-relative", "KEV publisher output path must be absolute")
    if not request.dry_run and (
        request.output_root is None or request.key_id is None or request.signing_key_file is None
    ):
        raise KevPublisherError(
            "publish-request-invalid",
            "signed KEV publishing requires output, key ID, and key file",
        )
    if not 1 <= request.manifest_validity_days <= 366:
        raise KevPublisherError("manifest-validity-invalid", "KEV manifest validity must be between 1 and 366 days")
    if not math.isfinite(total_timeout_seconds) or not 1 <= total_timeout_seconds <= 300:
        raise KevPublisherError("publish-timeout-invalid", "KEV publisher timeout must be between 1 and 300 seconds")
    deadline = clock() + total_timeout_seconds

    def remaining() -> float:
        value = deadline - clock()
        if value <= 0:
            raise KevPublisherError("publish-timeout", "KEV publishing exceeded the absolute run deadline")
        return value

    current = (now or (lambda: datetime.now(timezone.utc)))().astimezone(timezone.utc)
    body = source.fetch(total_timeout_seconds=remaining())
    remaining()
    source_digest = hashlib.sha256(body).hexdigest()
    source_catalog = parse_cisa_kev_bytes(body)
    remaining()
    if source_catalog.date_released > current + timedelta(minutes=5):
        raise KevPublisherError("source-future-dated", "CISA KEV catalog release time is in the future")
    catalog = normalize_cisa_kev_catalog(source_catalog)
    payload = canonical_kev_bytes(catalog)
    remaining()
    payload_digest = hashlib.sha256(payload).hexdigest()
    state = load_state(request.state_path)
    unchanged = False
    if state is not None:
        if source_catalog.date_released < state.catalog_date_released:
            raise KevPublisherError("catalog-downgrade", "CISA KEV catalog release time regressed")
        if (
            source_catalog.catalog_version == state.catalog_version
            and source_digest != state.source_digest
        ):
            raise KevPublisherError("catalog-version-replay", "CISA KEV catalog bytes changed without a new catalog version")
        if source_digest == state.source_digest and payload_digest != state.payload_digest:
            raise KevPublisherError("publisher-state-digest-invalid", "KEV publisher state conflicts with the unchanged source")
        unchanged = (
            state.publication_status == "published"
            and
            source_catalog.catalog_version == state.catalog_version
            and source_catalog.date_released == state.catalog_date_released
            and source_digest == state.source_digest
            and payload_digest == state.payload_digest
        )
    sequence = (
        state.run_sequence
        if state is not None and unchanged
        else max(state.run_sequence if state else 0, request.sequence_floor) + 1
    )
    status = "dry-run-complete" if request.dry_run else ("no-change" if unchanged else "bundle-complete")
    report = {
        "schema_version": PUBLISHER_REPORT_SCHEMA,
        "status": status,
        "source_id": CISA_KEV_SOURCE_ID,
        "source_name": CISA_KEV_SOURCE_NAME,
        "official_mirror_host": CISA_KEV_HOST,
        "official_mirror_path": CISA_KEV_PATH,
        "canonical_documentation_url": CISA_KEV_DOCUMENTATION_URL,
        "license_identifier": CISA_KEV_LICENSE,
        "attribution": CISA_KEV_ATTRIBUTION,
        "adapter_version": KEV_ADAPTER_VERSION,
        "catalog_version": catalog.catalog_version,
        "catalog_date_released": catalog.catalog_date_released.isoformat().replace("+00:00", "Z"),
        "record_count": len(catalog.records),
        "source_sha256": source_digest,
        "payload_sha256": payload_digest,
        "run_sequence": None if request.dry_run else sequence,
        "raw_catalog_persisted": False,
        "required_action_execution": "disabled",
        "local_compromise_claim": False,
    }
    publisher_report_bytes(report)
    if request.dry_run:
        return PublishResult("dry-run-complete", report)
    if unchanged:
        return PublishResult("no-change", report)
    assert request.output_root is not None
    assert request.key_id is not None
    assert request.signing_key_file is not None
    private_key = load_signing_key(
        key_file=request.signing_key_file,
        environment_name=None,
    )
    remaining()
    payload, manifest, signature, verified = sign_kev_bundle(
        catalog,
        source_digest=source_digest,
        key_id=request.key_id,
        private_key=private_key,
        sequence=sequence,
        created_at=current,
        validity_days=request.manifest_validity_days,
    )
    remaining()
    # Reserve the signed sequence before publishing the output directory. A
    # crash may skip a sequence, but it cannot leave a reusable sequence that
    # can sign a conflicting bundle on retry.
    write_state(
        request.state_path,
        KevPublisherState(
            schema_version=PUBLISHER_STATE_SCHEMA,
            source_id=CISA_KEV_SOURCE_ID,
            adapter_version=KEV_ADAPTER_VERSION,
            run_sequence=sequence,
            catalog_version=catalog.catalog_version,
            catalog_date_released=catalog.catalog_date_released,
            source_digest=source_digest,
            payload_digest=payload_digest,
            last_successful_run_at=current,
            publication_status="reserved",
        ),
    )
    remaining()
    output = _publish_output(
        output_root=request.output_root,
        payload=payload,
        manifest=manifest,
        signature=signature,
        report=publisher_report_bytes(report),
        sequence=sequence,
        verified=verified,
    )
    write_state(
        request.state_path,
        KevPublisherState(
            schema_version=PUBLISHER_STATE_SCHEMA,
            source_id=CISA_KEV_SOURCE_ID,
            adapter_version=KEV_ADAPTER_VERSION,
            run_sequence=sequence,
            catalog_version=catalog.catalog_version,
            catalog_date_released=catalog.catalog_date_released,
            source_digest=source_digest,
            payload_digest=payload_digest,
            last_successful_run_at=current,
            publication_status="published",
        ),
    )
    remaining()
    return PublishResult("bundle-complete", report, output, verified)


def live_source_smoke(
    source: KevSource | None = None,
    *,
    total_timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    body = (source or CisaKevHttpSource()).fetch(total_timeout_seconds=total_timeout_seconds)
    catalog = parse_cisa_kev_bytes(body)
    normalized = normalize_cisa_kev_catalog(catalog)
    return {
        "status": "live-source-smoke-complete",
        "source_id": CISA_KEV_SOURCE_ID,
        "catalog_version": normalized.catalog_version,
        "catalog_date_released": normalized.catalog_date_released.isoformat().replace("+00:00", "Z"),
        "record_count": len(normalized.records),
        "source_sha256": hashlib.sha256(body).hexdigest(),
        "payload_sha256": hashlib.sha256(canonical_kev_bytes(normalized)).hexdigest(),
        "license_identifier": CISA_KEV_LICENSE,
        "raw_catalog_persisted": False,
    }
