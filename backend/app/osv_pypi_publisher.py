"""One-shot bounded OSV PyPI retrieval, state, signing, and local publishing."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import random
import re
import secrets
import signal
import socket
import ssl
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Literal, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .advisory_bundle import AdvisoryBundleManifest, UpstreamProvenance, VerifiedBundle, verify_bundle
from .advisory_catalog import ADVISORY_SCHEMA_VERSION, MAX_ADVISORIES, AdvisoryRecord
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
    MAX_RESPONSE_HEADERS,
    READ_CHUNK_BYTES,
    DownloadSecurityError,
    HttpsTransport,
    PinnedHttpsTransport,
    PrivateStagingArea,
    StagingSecurityError,
    _fsync_directory,
    read_single_link_file,
    resolve_public_addresses,
)
from .osv_pypi_adapter import (
    ADAPTER_NAME,
    ADAPTER_VERSION,
    MAX_INDEX_BYTES,
    MAX_INDEX_ROWS,
    MAX_OSV_RECORD_BYTES,
    OSV_HOST,
    OSV_INDEX_PATH,
    PRODUCTION_POLICY,
    PUBLISHER_STATE_SCHEMA,
    CatalogBuild,
    ModifiedIndex,
    NormalizationReport,
    OsvPublisherError,
    PublisherPolicy,
    build_catalog,
    canonical_json_bytes,
    format_utc,
    normalize_osv_record,
    parse_modified_index,
    parse_osv_record_bytes,
    record_path,
    validate_publisher_policy,
)


PUBLISHER_USER_AGENT = (
    "OpenAssetWatch-OSV-PyPI-Publisher/1.0 "
    "(+https://github.com/PKXLIVE/openassetwatch)"
)
MAX_TOTAL_DOWNLOAD_BYTES = 64 << 20
MAX_STATE_BYTES = 16 << 20
MAX_SIGNING_KEY_BYTES = 8 << 10
MAX_OUTPUT_REPORT_BYTES = 256 << 10
DEFAULT_TOTAL_TIMEOUT_SECONDS = 300.0
DEFAULT_CONNECT_TIMEOUT_SECONDS = 5.0
DEFAULT_READ_TIMEOUT_SECONDS = 15.0
DEFAULT_RETRIES = 3
DEFAULT_CONCURRENCY = 4
DEFAULT_OVERLAP_SECONDS = 3_600
DEFAULT_MANIFEST_VALIDITY_DAYS = 30

_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,95}$")
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,79}$")
_STATE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
_RETRYABLE_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
_INDEX_CONTENT_TYPES = frozenset({"text/csv", "text/plain", "application/octet-stream"})
_RECORD_CONTENT_TYPES = frozenset({"application/json", "application/octet-stream"})


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class PublisherCursor(_StrictModel):
    modified_at: datetime
    record_id: str = Field(..., pattern=r"^PYSEC-[0-9]{4}-[0-9]{1,12}$")
    index_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")

    @field_validator("modified_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("publisher cursor timestamp requires a timezone")
        return value.astimezone(timezone.utc)


class PublisherState(_StrictModel):
    schema_version: Literal["oaw.osv-pypi-publisher-state.v1"]
    source_id: str
    source_name: str
    adapter_name: Literal["OpenAssetWatch OSV PyPI publisher"]
    adapter_version: str
    catalog_schema: Literal["oaw.advisory-catalog.v1"]
    run_sequence: int = Field(..., ge=1)
    cursor: PublisherCursor
    catalog_version: str = Field(..., min_length=1, max_length=120)
    payload_digest: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    last_successful_run_at: datetime
    records: list[AdvisoryRecord] = Field(..., min_length=1, max_length=MAX_ADVISORIES)

    @field_validator("last_successful_run_at")
    @classmethod
    def validate_success_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("publisher success timestamp requires a timezone")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_record_order(self) -> "PublisherState":
        ids = [record.id for record in self.records]
        if ids != sorted(ids, key=str.casefold) or len(ids) != len({value.casefold() for value in ids}):
            raise ValueError("publisher state records must be uniquely sorted")
        return self


@dataclass(frozen=True)
class PublisherLimits:
    maximum_records: int = 10_000
    maximum_index_bytes: int = MAX_INDEX_BYTES
    maximum_index_rows: int = MAX_INDEX_ROWS
    maximum_record_bytes: int = MAX_OSV_RECORD_BYTES
    maximum_total_bytes: int = MAX_TOTAL_DOWNLOAD_BYTES
    total_timeout_seconds: float = DEFAULT_TOTAL_TIMEOUT_SECONDS
    connection_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS
    read_timeout_seconds: float = DEFAULT_READ_TIMEOUT_SECONDS
    retries: int = DEFAULT_RETRIES
    concurrency: int = DEFAULT_CONCURRENCY
    overlap_seconds: int = DEFAULT_OVERLAP_SECONDS

    def __post_init__(self) -> None:
        if not 1 <= self.maximum_records <= MAX_ADVISORIES:
            raise ValueError("maximum records is outside the catalog bound")
        if not 1 <= self.maximum_index_bytes <= MAX_INDEX_BYTES:
            raise ValueError("maximum index bytes is outside the reviewed bound")
        if not 1 <= self.maximum_index_rows <= MAX_INDEX_ROWS:
            raise ValueError("maximum index rows is outside the reviewed bound")
        if not 1 <= self.maximum_record_bytes <= MAX_OSV_RECORD_BYTES:
            raise ValueError("maximum record bytes is outside the reviewed bound")
        if not self.maximum_index_bytes <= self.maximum_total_bytes <= MAX_TOTAL_DOWNLOAD_BYTES:
            raise ValueError("maximum total bytes is outside the reviewed bound")
        if not 1 <= self.total_timeout_seconds <= 900:
            raise ValueError("publisher total timeout is outside the reviewed bound")
        if not 0.5 <= self.connection_timeout_seconds <= 30:
            raise ValueError("publisher connect timeout is outside the reviewed bound")
        if not 0.5 <= self.read_timeout_seconds <= 60:
            raise ValueError("publisher read timeout is outside the reviewed bound")
        if not 0 <= self.retries <= 4:
            raise ValueError("publisher retries are outside the reviewed bound")
        if not 1 <= self.concurrency <= 8:
            raise ValueError("publisher concurrency is outside the reviewed bound")
        if not 0 <= self.overlap_seconds <= 86_400:
            raise ValueError("publisher overlap is outside the reviewed bound")


@dataclass(frozen=True)
class PublishRequest:
    state_path: Path
    output_root: Path | None
    full: bool = False
    dry_run: bool = False
    key_id: str | None = None
    signing_key_file: Path | None = None
    signing_key_env: str | None = None
    manifest_validity_days: int = DEFAULT_MANIFEST_VALIDITY_DAYS
    sequence_floor: int = 0

    def __post_init__(self) -> None:
        if not self.state_path.is_absolute():
            raise ValueError("publisher state path must be absolute")
        if not _STATE_NAME_RE.fullmatch(self.state_path.name):
            raise ValueError("publisher state file name is unsafe")
        if self.output_root is not None and not self.output_root.is_absolute():
            raise ValueError("publisher output root must be absolute")
        if self.dry_run:
            if self.output_root is not None or self.signing_key_file is not None or self.signing_key_env is not None:
                raise ValueError("dry run does not accept output or signing-key inputs")
        else:
            if self.output_root is None:
                raise ValueError("publisher output root is required")
            if not self.key_id or not _KEY_ID_RE.fullmatch(self.key_id):
                raise ValueError("publisher key ID is required and must be safe")
            if (self.signing_key_file is None) == (self.signing_key_env is None):
                raise ValueError("exactly one signing-key source is required")
        if self.signing_key_file is not None and not self.signing_key_file.is_absolute():
            raise ValueError("publisher signing-key path must be absolute")
        if self.signing_key_env is not None and not _ENV_NAME_RE.fullmatch(self.signing_key_env):
            raise ValueError("publisher signing-key environment reference is unsafe")
        if not 1 <= self.manifest_validity_days <= 366:
            raise ValueError("manifest validity is outside the verifier bound")
        if not 0 <= self.sequence_floor < 9_223_372_036_854_775_807:
            raise ValueError("publisher sequence floor is outside the manifest bound")


@dataclass(frozen=True)
class PublishResult:
    status: str
    report: dict[str, Any]
    bundle_directory: Path | None = None
    verified_bundle: VerifiedBundle | None = None


class OsvSource(Protocol):
    def fetch_index(self, *, maximum_bytes: int) -> bytes: ...

    def fetch_record(self, record_id: str, *, maximum_bytes: int) -> bytes: ...


class _RetryableFetch(Exception):
    pass


def _native_windows() -> bool:
    return os.name == "nt"


class _RunDeadline:
    """Absolute POSIX deadline for the complete operator-run publication."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self.started = time.monotonic()
        self._armed = False
        self._previous_handler: Any = None
        self._previous_timer: tuple[float, float] | None = None

    @property
    def can_interrupt(self) -> bool:
        return (
            not _native_windows()
            and threading.current_thread() is threading.main_thread()
            and hasattr(signal, "SIGALRM")
            and hasattr(signal, "setitimer")
        )

    def check(self) -> None:
        if time.monotonic() - self.started >= self.seconds:
            raise OsvPublisherError("publisher-timeout", "OSV publisher exceeded its absolute run deadline")

    def __enter__(self) -> "_RunDeadline":
        if self.can_interrupt:
            self._previous_handler = signal.getsignal(signal.SIGALRM)

            def _expired(_signum: int, _frame: Any) -> None:
                raise OsvPublisherError(
                    "publisher-timeout",
                    "OSV publisher exceeded its absolute run deadline",
                )

            signal.signal(signal.SIGALRM, _expired)
            self._previous_timer = signal.setitimer(signal.ITIMER_REAL, self.seconds)
            self._armed = True
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        if self._armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self._previous_handler)
            if self._previous_timer and self._previous_timer[0] > 0:
                elapsed = time.monotonic() - self.started
                signal.setitimer(
                    signal.ITIMER_REAL,
                    max(1e-6, self._previous_timer[0] - elapsed),
                    self._previous_timer[1],
                )


class OsvHttpClient:
    """Exact-path, DNS-pinned source client with bounded retries and bytes."""

    def __init__(
        self,
        *,
        limits: PublisherLimits,
        transport: HttpsTransport | None = None,
        resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        jitter: Callable[[float, float], float] | None = None,
    ) -> None:
        self.limits = limits
        self.transport = transport or PinnedHttpsTransport(user_agent=PUBLISHER_USER_AGENT)
        self.resolver = resolver
        self.clock = clock
        self.sleeper = sleeper
        self.jitter = jitter or random.SystemRandom().uniform
        self.started = clock()
        self._total_bytes = 0
        self._bytes_lock = threading.Lock()

    @property
    def total_bytes(self) -> int:
        with self._bytes_lock:
            return self._total_bytes

    def _remaining(self) -> float:
        remaining = self.limits.total_timeout_seconds - (self.clock() - self.started)
        if remaining <= 0:
            raise OsvPublisherError("source-timeout", "OSV publisher exceeded its total source timeout")
        return remaining

    @staticmethod
    def _validate_path(path: str, *, record: bool) -> None:
        if record:
            record_id = path.removeprefix("/osv-vulnerabilities/PyPI/").removesuffix(".json")
            if path != record_path(record_id):
                raise OsvPublisherError("source-path-invalid", "OSV record path is outside the reviewed prefix")
        elif path != OSV_INDEX_PATH:
            raise OsvPublisherError("source-path-invalid", "OSV index path is not the reviewed endpoint")

    def fetch_index(self, *, maximum_bytes: int) -> bytes:
        return self._fetch(
            OSV_INDEX_PATH,
            maximum_bytes=maximum_bytes,
            allowed_content_types=_INDEX_CONTENT_TYPES,
            record=False,
        )

    def fetch_record(self, record_id: str, *, maximum_bytes: int) -> bytes:
        return self._fetch(
            record_path(record_id),
            maximum_bytes=maximum_bytes,
            allowed_content_types=_RECORD_CONTENT_TYPES,
            record=True,
        )

    def _fetch(
        self,
        path: str,
        *,
        maximum_bytes: int,
        allowed_content_types: frozenset[str],
        record: bool,
    ) -> bytes:
        self._validate_path(path, record=record)
        last_error: Exception | None = None
        for attempt in range(self.limits.retries + 1):
            self._remaining()
            try:
                return self._fetch_once_with_deadline(
                    path,
                    maximum_bytes=maximum_bytes,
                    allowed_content_types=allowed_content_types,
                )
            except DownloadSecurityError as exc:
                if exc.code != "dns-resolution-failed":
                    raise OsvPublisherError(exc.code, exc.summary) from exc
                last_error = exc
            except _RetryableFetch as exc:
                last_error = exc
            except (OSError, TimeoutError, socket.timeout, ssl.SSLError, http.client.HTTPException) as exc:
                last_error = exc
            if attempt >= self.limits.retries:
                break
            delay = min(2.0, 0.25 * (2**attempt)) + self.jitter(0.0, 0.25)
            if delay >= self._remaining():
                break
            self.sleeper(delay)
        raise OsvPublisherError("source-unavailable", "OSV source request failed after bounded retries") from last_error

    def _fetch_once_with_deadline(
        self,
        path: str,
        *,
        maximum_bytes: int,
        allowed_content_types: frozenset[str],
    ) -> bytes:
        result: list[bytes] = []
        errors: list[BaseException] = []

        def run() -> None:
            try:
                result.append(
                    self._fetch_once(
                        path,
                        maximum_bytes=maximum_bytes,
                        allowed_content_types=allowed_content_types,
                    )
                )
            except BaseException as exc:  # transported to the bounded caller thread
                errors.append(exc)

        worker = threading.Thread(target=run, name="oaw-osv-fetch-attempt", daemon=True)
        worker.start()
        worker.join(self._remaining())
        if worker.is_alive():
            raise OsvPublisherError("source-timeout", "OSV source request exceeded the remaining deadline")
        if errors:
            raise errors[0]
        if len(result) != 1:
            raise OsvPublisherError("transport-invalid", "OSV source request returned no bounded result")
        return result[0]

    def _fetch_once(
        self,
        path: str,
        *,
        maximum_bytes: int,
        allowed_content_types: frozenset[str],
    ) -> bytes:
        addresses = resolve_public_addresses(OSV_HOST, resolver=self.resolver)
        pinned_ip = addresses[0]
        response = self.transport.get(
            host=OSV_HOST,
            path=path,
            pinned_ip=pinned_ip,
            connection_timeout=min(self.limits.connection_timeout_seconds, self._remaining()),
            read_timeout=min(self.limits.read_timeout_seconds, self._remaining()),
        )
        try:
            if response.peer_ip != pinned_ip:
                raise OsvPublisherError(
                    "dns-peer-mismatch",
                    "OSV connected peer did not match the validated DNS address",
                )
            if 300 <= response.status <= 399:
                raise OsvPublisherError("redirect-rejected", "OSV source redirects are disabled")
            if response.status in _RETRYABLE_STATUSES:
                raise _RetryableFetch(f"retryable status {response.status}")
            if response.status != 200:
                raise OsvPublisherError("http-status-rejected", "OSV source returned an unexpected HTTP status")
            if len(response.headers) > MAX_RESPONSE_HEADERS:
                raise OsvPublisherError("response-headers-too-large", "OSV source returned too many headers")
            headers: dict[str, str] = {}
            header_bytes = 0
            for name, value in response.headers:
                key = name.casefold()
                header_bytes += len(name.encode("utf-8", "replace")) + len(value.encode("utf-8", "replace")) + 4
                if key in headers and key in {"content-length", "content-type", "content-encoding", "location"}:
                    raise OsvPublisherError(
                        "response-header-ambiguous",
                        "OSV source returned an ambiguous security-sensitive header",
                    )
                headers[key] = value.strip()
            if header_bytes > 16 << 10:
                raise OsvPublisherError("response-headers-too-large", "OSV source headers exceed the byte limit")
            if headers.get("content-encoding", "identity").casefold() not in {"", "identity"}:
                raise OsvPublisherError("content-encoding-rejected", "OSV HTTP content encoding is not supported")
            content_type = headers.get("content-type", "").split(";", 1)[0].strip().casefold()
            if content_type not in allowed_content_types:
                raise OsvPublisherError("content-type-rejected", "OSV source content type is not approved")
            declared_text = headers.get("content-length")
            declared: int | None = None
            if declared_text:
                try:
                    declared = int(declared_text, 10)
                except ValueError as exc:
                    raise OsvPublisherError("content-length-invalid", "OSV content length is invalid") from exc
                if declared < 1 or declared > maximum_bytes:
                    raise OsvPublisherError("source-body-too-large", "OSV source body exceeds the byte limit")
            output = bytearray()
            for chunk in response.body_chunks:
                self._remaining()
                if not isinstance(chunk, bytes):
                    raise OsvPublisherError("transport-invalid", "OSV transport returned an invalid body chunk")
                output.extend(chunk)
                if len(output) > maximum_bytes:
                    raise OsvPublisherError("source-body-too-large", "OSV source body exceeds the byte limit")
                with self._bytes_lock:
                    self._total_bytes += len(chunk)
                    if self._total_bytes > self.limits.maximum_total_bytes:
                        raise OsvPublisherError(
                            "source-total-bytes-exceeded",
                            "OSV publisher exceeded its total download byte limit",
                        )
            if declared is not None and len(output) != declared:
                raise OsvPublisherError(
                    "content-length-mismatch",
                    "OSV source body length does not match response metadata",
                )
            if not output:
                raise OsvPublisherError("source-body-empty", "OSV source returned an empty body")
            return bytes(output)
        finally:
            response.close()


def _directory_identity(path: Path) -> tuple[int, int]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise OsvPublisherError("fixture-directory-invalid", "fixture directory cannot be inspected safely") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise OsvPublisherError("fixture-directory-invalid", "fixture path must be a directory")
    return info.st_dev, info.st_ino


class DirectoryOsvSource:
    """Read a bounded synthetic or operator-supplied fixture without traversal."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise ValueError("fixture directory must be absolute")
        self.root = root
        self.identity = _directory_identity(root)

    def _check_root(self) -> None:
        if _directory_identity(self.root) != self.identity:
            raise OsvPublisherError("fixture-directory-changed", "fixture directory changed during the run")

    def fetch_index(self, *, maximum_bytes: int) -> bytes:
        self._check_root()
        value = read_single_link_file(self.root / "modified_id.csv", maximum_bytes=maximum_bytes)
        self._check_root()
        return value

    def fetch_record(self, record_id: str, *, maximum_bytes: int) -> bytes:
        path = record_path(record_id)
        name = path.rsplit("/", 1)[-1]
        self._check_root()
        value = read_single_link_file(self.root / name, maximum_bytes=maximum_bytes)
        self._check_root()
        return value


def _safe_state_parent(path: Path) -> PrivateStagingArea:
    if not path.is_absolute() or not _STATE_NAME_RE.fullmatch(path.name):
        raise OsvPublisherError("state-path-invalid", "publisher state path must be absolute and bounded")
    area = PrivateStagingArea(path.parent)
    area.ensure_root()
    return area


def _atomic_replace_private_file(path: Path, data: bytes, *, maximum_bytes: int) -> None:
    if not data or len(data) > maximum_bytes:
        raise OsvPublisherError("private-file-size-invalid", "publisher private file size is outside its limit")
    area = _safe_state_parent(path)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OsvPublisherError("private-file-unsafe", "publisher private file is not a single-link regular file")
    temporary = path.parent / f".{path.name}.{secrets.token_hex(12)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OsvPublisherError("private-file-write-failed", "publisher private file write failed")
            view = view[written:]
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise OsvPublisherError("private-file-unsafe", "publisher private file became unsafe")
    finally:
        os.close(descriptor)
    try:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OsvPublisherError("private-file-unsafe", "publisher private file was replaced unsafely")
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if temporary.exists():
            info = temporary.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                temporary.unlink()
    # Revalidate after replacement while the private parent prevents an
    # unprivileged path swap.
    read_single_link_file(path, maximum_bytes=maximum_bytes)
    area.ensure_root()


def load_publisher_state(
    path: Path,
    *,
    policy: PublisherPolicy = PRODUCTION_POLICY,
    now: datetime | None = None,
) -> PublisherState | None:
    if not path.exists() and not path.is_symlink():
        return None
    _safe_state_parent(path)
    try:
        raw = json.loads(
            read_single_link_file(path, maximum_bytes=MAX_STATE_BYTES).decode("utf-8")
        )
        state = PublisherState.model_validate(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError, StagingSecurityError) as exc:
        raise OsvPublisherError("state-corrupt", "publisher state is invalid and requires operator recovery") from exc
    if (
        state.source_id != policy.source_id
        or state.source_name != policy.source_name
        or state.adapter_version != ADAPTER_VERSION
        or state.catalog_schema != ADVISORY_SCHEMA_VERSION
    ):
        raise OsvPublisherError("state-incompatible", "publisher state does not match the reviewed adapter")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if state.last_successful_run_at > current + timedelta(minutes=5):
        raise OsvPublisherError("state-future-dated", "publisher state has an invalid future success time")
    rebuilt = build_catalog(
        list(state.records),
        highest_modified=state.cursor.modified_at,
        policy=policy,
    )
    if rebuilt.catalog.catalog_version != state.catalog_version or rebuilt.payload_digest != state.payload_digest:
        raise OsvPublisherError("state-digest-invalid", "publisher state catalog digest does not verify")
    return state


def write_publisher_state(path: Path, state: PublisherState) -> None:
    _atomic_replace_private_file(
        path,
        canonical_json_bytes(state) + b"\n",
        maximum_bytes=MAX_STATE_BYTES,
    )


def _read_signing_key_file(path: Path) -> bytes:
    if not path.is_absolute():
        raise OsvPublisherError("signing-key-path-invalid", "signing key path must be absolute")
    if _native_windows():
        raise OsvPublisherError(
            "windows-private-storage-unavailable",
            "native Windows signing-key privacy cannot be validated safely; use a Linux private volume",
        )
    try:
        info = path.lstat()
    except OSError as exc:
        raise OsvPublisherError("signing-key-invalid", "signing key file cannot be inspected safely") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise OsvPublisherError(
            "signing-key-unsafe",
            "signing key must be a single-link regular file",
        )
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise OsvPublisherError("signing-key-owner-unsafe", "signing key has the wrong owner")
    if info.st_mode & 0o077:
        raise OsvPublisherError("signing-key-permissions-unsafe", "signing key permissions are not private")
    try:
        return read_single_link_file(path, maximum_bytes=MAX_SIGNING_KEY_BYTES)
    except StagingSecurityError as exc:
        raise OsvPublisherError("signing-key-unsafe", "signing key changed during safe open") from exc


def _decode_raw_private_key(data: bytes) -> Ed25519PrivateKey:
    encoded = data[:-2] if data.endswith(b"\r\n") else data[:-1] if data.endswith(b"\n") else data
    if not encoded or any(character in b" \t\r\n" for character in encoded):
        raise OsvPublisherError("signing-key-invalid", "raw signing key must use canonical base64")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise OsvPublisherError("signing-key-invalid", "raw signing key must use canonical base64") from exc
    if len(raw) != 32 or base64.b64encode(raw) != encoded:
        raise OsvPublisherError("signing-key-invalid", "Ed25519 private key must contain exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_signing_key(
    *,
    key_file: Path | None,
    environment_name: str | None,
    environ: dict[str, str] | None = None,
) -> Ed25519PrivateKey:
    if (key_file is None) == (environment_name is None):
        raise OsvPublisherError("signing-key-source-invalid", "exactly one signing-key source is required")
    if key_file is not None:
        data = _read_signing_key_file(key_file)
        if data.startswith(b"-----BEGIN"):
            try:
                key = serialization.load_pem_private_key(data, password=None)
            except (TypeError, ValueError) as exc:
                raise OsvPublisherError("signing-key-invalid", "signing key PEM is invalid or encrypted") from exc
            if not isinstance(key, Ed25519PrivateKey):
                raise OsvPublisherError("signing-key-algorithm", "signing key is not Ed25519")
            return key
        return _decode_raw_private_key(data)
    if environment_name is None or not _ENV_NAME_RE.fullmatch(environment_name):
        raise OsvPublisherError("signing-key-environment-invalid", "signing-key environment reference is unsafe")
    value = (environ if environ is not None else os.environ).get(environment_name)
    if not value:
        raise OsvPublisherError("signing-key-missing", "signing-key environment reference is not set")
    try:
        encoded_value = value.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise OsvPublisherError(
            "signing-key-invalid",
            "raw signing key must use canonical base64",
        ) from exc
    return _decode_raw_private_key(encoded_value)


def build_local_verification_registry(
    *,
    policy: PublisherPolicy,
    key_id: str,
    private_key: Ed25519PrivateKey,
) -> tuple[ReviewedFeedRegistry, FeedSource]:
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    source = FeedSource(
        source_id=policy.source_id,
        display_name=policy.source_name,
        enabled=True,
        adapter_type="oaw-catalog-v1",
        adapter_version="1",
        endpoint=FeedEndpoint(
            host="osv-pypi-publisher.openassetwatch.invalid",
            manifest_path="/v1/osv-pypi/manifest.json",
            signature_path="/v1/osv-pypi/manifest.ed25519",
            payload_path="/v1/osv-pypi/catalog.json",
        ),
        expected_manifest_schema="oaw.advisory-bundle.manifest.v1",
        expected_payload_schema="oaw.advisory-catalog.v1",
        expected_payload_name="catalog.json",
        expected_catalog_source=policy.source_name,
        trusted_publisher_key_ids=[key_id],
        accepted_licenses=[policy.license_identifier],
        required_attribution=policy.attribution,
        expected_content_types={
            "manifest": ["application/json"],
            "signature": ["application/octet-stream", "text/plain"],
            "payload": ["application/json"],
        },
        limits=FeedLimits(
            maximum_compressed_bytes=8 << 20,
            maximum_uncompressed_bytes=8 << 20,
            maximum_advisories=MAX_ADVISORIES,
            maximum_aliases=MAX_ADVISORIES * 32,
            maximum_references=MAX_ADVISORIES * 16,
            minimum_sync_interval_seconds=0,
            control_action_cooldown_seconds=0,
        ),
        documentation_url=policy.source_documentation_url,
        documentation_note=(
            "Local publisher verification policy. Configure the same public key and hosted "
            "artifact endpoints in the canonical reviewed registry before distribution."
        ),
    )
    publisher = PublisherKey(
        key_id=key_id,
        publisher_id="openassetwatch-osv-pypi-publisher",
        publisher_name=ADAPTER_NAME,
        algorithm="ed25519",
        public_key_base64=base64.b64encode(public_bytes).decode("ascii"),
        status="active",
    )
    registry = ReviewedFeedRegistry(
        FeedRegistryDocument(
            schema_version="oaw.advisory-feed-registry.v1",
            registry_version="local-publisher-verification",
            sources=[source],
        ),
        PublisherKeyringDocument(
            schema_version="oaw.advisory-publisher-keyring.v1",
            keyring_version="local-publisher-verification",
            keys=[publisher],
        ),
    )
    return registry, source


@dataclass(frozen=True)
class SignedBundle:
    catalog: CatalogBuild
    manifest_bytes: bytes
    signature_bytes: bytes
    verified: VerifiedBundle
    registry: ReviewedFeedRegistry
    source: FeedSource


def sign_catalog_bundle(
    catalog: CatalogBuild,
    *,
    policy: PublisherPolicy,
    index: ModifiedIndex,
    key_id: str,
    private_key: Ed25519PrivateKey,
    sequence: int,
    created_at: datetime,
    validity_days: int = DEFAULT_MANIFEST_VALIDITY_DAYS,
) -> SignedBundle:
    validate_publisher_policy(policy)
    current = created_at.astimezone(timezone.utc)
    manifest = AdvisoryBundleManifest(
        schema_id="oaw.advisory-bundle.manifest.v1",
        schema_version=1,
        source_id=policy.source_id,
        publisher_key_id=key_id,
        catalog_version=catalog.catalog.catalog_version,
        catalog_sequence=sequence,
        created_at=current,
        expires_at=current + timedelta(days=validity_days),
        payload_name="catalog.json",
        payload_media_type="application/vnd.openassetwatch.advisory-catalog+json",
        payload_compression="none",
        payload_sha256=catalog.payload_digest,
        compressed_bytes=len(catalog.payload_bytes),
        uncompressed_bytes=len(catalog.payload_bytes),
        advisory_count=len(catalog.catalog.advisories),
        alias_count=sum(len(record.aliases) for record in catalog.catalog.advisories),
        reference_count=sum(len(record.references) for record in catalog.catalog.advisories),
        license_identifier=policy.license_identifier,
        attribution=policy.attribution,
        upstream_provenance=UpstreamProvenance(
            source_name=policy.source_name,
            source_version=catalog.catalog.source.version,
            dataset_id=f"osv-pypi-pysec:{index.digest}",
            retrieved_at=current,
        ),
        adapter_version="1",
        minimum_supported_catalog_version=1,
    )
    manifest_bytes = canonical_json_bytes(manifest)
    signature_bytes = base64.b64encode(private_key.sign(manifest_bytes)) + b"\n"
    registry, source = build_local_verification_registry(
        policy=policy,
        key_id=key_id,
        private_key=private_key,
    )
    verified = verify_bundle(
        manifest_bytes=manifest_bytes,
        signature_bytes=signature_bytes,
        payload_bytes=catalog.payload_bytes,
        source=source,
        registry=registry,
        now=current,
    )
    return SignedBundle(catalog, manifest_bytes, signature_bytes, verified, registry, source)


def _output_report(
    *,
    policy: PublisherPolicy,
    mode: str,
    index: ModifiedIndex,
    normalization: NormalizationReport,
    catalog: CatalogBuild,
    sequence: int | None,
    retrieved_records: int,
    total_download_bytes: int,
    created_at: datetime,
    signature_status: str,
    key_id: str | None = None,
    public_key: bytes | None = None,
) -> dict[str, Any]:
    signing: dict[str, Any] = {"status": signature_status}
    if signature_status == "verified":
        if key_id is None or public_key is None:
            raise OsvPublisherError("publisher-report-invalid", "verified signing metadata is incomplete")
        signing.update(
            {
                "algorithm": "Ed25519",
                "key_id": key_id,
                "public_key_base64": base64.b64encode(public_key).decode("ascii"),
                "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
                "registration_authority": False,
            }
        )
    return {
        "schema_version": "oaw.osv-pypi-publisher-report.v1",
        "status": "bundle-complete" if signature_status == "verified" else "dry-run-complete",
        "complete": True,
        "mode": mode,
        "source": {
            "source_id": policy.source_id,
            "source_name": policy.source_name,
            "source_documentation_url": policy.source_documentation_url,
            "aggregator": "OSV.dev",
            "aggregator_documentation_url": "https://google.github.io/osv.dev/data/",
            "license_identifier": policy.license_identifier,
            "license_url": policy.license_url,
            "attribution": policy.attribution,
            "synthetic_fixture": policy.synthetic,
        },
        "adapter": {"name": ADAPTER_NAME, "version": ADAPTER_VERSION},
        "retrieved_at": format_utc(created_at),
        "index": {
            "sha256": index.digest,
            "total_rows": len(index.entries),
            "source_rows": len(index.source_entries),
            "highest_modified": format_utc(index.highest.modified_at),
            "highest_record_id": index.highest.record_id,
            "out_of_scope_total": index.out_of_scope_total,
            "out_of_scope_prefixes_total": index.out_of_scope_prefixes_total,
            "out_of_scope_by_prefix": index.out_of_scope_by_prefix,
            "out_of_scope_prefixes_truncated": (
                index.out_of_scope_prefixes_total > len(index.out_of_scope_by_prefix)
            ),
            "out_of_scope_samples": list(index.out_of_scope_samples),
            "out_of_scope_samples_truncated": (
                index.out_of_scope_total > len(index.out_of_scope_samples)
            ),
        },
        "retrieved_records": retrieved_records,
        "total_download_bytes": total_download_bytes,
        "normalization": normalization.as_dict(),
        "catalog": {
            "schema_version": ADVISORY_SCHEMA_VERSION,
            "catalog_version": catalog.catalog.catalog_version,
            "run_sequence": sequence,
            "advisory_count": len(catalog.catalog.advisories),
            "payload_bytes": len(catalog.payload_bytes),
            "payload_sha256": catalog.payload_digest,
            "records_sha256": catalog.records_digest,
        },
        "signature_status": signature_status,
        "signing": signing,
        "cursor_update_order": "after-atomic-output" if signature_status == "verified" else "not-requested",
        "raw_records_persisted": False,
    }


def publisher_report_bytes(report: dict[str, Any]) -> bytes:
    data = canonical_json_bytes(report) + b"\n"
    if len(data) > MAX_OUTPUT_REPORT_BYTES:
        raise OsvPublisherError(
            "publisher-report-too-large",
            "publisher report exceeds the serialized byte limit",
        )
    return data


def _publish_output(
    *,
    output_root: Path,
    bundle: SignedBundle,
    report_bytes: bytes,
    sequence: int,
) -> Path:
    area = PrivateStagingArea(output_root)
    run_id = "afrun_" + secrets.token_hex(16)
    run_directory = area.create_run_directory(run_id)
    try:
        area.write_artifact(run_directory, "catalog.json", bundle.catalog.payload_bytes)
        area.write_artifact(run_directory, "manifest.json", bundle.manifest_bytes)
        area.write_artifact(run_directory, "manifest.ed25519", bundle.signature_bytes)
        area.write_artifact(
            run_directory,
            "publisher-report.json",
            report_bytes,
        )
        # Re-read the exact staged bytes through the existing verifier before
        # exposing the directory as a complete local bundle.
        staged_manifest = read_single_link_file(
            run_directory / "manifest.json",
            maximum_bytes=64 << 10,
        )
        staged_signature = read_single_link_file(
            run_directory / "manifest.ed25519",
            maximum_bytes=256,
        )
        staged_payload = read_single_link_file(
            run_directory / "catalog.json",
            maximum_bytes=8 << 20,
        )
        staged_verified = verify_bundle(
            manifest_bytes=staged_manifest,
            signature_bytes=staged_signature,
            payload_bytes=staged_payload,
            source=bundle.source,
            registry=bundle.registry,
            now=bundle.verified.manifest.created_at,
        )
        if staged_verified.payload_digest != bundle.catalog.payload_digest:
            raise OsvPublisherError("output-digest-mismatch", "staged publisher payload digest changed")
        final_name = (
            f"osv-pypi-{sequence:08d}-"
            f"{bundle.catalog.catalog.catalog_version[-16:]}-"
            f"{bundle.verified.manifest_digest[:16]}"
        )
        final = output_root / final_name
        if final.exists() or final.is_symlink():
            raise OsvPublisherError("output-conflict", "publisher output directory already exists")
        os.replace(run_directory, final)
        _fsync_directory(output_root)
        info = final.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise OsvPublisherError("output-directory-unsafe", "publisher output was replaced unsafely")
        return final
    except Exception:
        if run_directory.exists():
            try:
                area.cleanup(run_directory)
            except StagingSecurityError:
                # Unsafe cleanup targets are deliberately left for operator
                # inspection rather than followed or removed.
                pass
        raise


def _validate_index_progress(
    index: ModifiedIndex,
    state: PublisherState | None,
    *,
    full: bool,
) -> None:
    if state is None:
        return
    highest = index.highest
    cursor = state.cursor
    if highest.modified_at < cursor.modified_at:
        raise OsvPublisherError("cursor-rollback", "OSV index is older than the last successful cursor")
    cursor_entry = next(
        (item for item in index.source_entries if item.record_id == cursor.record_id),
        None,
    )
    if not full and (
        cursor_entry is None or cursor_entry.modified_at < cursor.modified_at
    ):
        raise OsvPublisherError(
            "cursor-source-mismatch",
            "last successful cursor for a previously published record is not present in the current OSV index",
        )
    state_modified = {record.id: record.modified_at for record in state.records}
    for entry in index.source_entries:
        previous = state_modified.get(entry.record_id)
        if previous is not None and entry.modified_at < previous:
            raise OsvPublisherError(
                "record-timestamp-rollback",
                "OSV index regressed an existing record modification timestamp",
                record_id=entry.record_id,
            )


def _selected_entries(
    index: ModifiedIndex,
    *,
    state: PublisherState | None,
    full: bool,
    overlap_seconds: int,
) -> tuple[list[Any], str]:
    if full or state is None:
        return sorted(index.source_entries, key=lambda item: (item.modified_at, item.record_id)), (
            "full" if full else "initial-full"
        )
    index_ids = {item.record_id for item in index.source_entries}
    state_ids = {record.id for record in state.records}
    missing = sorted(state_ids - index_ids)
    if missing:
        raise OsvPublisherError(
            "source-record-missing",
            "OSV index no longer contains a previously published record; perform a reviewed full rebuild",
            record_id=missing[0],
        )
    threshold = state.cursor.modified_at - timedelta(seconds=overlap_seconds)
    selected = [item for item in index.source_entries if item.modified_at >= threshold]
    selected_ids = {item.record_id for item in selected}
    gaps = sorted(index_ids - state_ids - selected_ids)
    if gaps:
        raise OsvPublisherError(
            "cursor-gap-detected",
            "publisher cursor would skip an unprocessed OSV record; perform a full rebuild",
            record_id=gaps[0],
        )
    return sorted(selected, key=lambda item: (item.modified_at, item.record_id)), "incremental"


def _fetch_records(
    source: OsvSource,
    entries: list[Any],
    *,
    limits: PublisherLimits,
) -> dict[str, bytes]:
    output: dict[str, bytes] = {}
    errors: list[tuple[str, Exception]] = []
    with ThreadPoolExecutor(max_workers=limits.concurrency, thread_name_prefix="oaw-osv-pypi") as executor:
        futures = {
            executor.submit(
                source.fetch_record,
                entry.record_id,
                maximum_bytes=limits.maximum_record_bytes,
            ): entry.record_id
            for entry in entries
        }
        for future in as_completed(futures):
            record_id = futures[future]
            try:
                output[record_id] = future.result()
            except Exception as exc:  # normalized after all bounded workers close
                errors.append((record_id, exc))
    if errors:
        record_id, exc = sorted(errors, key=lambda item: item[0])[0]
        if isinstance(exc, OsvPublisherError):
            raise exc
        raise OsvPublisherError(
            "record-fetch-failed",
            "OSV record retrieval failed safely",
            record_id=record_id,
        ) from exc
    return output


def _publish_once(
    source: OsvSource,
    request: PublishRequest,
    *,
    deadline: _RunDeadline,
    limits: PublisherLimits | None = None,
    policy: PublisherPolicy = PRODUCTION_POLICY,
    now: Callable[[], datetime] | None = None,
    environ: dict[str, str] | None = None,
) -> PublishResult:
    validate_publisher_policy(policy)
    bounds = limits or PublisherLimits()
    deadline.check()
    current = (now or (lambda: datetime.now(timezone.utc)))().astimezone(timezone.utc)
    state = load_publisher_state(request.state_path, policy=policy, now=current)
    deadline.check()
    index_bytes = source.fetch_index(maximum_bytes=bounds.maximum_index_bytes)
    deadline.check()
    index = parse_modified_index(
        index_bytes,
        maximum_bytes=bounds.maximum_index_bytes,
        maximum_rows=bounds.maximum_index_rows,
    )
    if len(index.source_entries) > bounds.maximum_records:
        raise OsvPublisherError(
            "source-record-limit",
            "OSV PYSEC source exceeds the configured maximum record count",
        )
    if index.highest.modified_at > current + timedelta(minutes=5):
        raise OsvPublisherError("source-future-dated", "OSV index contains a future modification timestamp")
    _validate_index_progress(index, state, full=request.full)
    selected, mode = _selected_entries(
        index,
        state=state,
        full=request.full,
        overlap_seconds=bounds.overlap_seconds,
    )
    bodies = _fetch_records(source, selected, limits=bounds)
    deadline.check()
    normalization = NormalizationReport()
    records = {} if request.full or state is None else {record.id: record for record in state.records}
    by_id = {entry.record_id: entry for entry in selected}
    for record_id in sorted(bodies):
        deadline.check()
        parsed = parse_osv_record_bytes(bodies[record_id], expected_id=record_id)
        previous = records.get(record_id)
        normalized = normalize_osv_record(
            parsed,
            expected_modified=by_id[record_id].modified_at,
            policy=policy,
            report=normalization,
        )
        if previous is not None and previous.withdrawn_at is not None and (
            normalized.withdrawn_at is None
            or normalized.withdrawn_at < previous.withdrawn_at
        ):
            raise OsvPublisherError(
                "record-withdrawal-rollback",
                "OSV record regressed a previously published withdrawal",
                record_id=record_id,
            )
        records[record_id] = normalized
    expected_ids = {entry.record_id for entry in index.source_entries}
    if set(records) != expected_ids:
        raise OsvPublisherError(
            "catalog-incomplete",
            "publisher did not normalize the complete reviewed PYSEC source set",
        )
    catalog = build_catalog(
        list(records.values()),
        highest_modified=index.highest.modified_at,
        policy=policy,
    )
    deadline.check()
    total_bytes = (
        source.total_bytes
        if isinstance(source, OsvHttpClient)
        else len(index_bytes) + sum(len(value) for value in bodies.values())
    )
    sequence = max(state.run_sequence if state else 0, request.sequence_floor) + 1
    if request.dry_run:
        report = _output_report(
            policy=policy,
            mode=mode,
            index=index,
            normalization=normalization,
            catalog=catalog,
            sequence=None,
            retrieved_records=len(bodies),
            total_download_bytes=total_bytes,
            created_at=current,
            signature_status="not-requested",
        )
        publisher_report_bytes(report)
        return PublishResult("dry-run-complete", report)

    if request.key_id is None or request.output_root is None:
        raise OsvPublisherError("publish-request-invalid", "publisher signing and output configuration is missing")
    private_key = load_signing_key(
        key_file=request.signing_key_file,
        environment_name=request.signing_key_env,
        environ=environ,
    )
    deadline.check()
    bundle = sign_catalog_bundle(
        catalog,
        policy=policy,
        index=index,
        key_id=request.key_id,
        private_key=private_key,
        sequence=sequence,
        created_at=current,
        validity_days=request.manifest_validity_days,
    )
    report = _output_report(
        policy=policy,
        mode=mode,
        index=index,
        normalization=normalization,
        catalog=catalog,
        sequence=sequence,
        retrieved_records=len(bodies),
        total_download_bytes=total_bytes,
        created_at=current,
        signature_status="verified",
        key_id=request.key_id,
        public_key=private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )
    report_bytes = publisher_report_bytes(report)
    deadline.check()
    output = _publish_output(
        output_root=request.output_root,
        bundle=bundle,
        report_bytes=report_bytes,
        sequence=sequence,
    )
    deadline.check()
    next_state = PublisherState(
        schema_version=PUBLISHER_STATE_SCHEMA,
        source_id=policy.source_id,
        source_name=policy.source_name,
        adapter_name=ADAPTER_NAME,
        adapter_version=ADAPTER_VERSION,
        catalog_schema=ADVISORY_SCHEMA_VERSION,
        run_sequence=sequence,
        cursor=PublisherCursor(
            modified_at=index.highest.modified_at,
            record_id=index.highest.record_id,
            index_sha256=index.digest,
        ),
        catalog_version=catalog.catalog.catalog_version,
        payload_digest=catalog.payload_digest,
        last_successful_run_at=current,
        records=list(catalog.catalog.advisories),
    )
    write_publisher_state(request.state_path, next_state)
    return PublishResult("bundle-complete", report, output, bundle.verified)


def publish_once(
    source: OsvSource,
    request: PublishRequest,
    *,
    limits: PublisherLimits | None = None,
    policy: PublisherPolicy = PRODUCTION_POLICY,
    now: Callable[[], datetime] | None = None,
    environ: dict[str, str] | None = None,
) -> PublishResult:
    bounds = limits or PublisherLimits()
    if _native_windows() and policy == PRODUCTION_POLICY and not request.dry_run:
        raise OsvPublisherError(
            "windows-private-storage-unavailable",
            "native Windows signed publishing is disabled; use a Linux private volume",
        )
    deadline = _RunDeadline(bounds.total_timeout_seconds)
    if policy == PRODUCTION_POLICY and not request.dry_run and not deadline.can_interrupt:
        raise OsvPublisherError(
            "publisher-deadline-unavailable",
            "production publishing requires a platform with an enforceable absolute deadline",
        )
    with deadline:
        return _publish_once(
            source,
            request,
            limits=bounds,
            policy=policy,
            now=now,
            environ=environ,
            deadline=deadline,
        )


def live_source_smoke(
    source: OsvSource,
    *,
    record_id: str,
    limits: PublisherLimits | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    bounds = limits or PublisherLimits(
        maximum_records=MAX_ADVISORIES,
        maximum_total_bytes=MAX_INDEX_BYTES + MAX_OSV_RECORD_BYTES,
        total_timeout_seconds=60,
        retries=1,
        concurrency=1,
    )
    deadline = _RunDeadline(bounds.total_timeout_seconds)
    with deadline:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        index_bytes = source.fetch_index(maximum_bytes=bounds.maximum_index_bytes)
        deadline.check()
        index = parse_modified_index(
            index_bytes,
            maximum_bytes=bounds.maximum_index_bytes,
            maximum_rows=bounds.maximum_index_rows,
        )
        if len(index.source_entries) > bounds.maximum_records:
            raise OsvPublisherError(
                "source-record-limit",
                "OSV PYSEC source record count exceeds the configured maximum",
            )
        entry = next((item for item in index.source_entries if item.record_id == record_id), None)
        if entry is None:
            raise OsvPublisherError(
                "live-smoke-record-missing",
                "requested PYSEC record is not in the current index",
            )
        if entry.modified_at > current + timedelta(minutes=5):
            raise OsvPublisherError("source-future-dated", "OSV record index time is in the future")
        body = source.fetch_record(record_id, maximum_bytes=bounds.maximum_record_bytes)
        deadline.check()
        normalization = NormalizationReport()
        record = normalize_osv_record(
            parse_osv_record_bytes(body, expected_id=record_id),
            expected_modified=entry.modified_at,
            policy=PRODUCTION_POLICY,
            report=normalization,
        )
        deadline.check()
        digest = hashlib.sha256(canonical_json_bytes(record)).hexdigest()
        return {
            "status": "live-source-smoke-complete",
            "source_id": PRODUCTION_POLICY.source_id,
            "record_id": record.id,
            "record_modified": format_utc(record.modified_at),
            "normalized_record_sha256": digest,
            "license_identifier": record.source_license,
            "source_record_url": record.source_record_url,
            "adapter_version": ADAPTER_VERSION,
            "normalization": normalization.as_dict(),
            "raw_record_persisted": False,
        }
