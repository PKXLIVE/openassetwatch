"""SSRF-resistant advisory download and private staging primitives."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import os
import secrets
import socket
import ssl
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Literal, Protocol
from urllib.parse import urlsplit

from .advisory_feed_registry import FeedSource


ArtifactKind = Literal["index", "index_signature", "manifest", "signature", "payload"]
MAX_DNS_ANSWERS = 32
MAX_RESPONSE_HEADERS = 100
READ_CHUNK_BYTES = 64 << 10
SAFE_ARTIFACT_NAMES = frozenset(
    {
        "manifest.json",
        "manifest.ed25519",
        "payload.bin",
        "catalog.json",
        "publisher-report.json",
    }
)


class DownloadSecurityError(ValueError):
    """A bounded, non-secret advisory download rejection."""

    def __init__(self, code: str, summary: str) -> None:
        super().__init__(summary)
        self.code = code[:80]
        self.summary = summary[:240]


@dataclass(frozen=True)
class TransportResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body_chunks: Iterable[bytes]
    peer_ip: str
    close: Callable[[], None]


class HttpsTransport(Protocol):
    def get(
        self,
        *,
        host: str,
        path: str,
        pinned_ip: str,
        connection_timeout: float,
        read_timeout: float,
    ) -> TransportResponse: ...


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, *, pinned_ip: str, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(host, port=443, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_ip, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


class PinnedHttpsTransport:
    """Connect to a validated address while retaining hostname TLS checks."""

    def __init__(
        self,
        *,
        ssl_context: ssl.SSLContext | None = None,
        user_agent: str = "OpenAssetWatch-Advisory-Sync/1",
    ) -> None:
        if (
            not user_agent
            or len(user_agent) > 200
            or not user_agent.isascii()
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in user_agent)
        ):
            raise ValueError("HTTPS transport user agent must be bounded printable ASCII")
        self.ssl_context = ssl_context or ssl.create_default_context()
        self.user_agent = user_agent

    def get(
        self,
        *,
        host: str,
        path: str,
        pinned_ip: str,
        connection_timeout: float,
        read_timeout: float,
    ) -> TransportResponse:
        connection = _PinnedHTTPSConnection(
            host,
            pinned_ip=pinned_ip,
            timeout=connection_timeout,
            context=self.ssl_context,
        )
        try:
            connection.connect()
            if connection.sock is None:
                raise DownloadSecurityError("connection-failed", "HTTPS connection did not establish safely")
            peer_ip = str(connection.sock.getpeername()[0])
            connection.sock.settimeout(read_timeout)
            # Supply exactly one reviewed Host header. putrequest would
            # otherwise add another Host field before the explicit value.
            connection.putrequest(
                "GET",
                path,
                skip_host=True,
                skip_accept_encoding=True,
            )
            connection.putheader("Host", host)
            connection.putheader(
                "Accept",
                "application/json, text/csv, text/plain, application/octet-stream, application/gzip",
            )
            connection.putheader("User-Agent", self.user_agent)
            connection.putheader("Connection", "close")
            connection.endheaders()
            response = connection.getresponse()
            headers = tuple((name, value) for name, value in response.getheaders())

            def chunks() -> Iterable[bytes]:
                try:
                    while True:
                        chunk = response.read(READ_CHUNK_BYTES)
                        if not chunk:
                            break
                        yield chunk
                finally:
                    connection.close()

            return TransportResponse(
                status=response.status,
                headers=headers,
                body_chunks=chunks(),
                peer_ip=peer_ip,
                close=connection.close,
            )
        except Exception:
            connection.close()
            raise


def _is_prohibited_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return True
    # Keep the explicit categories even when ``is_global`` changes across
    # Python/IP registry releases.  Some runtimes classify multicast as global.
    return (
        not address.is_global
        or address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


def resolve_public_addresses(
    host: str,
    *,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
) -> tuple[str, ...]:
    try:
        answers = resolver(host, 443, type=socket.SOCK_STREAM)
    except (OSError, socket.gaierror) as exc:
        raise DownloadSecurityError("dns-resolution-failed", "feed hostname could not be resolved") from exc
    addresses: list[str] = []
    for answer in answers[: MAX_DNS_ANSWERS + 1]:
        if len(answer) < 5 or not answer[4]:
            continue
        value = str(answer[4][0]).split("%", 1)[0]
        if value not in addresses:
            addresses.append(value)
    if not addresses or len(addresses) > MAX_DNS_ANSWERS:
        raise DownloadSecurityError("dns-answer-invalid", "feed hostname returned no bounded address set")
    if any(_is_prohibited_address(value) for value in addresses):
        raise DownloadSecurityError("dns-address-prohibited", "feed hostname resolved to a prohibited address")
    return tuple(sorted(addresses, key=lambda value: (ipaddress.ip_address(value).version, value)))


def validate_download_url(source: FeedSource, kind: ArtifactKind, url: str) -> tuple[str, str]:
    """Validate a candidate against the reviewed endpoint without accepting it as input.

    Production callers derive URLs exclusively from ``FeedSource``.  This helper
    makes the exact scheme, credential, host, port, query, fragment, and path
    policy explicit and independently testable for future transport adapters.
    """

    if source.retrieval_mode != "direct-bundle" or source.endpoint is None:
        raise DownloadSecurityError("url-source-mode-rejected", "source does not use direct bundle URLs")
    if kind not in {"manifest", "signature", "payload"}:
        raise DownloadSecurityError("url-artifact-kind-rejected", "artifact kind is not valid for direct bundle URLs")
    expected_path = {
        "manifest": source.endpoint.manifest_path,
        "signature": source.endpoint.signature_path,
        "payload": source.endpoint.payload_path,
    }[kind]
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise DownloadSecurityError("url-scheme-rejected", "feed artifacts require HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise DownloadSecurityError("url-credentials-rejected", "feed artifact URLs must not contain credentials")
    if parsed.port is not None:
        raise DownloadSecurityError("url-port-rejected", "feed artifact URLs must use the default HTTPS port")
    if parsed.hostname != source.endpoint.host:
        raise DownloadSecurityError("url-host-rejected", "feed artifact host is not the reviewed source host")
    if parsed.path != expected_path or parsed.query or parsed.fragment:
        raise DownloadSecurityError("url-path-rejected", "feed artifact path is not approved for this source")
    return source.endpoint.host, expected_path


@dataclass(frozen=True)
class DownloadedArtifact:
    kind: ArtifactKind
    body: bytes
    sha256: str
    content_type: str
    peer_ip: str


class AdvisoryDownloader:
    def __init__(
        self,
        *,
        transport: HttpsTransport | None = None,
        resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.transport = transport or PinnedHttpsTransport()
        self.resolver = resolver
        self.clock = clock

    def fetch(
        self,
        source: FeedSource,
        kind: ArtifactKind,
        *,
        total_timeout_seconds: float | None = None,
    ) -> DownloadedArtifact:
        if source.retrieval_mode == "direct-bundle":
            if source.endpoint is None or kind not in {"manifest", "signature", "payload"}:
                raise DownloadSecurityError("artifact-kind-rejected", "artifact kind is not valid for this source")
            host = source.endpoint.host
            path = {
                "manifest": source.endpoint.manifest_path,
                "signature": source.endpoint.signature_path,
                "payload": source.endpoint.payload_path,
            }[kind]
        else:
            if source.mirror is None or kind not in {"index", "index_signature"}:
                raise DownloadSecurityError("artifact-kind-rejected", "artifact kind is not valid for this source")
            host = source.mirror.host
            path = {
                "index": source.mirror.index_path,
                "index_signature": source.mirror.signature_path,
            }[kind]
        return self._fetch_path(
            source,
            kind,
            host=host,
            path=path,
            total_timeout_seconds=total_timeout_seconds,
        )

    def fetch_mirror_artifact(
        self,
        source: FeedSource,
        kind: Literal["manifest", "signature", "payload"],
        relative_path: str,
        *,
        total_timeout_seconds: float | None = None,
    ) -> DownloadedArtifact:
        """Fetch one path authenticated by a verified mirror index from its reviewed host."""

        if source.retrieval_mode != "signed-mirror-index" or source.mirror is None:
            raise DownloadSecurityError("mirror-source-mode-rejected", "source does not use a signed mirror index")
        if not _valid_mirror_relative_path(relative_path):
            raise DownloadSecurityError("mirror-path-rejected", "signed mirror artifact path is unsafe")
        expected_name = {
            "manifest": "manifest.json",
            "signature": "manifest.ed25519",
            "payload": source.expected_payload_name,
        }[kind]
        if relative_path.rsplit("/", 1)[-1] != expected_name:
            raise DownloadSecurityError("mirror-path-kind-mismatch", "signed mirror path does not match its artifact kind")
        return self._fetch_path(
            source,
            kind,
            host=source.mirror.host,
            path=source.mirror.artifact_path(relative_path),
            total_timeout_seconds=total_timeout_seconds,
        )

    def _fetch_path(
        self,
        source: FeedSource,
        kind: ArtifactKind,
        *,
        host: str,
        path: str,
        total_timeout_seconds: float | None,
    ) -> DownloadedArtifact:
        maximum = {
            "index": source.limits.maximum_mirror_index_bytes,
            "index_signature": source.limits.maximum_signature_bytes,
            "manifest": source.limits.maximum_manifest_bytes,
            "signature": source.limits.maximum_signature_bytes,
            "payload": source.limits.maximum_compressed_bytes,
        }[kind]
        started = self.clock()
        total_timeout = min(
            source.limits.total_timeout_seconds,
            total_timeout_seconds
            if total_timeout_seconds is not None
            else source.limits.total_timeout_seconds,
        )
        if total_timeout <= 0:
            raise DownloadSecurityError("download-timeout", "feed artifact exceeded the total download timeout")
        addresses = resolve_public_addresses(host, resolver=self.resolver)
        pinned_ip = addresses[0]
        try:
            response = self.transport.get(
                host=host,
                path=path,
                pinned_ip=pinned_ip,
                connection_timeout=source.limits.connection_timeout_seconds,
                read_timeout=source.limits.read_timeout_seconds,
            )
        except DownloadSecurityError:
            raise
        except (OSError, TimeoutError, socket.timeout, ssl.SSLError, http.client.HTTPException) as exc:
            raise DownloadSecurityError("download-failed", "feed artifact download failed safely") from exc
        try:
            if response.peer_ip != pinned_ip:
                raise DownloadSecurityError("dns-peer-mismatch", "connected peer did not match the validated DNS address")
            if 300 <= response.status <= 399:
                raise DownloadSecurityError("redirect-rejected", "feed redirects are disabled")
            if response.status != 200:
                raise DownloadSecurityError("http-status-rejected", "feed returned an unexpected HTTP status")
            if len(response.headers) > MAX_RESPONSE_HEADERS:
                raise DownloadSecurityError("response-headers-too-large", "feed returned too many response headers")
            header_bytes = 0
            normalized_headers: dict[str, str] = {}
            for name, value in response.headers:
                key = name.casefold()
                header_bytes += len(name.encode("utf-8", "replace")) + len(value.encode("utf-8", "replace")) + 4
                if key in normalized_headers and key in {"content-length", "content-type", "content-encoding", "location"}:
                    raise DownloadSecurityError("response-header-ambiguous", "feed returned an ambiguous security-sensitive header")
                normalized_headers[key] = value.strip()
            if header_bytes > source.limits.maximum_response_header_bytes:
                raise DownloadSecurityError("response-headers-too-large", "feed response headers exceed the configured limit")
            content_encoding = normalized_headers.get("content-encoding", "identity").casefold()
            if content_encoding not in {"", "identity"}:
                raise DownloadSecurityError("http-content-encoding-rejected", "HTTP content encoding is not supported for feed artifacts")
            content_type = normalized_headers.get("content-type", "").split(";", 1)[0].strip().casefold()
            if content_type not in source.expected_content_types[kind]:
                raise DownloadSecurityError("content-type-rejected", "feed artifact content type is not approved")
            declared_length = normalized_headers.get("content-length")
            if declared_length:
                try:
                    declared = int(declared_length, 10)
                except ValueError as exc:
                    raise DownloadSecurityError("content-length-invalid", "feed content length is invalid") from exc
                if declared < 0 or declared > maximum:
                    raise DownloadSecurityError("artifact-too-large", "feed artifact exceeds the configured byte limit")
            body = bytearray()
            digest = hashlib.sha256()
            for chunk in response.body_chunks:
                if self.clock() - started > total_timeout:
                    raise DownloadSecurityError("download-timeout", "feed artifact exceeded the total download timeout")
                if not isinstance(chunk, bytes):
                    raise DownloadSecurityError("transport-invalid", "feed transport returned an invalid body chunk")
                body.extend(chunk)
                if len(body) > maximum:
                    raise DownloadSecurityError("artifact-too-large", "feed artifact exceeds the configured byte limit")
                digest.update(chunk)
            if declared_length and len(body) != int(declared_length, 10):
                raise DownloadSecurityError("content-length-mismatch", "feed artifact length does not match response metadata")
            if not body:
                raise DownloadSecurityError("artifact-empty", "feed artifact is empty")
            return DownloadedArtifact(
                kind=kind,
                body=bytes(body),
                sha256=digest.hexdigest(),
                content_type=content_type,
                peer_ip=pinned_ip,
            )
        except DownloadSecurityError:
            raise
        except (OSError, TimeoutError, socket.timeout, http.client.HTTPException) as exc:
            raise DownloadSecurityError("download-failed", "feed artifact body could not be read safely") from exc
        finally:
            response.close()


def _valid_mirror_relative_path(value: str) -> bool:
    if (
        not value
        or len(value) > 500
        or not value.isascii()
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or "%" in value
        or "?" in value
        or "#" in value
        or "//" in value
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in value)
    ):
        return False
    segments = value.split("/")
    return all(segment not in {"", ".", ".."} for segment in segments)


class StagingSecurityError(ValueError):
    def __init__(self, code: str, summary: str) -> None:
        super().__init__(summary)
        self.code = code[:80]
        self.summary = summary[:240]


def configured_staging_root() -> Path:
    configured = os.getenv("OPENASSETWATCH_ADVISORY_STAGING_ROOT", "").strip()
    if configured:
        candidate = Path(configured)
        if not candidate.is_absolute():
            raise StagingSecurityError("staging-root-relative", "advisory staging root must be absolute")
        return candidate
    if os.name == "nt":
        return Path(tempfile.gettempdir()) / "openassetwatch-advisory-staging"
    return Path("/var/lib/openassetwatch/advisory-staging")


def _fsync_directory(path: Path) -> None:
    if os.name == "nt" or not hasattr(os, "O_DIRECTORY"):
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_single_link_file(path: Path, *, maximum_bytes: int) -> bytes:
    """Read one reviewed local artifact without following replacement links."""

    if not path.is_absolute() or maximum_bytes < 1:
        raise StagingSecurityError("local-bundle-path-invalid", "reviewed local bundle path is invalid")
    try:
        path_info = path.lstat()
    except OSError as exc:
        raise StagingSecurityError("local-bundle-file-invalid", "reviewed local bundle file could not be inspected") from exc
    if not stat.S_ISREG(path_info.st_mode) or path_info.st_nlink != 1:
        raise StagingSecurityError("local-bundle-file-unsafe", "reviewed local bundle artifact must be a single-link regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StagingSecurityError("local-bundle-open-failed", "reviewed local bundle artifact could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (path_info.st_dev, path_info.st_ino)
            or opened.st_size > maximum_bytes
        ):
            raise StagingSecurityError("local-bundle-file-unsafe", "reviewed local bundle artifact changed or exceeds its limit")
        output = bytearray()
        while len(output) <= maximum_bytes:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, maximum_bytes + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
        after = os.fstat(descriptor)
        if len(output) > maximum_bytes:
            raise StagingSecurityError("local-bundle-file-too-large", "reviewed local bundle artifact exceeds its limit")
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise StagingSecurityError("local-bundle-file-changed", "reviewed local bundle artifact changed while it was read")
        path_after = path.lstat()
        if (path_after.st_dev, path_after.st_ino, path_after.st_nlink) != (
            opened.st_dev,
            opened.st_ino,
            1,
        ):
            raise StagingSecurityError("local-bundle-file-changed", "reviewed local bundle path changed while it was read")
        return bytes(output)
    finally:
        os.close(descriptor)


def _validate_directory(
    path: Path,
    *,
    require_private: bool,
    allow_root_owner: bool = False,
) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise StagingSecurityError("staging-directory-invalid", "staging directory could not be inspected safely") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise StagingSecurityError("staging-directory-invalid", "staging path must be a directory")
    if require_private and os.name != "nt" and info.st_mode & 0o077:
        raise StagingSecurityError("staging-permissions-unsafe", "staging directory permissions are not private")
    if hasattr(os, "getuid"):
        allowed_owners = {os.getuid()}
        if allow_root_owner:
            allowed_owners.add(0)
        if info.st_uid not in allowed_owners:
            raise StagingSecurityError("staging-owner-unsafe", "staging directory has the wrong owner")
    return info


def _validate_parent_chain(path: Path) -> None:
    """Reject link traversal and writable/foreign owners in existing parents."""

    if os.name == "nt":
        return
    allowed_owners = {0}
    if hasattr(os, "getuid"):
        allowed_owners.add(os.getuid())
    current = path
    while True:
        info = _validate_directory(
            current,
            require_private=False,
            allow_root_owner=True,
        )
        if info.st_uid not in allowed_owners:
            raise StagingSecurityError("staging-parent-owner-unsafe", "staging parent has an untrusted owner")
        writable = info.st_mode & 0o022
        if writable and not (info.st_mode & stat.S_ISVTX):
            raise StagingSecurityError("staging-parent-unsafe", "staging parent is writable by another account")
        if current == current.parent:
            break
        current = current.parent


class PrivateStagingArea:
    """Write only known artifacts beneath a private, process-owned root."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or configured_staging_root()).absolute()
        static_root = (Path(__file__).resolve().parent / "static").absolute()
        try:
            self.root.relative_to(static_root)
        except ValueError:
            pass
        else:
            raise StagingSecurityError("staging-under-web-root", "advisory staging must remain outside the web root")

    def ensure_root(self) -> None:
        parent = self.root.parent
        if not parent.exists():
            raise StagingSecurityError(
                "staging-parent-missing",
                "advisory staging parent must be created by the deployment owner",
            )
        _validate_parent_chain(parent)
        try:
            os.mkdir(self.root, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise StagingSecurityError(
                "staging-directory-invalid",
                "staging directory could not be created safely",
            ) from exc
        _validate_parent_chain(parent)
        if os.name == "nt":
            _validate_directory(self.root, require_private=True)
            return

        no_follow = getattr(os, "O_NOFOLLOW", 0)
        if not no_follow:
            raise StagingSecurityError(
                "staging-no-follow-unavailable",
                "platform cannot open the staging root without following links",
            )
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | no_follow
        try:
            descriptor = os.open(self.root, flags)
        except OSError as exc:
            raise StagingSecurityError(
                "staging-directory-invalid",
                "staging directory could not be opened without following links",
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISDIR(opened.st_mode):
                raise StagingSecurityError("staging-directory-invalid", "staging path is not a directory")
            if hasattr(os, "getuid") and opened.st_uid != os.getuid():
                raise StagingSecurityError("staging-owner-unsafe", "staging directory has the wrong owner")
            os.fchmod(descriptor, 0o700)
            opened = os.fstat(descriptor)
            if opened.st_mode & 0o077:
                raise StagingSecurityError("staging-permissions-unsafe", "staging directory permissions are not private")
            linked = self.root.lstat()
            if (
                not stat.S_ISDIR(linked.st_mode)
                or linked.st_dev != opened.st_dev
                or linked.st_ino != opened.st_ino
            ):
                raise StagingSecurityError(
                    "staging-directory-changed",
                    "staging directory changed while it was opened",
                )
        finally:
            os.close(descriptor)

    def create_run_directory(self, run_id: str) -> Path:
        if not run_id.startswith("afrun_") or len(run_id) > 80 or not run_id.replace("_", "").isalnum():
            raise StagingSecurityError("run-id-invalid", "run ID is not safe for private staging")
        self.ensure_root()
        path = self.root / f"{run_id}-{secrets.token_hex(8)}"
        path.mkdir(mode=0o700)
        if os.name != "nt":
            os.chmod(path, 0o700)
        _validate_directory(path, require_private=True)
        _fsync_directory(self.root)
        return path

    def write_artifact(self, run_directory: Path, name: str, data: bytes) -> Path:
        if name not in SAFE_ARTIFACT_NAMES:
            raise StagingSecurityError("staging-name-invalid", "staging artifact name is not approved")
        run_info = _validate_directory(run_directory, require_private=True)
        root_info = _validate_directory(self.root, require_private=True)
        if run_directory.parent != self.root or run_info.st_dev != root_info.st_dev:
            raise StagingSecurityError("staging-path-invalid", "run staging directory is outside the private root")
        temporary = run_directory / f".{name}.{secrets.token_hex(8)}.tmp"
        final = run_directory / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise StagingSecurityError("staging-write-failed", "staging artifact could not be written safely")
                view = view[written:]
            os.fsync(descriptor)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise StagingSecurityError("staging-file-unsafe", "staging artifact is not a single-link regular file")
        finally:
            os.close(descriptor)
        if final.exists() or final.is_symlink():
            temporary.unlink(missing_ok=True)
            raise StagingSecurityError("staging-file-exists", "staging artifact already exists")
        os.replace(temporary, final)
        _fsync_directory(run_directory)
        final_info = final.lstat()
        if not stat.S_ISREG(final_info.st_mode) or final_info.st_nlink != 1:
            raise StagingSecurityError("staging-file-unsafe", "staging artifact was replaced unsafely")
        return final

    def cleanup(self, run_directory: Path) -> None:
        if run_directory.parent != self.root:
            raise StagingSecurityError("staging-path-invalid", "cleanup target is outside the private staging root")
        _validate_directory(run_directory, require_private=True)
        for entry in run_directory.iterdir():
            info = entry.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise StagingSecurityError("staging-cleanup-unsafe", "staging cleanup found an unexpected entry")
            entry.unlink()
        run_directory.rmdir()
        _fsync_directory(self.root)

    def cleanup_abandoned(
        self,
        *,
        older_than_seconds: int = 3600,
        maximum_directories: int = 100,
        wall_clock: Callable[[], float] = time.time,
    ) -> int:
        if older_than_seconds < 300 or not 1 <= maximum_directories <= 100:
            raise StagingSecurityError("staging-cleanup-bounds", "staging cleanup bounds are invalid")
        self.ensure_root()
        entries = list(self.root.iterdir())
        if len(entries) > maximum_directories:
            raise StagingSecurityError("staging-cleanup-limit", "staging directory count exceeds the cleanup limit")
        removed = 0
        cutoff = wall_clock() - older_than_seconds
        for entry in entries:
            info = entry.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or not entry.name.startswith("afrun_")
                or entry.name.count("-") != 1
                or info.st_mtime > cutoff
            ):
                continue
            self.cleanup(entry)
            removed += 1
        return removed
