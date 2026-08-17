"""Bounded local vendor/OUI catalog support.

The catalog is local data only.  This module never performs network requests
and accepts no URL as an import source.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Mapping

from .classification import bounded_text


CATALOG_SCHEMA_VERSION = "oaw.vendor-catalog.v1"
DEFAULT_CATALOG_FILENAME = "vendor-catalog.json"
MAX_CATALOG_BYTES = 1 << 20
MAX_CATALOG_ENTRIES = 4096
MAX_VENDOR_NAME_LENGTH = 160
CATALOG_PATH_ENV = "OPENASSETWATCH_VENDOR_CATALOG_PATH"
_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_PREFIX_PATTERN = re.compile(r"^[0-9A-F]{6}$")
_CHECKSUM_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class CatalogValidationError(ValueError):
    """The catalog is malformed, ambiguous, or exceeds reviewed bounds."""


class CatalogPathError(ValueError):
    """The catalog path or filesystem object is unsafe."""


@dataclass(frozen=True)
class VendorCatalogEntry:
    prefix: str
    manufacturer: str


@dataclass(frozen=True)
class VendorCatalog:
    schema_version: str
    catalog_version: str
    source_name: str
    source_license: str
    source_url: str | None
    checksum: str | None
    entries: tuple[VendorCatalogEntry, ...]

    def lookup(self, mac_address: str | None) -> str | None:
        prefix = normalize_mac_prefix(mac_address)
        if prefix is None:
            return None
        for entry in self.entries:
            if entry.prefix == prefix:
                return entry.manufacturer
        return None

    def status(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "catalog_version": self.catalog_version,
            "source_name": self.source_name,
            "source_license": self.source_license,
            "source_url": self.source_url,
            "checksum": self.checksum,
            "entry_count": len(self.entries),
            "network_lookup": False,
        }


def normalize_prefix(value: Any) -> str:
    if not isinstance(value, str):
        raise CatalogValidationError("catalog prefix must be a string")
    compact = re.sub(r"[-:.]", "", value.strip()).upper()
    if not _PREFIX_PATTERN.fullmatch(compact):
        raise CatalogValidationError("catalog prefixes must contain exactly six hexadecimal digits")
    return compact


def normalize_mac_prefix(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    compact = re.sub(r"[-:.]", "", value.strip()).upper()
    if len(compact) != 12 or any(character not in "0123456789ABCDEF" for character in compact):
        return None
    return compact[:6]


def _strict_keys(
    value: Mapping[str, Any],
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
    label: str,
) -> None:
    keys = frozenset(value)
    missing = required - keys
    unexpected = keys - required - optional
    if missing:
        raise CatalogValidationError(f"{label} is missing required fields: {', '.join(sorted(missing))}")
    if unexpected:
        raise CatalogValidationError(f"{label} contains unsupported fields: {', '.join(sorted(unexpected))}")


def _catalog_checksum(payload: Mapping[str, Any]) -> str:
    material = {
        "schema_version": payload["schema_version"],
        "catalog_version": payload["catalog_version"],
        "source": payload["source"],
        "entries": payload["entries"],
    }
    encoded = json.dumps(
        material,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def parse_catalog_bytes(data: bytes) -> VendorCatalog:
    if len(data) > MAX_CATALOG_BYTES:
        raise CatalogValidationError("catalog exceeds the maximum supported size")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogValidationError("catalog must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise CatalogValidationError("catalog root must be a JSON object")
    _strict_keys(
        payload,
        required=frozenset({"schema_version", "catalog_version", "source", "entries"}),
        optional=frozenset({"checksum"}),
        label="catalog",
    )
    if payload["schema_version"] != CATALOG_SCHEMA_VERSION:
        raise CatalogValidationError("unsupported catalog schema version")
    catalog_version = bounded_text(payload["catalog_version"], limit=80)
    if not _VERSION_PATTERN.fullmatch(catalog_version):
        raise CatalogValidationError("invalid catalog version")
    source = payload["source"]
    if not isinstance(source, dict):
        raise CatalogValidationError("catalog source must be an object")
    _strict_keys(
        source,
        required=frozenset({"name", "license"}),
        optional=frozenset({"url"}),
        label="catalog source",
    )
    source_name = bounded_text(source["name"], limit=160)
    source_license = bounded_text(source["license"], limit=120)
    source_url = bounded_text(source.get("url"), limit=512) or None
    if not source_name or not source_license:
        raise CatalogValidationError("catalog source name and license are required")
    entries = payload["entries"]
    if not isinstance(entries, list):
        raise CatalogValidationError("catalog entries must be an array")
    if len(entries) > MAX_CATALOG_ENTRIES:
        raise CatalogValidationError("catalog contains too many entries")
    parsed_entries: list[VendorCatalogEntry] = []
    seen_prefixes: set[str] = set()
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            raise CatalogValidationError(f"catalog entry {index} must be an object")
        _strict_keys(
            item,
            required=frozenset({"prefix", "manufacturer"}),
            label=f"catalog entry {index}",
        )
        prefix = normalize_prefix(item["prefix"])
        manufacturer = bounded_text(item["manufacturer"], limit=MAX_VENDOR_NAME_LENGTH)
        if not manufacturer:
            raise CatalogValidationError(f"catalog entry {index} has an empty manufacturer")
        if prefix in seen_prefixes:
            raise CatalogValidationError(f"duplicate catalog prefix: {prefix}")
        seen_prefixes.add(prefix)
        parsed_entries.append(VendorCatalogEntry(prefix=prefix, manufacturer=manufacturer))
    checksum = payload.get("checksum")
    if checksum is not None:
        if not isinstance(checksum, str) or not _CHECKSUM_PATTERN.fullmatch(checksum):
            raise CatalogValidationError("catalog checksum must use sha256:<lowercase hex>")
        calculated = _catalog_checksum(payload)
        if not secrets.compare_digest(checksum, calculated):
            raise CatalogValidationError("catalog checksum does not match its contents")
    return VendorCatalog(
        schema_version=CATALOG_SCHEMA_VERSION,
        catalog_version=catalog_version,
        source_name=source_name,
        source_license=source_license,
        source_url=source_url,
        checksum=checksum,
        entries=tuple(sorted(parsed_entries, key=lambda entry: entry.prefix)),
    )


def _safe_open_read(path: Path) -> tuple[int, BinaryIO]:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CatalogPathError("catalog could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise CatalogPathError("catalog must be a regular file")
        if opened.st_nlink != 1:
            raise CatalogPathError("catalog must have exactly one filesystem link")
        if opened.st_size > MAX_CATALOG_BYTES:
            raise CatalogValidationError("catalog exceeds the maximum supported size")
        current = path.lstat()
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_dev != opened.st_dev
            or current.st_ino != opened.st_ino
        ):
            raise CatalogPathError("catalog path changed while it was opened")
        return descriptor, os.fdopen(descriptor, "rb", closefd=False)
    except Exception:
        os.close(descriptor)
        raise


def load_catalog(path: str | os.PathLike[str]) -> VendorCatalog:
    catalog_path = Path(path)
    if not catalog_path.is_absolute():
        raise CatalogPathError("catalog path must be absolute")
    descriptor, handle = _safe_open_read(catalog_path)
    try:
        data = handle.read(MAX_CATALOG_BYTES + 1)
    finally:
        handle.close()
        os.close(descriptor)
    return parse_catalog_bytes(data)


def configured_catalog_path(environ: Mapping[str, str] | None = None) -> Path:
    values = os.environ if environ is None else environ
    configured = values.get(CATALOG_PATH_ENV)
    if configured and configured.strip():
        path = Path(configured.strip())
        if not path.is_absolute():
            raise CatalogPathError("configured catalog path must be absolute")
        return path
    return Path(__file__).resolve().parents[1] / "catalogs" / "synthetic-vendor-catalog.json"


def load_configured_catalog(environ: Mapping[str, str] | None = None) -> VendorCatalog:
    return load_catalog(configured_catalog_path(environ))


def configured_catalog_status(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    try:
        catalog = load_configured_catalog(environ)
    except FileNotFoundError:
        return {
            "available": False,
            "network_lookup": False,
            "status": "not-configured",
            "error_code": "catalog-not-found",
        }
    except CatalogPathError:
        return {
            "available": False,
            "network_lookup": False,
            "status": "invalid",
            "error_code": "unsafe-catalog-path",
        }
    except CatalogValidationError:
        return {
            "available": False,
            "network_lookup": False,
            "status": "invalid",
            "error_code": "invalid-catalog",
        }
    return {
        "available": True,
        **catalog.status(),
        "status": "ready",
        "error_code": None,
    }


def _validate_directory_metadata(metadata: os.stat_result, *, target: bool) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise CatalogPathError("catalog path must contain only real directories")
    if target:
        if metadata.st_uid != os.geteuid():
            raise CatalogPathError("catalog target directory has the wrong owner")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise CatalogPathError("catalog target directory is group- or world-writable")
        return
    writable_by_others = metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    sticky = metadata.st_mode & stat.S_ISVTX
    if writable_by_others and not sticky:
        raise CatalogPathError("catalog target has an unsafe writable ancestor")


def _validate_target_directory(directory: Path) -> tuple[Path, os.stat_result]:
    if not directory.is_absolute():
        raise CatalogPathError("catalog target directory must be absolute")
    if os.name != "posix":
        raise CatalogPathError(
            "safe catalog replacement requires POSIX directory-relative filesystem operations"
        )
    try:
        metadata = directory.lstat()
    except OSError as exc:
        raise CatalogPathError("catalog target directory does not exist") from exc
    if not stat.S_ISDIR(metadata.st_mode) or directory.is_symlink():
        raise CatalogPathError("catalog target must be a real directory")
    _validate_directory_metadata(metadata, target=True)
    for ancestor in directory.parents:
        try:
            ancestor_metadata = ancestor.lstat()
        except OSError as exc:
            raise CatalogPathError("catalog target ancestor could not be inspected") from exc
        if ancestor.is_symlink():
            raise CatalogPathError("catalog target may not traverse symlinked directories")
        _validate_directory_metadata(ancestor_metadata, target=False)
    return directory, metadata


def replace_catalog(
    *,
    source_path: str | os.PathLike[str],
    target_directory: str | os.PathLike[str],
) -> Path:
    """Validate and atomically install one catalog at a fixed local filename."""

    source = Path(source_path)
    catalog = load_catalog(source)
    directory, validated_directory = _validate_target_directory(Path(target_directory))
    target = directory / DEFAULT_CATALOG_FILENAME
    serialized_payload: dict[str, Any] = {
        "schema_version": catalog.schema_version,
        "catalog_version": catalog.catalog_version,
        "source": {
            "name": catalog.source_name,
            "license": catalog.source_license,
            **({"url": catalog.source_url} if catalog.source_url else {}),
        },
        "entries": [
            {"prefix": entry.prefix, "manufacturer": entry.manufacturer}
            for entry in catalog.entries
        ],
    }
    if catalog.checksum:
        serialized_payload["checksum"] = catalog.checksum
    serialized = (
        json.dumps(serialized_payload, ensure_ascii=True, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")

    dir_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    directory_descriptor: int | None = None
    if os.name == "posix":
        dir_flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            directory_descriptor = os.open(directory, dir_flags)
        except OSError as exc:
            raise CatalogPathError("catalog target directory could not be opened safely") from exc
        opened_directory = os.fstat(directory_descriptor)
        try:
            current_directory = directory.lstat()
        except OSError as exc:
            os.close(directory_descriptor)
            raise CatalogPathError("catalog target directory changed during open") from exc
        if (
            opened_directory.st_dev != validated_directory.st_dev
            or opened_directory.st_ino != validated_directory.st_ino
            or current_directory.st_dev != opened_directory.st_dev
            or current_directory.st_ino != opened_directory.st_ino
        ):
            os.close(directory_descriptor)
            raise CatalogPathError("catalog target directory changed during open")
        try:
            _validate_directory_metadata(opened_directory, target=True)
        except Exception:
            os.close(directory_descriptor)
            raise
    temporary_name = f".{DEFAULT_CATALOG_FILENAME}.{secrets.token_hex(12)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        if directory_descriptor is None:
            raise CatalogPathError("safe catalog replacement is unavailable")
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_descriptor)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary_name,
            DEFAULT_CATALOG_FILENAME,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        os.fsync(directory_descriptor)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            if directory_descriptor is not None:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
        except OSError:
            pass
        raise
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
    return target
