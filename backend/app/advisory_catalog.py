"""Strict bounded offline advisory catalog parsing."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from .component_intelligence import (
    SUPPORTED_ECOSYSTEMS,
    normalize_ecosystem,
    normalize_version_text,
    parse_purl,
    purl_identity,
    validate_reference_url,
)
from .version_intelligence import compare_versions


ADVISORY_SCHEMA_VERSION = "oaw.advisory-catalog.v1"
MAX_CATALOG_BYTES = 8 << 20
MAX_ADVISORIES = 20_000
MAX_ALIASES = 32
MAX_AFFECTED_COMPONENTS = 64
MAX_RANGES = 32
MAX_REFERENCES = 16
MAX_EXACT_VERSIONS = 256
MAX_FIXED_VERSIONS = 32
MAX_PLATFORM_CONSTRAINTS = 16
MAX_CREDITS = 32
MAX_CREDIT_CONTACTS = 8
MAX_SEVERITY_VECTORS = 16

Severity = Literal["critical", "high", "medium", "low", "informational"]


class CatalogValidationError(ValueError):
    """Raised when an offline advisory catalog violates its strict contract."""


class StrictCatalogModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CatalogSource(StrictCatalogModel):
    name: str = Field(..., min_length=1, max_length=120)
    version: str = Field(..., min_length=1, max_length=80)
    license: str = Field(..., min_length=1, max_length=120)
    provenance: str = Field(..., min_length=1, max_length=500)


class AdvisoryReference(StrictCatalogModel):
    type: str = Field(..., min_length=1, max_length=40)
    url: str = Field(..., min_length=8, max_length=500)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        validated = validate_reference_url(value)
        if validated is None:
            raise ValueError("reference must be a bounded HTTP(S) URL without credentials or fragments")
        return validated


class AdvisoryCredit(StrictCatalogModel):
    name: str = Field(..., min_length=1, max_length=200)
    type: str | None = Field(default=None, min_length=1, max_length=40)
    contact: list[str] = Field(default_factory=list, max_length=MAX_CREDIT_CONTACTS)

    @field_validator("contact")
    @classmethod
    def validate_contacts(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            validated = validate_reference_url(value)
            if validated is None:
                raise ValueError("credit contacts must be bounded HTTP(S) URLs")
            normalized.append(validated)
        if len(normalized) != len(set(normalized)):
            raise ValueError("credit contacts contain duplicates")
        return normalized


class AdvisorySeverityVector(StrictCatalogModel):
    type: str = Field(..., min_length=1, max_length=40)
    score: str = Field(..., min_length=1, max_length=300)
    source: str | None = Field(default=None, min_length=1, max_length=120)


class AdvisoryRange(StrictCatalogModel):
    introduced: str | None = Field(default=None, max_length=160)
    introduced_unbounded: bool = False
    introduced_inclusive: bool = True
    fixed: str | None = Field(default=None, max_length=160)
    fixed_inclusive: bool = False
    last_affected: str | None = Field(default=None, max_length=160)
    last_affected_inclusive: bool = True

    @field_validator("introduced", "fixed", "last_affected")
    @classmethod
    def validate_versions(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = normalize_version_text(value)
        if normalized is None:
            raise ValueError("range version must be non-empty")
        return normalized

    @model_validator(mode="after")
    def require_boundary(self) -> "AdvisoryRange":
        if self.introduced_unbounded and self.introduced is not None:
            raise ValueError("unbounded range cannot have an introduced version")
        if (
            self.introduced is None
            and not self.introduced_unbounded
            and self.fixed is None
            and self.last_affected is None
        ):
            raise ValueError("range requires an introduced, fixed, or last_affected boundary")
        if self.fixed is not None and self.last_affected is not None:
            raise ValueError("range cannot use fixed and last_affected together")
        return self


class AffectedComponent(StrictCatalogModel):
    ecosystem: str = Field(..., min_length=1, max_length=40)
    name: str = Field(..., min_length=1, max_length=240)
    identifier: str | None = Field(default=None, max_length=600)
    namespace: str | None = Field(default=None, max_length=160)
    vendor: str | None = Field(default=None, max_length=160)
    ranges: list[AdvisoryRange] = Field(
        default_factory=list,
        max_length=MAX_RANGES,
    )
    exact_versions: list[str] = Field(
        default_factory=list,
        max_length=MAX_EXACT_VERSIONS,
    )
    fixed_versions: list[str] = Field(
        default_factory=list,
        max_length=MAX_FIXED_VERSIONS,
    )
    architectures: list[str] = Field(
        default_factory=list,
        max_length=MAX_PLATFORM_CONSTRAINTS,
    )
    platforms: list[str] = Field(
        default_factory=list,
        max_length=MAX_PLATFORM_CONSTRAINTS,
    )

    @field_validator("ecosystem")
    @classmethod
    def validate_ecosystem(cls, value: str) -> str:
        normalized = normalize_ecosystem(value)
        if normalized not in SUPPORTED_ECOSYSTEMS:
            raise ValueError("unsupported advisory ecosystem")
        return normalized

    @field_validator("identifier")
    @classmethod
    def validate_identifier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        identity = purl_identity(value)
        if identity is None:
            raise ValueError("identifier must be a canonical Package URL without a version")
        return identity

    @field_validator("exact_versions", "fixed_versions")
    @classmethod
    def validate_version_list(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            item = normalize_version_text(value)
            if item is None:
                raise ValueError("version list contains an empty version")
            normalized.append(item)
        if len(normalized) != len(set(normalized)):
            raise ValueError("version list contains duplicates")
        return normalized

    @field_validator("architectures", "platforms")
    @classmethod
    def validate_constraints(cls, values: list[str]) -> list[str]:
        normalized = [value.casefold() for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("constraint list contains duplicates")
        return normalized

    @model_validator(mode="after")
    def validate_identity_and_ranges(self) -> "AffectedComponent":
        if self.identifier is not None:
            parsed = parse_purl(self.identifier)
            if parsed is None or parsed.ecosystem != self.ecosystem:
                raise ValueError("identifier ecosystem does not match affected ecosystem")
        if not self.identifier and not self.vendor and self.ecosystem in {
            "firmware",
            "generic",
            "operating-system",
        }:
            raise ValueError("generic, firmware, and operating-system advisories require a reviewed vendor")
        if not self.ranges and not self.exact_versions:
            raise ValueError("affected component requires a range or exact version")
        for version_range in self.ranges:
            upper = version_range.fixed or version_range.last_affected
            if version_range.introduced is None or upper is None:
                continue
            comparison = compare_versions(
                self.ecosystem,
                version_range.introduced,
                upper,
            )
            if comparison.status != "supported" or comparison.order is None:
                raise ValueError(
                    "range boundaries must use a supported ecosystem version form"
                )
            if comparison.order > 0:
                raise ValueError(
                    "range introduced boundary must not exceed its upper boundary"
                )
            upper_inclusive = (
                version_range.fixed_inclusive
                if version_range.fixed is not None
                else version_range.last_affected_inclusive
            )
            if (
                comparison.order == 0
                and not (
                    version_range.introduced_inclusive
                    and upper_inclusive
                )
            ):
                raise ValueError("range boundaries define an empty interval")
        return self


class AdvisoryRecord(StrictCatalogModel):
    id: str = Field(..., pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$")
    aliases: list[str] = Field(default_factory=list, max_length=MAX_ALIASES)
    title: str = Field(..., min_length=1, max_length=240)
    summary: str = Field(..., min_length=1, max_length=1_000)
    severity: Severity
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    known_exploited: bool = False
    published_at: datetime
    modified_at: datetime
    withdrawn_at: datetime | None = None
    affected: list[AffectedComponent] = Field(
        ...,
        min_length=1,
        max_length=MAX_AFFECTED_COMPONENTS,
    )
    references: list[AdvisoryReference] = Field(
        default_factory=list,
        max_length=MAX_REFERENCES,
    )
    upstream: list[str] = Field(default_factory=list, max_length=MAX_ALIASES)
    related: list[str] = Field(default_factory=list, max_length=MAX_ALIASES)
    source_record_url: str | None = Field(default=None, min_length=8, max_length=500)
    source_license: str | None = Field(default=None, min_length=1, max_length=120)
    severity_basis: Literal[
        "legacy",
        "upstream-categorical",
        "upstream-vector",
        "derived-cvss-v3",
        "not-reported",
    ] = "legacy"
    upstream_severity: str | None = Field(default=None, min_length=1, max_length=80)
    severity_vectors: list[AdvisorySeverityVector] = Field(
        default_factory=list,
        max_length=MAX_SEVERITY_VECTORS,
    )
    credits: list[AdvisoryCredit] = Field(default_factory=list, max_length=MAX_CREDITS)

    @field_validator("aliases", "upstream", "related")
    @classmethod
    def validate_identifiers(cls, values: list[str]) -> list[str]:
        normalized = [value.strip().upper() for value in values]
        if any(not value or len(value) > 120 for value in normalized):
            raise ValueError("advisory identifier must be between 1 and 120 characters")
        if len(normalized) != len(set(normalized)):
            raise ValueError("advisory identifier list contains duplicates")
        return normalized

    @field_validator("source_record_url")
    @classmethod
    def validate_source_record_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        validated = validate_reference_url(value)
        if validated is None:
            raise ValueError("source record URL must be bounded and credential-free")
        return validated

    @field_validator("published_at", "modified_at", "withdrawn_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("advisory timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_timeline(self) -> "AdvisoryRecord":
        if self.modified_at < self.published_at:
            raise ValueError("modified_at must not precede published_at")
        if self.withdrawn_at is not None and self.withdrawn_at < self.published_at:
            raise ValueError("withdrawn_at must not precede published_at")
        if (self.source_record_url is None) != (self.source_license is None):
            raise ValueError("source record URL and source license must be supplied together")
        if self.severity_basis == "upstream-categorical" and not self.upstream_severity:
            raise ValueError("categorical severity requires its upstream value")
        if self.severity_basis == "upstream-vector" and not self.severity_vectors:
            raise ValueError("vector severity requires an upstream vector")
        if self.severity_basis == "derived-cvss-v3" and (
            not self.severity_vectors or self.cvss is None
        ):
            raise ValueError("derived CVSS severity requires a vector and base score")
        if self.severity_basis == "not-reported" and (
            self.upstream_severity is not None or self.severity_vectors
        ):
            raise ValueError("unreported severity cannot include upstream severity evidence")
        return self


class AdvisoryCatalog(StrictCatalogModel):
    schema_version: Literal["oaw.advisory-catalog.v1"]
    catalog_version: str = Field(..., min_length=1, max_length=120)
    source: CatalogSource
    generated_at: datetime
    advisories: list[AdvisoryRecord] = Field(
        ...,
        max_length=MAX_ADVISORIES,
    )

    @field_validator("generated_at")
    @classmethod
    def require_generated_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("generated_at must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_catalog_uniqueness(self) -> "AdvisoryCatalog":
        record_ids = [record.id.casefold() for record in self.advisories]
        if len(record_ids) != len(set(record_ids)):
            raise ValueError(
                "catalog contains case-insensitive duplicate advisory ids"
            )
        aliases: dict[str, str] = {}
        for record in self.advisories:
            for alias in record.aliases:
                owner = aliases.setdefault(alias, record.id)
                if owner != record.id:
                    raise ValueError("catalog alias maps to multiple advisories")
        return self


def catalog_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_catalog_bytes(data: bytes) -> tuple[AdvisoryCatalog, str]:
    if len(data) > MAX_CATALOG_BYTES:
        raise CatalogValidationError("advisory catalog exceeds the 8 MiB limit")
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogValidationError("advisory catalog must be valid UTF-8 JSON") from exc
    if not isinstance(raw, dict):
        raise CatalogValidationError("advisory catalog root must be an object")
    try:
        catalog = AdvisoryCatalog.model_validate(raw)
    except ValidationError as exc:
        raise CatalogValidationError(f"advisory catalog validation failed: {exc}") from exc
    canonical = json.dumps(
        catalog.model_dump(mode="json"),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return catalog, catalog_checksum(canonical)


def load_catalog(path: str | os.PathLike[str]) -> tuple[AdvisoryCatalog, str]:
    """Read a local regular file without following a final-component symlink."""

    candidate = Path(path)
    if not candidate.is_absolute():
        raise CatalogValidationError("advisory catalog path must be absolute")
    try:
        path_before = candidate.lstat()
    except OSError as exc:
        raise CatalogValidationError(
            "advisory catalog could not be inspected safely"
        ) from exc
    if not stat.S_ISREG(path_before.st_mode):
        raise CatalogValidationError(
            "advisory catalog path must name a regular file"
        )
    if path_before.st_nlink != 1:
        raise CatalogValidationError(
            "advisory catalog must have exactly one link"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise CatalogValidationError(
            "advisory catalog could not be opened safely"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CatalogValidationError("advisory catalog must be a regular file")
        if before.st_nlink != 1:
            raise CatalogValidationError("advisory catalog must have exactly one link")
        if before.st_size > MAX_CATALOG_BYTES:
            raise CatalogValidationError("advisory catalog exceeds the 8 MiB limit")
        if (
            before.st_dev,
            before.st_ino,
        ) != (
            path_before.st_dev,
            path_before.st_ino,
        ):
            raise CatalogValidationError(
                "advisory catalog path changed while it was opened"
            )
        try:
            path_after_open = candidate.lstat()
        except OSError as exc:
            raise CatalogValidationError(
                "advisory catalog path changed while it was opened"
            ) from exc
        if (
            not stat.S_ISREG(path_after_open.st_mode)
            or path_after_open.st_dev != before.st_dev
            or path_after_open.st_ino != before.st_ino
            or path_after_open.st_nlink != 1
        ):
            raise CatalogValidationError(
                "advisory catalog path changed while it was opened"
            )
        chunks: list[bytes] = []
        remaining = MAX_CATALOG_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 << 10, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise CatalogValidationError("advisory catalog changed while it was read")
    finally:
        os.close(descriptor)
    return parse_catalog_bytes(data)
