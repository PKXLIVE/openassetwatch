"""Strict OSV PyPI source parsing and OpenAssetWatch catalog normalization.

This module is imported only by the one-shot publisher.  It does not perform
network I/O and is never imported by backend request handling or startup.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urlsplit

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .advisory_catalog import (
    ADVISORY_SCHEMA_VERSION,
    MAX_ADVISORIES,
    MAX_CREDITS,
    MAX_EXACT_VERSIONS,
    MAX_FIXED_VERSIONS,
    MAX_RANGES,
    MAX_REFERENCES,
    MAX_SEVERITY_VECTORS,
    AdvisoryCatalog,
    AdvisoryCredit,
    AdvisoryRange,
    AdvisoryRecord,
    AdvisoryReference,
    AdvisorySeverityVector,
    AffectedComponent,
    CatalogSource,
)
from .component_intelligence import build_purl, parse_purl, validate_reference_url
from .version_intelligence import compare_versions, version_satisfies_range


ADAPTER_NAME = "OpenAssetWatch OSV PyPI publisher"
ADAPTER_VERSION = "1.0.0"
PUBLISHER_STATE_SCHEMA = "oaw.osv-pypi-publisher-state.v1"
OSV_HOST = "storage.googleapis.com"
OSV_INDEX_PATH = "/osv-vulnerabilities/PyPI/modified_id.csv"
OSV_RECORD_PREFIX = "/osv-vulnerabilities/PyPI/"
OSV_INDEX_URL = f"https://{OSV_HOST}{OSV_INDEX_PATH}"
PYPI_DATABASE_URL = "https://github.com/pypa/advisory-database"
OSV_DATA_DOCUMENTATION_URL = "https://google.github.io/osv.dev/data/"
CC_BY_LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/"
PYPI_LICENSE = "CC-BY-4.0"

MAX_INDEX_BYTES = 4 << 20
MAX_INDEX_ROWS = 50_000
MAX_OSV_RECORD_BYTES = 512 << 10
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 25_000
MAX_OSV_DETAILS = 64_000
MAX_OSV_VERSIONS = 4_096
MAX_OSV_AFFECTED = 64
MAX_OSV_EVENTS = 128
MAX_OSV_ALIASES = 32
MAX_OSV_IDENTIFIER = 120
MAX_REPORT_IDS = 20
MAX_REPORT_PREFIXES = 20

_INDEX_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_PYSEC_ID_RE = re.compile(r"^PYSEC-[0-9]{4}-[0-9]{1,12}$")
_OSV_SCHEMA_RE = re.compile(r"^(?P<major>[0-9]+)(?:\.[0-9]+){1,2}$")
_UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$"
)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CATEGORY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "informational",
    "UNKNOWN": "informational",
}
_CVSS3_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},
}
_CVSS3_REQUIRED = frozenset({"AV", "AC", "PR", "UI", "S", "C", "I", "A"})


class OsvPublisherError(ValueError):
    """A bounded publisher rejection safe to expose in status output."""

    def __init__(self, code: str, summary: str, *, record_id: str | None = None) -> None:
        super().__init__(summary)
        self.code = code[:80]
        self.summary = summary[:240]
        self.record_id = record_id[:120] if record_id else None


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class OsvSeverity(_StrictModel):
    type: str = Field(..., min_length=1, max_length=40)
    score: str = Field(..., min_length=1, max_length=300)
    source: str | None = Field(default=None, min_length=1, max_length=120)


class OsvPackage(_StrictModel):
    ecosystem: str = Field(..., min_length=1, max_length=40)
    name: str = Field(..., min_length=1, max_length=240)
    purl: str | None = Field(default=None, min_length=8, max_length=600)


class OsvRangeEvent(_StrictModel):
    introduced: str | None = Field(default=None, min_length=1, max_length=160)
    fixed: str | None = Field(default=None, min_length=1, max_length=160)
    last_affected: str | None = Field(default=None, min_length=1, max_length=160)
    limit: str | None = Field(default=None, min_length=1, max_length=160)

    @model_validator(mode="after")
    def exactly_one_event(self) -> "OsvRangeEvent":
        if sum(value is not None for value in (self.introduced, self.fixed, self.last_affected, self.limit)) != 1:
            raise ValueError("OSV range event must contain exactly one boundary")
        return self


class OsvRange(_StrictModel):
    type: str = Field(..., min_length=1, max_length=40)
    repo: str | None = Field(default=None, min_length=1, max_length=500)
    events: list[OsvRangeEvent] = Field(..., min_length=1, max_length=MAX_OSV_EVENTS)
    database_specific: dict[str, Any] = Field(default_factory=dict)

    @field_validator("database_specific")
    @classmethod
    def reject_range_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        if value:
            raise ValueError("OSV range database_specific metadata is not allowlisted")
        return value


class OsvAffected(_StrictModel):
    package: OsvPackage
    severity: list[OsvSeverity] = Field(default_factory=list, max_length=MAX_SEVERITY_VECTORS)
    ranges: list[OsvRange] = Field(default_factory=list, max_length=MAX_RANGES)
    versions: list[str] = Field(default_factory=list, max_length=MAX_OSV_VERSIONS)
    ecosystem_specific: dict[str, Any] = Field(default_factory=dict)
    database_specific: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ecosystem_specific")
    @classmethod
    def allow_ecosystem_severity(cls, value: dict[str, Any]) -> dict[str, Any]:
        if set(value) - {"severity"}:
            raise ValueError("OSV ecosystem_specific metadata contains unreviewed fields")
        if "severity" in value and (
            not isinstance(value["severity"], str) or not 1 <= len(value["severity"]) <= 80
        ):
            raise ValueError("OSV ecosystem severity is invalid")
        return value

    @field_validator("database_specific")
    @classmethod
    def allow_source_link(cls, value: dict[str, Any]) -> dict[str, Any]:
        if set(value) - {"source"}:
            raise ValueError("OSV affected database_specific metadata contains unreviewed fields")
        if "source" in value and (
            not isinstance(value["source"], str) or not 8 <= len(value["source"]) <= 500
        ):
            raise ValueError("OSV affected source metadata is invalid")
        return value


class OsvReference(_StrictModel):
    type: str = Field(..., min_length=1, max_length=40)
    url: str = Field(..., min_length=8, max_length=500)


class OsvCredit(_StrictModel):
    name: str = Field(..., min_length=1, max_length=200)
    contact: list[str] = Field(default_factory=list, max_length=8)
    type: str | None = Field(default=None, min_length=1, max_length=40)


class OsvRecord(_StrictModel):
    schema_version: str = Field(..., min_length=3, max_length=20)
    id: str = Field(..., min_length=3, max_length=120)
    modified: str = Field(..., min_length=20, max_length=40)
    published: str | None = Field(default=None, min_length=20, max_length=40)
    withdrawn: str | None = Field(default=None, min_length=20, max_length=40)
    aliases: list[str] = Field(default_factory=list, max_length=MAX_OSV_ALIASES)
    upstream: list[str] = Field(default_factory=list, max_length=MAX_OSV_ALIASES)
    related: list[str] = Field(default_factory=list, max_length=MAX_OSV_ALIASES)
    summary: str | None = Field(default=None, max_length=4_000)
    details: str | None = Field(default=None, max_length=MAX_OSV_DETAILS)
    severity: list[OsvSeverity] = Field(default_factory=list, max_length=MAX_SEVERITY_VECTORS)
    affected: list[OsvAffected] = Field(..., min_length=1, max_length=MAX_OSV_AFFECTED)
    references: list[OsvReference] = Field(default_factory=list, max_length=MAX_REFERENCES - 2)
    credits: list[OsvCredit] = Field(default_factory=list, max_length=MAX_CREDITS)
    database_specific: dict[str, Any] = Field(default_factory=dict)

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: str) -> str:
        match = _OSV_SCHEMA_RE.fullmatch(value)
        if match is None or match.group("major") != "1":
            raise ValueError("only reviewed OSV 1.x schema versions are supported")
        return value

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not _PYSEC_ID_RE.fullmatch(value):
            raise ValueError("record is not a PyPI Advisory Database PYSEC record")
        return value

    @field_validator("modified", "published", "withdrawn")
    @classmethod
    def validate_timestamp(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parse_utc_timestamp(value)
        return value

    @field_validator("aliases", "upstream", "related")
    @classmethod
    def validate_identifiers(cls, values: list[str]) -> list[str]:
        if any(not _IDENTIFIER_RE.fullmatch(value) for value in values):
            raise ValueError("OSV identifier list contains an invalid identifier")
        folded = [value.casefold() for value in values]
        if len(folded) != len(set(folded)):
            raise ValueError("OSV identifier list contains duplicates")
        return values

    @field_validator("database_specific")
    @classmethod
    def allow_top_level_severity(cls, value: dict[str, Any]) -> dict[str, Any]:
        if set(value) - {"severity"}:
            raise ValueError("OSV database_specific metadata contains unreviewed fields")
        if "severity" in value and (
            not isinstance(value["severity"], str) or not 1 <= len(value["severity"]) <= 80
        ):
            raise ValueError("OSV database severity is invalid")
        return value

    @model_validator(mode="after")
    def validate_required_content(self) -> "OsvRecord":
        if self.published is None:
            raise ValueError("OSV record requires a published timestamp for catalog import")
        if not _bounded_plain_text(self.summary or self.details or "", limit=MAX_OSV_DETAILS):
            raise ValueError("OSV record requires a usable summary or details field")
        return self


@dataclass(frozen=True)
class ModifiedIndexEntry:
    modified_at: datetime
    modified_text: str
    record_id: str


@dataclass(frozen=True)
class ModifiedIndex:
    entries: tuple[ModifiedIndexEntry, ...]
    source_entries: tuple[ModifiedIndexEntry, ...]
    digest: str
    out_of_scope_total: int
    out_of_scope_prefixes_total: int
    out_of_scope_by_prefix: dict[str, int]
    out_of_scope_samples: tuple[str, ...]

    @property
    def highest(self) -> ModifiedIndexEntry:
        if not self.source_entries:
            raise OsvPublisherError("source-empty", "OSV PyPI index contained no PYSEC records")
        return max(self.source_entries, key=lambda item: (item.modified_at, item.record_id))


@dataclass(frozen=True)
class PublisherPolicy:
    source_id: str
    source_name: str
    source_documentation_url: str
    license_identifier: str
    license_url: str
    attribution: str
    source_repository: str
    source_path_prefix: str
    synthetic: bool = False


PRODUCTION_POLICY = PublisherPolicy(
    source_id="osv-pypi-pysec-signed",
    source_name="PyPI Advisory Database via OSV.dev",
    source_documentation_url=PYPI_DATABASE_URL,
    license_identifier=PYPI_LICENSE,
    license_url=CC_BY_LICENSE_URL,
    attribution=(
        "Python Packaging Advisory Database contributors; retrieved through OSV.dev; "
        "licensed CC BY 4.0; normalized by the OpenAssetWatch OSV PyPI publisher."
    ),
    source_repository="pypa/advisory-database",
    source_path_prefix="/pypa/advisory-database/blob/main/vulns/",
)

SYNTHETIC_DEMO_POLICY = PublisherPolicy(
    source_id="openassetwatch-synthetic-osv-pypi",
    source_name="OpenAssetWatch Synthetic OSV PyPI Publisher Fixture",
    source_documentation_url="https://github.com/PKXLIVE/openassetwatch",
    license_identifier="Apache-2.0",
    license_url="https://www.apache.org/licenses/LICENSE-2.0",
    attribution="OpenAssetWatch synthetic test data; fictional advisories only.",
    source_repository="PKXLIVE/openassetwatch",
    source_path_prefix="/PKXLIVE/openassetwatch/blob/main/backend/tests/fixtures/osv-pypi/",
    synthetic=True,
)


def validate_publisher_policy(policy: PublisherPolicy) -> None:
    """Reject source or license substitutions instead of accepting CLI policy."""

    if policy not in {PRODUCTION_POLICY, SYNTHETIC_DEMO_POLICY}:
        raise OsvPublisherError(
            "publisher-policy-invalid",
            "publisher source, license, or attribution policy is not reviewed",
        )


@dataclass
class NormalizationReport:
    normalized_records: int = 0
    derived_purls: int = 0
    redundant_versions_omitted: int = 0
    truncated_text_fields: int = 0
    severity_not_reported: int = 0
    severity_vector_only: int = 0
    _samples: dict[str, list[str]] = field(default_factory=dict)

    def sample(self, category: str, record_id: str) -> None:
        values = self._samples.setdefault(category, [])
        if len(values) < MAX_REPORT_IDS and record_id not in values:
            values.append(record_id)

    def as_dict(self) -> dict[str, Any]:
        return {
            "normalized_records": self.normalized_records,
            "derived_purls": self.derived_purls,
            "redundant_versions_omitted": self.redundant_versions_omitted,
            "truncated_text_fields": self.truncated_text_fields,
            "severity_not_reported": self.severity_not_reported,
            "severity_vector_only": self.severity_vector_only,
            "samples": {key: list(value) for key, value in sorted(self._samples.items())},
        }


@dataclass(frozen=True)
class CatalogBuild:
    catalog: AdvisoryCatalog
    payload_bytes: bytes
    payload_digest: str
    records_digest: str


def canonical_json_bytes(value: Any) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    elif isinstance(value, (list, tuple)):
        value = [
            item.model_dump(mode="json") if isinstance(item, BaseModel) else item
            for item in value
        ]
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def parse_utc_timestamp(value: str) -> datetime:
    if not _UTC_TIMESTAMP_RE.fullmatch(value):
        raise ValueError("timestamp must be RFC3339 UTC with a trailing Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("timestamp is not a valid calendar time") from exc
    return parsed.astimezone(timezone.utc)


def format_utc(value: datetime) -> str:
    current = value.astimezone(timezone.utc)
    text = current.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return text.replace(".000000Z", "Z")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OsvPublisherError("osv-json-duplicate-key", "OSV JSON contains a duplicate object key")
        result[key] = value
    return result


def _validate_json_shape(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise OsvPublisherError("osv-json-too-complex", "OSV JSON exceeds the bounded node count")
        if depth > MAX_JSON_DEPTH:
            raise OsvPublisherError("osv-json-too-deep", "OSV JSON exceeds the bounded nesting depth")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str) and len(item) > MAX_OSV_DETAILS:
            raise OsvPublisherError("osv-string-too-large", "OSV JSON contains an oversized string")


def parse_osv_record_bytes(data: bytes, *, expected_id: str | None = None) -> OsvRecord:
    if not data or len(data) > MAX_OSV_RECORD_BYTES:
        raise OsvPublisherError("osv-record-size-invalid", "OSV record size is outside the configured limit")
    if data.startswith(b"\xef\xbb\xbf"):
        raise OsvPublisherError("osv-record-encoding-invalid", "OSV record must be UTF-8 without a byte-order mark")
    try:
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except OsvPublisherError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OsvPublisherError("osv-record-invalid-json", "OSV record must be valid UTF-8 JSON") from exc
    if not isinstance(raw, dict):
        raise OsvPublisherError("osv-record-root-invalid", "OSV record root must be an object")
    _validate_json_shape(raw)
    try:
        record = OsvRecord.model_validate(raw)
    except ValidationError as exc:
        record_id = raw.get("id") if isinstance(raw.get("id"), str) else expected_id
        raise OsvPublisherError(
            "osv-record-schema-invalid",
            "OSV record violates the reviewed bounded schema",
            record_id=record_id,
        ) from exc
    if expected_id is not None and record.id != expected_id:
        raise OsvPublisherError(
            "osv-record-id-mismatch",
            "OSV record ID does not match the requested index entry",
            record_id=expected_id,
        )
    return record


def parse_modified_index(
    data: bytes,
    *,
    maximum_bytes: int = MAX_INDEX_BYTES,
    maximum_rows: int = MAX_INDEX_ROWS,
) -> ModifiedIndex:
    if not data or len(data) > maximum_bytes:
        raise OsvPublisherError("index-size-invalid", "OSV modified index size is outside the configured limit")
    if data.startswith(b"\xef\xbb\xbf"):
        raise OsvPublisherError("index-encoding-invalid", "OSV modified index must be UTF-8 without a byte-order mark")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OsvPublisherError("index-encoding-invalid", "OSV modified index must be UTF-8") from exc
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    entries: list[ModifiedIndexEntry] = []
    seen: set[str] = set()
    previous: datetime | None = None
    try:
        for row_number, row in enumerate(reader, start=1):
            if row_number > maximum_rows:
                raise OsvPublisherError("index-record-limit", "OSV modified index exceeds the record limit")
            if len(row) != 2:
                raise OsvPublisherError("index-row-invalid", "OSV modified index row must have exactly two columns")
            modified_text, record_id = row
            if (
                modified_text != modified_text.strip()
                or record_id != record_id.strip()
                or not _INDEX_ID_RE.fullmatch(record_id)
                or any(token in record_id for token in ("/", "\\", "?", "#", ":"))
                or _CONTROL_RE.search(record_id)
            ):
                raise OsvPublisherError("index-id-invalid", "OSV modified index contains an unsafe record ID")
            try:
                modified_at = parse_utc_timestamp(modified_text)
            except ValueError as exc:
                raise OsvPublisherError("index-timestamp-invalid", "OSV modified index contains an invalid timestamp") from exc
            if previous is not None and modified_at > previous:
                raise OsvPublisherError("index-order-invalid", "OSV modified index is not reverse chronological")
            if record_id.casefold() in seen:
                raise OsvPublisherError("index-duplicate-id", "OSV modified index contains a duplicate record ID")
            seen.add(record_id.casefold())
            previous = modified_at
            entries.append(ModifiedIndexEntry(modified_at, modified_text, record_id))
    except csv.Error as exc:
        raise OsvPublisherError("index-csv-invalid", "OSV modified index is malformed CSV") from exc
    if not entries:
        raise OsvPublisherError("index-empty", "OSV modified index contains no records")
    source_entries = tuple(item for item in entries if _PYSEC_ID_RE.fullmatch(item.record_id))
    prefixes = Counter(
        item.record_id.split("-", 1)[0].upper()
        for item in entries
        if not _PYSEC_ID_RE.fullmatch(item.record_id)
    )
    sorted_prefixes = sorted(prefixes.items())
    samples = tuple(
        item.record_id
        for item in entries
        if not _PYSEC_ID_RE.fullmatch(item.record_id)
    )[:MAX_REPORT_IDS]
    return ModifiedIndex(
        entries=tuple(entries),
        source_entries=source_entries,
        digest=hashlib.sha256(data).hexdigest(),
        out_of_scope_total=sum(prefixes.values()),
        out_of_scope_prefixes_total=len(prefixes),
        out_of_scope_by_prefix=dict(sorted_prefixes[:MAX_REPORT_PREFIXES]),
        out_of_scope_samples=samples,
    )


def record_path(record_id: str) -> str:
    if not _PYSEC_ID_RE.fullmatch(record_id):
        raise OsvPublisherError("record-id-invalid", "publisher record ID is not an approved PYSEC identifier")
    return f"{OSV_RECORD_PREFIX}{record_id}.json"


def record_url(record_id: str) -> str:
    return f"https://{OSV_HOST}{record_path(record_id)}"


def _bounded_plain_text(value: str, *, limit: int) -> str:
    if _CONTROL_RE.search(value):
        raise ValueError("text contains prohibited control characters")
    normalized = " ".join(value.split())
    return normalized[:limit]


def _truncate(value: str, *, limit: int, report: NormalizationReport, record_id: str) -> str:
    if len(value) <= limit:
        return value
    report.truncated_text_fields += 1
    report.sample("truncated_text", record_id)
    return value[: max(1, limit - 1)].rstrip() + "…"


def _source_record_url(value: str, *, record_id: str, policy: PublisherPolicy) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith(policy.source_path_prefix)
        or not parsed.path.endswith(f"/{record_id}.yaml")
        or any(segment in {"", ".", ".."} for segment in parsed.path.split("/")[1:])
    ):
        raise OsvPublisherError(
            "source-record-url-invalid",
            "OSV record does not identify the reviewed source repository",
            record_id=record_id,
        )
    validated = validate_reference_url(value)
    if validated is None:
        raise OsvPublisherError(
            "source-record-url-invalid",
            "OSV source record URL is not a bounded credential-free URL",
            record_id=record_id,
        )
    return validated


def _normalize_identifier_list(values: list[str], *, own_id: str) -> list[str]:
    result = sorted(
        {value.upper() for value in values if value.casefold() != own_id.casefold()},
        key=str.casefold,
    )
    if len(result) != len(values) - sum(value.casefold() == own_id.casefold() for value in values):
        raise OsvPublisherError("identifier-duplicate", "OSV identifier list is ambiguous", record_id=own_id)
    return result


def _validate_pep440(value: str, *, record_id: str) -> str:
    try:
        Version(value)
    except InvalidVersion as exc:
        raise OsvPublisherError(
            "pypi-version-unsupported",
            "OSV PyPI version is not valid PEP 440",
            record_id=record_id,
        ) from exc
    return value


def _normalize_range(source_range: OsvRange, *, record_id: str) -> tuple[list[AdvisoryRange], list[str]]:
    if source_range.type != "ECOSYSTEM":
        raise OsvPublisherError(
            "range-type-unsupported",
            "OSV PyPI publisher supports only ECOSYSTEM version ranges",
            record_id=record_id,
        )
    if source_range.repo is not None:
        raise OsvPublisherError(
            "range-repository-unexpected",
            "OSV ECOSYSTEM range must not carry a repository",
            record_id=record_id,
        )
    output: list[AdvisoryRange] = []
    fixed_versions: list[str] = []
    introduced: str | None = None
    introduced_unbounded = False
    interval_open = False
    for event in source_range.events:
        if event.limit is not None:
            raise OsvPublisherError(
                "range-limit-unsupported",
                "OSV PyPI limit events are not supported",
                record_id=record_id,
            )
        if event.introduced is not None:
            if interval_open:
                raise OsvPublisherError(
                    "range-events-contradictory",
                    "OSV range introduces a second interval before closing the first",
                    record_id=record_id,
                )
            interval_open = True
            if event.introduced == "0":
                introduced = None
                introduced_unbounded = True
            else:
                introduced = _validate_pep440(event.introduced, record_id=record_id)
                introduced_unbounded = False
            continue
        if not interval_open:
            raise OsvPublisherError(
                "range-events-contradictory",
                "OSV range closes an interval before an introduced event",
                record_id=record_id,
            )
        fixed = _validate_pep440(event.fixed, record_id=record_id) if event.fixed is not None else None
        last = (
            _validate_pep440(event.last_affected, record_id=record_id)
            if event.last_affected is not None
            else None
        )
        upper = fixed or last
        if introduced is not None:
            comparison = compare_versions("pypi", introduced, upper)
            if comparison.status != "supported" or comparison.order is None or comparison.order > 0:
                raise OsvPublisherError(
                    "range-boundaries-invalid",
                    "OSV PyPI range boundaries are invalid or inverted",
                    record_id=record_id,
                )
            if comparison.order == 0 and fixed is not None:
                raise OsvPublisherError(
                    "range-boundaries-empty",
                    "OSV PyPI fixed boundary defines an empty interval",
                    record_id=record_id,
                )
        output.append(
            AdvisoryRange(
                introduced=introduced,
                introduced_unbounded=introduced_unbounded,
                introduced_inclusive=True,
                fixed=fixed,
                fixed_inclusive=False,
                last_affected=last,
                last_affected_inclusive=True,
            )
        )
        if fixed is not None:
            fixed_versions.append(fixed)
        introduced = None
        introduced_unbounded = False
        interval_open = False
    if interval_open:
        output.append(
            AdvisoryRange(
                introduced=introduced,
                introduced_unbounded=introduced_unbounded,
            )
        )
    if not output:
        raise OsvPublisherError("range-empty", "OSV PyPI range produced no usable interval", record_id=record_id)
    return output, fixed_versions


def _round_up_cvss(value: float) -> float:
    return math.ceil((value * 10.0) - 1e-10) / 10.0


def _parse_cvss3_base(vector: str, *, record_id: str) -> float:
    parts = vector.split("/")
    if len(parts) != 9 or parts[0] not in {"CVSS:3.0", "CVSS:3.1"}:
        raise OsvPublisherError(
            "severity-vector-unsupported",
            "OSV severity vector is not a supported CVSS v3 base vector",
            record_id=record_id,
        )
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if part.count(":") != 1:
            raise OsvPublisherError(
                "severity-vector-malformed",
                "OSV CVSS v3 vector is malformed",
                record_id=record_id,
            )
        name, value = part.split(":", 1)
        if name in metrics or name not in _CVSS3_REQUIRED:
            raise OsvPublisherError(
                "severity-vector-malformed",
                "OSV CVSS v3 vector has duplicate or unsupported metrics",
                record_id=record_id,
            )
        metrics[name] = value
    if set(metrics) != _CVSS3_REQUIRED or metrics["S"] not in {"U", "C"}:
        raise OsvPublisherError(
            "severity-vector-malformed",
            "OSV CVSS v3 vector is missing or has invalid base metrics",
            record_id=record_id,
        )
    for name, allowed in _CVSS3_METRICS.items():
        if metrics[name] not in allowed:
            raise OsvPublisherError(
                "severity-vector-malformed",
                "OSV CVSS v3 vector contains an invalid metric value",
                record_id=record_id,
            )
    privileges = (
        {"N": 0.85, "L": 0.62, "H": 0.27}
        if metrics["S"] == "U"
        else {"N": 0.85, "L": 0.68, "H": 0.5}
    )
    if metrics["PR"] not in privileges:
        raise OsvPublisherError(
            "severity-vector-malformed",
            "OSV CVSS v3 vector contains an invalid privilege metric",
            record_id=record_id,
        )
    impact_base = 1.0 - (
        (1.0 - _CVSS3_METRICS["C"][metrics["C"]])
        * (1.0 - _CVSS3_METRICS["I"][metrics["I"]])
        * (1.0 - _CVSS3_METRICS["A"][metrics["A"]])
    )
    if metrics["S"] == "U":
        impact = 6.42 * impact_base
    else:
        impact = 7.52 * (impact_base - 0.029) - 3.25 * ((impact_base - 0.02) ** 15)
    if impact <= 0:
        return 0.0
    exploitability = (
        8.22
        * _CVSS3_METRICS["AV"][metrics["AV"]]
        * _CVSS3_METRICS["AC"][metrics["AC"]]
        * privileges[metrics["PR"]]
        * _CVSS3_METRICS["UI"][metrics["UI"]]
    )
    base = impact + exploitability
    if metrics["S"] == "C":
        base *= 1.08
    return _round_up_cvss(min(base, 10.0))


def _severity_from_score(score: float) -> str:
    if score == 0:
        return "informational"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def _severity(
    record: OsvRecord,
    *,
    report: NormalizationReport,
) -> tuple[str, str, str | None, list[AdvisorySeverityVector], float | None]:
    vectors = list(record.severity)
    labels: list[str] = []
    if isinstance(record.database_specific.get("severity"), str):
        labels.append(str(record.database_specific["severity"]))
    for affected in record.affected:
        vectors.extend(affected.severity)
        for metadata in (affected.ecosystem_specific, affected.database_specific):
            if isinstance(metadata.get("severity"), str):
                labels.append(str(metadata["severity"]))
    unique_labels = {value.strip().upper() for value in labels}
    if len(unique_labels) > 1:
        raise OsvPublisherError(
            "severity-conflict",
            "OSV record contains conflicting categorical severity values",
            record_id=record.id,
        )
    normalized_vectors = sorted(
        {
            (item.type.upper(), item.score, item.source)
            for item in vectors
        },
        key=lambda item: (item[0], item[1], item[2] or ""),
    )
    vector_models = [
        AdvisorySeverityVector(type=kind, score=score, source=source)
        for kind, score, source in normalized_vectors
    ]
    vector_scores: list[float] = []
    for kind, score, _source in normalized_vectors:
        if kind != "CVSS_V3":
            raise OsvPublisherError(
                "severity-vector-unsupported",
                "OSV record contains an unsupported severity vector type",
                record_id=record.id,
            )
        vector_scores.append(_parse_cvss3_base(score, record_id=record.id))
    cvss = max(vector_scores) if vector_scores else None
    if unique_labels:
        label = next(iter(unique_labels))
        mapped = _CATEGORY_MAP.get(label)
        if mapped is None:
            raise OsvPublisherError(
                "severity-unsupported",
                "OSV record contains an unsupported categorical severity",
                record_id=record.id,
            )
        return mapped, "upstream-categorical", label, vector_models, cvss
    if vector_models:
        report.severity_vector_only += 1
        report.sample("severity_vector_only", record.id)
        if cvss is None:
            raise OsvPublisherError(
                "severity-vector-unsupported",
                "OSV vector-only severity could not be parsed safely",
                record_id=record.id,
            )
        return _severity_from_score(cvss), "derived-cvss-v3", None, vector_models, cvss
    report.severity_not_reported += 1
    report.sample("severity_not_reported", record.id)
    return "informational", "not-reported", None, [], None


def normalize_osv_record(
    record: OsvRecord,
    *,
    expected_modified: datetime | None = None,
    policy: PublisherPolicy = PRODUCTION_POLICY,
    report: NormalizationReport | None = None,
) -> AdvisoryRecord:
    validate_publisher_policy(policy)
    report = report or NormalizationReport()
    modified_at = parse_utc_timestamp(record.modified)
    if expected_modified is not None and modified_at != expected_modified.astimezone(timezone.utc):
        raise OsvPublisherError(
            "record-modified-mismatch",
            "OSV record modification time does not match the signed index entry",
            record_id=record.id,
        )
    published_at = parse_utc_timestamp(record.published or "")
    withdrawn_at = parse_utc_timestamp(record.withdrawn) if record.withdrawn else None
    if modified_at < published_at:
        raise OsvPublisherError(
            "record-timeline-invalid",
            "OSV modified timestamp precedes its published timestamp",
            record_id=record.id,
        )

    source_urls: set[str] = set()
    affected_output: list[AffectedComponent] = []
    for affected in record.affected:
        if affected.package.ecosystem != "PyPI":
            raise OsvPublisherError(
                "ecosystem-mismatch",
                "OSV PYSEC record contains a non-PyPI affected package",
                record_id=record.id,
            )
        raw_source = affected.database_specific.get("source")
        if not isinstance(raw_source, str):
            raise OsvPublisherError(
                "source-record-url-missing",
                "OSV PYSEC affected package is missing reviewed source provenance",
                record_id=record.id,
            )
        source_urls.add(_source_record_url(raw_source, record_id=record.id, policy=policy))

        parsed_purl = parse_purl(affected.package.purl) if affected.package.purl else None
        if affected.package.purl and (
            parsed_purl is None or parsed_purl.ecosystem != "pypi" or parsed_purl.version is not None
        ):
            raise OsvPublisherError(
                "package-purl-invalid",
                "OSV PyPI Package URL is malformed or version-qualified",
                record_id=record.id,
            )
        derived = build_purl(ecosystem="pypi", namespace=None, name=affected.package.name)
        if derived is None:
            raise OsvPublisherError(
                "package-identity-invalid",
                "OSV PyPI package name cannot form a canonical identity",
                record_id=record.id,
            )
        if parsed_purl is not None and parsed_purl.canonical != derived:
            raise OsvPublisherError(
                "package-purl-mismatch",
                "OSV PyPI Package URL disagrees with the package name",
                record_id=record.id,
            )
        if parsed_purl is None:
            report.derived_purls += 1
            report.sample("derived_purl", record.id)
        normalized_purl = parsed_purl or parse_purl(derived)
        if normalized_purl is None:
            raise OsvPublisherError(
                "package-identity-invalid",
                "normalized PyPI Package URL could not be parsed",
                record_id=record.id,
            )

        ranges: list[AdvisoryRange] = []
        fixed_versions: list[str] = []
        for source_range in affected.ranges:
            normalized_ranges, normalized_fixed = _normalize_range(source_range, record_id=record.id)
            ranges.extend(normalized_ranges)
            fixed_versions.extend(normalized_fixed)
        if len(ranges) > MAX_RANGES or len(set(fixed_versions)) > MAX_FIXED_VERSIONS:
            raise OsvPublisherError(
                "normalized-range-limit",
                "OSV record exceeds OpenAssetWatch range or fixed-version bounds",
                record_id=record.id,
            )
        explicit_versions = [
            _validate_pep440(value, record_id=record.id)
            for value in affected.versions
        ]
        if len(explicit_versions) != len(set(explicit_versions)):
            raise OsvPublisherError(
                "explicit-version-duplicate",
                "OSV record contains duplicate explicit versions",
                record_id=record.id,
            )
        exact_versions: list[str] = []
        for version in explicit_versions:
            covered = False
            for version_range in ranges:
                status, _reason = version_satisfies_range(
                    ecosystem="pypi",
                    installed_version=version,
                    introduced=version_range.introduced,
                    introduced_inclusive=version_range.introduced_inclusive,
                    fixed=version_range.fixed,
                    fixed_inclusive=version_range.fixed_inclusive,
                    last_affected=version_range.last_affected,
                    last_affected_inclusive=version_range.last_affected_inclusive,
                )
                if status == "unsupported-comparison":
                    raise OsvPublisherError(
                        "explicit-version-comparison-unsupported",
                        "OSV explicit version cannot be compared with its range safely",
                        record_id=record.id,
                    )
                if status == "affected":
                    covered = True
                    break
            if covered:
                report.redundant_versions_omitted += 1
                report.sample("redundant_versions_omitted", record.id)
            else:
                exact_versions.append(version)
        if len(exact_versions) > MAX_EXACT_VERSIONS:
            raise OsvPublisherError(
                "explicit-version-limit",
                "OSV record exceeds the exact-version catalog bound",
                record_id=record.id,
            )
        exact_versions = sorted(exact_versions, key=Version)
        if not ranges and not exact_versions:
            raise OsvPublisherError(
                "affected-range-missing",
                "OSV PyPI affected package has no usable range or explicit version",
                record_id=record.id,
            )
        affected_output.append(
            AffectedComponent(
                ecosystem="pypi",
                name=normalized_purl.name,
                identifier=derived,
                ranges=ranges,
                exact_versions=exact_versions,
                fixed_versions=sorted(set(fixed_versions), key=Version),
            )
        )
    if len(source_urls) != 1:
        raise OsvPublisherError(
            "source-record-url-conflict",
            "OSV record contains inconsistent source provenance",
            record_id=record.id,
        )
    if len({canonical_json_bytes(item).decode("utf-8") for item in affected_output}) != len(affected_output):
        raise OsvPublisherError(
            "affected-component-duplicate",
            "OSV record contains duplicate affected package definitions",
            record_id=record.id,
        )

    raw_title = _bounded_plain_text(record.summary or record.details or "", limit=MAX_OSV_DETAILS)
    raw_details = _bounded_plain_text(record.details or record.summary or "", limit=MAX_OSV_DETAILS)
    title = _truncate(raw_title, limit=240, report=report, record_id=record.id)
    summary = _truncate(raw_details, limit=1_000, report=report, record_id=record.id)
    severity, severity_basis, upstream_severity, severity_vectors, cvss = _severity(
        record,
        report=report,
    )

    references: set[tuple[str, str]] = set()
    for reference in record.references:
        validated = validate_reference_url(reference.url)
        if validated is None:
            raise OsvPublisherError(
                "reference-url-invalid",
                "OSV record contains an unsafe reference URL",
                record_id=record.id,
            )
        references.add((reference.type.upper(), validated))
    references.add(("SOURCE", next(iter(source_urls))))
    references.add(("OSV", record_url(record.id)))
    if len(references) > MAX_REFERENCES:
        raise OsvPublisherError(
            "reference-limit",
            "OSV record exceeds the normalized reference bound",
            record_id=record.id,
        )

    credits: list[AdvisoryCredit] = []
    for credit in record.credits:
        contacts: list[str] = []
        for contact in credit.contact:
            validated = validate_reference_url(contact)
            if validated is None:
                raise OsvPublisherError(
                    "credit-contact-invalid",
                    "OSV record contains an unsafe credit contact",
                    record_id=record.id,
                )
            contacts.append(validated)
        if len(contacts) != len(set(contacts)):
            raise OsvPublisherError(
                "credit-contact-duplicate",
                "OSV record contains duplicate credit contacts",
                record_id=record.id,
            )
        credits.append(
            AdvisoryCredit(
                name=credit.name,
                type=credit.type.upper() if credit.type else None,
                contact=sorted(contacts),
            )
        )
    if len({canonical_json_bytes(item).decode("utf-8") for item in credits}) != len(credits):
        raise OsvPublisherError("credit-duplicate", "OSV record contains duplicate credits", record_id=record.id)

    normalized = AdvisoryRecord(
        id=record.id,
        aliases=_normalize_identifier_list(record.aliases, own_id=record.id),
        upstream=_normalize_identifier_list(record.upstream, own_id=record.id),
        related=_normalize_identifier_list(record.related, own_id=record.id),
        title=title,
        summary=summary,
        severity=severity,
        cvss=cvss,
        known_exploited=False,
        published_at=published_at,
        modified_at=modified_at,
        withdrawn_at=withdrawn_at,
        affected=affected_output,
        references=[
            AdvisoryReference(type=kind, url=url)
            for kind, url in sorted(references, key=lambda item: (item[0], item[1]))
        ],
        source_record_url=next(iter(source_urls)),
        source_license=policy.license_identifier,
        severity_basis=severity_basis,
        upstream_severity=upstream_severity,
        severity_vectors=severity_vectors,
        credits=sorted(credits, key=lambda item: (item.name.casefold(), item.type or "", tuple(item.contact))),
    )
    report.normalized_records += 1
    return normalized


def build_catalog(
    records: list[AdvisoryRecord],
    *,
    highest_modified: datetime,
    policy: PublisherPolicy = PRODUCTION_POLICY,
) -> CatalogBuild:
    validate_publisher_policy(policy)
    if not records or len(records) > MAX_ADVISORIES:
        raise OsvPublisherError("catalog-record-limit", "normalized catalog record count is outside the supported bound")
    sorted_records = sorted(records, key=lambda item: item.id.casefold())
    if len({record.id.casefold() for record in sorted_records}) != len(sorted_records):
        raise OsvPublisherError("catalog-record-duplicate", "normalized catalog contains duplicate advisory IDs")
    records_bytes = canonical_json_bytes(sorted_records)
    records_digest = hashlib.sha256(records_bytes).hexdigest()
    timestamp = highest_modified.astimezone(timezone.utc)
    compact = timestamp.strftime("%Y%m%dT%H%M%S") + (
        f"{timestamp.microsecond:06d}".rstrip("0") if timestamp.microsecond else ""
    ) + "Z"
    catalog_version = f"osv-pypi-pysec-v1-{compact}-{records_digest[:16]}"
    source_version = f"PYSEC@{format_utc(timestamp)}"
    catalog = AdvisoryCatalog(
        schema_version=ADVISORY_SCHEMA_VERSION,
        catalog_version=catalog_version,
        source=CatalogSource(
            name=policy.source_name,
            version=source_version,
            license=policy.license_identifier,
            provenance=(
                f"{policy.source_documentation_url}; aggregated by {OSV_DATA_DOCUMENTATION_URL}; "
                f"normalized by {ADAPTER_NAME} {ADAPTER_VERSION}"
            ),
        ),
        generated_at=timestamp,
        advisories=sorted_records,
    )
    payload_bytes = canonical_json_bytes(catalog)
    if len(payload_bytes) > 8 << 20:
        raise OsvPublisherError("catalog-payload-too-large", "normalized catalog exceeds the trusted-feed payload bound")
    return CatalogBuild(
        catalog=catalog,
        payload_bytes=payload_bytes,
        payload_digest=hashlib.sha256(payload_bytes).hexdigest(),
        records_digest=records_digest,
    )
