"""Strict CISA KEV source parsing and normalized enrichment catalogs.

KEV is prioritization intelligence only.  This module deliberately contains
no component-version matching logic and treats every upstream string as
bounded, untrusted text.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, timezone
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)


KEV_SCHEMA_VERSION = "oaw.kev-catalog.v1"
KEV_ADAPTER_VERSION = "1"
CISA_KEV_SOURCE_ID = "cisa-kev-official"
CISA_KEV_SOURCE_NAME = "CISA Known Exploited Vulnerabilities"
CISA_KEV_LICENSE = "CC0-1.0"
CISA_KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)
CISA_KEV_SCHEMA_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities_schema.json"
)
CISA_KEV_DOCUMENTATION_URL = (
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
)
CISA_KEV_ATTRIBUTION = (
    "CISA Known Exploited Vulnerabilities catalog; CC0 1.0; official GitHub "
    "source is a machine-readable mirror of the canonical CISA catalog; "
    "normalized by OpenAssetWatch."
)

MAX_CISA_KEV_BYTES = 8 << 20
MAX_KEV_RECORDS = 10_000
MAX_KEV_TEXT = 4_000
MAX_KEV_NOTES = 8_000
MAX_KEV_CWES = 64
MAX_JSON_DEPTH = 8
MAX_JSON_NODES = 200_000
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
_CWE_RE = re.compile(r"^CWE-[0-9]+$")
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$"
)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class KevValidationError(ValueError):
    """A bounded KEV validation rejection safe to expose by code."""

    def __init__(self, code: str, summary: str) -> None:
        super().__init__(summary)
        self.code = code[:80]
        self.summary = summary[:240]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def normalize_cve(value: str) -> str:
    normalized = value.strip().upper()
    if not _CVE_RE.fullmatch(normalized):
        raise ValueError("CVE identifier is invalid")
    return normalized


def _plain_text(value: str, *, maximum: int) -> str:
    if not value or len(value) > maximum or _CONTROL_RE.search(value):
        raise ValueError("KEV text is empty, oversized, or contains control characters")
    return value


def _parse_date(value: str) -> date:
    if not _DATE_RE.fullmatch(value):
        raise ValueError("date must use YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("date is not a valid calendar date") from exc


def _parse_utc(value: str) -> datetime:
    if not _UTC_RE.fullmatch(value):
        raise ValueError("timestamp must be RFC3339 UTC with a trailing Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("timestamp is not a valid calendar time") from exc
    return parsed.astimezone(timezone.utc)


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise KevValidationError(
                "kev-json-duplicate-key",
                "CISA KEV JSON contains a duplicate object key",
            )
        value[key] = item
    return value


def _validate_json_shape(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise KevValidationError(
                "kev-json-too-complex",
                "CISA KEV JSON exceeds the bounded node count",
            )
        if depth > MAX_JSON_DEPTH:
            raise KevValidationError(
                "kev-json-too-deep",
                "CISA KEV JSON exceeds the bounded nesting depth",
            )
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str) and len(item) > MAX_KEV_NOTES:
            raise KevValidationError(
                "kev-string-too-large",
                "CISA KEV JSON contains an oversized string",
            )


class CisaKevRecord(_StrictModel):
    cve_id: str = Field(..., alias="cveID", min_length=13, max_length=28)
    vendor_project: str = Field(..., alias="vendorProject", min_length=1, max_length=500)
    product: str = Field(..., min_length=1, max_length=500)
    vulnerability_name: str = Field(..., alias="vulnerabilityName", min_length=1, max_length=1_000)
    date_added: date = Field(..., alias="dateAdded")
    short_description: str = Field(..., alias="shortDescription", min_length=1, max_length=MAX_KEV_TEXT)
    required_action: str = Field(..., alias="requiredAction", min_length=1, max_length=MAX_KEV_TEXT)
    due_date: date = Field(..., alias="dueDate")
    known_ransomware_campaign_use: Literal["Known", "Unknown"] | None = Field(
        default=None,
        alias="knownRansomwareCampaignUse",
    )
    notes: str | None = Field(default=None, max_length=MAX_KEV_NOTES)
    cwes: list[str] = Field(default_factory=list, max_length=MAX_KEV_CWES)

    @field_validator("cve_id", mode="before")
    @classmethod
    def validate_cve(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("CVE identifier must be a string")
        return normalize_cve(value)

    @field_validator("date_added", "due_date", mode="before")
    @classmethod
    def validate_date(cls, value: Any) -> date:
        if not isinstance(value, str):
            raise ValueError("CISA KEV dates must be strings")
        return _parse_date(value)

    @field_validator(
        "vendor_project",
        "product",
        "vulnerability_name",
        "short_description",
        "required_action",
    )
    @classmethod
    def validate_text(cls, value: str) -> str:
        return _plain_text(value, maximum=MAX_KEV_TEXT)

    @field_validator("notes")
    @classmethod
    def validate_notes(cls, value: str | None) -> str | None:
        return None if value is None else _plain_text(value, maximum=MAX_KEV_NOTES)

    @field_validator("cwes")
    @classmethod
    def validate_cwes(cls, values: list[str]) -> list[str]:
        normalized = [value.upper() for value in values]
        if any(not _CWE_RE.fullmatch(value) for value in normalized):
            raise ValueError("CWE identifier is invalid")
        if len(normalized) != len(set(normalized)):
            raise ValueError("CWE list contains duplicates")
        return normalized


class CisaKevCatalog(_StrictModel):
    catalog_version: str = Field(..., alias="catalogVersion", min_length=1, max_length=120)
    date_released: datetime = Field(..., alias="dateReleased")
    count: int = Field(..., ge=0, le=MAX_KEV_RECORDS)
    vulnerabilities: list[CisaKevRecord] = Field(..., max_length=MAX_KEV_RECORDS)

    @field_validator("date_released", mode="before")
    @classmethod
    def validate_released(cls, value: Any) -> datetime:
        if not isinstance(value, str):
            raise ValueError("catalog release time must be a string")
        return _parse_utc(value)

    @model_validator(mode="after")
    def validate_catalog(self) -> "CisaKevCatalog":
        if self.count != len(self.vulnerabilities):
            raise ValueError("catalog count does not match validated records")
        cves = [record.cve_id for record in self.vulnerabilities]
        if len(cves) != len(set(cves)):
            raise ValueError("catalog contains a duplicate CVE")
        return self


class KevCatalogSource(_StrictModel):
    source_id: Literal["cisa-kev-official"]
    name: Literal["CISA Known Exploited Vulnerabilities"]
    official_mirror_url: Literal[CISA_KEV_URL]
    canonical_documentation_url: Literal[CISA_KEV_DOCUMENTATION_URL]
    license_identifier: Literal["CC0-1.0"]
    provenance: str = Field(..., min_length=1, max_length=1_000)


class KevRecord(_StrictModel):
    kev_record_id: str = Field(..., pattern=r"^kev_[0-9a-f]{64}$")
    cve_id: str = Field(..., min_length=13, max_length=28)
    vendor_project: str = Field(..., min_length=1, max_length=500)
    product: str = Field(..., min_length=1, max_length=500)
    vulnerability_name: str = Field(..., min_length=1, max_length=1_000)
    date_added: date
    short_description: str = Field(..., min_length=1, max_length=MAX_KEV_TEXT)
    required_action: str = Field(..., min_length=1, max_length=MAX_KEV_TEXT)
    cisa_due_date: date
    ransomware_campaign_status: Literal["Known", "Unknown", "Not supplied"]
    notes: str | None = Field(default=None, max_length=MAX_KEV_NOTES)
    cwes: list[str] = Field(default_factory=list, max_length=MAX_KEV_CWES)

    @field_validator("cve_id")
    @classmethod
    def validate_cve(cls, value: str) -> str:
        return normalize_cve(value)


class KevCatalog(_StrictModel):
    schema_version: Literal["oaw.kev-catalog.v1"]
    source: KevCatalogSource
    catalog_version: str = Field(..., min_length=1, max_length=120)
    catalog_date_released: datetime
    records: list[KevRecord] = Field(..., max_length=MAX_KEV_RECORDS)

    @field_validator("catalog_date_released")
    @classmethod
    def validate_release_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("catalog release time requires a timezone")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_records(self) -> "KevCatalog":
        cves = [record.cve_id for record in self.records]
        record_ids = [record.kev_record_id for record in self.records]
        if len(cves) != len(set(cves)) or len(record_ids) != len(set(record_ids)):
            raise ValueError("normalized KEV records must have unique CVEs and IDs")
        if cves != sorted(cves):
            raise ValueError("normalized KEV records must use deterministic CVE order")
        return self


def parse_cisa_kev_bytes(data: bytes, *, maximum_bytes: int = MAX_CISA_KEV_BYTES) -> CisaKevCatalog:
    if not data or len(data) > maximum_bytes:
        raise KevValidationError(
            "kev-source-size-invalid",
            "CISA KEV source size is outside the reviewed limit",
        )
    if data.startswith(b"\xef\xbb\xbf"):
        raise KevValidationError(
            "kev-source-encoding-invalid",
            "CISA KEV source must be UTF-8 without a byte-order mark",
        )
    try:
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except KevValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KevValidationError(
            "kev-source-invalid-json",
            "CISA KEV source must be valid UTF-8 JSON",
        ) from exc
    _validate_json_shape(raw)
    if not isinstance(raw, dict):
        raise KevValidationError("kev-source-root-invalid", "CISA KEV source root must be an object")
    try:
        return CisaKevCatalog.model_validate(raw)
    except ValidationError as exc:
        raise KevValidationError(
            "kev-source-schema-invalid",
            "CISA KEV source violates the reviewed schema",
        ) from exc


def normalize_cisa_kev_catalog(source: CisaKevCatalog) -> KevCatalog:
    records = []
    for item in sorted(source.vulnerabilities, key=lambda value: value.cve_id):
        records.append(
            KevRecord(
                kev_record_id="kev_" + hashlib.sha256(item.cve_id.encode("ascii")).hexdigest(),
                cve_id=item.cve_id,
                vendor_project=item.vendor_project,
                product=item.product,
                vulnerability_name=item.vulnerability_name,
                date_added=item.date_added,
                short_description=item.short_description,
                required_action=item.required_action,
                cisa_due_date=item.due_date,
                ransomware_campaign_status=item.known_ransomware_campaign_use or "Not supplied",
                notes=item.notes,
                cwes=item.cwes,
            )
        )
    return KevCatalog(
        schema_version=KEV_SCHEMA_VERSION,
        source=KevCatalogSource(
            source_id=CISA_KEV_SOURCE_ID,
            name=CISA_KEV_SOURCE_NAME,
            official_mirror_url=CISA_KEV_URL,
            canonical_documentation_url=CISA_KEV_DOCUMENTATION_URL,
            license_identifier=CISA_KEV_LICENSE,
            provenance=CISA_KEV_ATTRIBUTION,
        ),
        catalog_version=source.catalog_version,
        catalog_date_released=source.date_released,
        records=records,
    )


def canonical_kev_bytes(catalog: KevCatalog) -> bytes:
    return json.dumps(
        catalog.model_dump(mode="json"),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def parse_kev_catalog_bytes(data: bytes) -> tuple[KevCatalog, str]:
    if not data or len(data) > MAX_CISA_KEV_BYTES:
        raise KevValidationError("kev-catalog-size-invalid", "KEV catalog size is outside the reviewed limit")
    if data.startswith(b"\xef\xbb\xbf"):
        raise KevValidationError("kev-catalog-encoding-invalid", "KEV catalog must use UTF-8 without a BOM")
    try:
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except KevValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KevValidationError("kev-catalog-invalid-json", "KEV catalog must be valid UTF-8 JSON") from exc
    _validate_json_shape(raw)
    try:
        catalog = KevCatalog.model_validate(raw)
    except ValidationError as exc:
        raise KevValidationError("kev-catalog-schema-invalid", "KEV catalog violates the supported schema") from exc
    canonical = canonical_kev_bytes(catalog)
    if canonical != data:
        raise KevValidationError("kev-catalog-noncanonical", "KEV catalog must use canonical JSON bytes")
    return catalog, hashlib.sha256(canonical).hexdigest()


def changed_cves(current: KevCatalog, previous: KevCatalog | None) -> list[str]:
    current_records = {record.cve_id: record for record in current.records}
    previous_records = {record.cve_id: record for record in (previous.records if previous else [])}
    changed = set(current_records) ^ set(previous_records)
    changed.update(
        cve
        for cve in set(current_records) & set(previous_records)
        if current_records[cve] != previous_records[cve]
    )
    return sorted(changed)


def preview_kev_catalog(current: KevCatalog, previous: KevCatalog | None) -> dict[str, Any]:
    current_by_cve = {record.cve_id: record for record in current.records}
    previous_by_cve = {record.cve_id: record for record in (previous.records if previous else [])}
    added = set(current_by_cve) - set(previous_by_cve)
    removed = set(previous_by_cve) - set(current_by_cve)
    updated = {
        cve
        for cve in set(current_by_cve) & set(previous_by_cve)
        if current_by_cve[cve] != previous_by_cve[cve]
    }
    changed = sorted(added | removed | updated)
    return {
        "payload_kind": "kev-prioritization",
        "catalog_version": current.catalog_version,
        "catalog_date_released": current.catalog_date_released,
        "total_records": len(current.records),
        "added_records": len(added),
        "updated_records": len(updated),
        "removed_records": len(removed),
        "ransomware_confirmed_count": sum(
            record.ransomware_campaign_status == "Known" for record in current.records
        ),
        "changed_cves": changed[:100],
        "changed_cve_count": len(changed),
        "changed_cves_truncated": len(changed) > 100,
        "correlation_policy": "exact-normalized-cve-alias-current-affected-only",
        "required_action_execution": "disabled",
        "local_compromise_claim": False,
    }
