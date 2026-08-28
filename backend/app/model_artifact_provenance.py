"""Provider-neutral model artifact provenance, qualification, and advisory contracts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


MODEL_ARTIFACT_MANIFEST_VERSION = "oaw.model-artifact-manifest.v1"
MODEL_ARTIFACT_ADVISORY_VERSION = "oaw.model-artifact-advisory.v1"
MODEL_ARTIFACT_ADVISORY_REGISTRY_VERSION = "oaw.model-artifact-advisory-registry.v1"
MODEL_QUALIFICATION_BINDING_VERSION = "oaw.model-qualification-binding.v1"
MAX_MODEL_ARTIFACT_MANIFEST_BYTES = 512_000
MAX_MODEL_ARTIFACT_ADVISORY_REGISTRY_BYTES = 512_000
MAX_ARTIFACT_SPLITS = 1_024
MAX_ARTIFACT_ADVISORIES = 128
SHA256_PATTERN = r"^[0-9a-f]{64}$"
IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$"
MUTABLE_REVISIONS = frozenset({"current", "head", "latest", "main", "master"})

ModelCapability = Literal[
    "reasoning",
    "classification",
    "structured_output",
    "tool_calling",
    "coding",
    "summarization",
    "report_writing",
    "streaming",
    "mtp",
    "speculative_decoding",
    "moe",
    "long_context",
]
ProvenanceState = Literal[
    "complete",
    "partial",
    "unknown",
    "invalid",
    "superseded",
    "requalification-required",
]
ArtifactAdvisoryState = Literal["not-configured", "clear", "matched", "invalid"]
QualificationBindingState = Literal[
    "not-configured",
    "legacy-unbound",
    "matched",
    "mismatch",
    "required-missing",
    "invalid",
]
ArtifactComponentType = Literal[
    "source-checkpoint",
    "converter",
    "quantizer",
    "runtime",
    "artifact-format",
    "qualification-suite",
]
ArtifactRequiredAction = Literal[
    "informational",
    "requalification-required",
    "reconversion-required",
    "requantization-required",
    "runtime-upgrade-required",
    "block-use",
]


def _looks_like_absolute_local_path(value: str) -> bool:
    return bool(
        value.startswith(("/", "\\", "file://"))
        or re.match(r"^[A-Za-z]:[\\/]", value)
    )


def _validate_reference(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("provenance references must be credential-free HTTPS URLs")
    return value


def _require_immutable_revision(value: str | None) -> str | None:
    if value is not None and value.casefold() in MUTABLE_REVISIONS:
        raise ValueError("mutable source revisions are not accepted")
    return value


def _sorted_unique(values: list[str], *, field: str) -> list[str]:
    normalized = sorted(values, key=lambda item: (item.casefold(), item))
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{field} values must be unique")
    return normalized


def _bounded_identifiers(values: list[str], *, field: str) -> list[str]:
    for value in values:
        if not 1 <= len(value) <= 128 or re.fullmatch(IDENTIFIER_PATTERN, value) is None:
            raise ValueError(f"{field} entries must be bounded identifiers")
    return _sorted_unique(values, field=field)


def normalize_sha256_digest(value: str) -> str:
    normalized = value.removeprefix("sha256:")
    if re.fullmatch(SHA256_PATTERN, normalized) is None:
        raise ValueError("digest must be a lowercase SHA-256 value")
    return normalized


class StrictProvenanceModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )

    @field_validator("*", mode="before")
    @classmethod
    def reject_local_paths_and_controls(cls, value: Any) -> Any:
        if isinstance(value, str):
            if _looks_like_absolute_local_path(value):
                raise ValueError("local absolute paths are not permitted in provenance")
            if any(ord(character) < 32 for character in value):
                raise ValueError("control characters are not permitted in provenance")
        return value

    @field_validator("*", mode="after")
    @classmethod
    def normalize_timestamps(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("provenance timestamps must include a timezone")
            return value.astimezone(timezone.utc)
        return value


class ModelIdentity(StrictProvenanceModel):
    model_name: str = Field(..., min_length=1, max_length=256)
    model_family: str = Field(..., min_length=1, max_length=128)
    model_architecture: str = Field(..., min_length=1, max_length=128)
    model_purpose: str = Field(..., min_length=1, max_length=500)
    model_capabilities: list[ModelCapability] = Field(..., min_length=1, max_length=16)
    upstream_model_name: str = Field(..., min_length=1, max_length=256)
    upstream_model_revision: str | None = Field(default=None, max_length=160)
    license: str = Field(..., min_length=1, max_length=256)
    license_reference: str | None = Field(default=None, max_length=2048)

    @field_validator("upstream_model_revision")
    @classmethod
    def immutable_revision(cls, value: str | None) -> str | None:
        return _require_immutable_revision(value)

    @field_validator("license_reference")
    @classmethod
    def safe_license_reference(cls, value: str | None) -> str | None:
        return _validate_reference(value)

    @field_validator("model_capabilities")
    @classmethod
    def canonical_capabilities(cls, value: list[ModelCapability]) -> list[ModelCapability]:
        normalized = sorted(value)
        if len(normalized) != len(set(normalized)):
            raise ValueError("model capabilities must be unique")
        return normalized


class SourceCheckpointProvenance(StrictProvenanceModel):
    source_name: str = Field(..., min_length=1, max_length=256)
    source_revision: str | None = Field(default=None, max_length=160)
    source_checkpoint_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    source_digest_algorithm: Literal["sha256"] = "sha256"
    source_format: str | None = Field(default=None, max_length=128)
    source_size_bytes: int | None = Field(default=None, ge=0)
    source_license: str | None = Field(default=None, max_length=256)
    source_reference: str | None = Field(default=None, max_length=2048)

    @field_validator("source_revision")
    @classmethod
    def immutable_revision(cls, value: str | None) -> str | None:
        return _require_immutable_revision(value)

    @field_validator("source_reference")
    @classmethod
    def safe_source_reference(cls, value: str | None) -> str | None:
        return _validate_reference(value)


class ConversionProvenance(StrictProvenanceModel):
    converter_name: str | None = Field(default=None, max_length=160)
    converter_version: str | None = Field(default=None, max_length=128)
    converter_commit: str | None = Field(default=None, max_length=128, pattern=IDENTIFIER_PATTERN)
    converter_source: str | None = Field(default=None, max_length=2048)
    conversion_profile: str | None = Field(default=None, max_length=256)
    input_checkpoint_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    output_intermediate_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    conversion_started_at: datetime | None = None
    conversion_completed_at: datetime | None = None

    @field_validator("converter_source")
    @classmethod
    def safe_converter_source(cls, value: str | None) -> str | None:
        return _validate_reference(value)

    @model_validator(mode="after")
    def valid_interval(self) -> "ConversionProvenance":
        if (self.conversion_started_at is None) != (self.conversion_completed_at is None):
            raise ValueError("conversion timestamps must be supplied together")
        if (
            self.conversion_started_at is not None
            and self.conversion_completed_at is not None
            and self.conversion_completed_at < self.conversion_started_at
        ):
            raise ValueError("conversion completion cannot precede its start")
        return self


class QuantizationProvenance(StrictProvenanceModel):
    quantizer_name: str | None = Field(default=None, max_length=160)
    quantizer_version: str | None = Field(default=None, max_length=128)
    quantizer_commit: str | None = Field(default=None, max_length=128, pattern=IDENTIFIER_PATTERN)
    quantizer_source: str | None = Field(default=None, max_length=2048)
    source_artifact_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    quantization_type: str | None = Field(default=None, max_length=128)
    quantization_profile: str | None = Field(default=None, max_length=256)
    importance_matrix_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    output_artifact_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    quantization_started_at: datetime | None = None
    quantization_completed_at: datetime | None = None

    @field_validator("quantizer_source")
    @classmethod
    def safe_quantizer_source(cls, value: str | None) -> str | None:
        return _validate_reference(value)

    @model_validator(mode="after")
    def valid_interval(self) -> "QuantizationProvenance":
        if (self.quantization_started_at is None) != (self.quantization_completed_at is None):
            raise ValueError("quantization timestamps must be supplied together")
        if (
            self.quantization_started_at is not None
            and self.quantization_completed_at is not None
            and self.quantization_completed_at < self.quantization_started_at
        ):
            raise ValueError("quantization completion cannot precede its start")
        return self


class ArtifactSplit(StrictProvenanceModel):
    ordinal: int = Field(..., ge=1, le=MAX_ARTIFACT_SPLITS)
    name: str = Field(..., min_length=1, max_length=256)
    digest: str = Field(..., pattern=SHA256_PATTERN)
    size_bytes: int = Field(..., ge=0)


def split_manifest_digest(splits: list[ArtifactSplit]) -> str:
    content = [item.model_dump(mode="json") for item in sorted(splits, key=lambda item: item.ordinal)]
    encoded = json.dumps(
        content,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ModelArtifactIdentity(StrictProvenanceModel):
    artifact_name: str = Field(..., min_length=1, max_length=256)
    artifact_format: str = Field(..., min_length=1, max_length=128)
    artifact_digest: str = Field(..., pattern=SHA256_PATTERN)
    artifact_digest_algorithm: Literal["sha256"] = "sha256"
    artifact_size_bytes: int = Field(..., ge=0)
    split_count: int = Field(default=0, ge=0, le=MAX_ARTIFACT_SPLITS)
    splits: list[ArtifactSplit] = Field(default_factory=list, max_length=MAX_ARTIFACT_SPLITS)
    split_manifest_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    parent_artifact_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    created_at: datetime

    @model_validator(mode="after")
    def validate_splits(self) -> "ModelArtifactIdentity":
        self.splits = sorted(self.splits, key=lambda item: item.ordinal)
        if self.split_count != len(self.splits):
            raise ValueError("artifact split_count must match the split manifest")
        if self.splits:
            if [item.ordinal for item in self.splits] != list(range(1, len(self.splits) + 1)):
                raise ValueError("artifact split ordinals must be contiguous from one")
            if len({item.name for item in self.splits}) != len(self.splits):
                raise ValueError("artifact split names must be unique")
            expected = split_manifest_digest(self.splits)
            if self.split_manifest_digest != expected:
                raise ValueError("artifact split manifest digest does not match its ordered entries")
        elif self.split_manifest_digest is not None:
            raise ValueError("a non-split artifact cannot have a split manifest digest")
        return self


class RuntimeCompatibility(StrictProvenanceModel):
    runtime_type: str | None = Field(default=None, max_length=128)
    runtime_version: str | None = Field(default=None, max_length=128)
    runtime_commit: str | None = Field(default=None, max_length=128, pattern=IDENTIFIER_PATTERN)
    provider_protocol: Literal["openai-compatible"] = "openai-compatible"
    supported_backends: list[str] = Field(default_factory=list, max_length=32)
    supported_hardware_architectures: list[str] = Field(default_factory=list, max_length=32)
    minimum_runtime_commit: str | None = Field(default=None, max_length=128, pattern=IDENTIFIER_PATTERN)
    maximum_tested_context: int | None = Field(default=None, ge=1, le=16_777_216)
    required_memory_bytes: int | None = Field(default=None, ge=0)

    @field_validator("supported_backends", "supported_hardware_architectures")
    @classmethod
    def canonical_string_sets(cls, value: list[str], info: Any) -> list[str]:
        return _bounded_identifiers(value, field=info.field_name)


class ResourceObservations(StrictProvenanceModel):
    input_size_bytes: int | None = Field(default=None, ge=0)
    output_size_bytes: int | None = Field(default=None, ge=0)
    peak_rss_bytes: int | None = Field(default=None, ge=0)
    peak_gpu_memory_bytes: int | None = Field(default=None, ge=0)
    temporary_storage_bytes: int | None = Field(default=None, ge=0)
    staging_limit_bytes: int | None = Field(default=None, ge=0)
    streaming_output: bool | None = None
    elapsed_seconds: float | None = Field(default=None, ge=0)
    measurement_environment: str | None = Field(default=None, max_length=500)
    measurement_classification: Literal["measured", "estimated", "synthetic", "unknown"]


def canonical_manifest_bytes(manifest: "ModelArtifactManifest") -> bytes:
    payload = manifest.model_dump(mode="json", exclude={"manifest_digest"})
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def compute_manifest_digest(manifest: "ModelArtifactManifest") -> str:
    return hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


class ModelArtifactManifest(StrictProvenanceModel):
    schema_version: Literal["oaw.model-artifact-manifest.v1"] = MODEL_ARTIFACT_MANIFEST_VERSION
    manifest_id: str = Field(..., min_length=1, max_length=160, pattern=IDENTIFIER_PATTERN)
    manifest_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    model_identity: ModelIdentity
    source_checkpoint: SourceCheckpointProvenance
    conversion: ConversionProvenance
    quantization: QuantizationProvenance
    artifact: ModelArtifactIdentity
    runtime_compatibility: RuntimeCompatibility
    resource_observations: ResourceObservations | None = None
    provenance_state: ProvenanceState
    created_at: datetime

    @model_validator(mode="after")
    def validate_lineage_and_digest(self) -> "ModelArtifactManifest":
        upstream_revision = self.model_identity.upstream_model_revision
        source_revision = self.source_checkpoint.source_revision
        if (
            upstream_revision is not None
            and source_revision is not None
            and upstream_revision != source_revision
        ):
            raise ValueError("source checkpoint revision does not match model identity")
        source_digest = self.source_checkpoint.source_checkpoint_digest
        conversion_input = self.conversion.input_checkpoint_digest
        if source_digest is not None and conversion_input is not None and source_digest != conversion_input:
            raise ValueError("converter input digest does not match the source checkpoint")
        conversion_output = self.conversion.output_intermediate_digest
        quantization_input = self.quantization.source_artifact_digest
        if (
            conversion_output is not None
            and quantization_input is not None
            and conversion_output != quantization_input
        ):
            raise ValueError("quantizer source digest does not match conversion output")
        quantization_output = self.quantization.output_artifact_digest
        if quantization_output is not None and quantization_output != self.artifact.artifact_digest:
            raise ValueError("artifact digest does not match quantization output")
        conversion_completed = self.conversion.conversion_completed_at
        quantization_started = self.quantization.quantization_started_at
        quantization_completed = self.quantization.quantization_completed_at
        if (
            conversion_completed is not None
            and quantization_started is not None
            and quantization_started < conversion_completed
        ):
            raise ValueError("quantization cannot start before conversion completes")
        if (
            quantization_completed is not None
            and self.artifact.created_at < quantization_completed
        ):
            raise ValueError("artifact creation cannot precede quantization completion")
        if self.created_at < self.artifact.created_at:
            raise ValueError("manifest creation cannot precede artifact creation")

        if self.provenance_state == "complete":
            required = (
                upstream_revision,
                source_revision,
                source_digest,
                self.source_checkpoint.source_format,
                self.source_checkpoint.source_size_bytes,
                self.source_checkpoint.source_license,
                self.source_checkpoint.source_reference,
                self.conversion.converter_name,
                self.conversion.converter_version,
                self.conversion.converter_commit,
                self.conversion.converter_source,
                self.conversion.conversion_profile,
                conversion_input,
                conversion_output,
                self.conversion.conversion_started_at,
                self.conversion.conversion_completed_at,
                self.quantization.quantizer_name,
                self.quantization.quantizer_version,
                self.quantization.quantizer_commit,
                self.quantization.quantizer_source,
                quantization_input,
                self.quantization.quantization_type,
                self.quantization.quantization_profile,
                quantization_output,
                self.quantization.quantization_started_at,
                self.quantization.quantization_completed_at,
                self.runtime_compatibility.runtime_type,
                self.runtime_compatibility.runtime_version,
                self.runtime_compatibility.runtime_commit,
            )
            if any(value is None or value == "" for value in required):
                raise ValueError("complete provenance requires immutable identity for every lifecycle stage")
        if self.provenance_state == "unknown" and any(
            (
                upstream_revision,
                source_revision,
                source_digest,
                self.conversion.converter_commit,
                self.quantization.quantizer_commit,
            )
        ):
            raise ValueError("unknown provenance cannot assert immutable lineage")

        expected = compute_manifest_digest(self)
        if self.manifest_digest is None:
            self.manifest_digest = expected
        elif self.manifest_digest != expected:
            raise ValueError("manifest digest does not match canonical manifest content")
        return self


def _json_without_duplicate_keys(raw: bytes) -> dict[str, Any]:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("configured provenance file must be UTF-8 JSON") from exc

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("configured provenance JSON contains duplicate keys")
            result[key] = value
        return result

    try:
        payload = json.loads(decoded, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("configured provenance file contains malformed JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("configured provenance JSON must be an object")
    return payload


def read_bounded_local_json(path: str | Path, *, maximum_bytes: int) -> dict[str, Any]:
    """Read one explicitly configured regular file without following a final symlink."""

    configured = Path(path)
    if any(part == ".." for part in configured.parts):
        raise ValueError("configured provenance paths cannot contain parent traversal")
    absolute = configured.absolute()
    if any(parent.is_symlink() for parent in absolute.parents):
        raise ValueError("configured provenance paths cannot traverse symlinked directories")
    before = configured.lstat()
    if not stat.S_ISREG(before.st_mode) or configured.is_symlink():
        raise ValueError("configured provenance path must be a regular non-symlink file")
    if before.st_size > maximum_bytes:
        raise ValueError("configured provenance file exceeds the safety limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(configured, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise ValueError("configured provenance file changed while being opened")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64_000, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise ValueError("configured provenance file exceeds the safety limit")
    finally:
        os.close(descriptor)
    after = configured.lstat()
    if (
        (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise ValueError("configured provenance file changed while being read")
    return _json_without_duplicate_keys(b"".join(chunks))


def load_model_artifact_manifest(path: str | Path) -> ModelArtifactManifest:
    payload = read_bounded_local_json(
        path,
        maximum_bytes=MAX_MODEL_ARTIFACT_MANIFEST_BYTES,
    )
    if "manifest_digest" not in payload:
        raise ValueError("configured manifest must include its canonical digest")
    return ModelArtifactManifest.model_validate(payload)


class ModelArtifactAdvisory(StrictProvenanceModel):
    schema_version: Literal["oaw.model-artifact-advisory.v1"] = MODEL_ARTIFACT_ADVISORY_VERSION
    advisory_id: str = Field(..., min_length=1, max_length=160, pattern=IDENTIFIER_PATTERN)
    title: str = Field(..., min_length=1, max_length=300)
    component_type: ArtifactComponentType
    component_name: str = Field(..., min_length=1, max_length=160)
    affected_exact_commits: list[str] = Field(default_factory=list, max_length=64)
    affected_versions: list[str] = Field(default_factory=list, max_length=64)
    fixed_in_commit: str | None = Field(default=None, max_length=128, pattern=IDENTIFIER_PATTERN)
    severity: Literal["low", "medium", "high", "critical"]
    status: Literal["active", "withdrawn", "superseded"] = "active"
    required_action: ArtifactRequiredAction
    source_reference: str = Field(..., max_length=2048)
    published_at: datetime
    reviewed_at: datetime

    @field_validator("source_reference")
    @classmethod
    def safe_source_reference(cls, value: str) -> str:
        validated = _validate_reference(value)
        assert validated is not None
        return validated

    @field_validator("affected_exact_commits", "affected_versions")
    @classmethod
    def canonical_affected_values(cls, value: list[str], info: Any) -> list[str]:
        return _bounded_identifiers(value, field=info.field_name)

    @model_validator(mode="after")
    def valid_review_time(self) -> "ModelArtifactAdvisory":
        if self.reviewed_at < self.published_at:
            raise ValueError("artifact advisory review cannot precede publication")
        return self


class ModelArtifactAdvisoryRegistry(StrictProvenanceModel):
    schema_version: Literal["oaw.model-artifact-advisory-registry.v1"] = (
        MODEL_ARTIFACT_ADVISORY_REGISTRY_VERSION
    )
    advisories: list[ModelArtifactAdvisory] = Field(
        default_factory=list,
        max_length=MAX_ARTIFACT_ADVISORIES,
    )

    @model_validator(mode="after")
    def unique_advisory_ids(self) -> "ModelArtifactAdvisoryRegistry":
        identifiers = [item.advisory_id for item in self.advisories]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("artifact advisory identifiers must be unique")
        self.advisories = sorted(self.advisories, key=lambda item: item.advisory_id)
        return self


def load_model_artifact_advisories(path: str | Path) -> ModelArtifactAdvisoryRegistry:
    payload = read_bounded_local_json(
        path,
        maximum_bytes=MAX_MODEL_ARTIFACT_ADVISORY_REGISTRY_BYTES,
    )
    return ModelArtifactAdvisoryRegistry.model_validate(payload)


class ArtifactInvalidationResult(StrictProvenanceModel):
    state: ProvenanceState
    matched_advisory_ids: list[str] = Field(default_factory=list, max_length=MAX_ARTIFACT_ADVISORIES)
    required_actions: list[ArtifactRequiredAction] = Field(
        default_factory=list,
        max_length=16,
    )
    qualification_valid: bool
    reason_codes: list[str] = Field(default_factory=list, max_length=64)


_ACTION_ORDER = {
    "informational": 0,
    "requalification-required": 1,
    "reconversion-required": 2,
    "requantization-required": 3,
    "runtime-upgrade-required": 4,
    "block-use": 5,
}


def _advisory_target(
    manifest: ModelArtifactManifest,
    advisory: ModelArtifactAdvisory,
    *,
    qualification_binding: "ModelQualificationBinding | None",
    qualification_suite_name: str | None,
) -> str | None:
    component = advisory.component_type
    if component == "source-checkpoint":
        if manifest.source_checkpoint.source_name.casefold() != advisory.component_name.casefold():
            return None
        return manifest.source_checkpoint.source_revision
    if component == "converter":
        if (manifest.conversion.converter_name or "").casefold() != advisory.component_name.casefold():
            return None
        return manifest.conversion.converter_commit
    if component == "quantizer":
        if (manifest.quantization.quantizer_name or "").casefold() != advisory.component_name.casefold():
            return None
        return manifest.quantization.quantizer_commit
    if component == "runtime":
        if (manifest.runtime_compatibility.runtime_type or "").casefold() != advisory.component_name.casefold():
            return None
        return manifest.runtime_compatibility.runtime_commit
    if component == "artifact-format":
        if manifest.artifact.artifact_format.casefold() != advisory.component_name.casefold():
            return None
        return manifest.artifact.artifact_format
    if component == "qualification-suite":
        if (
            qualification_binding is None
            or qualification_suite_name is None
            or qualification_suite_name.casefold() != advisory.component_name.casefold()
        ):
            return None
        return qualification_binding.qualification_suite_version
    return None


def evaluate_artifact_advisories(
    manifest: ModelArtifactManifest,
    advisories: list[ModelArtifactAdvisory] | tuple[ModelArtifactAdvisory, ...],
    *,
    current_qualification_valid: bool = True,
    qualification_binding: "ModelQualificationBinding | None" = None,
    qualification_suite_name: str | None = None,
) -> ArtifactInvalidationResult:
    identifiers = [item.advisory_id for item in advisories]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("artifact advisory identifiers must be unique")
    matched: list[ModelArtifactAdvisory] = []
    reasons: set[str] = set()
    actions: set[ArtifactRequiredAction] = set()
    for advisory in sorted(advisories, key=lambda item: item.advisory_id):
        if advisory.status != "active":
            continue
        target = _advisory_target(
            manifest,
            advisory,
            qualification_binding=qualification_binding,
            qualification_suite_name=qualification_suite_name,
        )
        if target is None:
            continue
        affected = target in advisory.affected_exact_commits or target in advisory.affected_versions
        if not affected:
            continue
        matched.append(advisory)
        actions.add(advisory.required_action)
        reasons.add(f"{advisory.component_type}-affected")
        if advisory.required_action in {
            "reconversion-required",
            "requantization-required",
            "runtime-upgrade-required",
        }:
            actions.add("requalification-required")
        if advisory.required_action == "block-use":
            actions.add("requalification-required")
            reasons.add("artifact-use-blocked")

    blocking = any(action != "informational" for action in actions)
    state: ProvenanceState = manifest.provenance_state
    if "block-use" in actions:
        state = "invalid"
    elif blocking:
        state = "requalification-required"
    return ArtifactInvalidationResult(
        state=state,
        matched_advisory_ids=[item.advisory_id for item in matched],
        required_actions=sorted(actions, key=lambda item: _ACTION_ORDER[item]),
        qualification_valid=current_qualification_valid and not blocking,
        reason_codes=sorted(reasons),
    )


class ModelQualificationBinding(StrictProvenanceModel):
    schema_version: Literal["oaw.model-qualification-binding.v1"] = (
        MODEL_QUALIFICATION_BINDING_VERSION
    )
    artifact_digest: str = Field(..., pattern=SHA256_PATTERN)
    artifact_manifest_digest: str = Field(..., pattern=SHA256_PATTERN)
    source_checkpoint_digest: str = Field(..., pattern=SHA256_PATTERN)
    source_checkpoint_revision: str = Field(
        ...,
        min_length=1,
        max_length=160,
        pattern=IDENTIFIER_PATTERN,
    )
    converter_commit: str = Field(..., min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    quantizer_commit: str = Field(..., min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    runtime_commit: str = Field(..., min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    qualification_suite_version: str = Field(..., min_length=1, max_length=128)
    qualification_fixture_version: str = Field(..., min_length=1, max_length=128)
    qualified_at: datetime


class QualificationBindingEvaluation(StrictProvenanceModel):
    state: QualificationBindingState
    matched: bool
    reason_codes: list[str] = Field(default_factory=list, max_length=16)


def build_qualification_binding(
    manifest: ModelArtifactManifest,
    *,
    runtime_commit: str,
    qualification_suite_version: str,
    qualification_fixture_version: str,
    qualified_at: datetime,
) -> ModelQualificationBinding:
    if manifest.provenance_state != "complete":
        raise ValueError("qualification binding requires complete model provenance")
    expected_runtime = manifest.runtime_compatibility.runtime_commit
    if not expected_runtime or runtime_commit != expected_runtime:
        raise ValueError("qualification runtime commit does not match the artifact manifest")
    assert manifest.manifest_digest is not None
    assert manifest.source_checkpoint.source_checkpoint_digest is not None
    assert manifest.source_checkpoint.source_revision is not None
    assert manifest.conversion.converter_commit is not None
    assert manifest.quantization.quantizer_commit is not None
    return ModelQualificationBinding(
        artifact_digest=manifest.artifact.artifact_digest,
        artifact_manifest_digest=manifest.manifest_digest,
        source_checkpoint_digest=manifest.source_checkpoint.source_checkpoint_digest,
        source_checkpoint_revision=manifest.source_checkpoint.source_revision,
        converter_commit=manifest.conversion.converter_commit,
        quantizer_commit=manifest.quantization.quantizer_commit,
        runtime_commit=runtime_commit,
        qualification_suite_version=qualification_suite_version,
        qualification_fixture_version=qualification_fixture_version,
        qualified_at=qualified_at,
    )


def evaluate_qualification_binding(
    manifest: ModelArtifactManifest,
    binding: ModelQualificationBinding | None,
    *,
    required_suite_version: str,
    required_fixture_version: str,
) -> QualificationBindingEvaluation:
    if binding is None:
        return QualificationBindingEvaluation(
            state="required-missing",
            matched=False,
            reason_codes=["qualification-binding-missing"],
        )
    if manifest.provenance_state != "complete" or manifest.manifest_digest is None:
        return QualificationBindingEvaluation(
            state="invalid",
            matched=False,
            reason_codes=["manifest-provenance-incomplete"],
        )
    comparisons = {
        "artifact-digest-mismatch": (
            binding.artifact_digest,
            manifest.artifact.artifact_digest,
        ),
        "manifest-digest-mismatch": (
            binding.artifact_manifest_digest,
            manifest.manifest_digest,
        ),
        "source-checkpoint-digest-mismatch": (
            binding.source_checkpoint_digest,
            manifest.source_checkpoint.source_checkpoint_digest,
        ),
        "source-checkpoint-revision-mismatch": (
            binding.source_checkpoint_revision,
            manifest.source_checkpoint.source_revision,
        ),
        "converter-commit-mismatch": (
            binding.converter_commit,
            manifest.conversion.converter_commit,
        ),
        "quantizer-commit-mismatch": (
            binding.quantizer_commit,
            manifest.quantization.quantizer_commit,
        ),
        "runtime-commit-mismatch": (
            binding.runtime_commit,
            manifest.runtime_compatibility.runtime_commit,
        ),
        "qualification-suite-version-mismatch": (
            binding.qualification_suite_version,
            required_suite_version,
        ),
        "qualification-fixture-version-mismatch": (
            binding.qualification_fixture_version,
            required_fixture_version,
        ),
    }
    reasons = sorted(
        reason
        for reason, (actual, expected) in comparisons.items()
        if actual != expected
    )
    return QualificationBindingEvaluation(
        state="matched" if not reasons else "mismatch",
        matched=not reasons,
        reason_codes=reasons,
    )
