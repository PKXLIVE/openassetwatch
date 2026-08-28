from __future__ import annotations

from datetime import datetime, timezone

from app.model_artifact_provenance import (
    ArtifactSplit,
    ModelArtifactManifest,
    split_manifest_digest,
)


FIXED_TIME = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
SOURCE_DIGEST = "a" * 64
INTERMEDIATE_DIGEST = "b" * 64
ARTIFACT_DIGEST = "c" * 64
CONVERTER_COMMIT = "converter-commit-001"
QUANTIZER_COMMIT = "quantizer-commit-001"
RUNTIME_COMMIT = "runtime-commit-001"
SOURCE_REVISION = "source-revision-001"


def complete_manifest() -> ModelArtifactManifest:
    return ModelArtifactManifest(
        manifest_id="advisor-model-artifact-001",
        model_identity={
            "model_name": "advisor-model",
            "model_family": "fixture-family",
            "model_architecture": "fixture-transformer",
            "model_purpose": "Bounded read-only Advisor fixture",
            "model_capabilities": ["structured_output", "reasoning"],
            "upstream_model_name": "fixture/upstream-model",
            "upstream_model_revision": SOURCE_REVISION,
            "license": "fixture-license",
            "license_reference": "https://models.example.invalid/licenses/fixture",
        },
        source_checkpoint={
            "source_name": "fixture/upstream-model",
            "source_revision": SOURCE_REVISION,
            "source_checkpoint_digest": SOURCE_DIGEST,
            "source_digest_algorithm": "sha256",
            "source_format": "safetensors",
            "source_size_bytes": 4_096,
            "source_license": "fixture-license",
            "source_reference": "https://models.example.invalid/fixture/source",
        },
        conversion={
            "converter_name": "fixture-converter",
            "converter_version": "1.0.0",
            "converter_commit": CONVERTER_COMMIT,
            "converter_source": "https://code.example.invalid/fixture/converter",
            "conversion_profile": "reviewed-default",
            "input_checkpoint_digest": SOURCE_DIGEST,
            "output_intermediate_digest": INTERMEDIATE_DIGEST,
            "conversion_started_at": FIXED_TIME,
            "conversion_completed_at": FIXED_TIME,
        },
        quantization={
            "quantizer_name": "fixture-quantizer",
            "quantizer_version": "1.0.0",
            "quantizer_commit": QUANTIZER_COMMIT,
            "quantizer_source": "https://code.example.invalid/fixture/quantizer",
            "source_artifact_digest": INTERMEDIATE_DIGEST,
            "quantization_type": "fixture-q4",
            "quantization_profile": "reviewed-default",
            "importance_matrix_digest": "d" * 64,
            "output_artifact_digest": ARTIFACT_DIGEST,
            "quantization_started_at": FIXED_TIME,
            "quantization_completed_at": FIXED_TIME,
        },
        artifact={
            "artifact_name": "advisor-model.fixture",
            "artifact_format": "fixture-format",
            "artifact_digest": ARTIFACT_DIGEST,
            "artifact_digest_algorithm": "sha256",
            "artifact_size_bytes": 2_048,
            "split_count": 0,
            "created_at": FIXED_TIME,
        },
        runtime_compatibility={
            "runtime_type": "openai-compatible",
            "runtime_version": "1.0.0",
            "runtime_commit": RUNTIME_COMMIT,
            "provider_protocol": "openai-compatible",
            "supported_backends": ["cpu", "rocm"],
            "supported_hardware_architectures": ["generic"],
            "minimum_runtime_commit": "runtime-commit-000",
            "maximum_tested_context": 8_192,
            "required_memory_bytes": 8_192,
        },
        resource_observations={
            "input_size_bytes": 4_096,
            "output_size_bytes": 2_048,
            "peak_rss_bytes": 16_384,
            "temporary_storage_bytes": 8_192,
            "staging_limit_bytes": 32_768,
            "streaming_output": True,
            "elapsed_seconds": 1.5,
            "measurement_environment": "bounded test fixture",
            "measurement_classification": "synthetic",
        },
        provenance_state="complete",
        created_at=FIXED_TIME,
    )


def complete_split_manifest(*, reversed_splits: bool = False) -> ModelArtifactManifest:
    splits = [
        ArtifactSplit(ordinal=1, name="part-0001", digest="1" * 64, size_bytes=100),
        ArtifactSplit(ordinal=2, name="part-0002", digest="2" * 64, size_bytes=200),
    ]
    logical_digest = split_manifest_digest(splits)
    if reversed_splits:
        splits.reverse()

    payload = complete_manifest().model_dump(mode="json")
    payload["manifest_digest"] = None
    payload["quantization"]["output_artifact_digest"] = logical_digest
    payload["artifact"].update(
        {
            "artifact_digest": logical_digest,
            "artifact_size_bytes": sum(item.size_bytes for item in splits),
            "split_count": len(splits),
            "splits": [item.model_dump(mode="json") for item in splits],
            "split_manifest_digest": logical_digest,
        }
    )
    return ModelArtifactManifest.model_validate(payload)


def partial_manifest() -> ModelArtifactManifest:
    payload = complete_manifest().model_dump(mode="json")
    payload["manifest_digest"] = None
    payload["provenance_state"] = "partial"
    payload["source_checkpoint"]["source_reference"] = None
    payload["conversion"]["converter_version"] = None
    return ModelArtifactManifest.model_validate(payload)


def unknown_manifest() -> ModelArtifactManifest:
    payload = complete_manifest().model_dump(mode="json")
    payload["manifest_digest"] = None
    payload["provenance_state"] = "unknown"
    payload["model_identity"]["upstream_model_revision"] = None
    payload["source_checkpoint"].update(
        {
            "source_revision": None,
            "source_checkpoint_digest": None,
            "source_format": None,
            "source_size_bytes": None,
            "source_license": None,
            "source_reference": None,
        }
    )
    payload["conversion"] = {}
    payload["quantization"] = {}
    payload["runtime_compatibility"] = {}
    return ModelArtifactManifest.model_validate(payload)
