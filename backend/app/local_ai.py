"""Provider-neutral local inference runtime and qualification contracts."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


QUALIFICATION_VERSION = "oaw.local-ai.v1"
MAX_QUALIFICATION_RESULT_BYTES = 1_000_000
REQUIRED_QUALIFICATION_TESTS = frozenset(
    {
        "models_reachable",
        "chat_completions_reachable",
        "basic_generation",
        "strict_structured_output",
        "evidence_grounding",
        "asset_grounding",
        "finding_grounding",
        "vulnerability_grounding",
        "prompt_injection_resistance",
        "authority_preservation",
        "advisory_only",
        "output_limits",
        "timeout_error_handling",
    }
)

QualificationTestStatus = Literal["passed", "failed", "skipped"]
QualificationState = Literal["not-configured", "approved", "rejected", "invalid"]
RuntimeHealthStatus = Literal["unknown", "available", "unavailable", "degraded"]


class StrictLocalAIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LocalAIHardwareMetadata(StrictLocalAIModel):
    vendor: str | None = Field(default=None, max_length=128)
    device_name: str | None = Field(default=None, max_length=256)
    architecture: str | None = Field(default=None, max_length=128)
    backend: str | None = Field(default=None, max_length=128)
    total_memory_bytes: int | None = Field(default=None, ge=0)
    available_memory_bytes: int | None = Field(default=None, ge=0)
    supported_precision: list[str] = Field(default_factory=list, max_length=32)


class LocalAIRuntimeMetrics(StrictLocalAIModel):
    request_count: int | None = Field(default=None, ge=0)
    latency_ms: float | None = Field(default=None, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    validation_failures: int | None = Field(default=None, ge=0)
    provider_failures: int | None = Field(default=None, ge=0)
    fallback_count: int | None = Field(default=None, ge=0)
    queue_depth: int | None = Field(default=None, ge=0)
    prompt_throughput_tokens_per_second: float | None = Field(default=None, ge=0)
    generation_throughput_tokens_per_second: float | None = Field(default=None, ge=0)
    gpu_memory_used_bytes: int | None = Field(default=None, ge=0)


class LocalAIRuntimeMetadata(StrictLocalAIModel):
    runtime_id: str = Field(..., min_length=1, max_length=160)
    runtime_type: str = Field(..., min_length=1, max_length=128)
    runtime_version: str | None = Field(default=None, max_length=128)
    runtime_commit: str | None = Field(default=None, max_length=128)
    provider_protocol: Literal["openai-compatible"] = "openai-compatible"
    base_url: str = Field(..., min_length=1, max_length=2048)
    deployment_location: Literal["local", "trusted-internal", "external"] = "local"
    backend: str | None = Field(default=None, max_length=128)
    hardware_architecture: str | None = Field(default=None, max_length=128)
    capabilities: dict[str, bool | None] = Field(default_factory=dict, max_length=64)
    validation_status: Literal["not-run", "passed", "failed"] = "not-run"
    health_status: RuntimeHealthStatus = "unknown"
    hardware: LocalAIHardwareMetadata | None = None
    metrics: LocalAIRuntimeMetrics = Field(default_factory=LocalAIRuntimeMetrics)
    loaded_at: datetime | None = None
    last_health_check: datetime | None = None


class LocalAIModelMetadata(StrictLocalAIModel):
    model_name: str = Field(..., min_length=1, max_length=512)
    model_digest: str | None = Field(default=None, max_length=256)
    model_size_bytes: int | None = Field(default=None, ge=0)
    quantization: str | None = Field(default=None, max_length=128)
    quant_profile: str | None = Field(default=None, max_length=128)
    source: str | None = Field(default=None, max_length=2048)
    license: str | None = Field(default=None, max_length=256)


class LocalAIQualificationTest(StrictLocalAIModel):
    test_id: str = Field(..., min_length=1, max_length=128)
    category: str = Field(..., min_length=1, max_length=128)
    required: bool = True
    status: QualificationTestStatus
    duration_ms: float | None = Field(default=None, ge=0)
    detail: str = Field(..., min_length=1, max_length=1000)


class LocalAIQualificationSummary(StrictLocalAIModel):
    passed: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)
    skipped: int = Field(default=0, ge=0)


class LocalAIQualificationResult(StrictLocalAIModel):
    qualification_version: Literal["oaw.local-ai.v1"] = QUALIFICATION_VERSION
    started_at: datetime
    completed_at: datetime
    runtime: LocalAIRuntimeMetadata
    model: LocalAIModelMetadata
    tests: list[LocalAIQualificationTest] = Field(..., min_length=1, max_length=128)
    summary: LocalAIQualificationSummary = Field(default_factory=LocalAIQualificationSummary)
    advisor_approved: bool = False

    @model_validator(mode="after")
    def derive_approval(self) -> "LocalAIQualificationResult":
        test_ids = [item.test_id for item in self.tests]
        if len(test_ids) != len(set(test_ids)):
            raise ValueError("qualification test identifiers must be unique")

        self.summary = LocalAIQualificationSummary(
            passed=sum(item.status == "passed" for item in self.tests),
            failed=sum(item.status == "failed" for item in self.tests),
            skipped=sum(item.status == "skipped" for item in self.tests),
        )
        required_by_id = {item.test_id: item for item in self.tests if item.required}
        required_ids = set(REQUIRED_QUALIFICATION_TESTS)
        if self.runtime.runtime_type.casefold() == "rocmfpx":
            required_ids.add("runtime_provenance")
        self.advisor_approved = (
            all(
                test_id in required_by_id
                and required_by_id[test_id].status == "passed"
                for test_id in required_ids
            )
            and all(item.status == "passed" for item in self.tests if item.required)
        )
        self.runtime.validation_status = "passed" if self.advisor_approved else "failed"
        return self


def load_qualification_result(path: str | Path) -> LocalAIQualificationResult:
    """Load one bounded operator-supplied qualification record."""

    result_path = Path(path)
    with result_path.open("rb") as handle:
        raw = handle.read(MAX_QUALIFICATION_RESULT_BYTES + 1)
    if len(raw) > MAX_QUALIFICATION_RESULT_BYTES:
        raise ValueError("qualification result exceeds the safety limit")
    return LocalAIQualificationResult.model_validate_json(raw)
