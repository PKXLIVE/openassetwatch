from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from app.ai_advisor import (
    OpenAICompatibleProvider,
    ProviderConfig,
    ProviderUnavailableError,
    provider_status,
)
from app.local_ai import (
    REQUIRED_QUALIFICATION_TESTS,
    LocalAIModelMetadata,
    LocalAIQualificationResult,
    LocalAIQualificationTest,
    LocalAIRuntimeMetadata,
    load_qualification_result,
)


NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


def qualification_result(
    *,
    runtime_type: str = "openai-compatible",
    include_provenance: bool = False,
) -> LocalAIQualificationResult:
    tests = [
        LocalAIQualificationTest(
            test_id=test_id,
            category="required",
            required=True,
            status="passed",
            detail="Mocked qualification gate passed.",
        )
        for test_id in sorted(REQUIRED_QUALIFICATION_TESTS)
    ]
    if include_provenance:
        tests.append(
            LocalAIQualificationTest(
                test_id="runtime_provenance",
                category="provenance",
                required=True,
                status="passed",
                detail="Runtime and model provenance were supplied.",
            )
        )
    return LocalAIQualificationResult(
        started_at=NOW,
        completed_at=NOW,
        runtime=LocalAIRuntimeMetadata(
            runtime_id="runtime-local-1",
            runtime_type=runtime_type,
            runtime_version="test-version",
            runtime_commit="c49ebdbd5c9f01ec242369f9e7f7967855f80cba",
            base_url="http://rocmfpx:8080/v1",
            backend="ROCm",
            hardware_architecture="gfx1201",
            capabilities={"structured_output": True, "streaming": None},
        ),
        model=LocalAIModelMetadata(
            model_name="advisor-model",
            model_digest="sha256:" + "a" * 64,
            model_size_bytes=1_024,
            quantization="test-quant",
            quant_profile="coherent",
            source="operator-supplied",
            license="unknown",
        ),
        tests=tests,
    )


class LocalAIContractTests(unittest.TestCase):
    def test_required_passes_derive_approval_and_summary(self) -> None:
        result = qualification_result()

        self.assertTrue(result.advisor_approved)
        self.assertEqual(result.runtime.validation_status, "passed")
        self.assertEqual(result.summary.passed, len(REQUIRED_QUALIFICATION_TESTS))
        self.assertEqual(result.summary.failed, 0)
        self.assertIsNone(result.runtime.metrics.queue_depth)
        self.assertIsNone(result.runtime.metrics.gpu_memory_used_bytes)

    def test_required_failure_cannot_be_overridden_by_input_flag(self) -> None:
        result = qualification_result()
        tests = list(result.tests)
        tests[0] = tests[0].model_copy(update={"status": "failed"})

        rejected = LocalAIQualificationResult(
            started_at=NOW,
            completed_at=NOW,
            runtime=result.runtime,
            model=result.model,
            tests=tests,
            advisor_approved=True,
        )

        self.assertFalse(rejected.advisor_approved)
        self.assertEqual(rejected.runtime.validation_status, "failed")

    def test_rocmfpx_approval_requires_explicit_provenance_gate(self) -> None:
        without_gate = qualification_result(runtime_type="ROCmFPX")
        with_gate = qualification_result(
            runtime_type="ROCmFPX",
            include_provenance=True,
        )

        self.assertFalse(without_gate.advisor_approved)
        self.assertTrue(with_gate.advisor_approved)

    def test_bounded_result_round_trip_and_provider_status(self) -> None:
        result = qualification_result()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qualification.json"
            path.write_text(result.model_dump_json(indent=2), encoding="utf-8")

            loaded = load_qualification_result(path)
            status = provider_status(
                ProviderConfig(
                    provider="openai-compatible",
                    external_enabled=False,
                    base_url="http://rocmfpx:8080/v1",
                    api_key=None,
                    model="advisor-model",
                    timeout_seconds=10,
                    local_provider_hosts=frozenset({"rocmfpx"}),
                    qualification_result_path=str(path),
                ),
                check_availability=False,
            )

        self.assertTrue(loaded.advisor_approved)
        self.assertEqual(status.qualification_state, "approved")
        self.assertEqual(status.runtime.runtime_id, "runtime-local-1")
        self.assertEqual(status.runtime.backend, "ROCm")
        self.assertEqual(status.runtime.hardware_architecture, "gfx1201")
        self.assertEqual(status.health_status, "unknown")

    def test_mismatched_or_malformed_result_is_never_reported_as_approved(self) -> None:
        result = qualification_result()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qualification.json"
            path.write_text(json.dumps({"advisor_approved": True}), encoding="utf-8")
            malformed = provider_status(
                ProviderConfig(
                    "openai-compatible",
                    False,
                    "http://rocmfpx:8080/v1",
                    None,
                    "advisor-model",
                    10,
                    frozenset({"rocmfpx"}),
                    str(path),
                ),
                check_availability=False,
            )

            path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
            mismatched = provider_status(
                ProviderConfig(
                    "openai-compatible",
                    False,
                    "http://rocmfpx:8080/v1",
                    None,
                    "different-model",
                    10,
                    frozenset({"rocmfpx"}),
                    str(path),
                ),
                check_availability=False,
            )

        self.assertEqual(malformed.qualification_state, "invalid")
        self.assertFalse(malformed.enabled)
        self.assertFalse(malformed.available)
        self.assertIsNone(malformed.runtime)
        self.assertEqual(mismatched.qualification_state, "invalid")
        self.assertFalse(mismatched.enabled)
        self.assertFalse(mismatched.available)
        self.assertIsNone(mismatched.runtime)

    def test_configured_rejected_qualification_blocks_provider_construction(self) -> None:
        result = qualification_result()
        failed_tests = list(result.tests)
        failed_tests[0] = failed_tests[0].model_copy(update={"status": "failed"})
        rejected = LocalAIQualificationResult(
            started_at=NOW,
            completed_at=NOW,
            runtime=result.runtime,
            model=result.model,
            tests=failed_tests,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qualification.json"
            path.write_text(rejected.model_dump_json(indent=2), encoding="utf-8")
            config = ProviderConfig(
                "openai-compatible",
                False,
                "http://rocmfpx:8080/v1",
                None,
                "advisor-model",
                10,
                frozenset({"rocmfpx"}),
                str(path),
            )

            with self.assertRaisesRegex(
                ProviderUnavailableError,
                "qualification is not approved",
            ):
                OpenAICompatibleProvider(config)


if __name__ == "__main__":
    unittest.main()
