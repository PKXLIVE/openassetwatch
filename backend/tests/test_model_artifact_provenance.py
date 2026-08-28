from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from app.ai_advisor import (
    ProviderConfig,
    ProviderUnavailableError,
    load_provider_config,
    provider_status,
)
from app.local_ai import (
    QUALIFICATION_FIXTURE_VERSION,
    QUALIFICATION_SUITE_VERSION,
    REQUIRED_QUALIFICATION_TESTS,
    LocalAIModelMetadata,
    LocalAIQualificationResult,
    LocalAIQualificationTest,
    LocalAIRuntimeMetadata,
)
from app.model_artifact_provenance import (
    MAX_MODEL_ARTIFACT_MANIFEST_BYTES,
    ArtifactSplit,
    ModelArtifactAdvisory,
    ModelArtifactAdvisoryRegistry,
    ModelArtifactManifest,
    build_qualification_binding,
    compute_manifest_digest,
    evaluate_artifact_advisories,
    evaluate_qualification_binding,
    load_model_artifact_manifest,
    read_bounded_local_json,
    split_manifest_digest,
)
from tests.model_artifact_fixtures import (
    ARTIFACT_DIGEST,
    CONVERTER_COMMIT,
    FIXED_TIME,
    INTERMEDIATE_DIGEST,
    QUANTIZER_COMMIT,
    RUNTIME_COMMIT,
    SOURCE_DIGEST,
    complete_manifest,
    partial_manifest,
    unknown_manifest,
)


def changed_manifest(section: str, field: str, value: object) -> ModelArtifactManifest:
    payload = complete_manifest().model_dump(mode="json")
    payload["manifest_digest"] = None
    payload[section][field] = value
    if section == "source_checkpoint" and field == "source_checkpoint_digest":
        payload["conversion"]["input_checkpoint_digest"] = value
    if section == "source_checkpoint" and field == "source_revision":
        payload["model_identity"]["upstream_model_revision"] = value
    if section == "conversion" and field == "output_intermediate_digest":
        payload["quantization"]["source_artifact_digest"] = value
    if section == "artifact" and field == "artifact_digest":
        payload["quantization"]["output_artifact_digest"] = value
    return ModelArtifactManifest.model_validate(payload)


def advisory(
    *,
    advisory_id: str = "OAW-MODEL-TEST-001",
    component_type: str = "converter",
    component_name: str = "fixture-converter",
    affected: str = CONVERTER_COMMIT,
    action: str = "reconversion-required",
) -> ModelArtifactAdvisory:
    return ModelArtifactAdvisory(
        advisory_id=advisory_id,
        title="Bounded model toolchain fixture",
        component_type=component_type,
        component_name=component_name,
        affected_exact_commits=[affected],
        severity="high",
        required_action=action,
        source_reference="https://security.example.invalid/advisories/model-test-001",
        published_at=FIXED_TIME,
        reviewed_at=FIXED_TIME,
    )


def bound_qualification(manifest: ModelArtifactManifest) -> LocalAIQualificationResult:
    binding = build_qualification_binding(
        manifest,
        runtime_commit=RUNTIME_COMMIT,
        qualification_suite_version=QUALIFICATION_SUITE_VERSION,
        qualification_fixture_version=QUALIFICATION_FIXTURE_VERSION,
        qualified_at=FIXED_TIME,
    )
    tests = [
        LocalAIQualificationTest(
            test_id=test_id,
            category="required",
            required=True,
            status="passed",
            detail="Bounded fixture passed.",
        )
        for test_id in sorted(REQUIRED_QUALIFICATION_TESTS)
    ]
    return LocalAIQualificationResult(
        started_at=FIXED_TIME,
        completed_at=FIXED_TIME,
        runtime=LocalAIRuntimeMetadata(
            runtime_id="fixture-runtime",
            runtime_type="openai-compatible",
            runtime_version="1.0.0",
            runtime_commit=RUNTIME_COMMIT,
            base_url="http://fixture-runtime:8080/v1",
        ),
        model=LocalAIModelMetadata(
            model_name="advisor-model",
            model_digest=ARTIFACT_DIGEST,
            model_size_bytes=2_048,
            quantization="fixture-q4",
            quant_profile="reviewed-default",
            source="operator-supplied",
            license="fixture-license",
        ),
        artifact_binding=binding,
        tests=tests,
    )


class ModelArtifactManifestTests(unittest.TestCase):
    def test_complete_partial_and_unknown_states_are_explicit(self) -> None:
        self.assertEqual(complete_manifest().provenance_state, "complete")
        self.assertEqual(partial_manifest().provenance_state, "partial")
        self.assertEqual(unknown_manifest().provenance_state, "unknown")

    def test_complete_manifest_requires_every_immutable_stage_identity(self) -> None:
        for section, field in (
            ("source_checkpoint", "source_revision"),
            ("conversion", "converter_commit"),
            ("quantization", "quantizer_commit"),
            ("runtime_compatibility", "runtime_commit"),
        ):
            with self.subTest(section=section, field=field):
                payload = complete_manifest().model_dump(mode="json")
                payload["manifest_digest"] = None
                payload[section][field] = None
                with self.assertRaisesRegex(ValidationError, "complete provenance"):
                    ModelArtifactManifest.model_validate(payload)

    def test_strict_schema_rejects_invalid_values_and_unsafe_metadata(self) -> None:
        mutations = (
            ("extra field", lambda payload: payload.update({"unexpected": True})),
            ("naive timestamp", lambda payload: payload.update({"created_at": "2026-08-28T12:00:00"})),
            ("negative size", lambda payload: payload["artifact"].update({"artifact_size_bytes": -1})),
            ("digest algorithm", lambda payload: payload["artifact"].update({"artifact_digest_algorithm": "md5"})),
            (
                "provider protocol",
                lambda payload: payload["runtime_compatibility"].update(
                    {"provider_protocol": "arbitrary-protocol"}
                ),
            ),
            ("malformed digest", lambda payload: payload["artifact"].update({"artifact_digest": "ABC"})),
            (
                "absolute path",
                lambda payload: payload["conversion"].update(
                    {"converter_source": "C:\\Users\\private\\converter"}
                ),
            ),
            (
                "URL credentials",
                lambda payload: payload["source_checkpoint"].update(
                    {"source_reference": "https://user:secret@example.invalid/source"}
                ),
            ),
            ("overlong field", lambda payload: payload["model_identity"].update({"model_family": "x" * 129})),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                payload = complete_manifest().model_dump(mode="json")
                payload["manifest_digest"] = None
                mutate(payload)
                with self.assertRaises(ValidationError):
                    ModelArtifactManifest.model_validate(payload)

    def test_mutable_source_revisions_and_unknown_assertions_are_rejected(self) -> None:
        payload = complete_manifest().model_dump(mode="json")
        payload["manifest_digest"] = None
        payload["source_checkpoint"]["source_revision"] = "latest"
        with self.assertRaisesRegex(ValidationError, "mutable source revisions"):
            ModelArtifactManifest.model_validate(payload)

        payload = unknown_manifest().model_dump(mode="json")
        payload["manifest_digest"] = None
        payload["conversion"]["converter_commit"] = CONVERTER_COMMIT
        with self.assertRaisesRegex(ValidationError, "unknown provenance"):
            ModelArtifactManifest.model_validate(payload)

    def test_manifest_digest_is_canonical_and_identity_sensitive(self) -> None:
        baseline = complete_manifest()
        identical = ModelArtifactManifest.model_validate(
            dict(reversed(list(baseline.model_dump(mode="json").items())))
        )
        self.assertEqual(baseline.manifest_digest, identical.manifest_digest)
        self.assertEqual(baseline.manifest_digest, compute_manifest_digest(baseline))

        variants = (
            changed_manifest("source_checkpoint", "source_checkpoint_digest", "e" * 64),
            changed_manifest("source_checkpoint", "source_revision", "source-revision-002"),
            changed_manifest("conversion", "converter_commit", "converter-commit-002"),
            changed_manifest("quantization", "quantizer_commit", "quantizer-commit-002"),
            changed_manifest("artifact", "artifact_digest", "f" * 64),
            changed_manifest("runtime_compatibility", "runtime_commit", "runtime-commit-002"),
        )
        for variant in variants:
            self.assertNotEqual(baseline.manifest_digest, variant.manifest_digest)

    def test_split_manifest_order_is_deterministic(self) -> None:
        splits = [
            ArtifactSplit(ordinal=1, name="part-0001", digest="1" * 64, size_bytes=100),
            ArtifactSplit(ordinal=2, name="part-0002", digest="2" * 64, size_bytes=200),
        ]
        expected = split_manifest_digest(splits)
        manifests = []
        for ordered in (splits, list(reversed(splits))):
            payload = complete_manifest().model_dump(mode="json")
            payload["manifest_digest"] = None
            payload["artifact"].update(
                {
                    "split_count": 2,
                    "splits": [item.model_dump(mode="json") for item in ordered],
                    "split_manifest_digest": expected,
                }
            )
            manifests.append(ModelArtifactManifest.model_validate(payload))
        self.assertEqual(manifests[0].manifest_digest, manifests[1].manifest_digest)
        self.assertEqual([item.ordinal for item in manifests[1].artifact.splits], [1, 2])

    def test_lineage_relationship_mismatches_fail(self) -> None:
        mutations = (
            ("conversion", "input_checkpoint_digest", "8" * 64),
            ("quantization", "source_artifact_digest", "8" * 64),
            ("quantization", "output_artifact_digest", "8" * 64),
        )
        for section, field, value in mutations:
            with self.subTest(section=section, field=field):
                payload = complete_manifest().model_dump(mode="json")
                payload["manifest_digest"] = None
                payload[section][field] = value
                with self.assertRaises(ValidationError):
                    ModelArtifactManifest.model_validate(payload)

        payload = complete_manifest().model_dump(mode="json")
        payload["manifest_digest"] = None
        payload["quantization"]["quantization_started_at"] = (
            FIXED_TIME - timedelta(seconds=1)
        ).isoformat()
        with self.assertRaisesRegex(ValidationError, "before conversion completes"):
            ModelArtifactManifest.model_validate(payload)

    def test_bounded_loader_rejects_oversize_duplicates_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oversized = root / "oversized.json"
            oversized.write_bytes(b"{" + b"x" * MAX_MODEL_ARTIFACT_MANIFEST_BYTES + b"}")
            with self.assertRaisesRegex(ValueError, "safety limit"):
                load_model_artifact_manifest(oversized)

            duplicate = root / "duplicate.json"
            duplicate.write_text('{"schema_version":"one","schema_version":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate keys"):
                read_bounded_local_json(duplicate, maximum_bytes=1_024)

            nested = root / "nested.json"
            nested.write_text(
                '{"nested":' + "[" * 20_000 + "0" + "]" * 20_000 + "}",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "malformed JSON"):
                read_bounded_local_json(nested, maximum_bytes=64_000)

            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "link.json"
            try:
                os.symlink(target, link)
            except OSError:
                return
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                read_bounded_local_json(link, maximum_bytes=1_024)

    def test_loader_rejects_manifest_content_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            payload = complete_manifest().model_dump(mode="json")
            payload["model_identity"]["model_purpose"] = "Tampered purpose"
            path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValidationError, "manifest digest does not match"):
                load_model_artifact_manifest(path)


class QualificationBindingTests(unittest.TestCase):
    def test_exact_binding_passes_and_each_identity_mismatch_fails(self) -> None:
        manifest = complete_manifest()
        binding = build_qualification_binding(
            manifest,
            runtime_commit=RUNTIME_COMMIT,
            qualification_suite_version=QUALIFICATION_SUITE_VERSION,
            qualification_fixture_version=QUALIFICATION_FIXTURE_VERSION,
            qualified_at=FIXED_TIME,
        )
        exact = evaluate_qualification_binding(
            manifest,
            binding,
            required_suite_version=QUALIFICATION_SUITE_VERSION,
            required_fixture_version=QUALIFICATION_FIXTURE_VERSION,
        )
        self.assertTrue(exact.matched)
        self.assertEqual(exact.state, "matched")

        mutations = {
            "artifact-digest-mismatch": {"artifact_digest": "1" * 64},
            "manifest-digest-mismatch": {"artifact_manifest_digest": "2" * 64},
            "source-checkpoint-digest-mismatch": {"source_checkpoint_digest": "3" * 64},
            "converter-commit-mismatch": {"converter_commit": "converter-commit-999"},
            "quantizer-commit-mismatch": {"quantizer_commit": "quantizer-commit-999"},
            "runtime-commit-mismatch": {"runtime_commit": "runtime-commit-999"},
            "qualification-suite-version-mismatch": {"qualification_suite_version": "oaw.local-ai.v0"},
            "qualification-fixture-version-mismatch": {"qualification_fixture_version": "fixtures-v0"},
        }
        for reason, update in mutations.items():
            with self.subTest(reason=reason):
                result = evaluate_qualification_binding(
                    manifest,
                    binding.model_copy(update=update),
                    required_suite_version=QUALIFICATION_SUITE_VERSION,
                    required_fixture_version=QUALIFICATION_FIXTURE_VERSION,
                )
                self.assertFalse(result.matched)
                self.assertIn(reason, result.reason_codes)

    def test_binding_completion_time_cannot_be_self_asserted(self) -> None:
        qualification = bound_qualification(complete_manifest())
        payload = qualification.model_dump(mode="json")
        payload["artifact_binding"]["qualified_at"] = (
            FIXED_TIME + timedelta(seconds=1)
        ).isoformat()

        reloaded = LocalAIQualificationResult.model_validate(payload)

        self.assertFalse(reloaded.advisor_approved)


class ArtifactAdvisoryTests(unittest.TestCase):
    def test_no_match_and_informational_match_preserve_qualification(self) -> None:
        manifest = complete_manifest()
        no_match = evaluate_artifact_advisories(
            manifest,
            [advisory(affected="converter-commit-other")],
        )
        informational = evaluate_artifact_advisories(
            manifest,
            [advisory(action="informational")],
        )
        self.assertEqual(no_match.state, "complete")
        self.assertTrue(no_match.qualification_valid)
        self.assertEqual(informational.state, "complete")
        self.assertTrue(informational.qualification_valid)
        self.assertEqual(informational.required_actions, ["informational"])

    def test_toolchain_matches_require_exact_remediation_and_requalification(self) -> None:
        cases = (
            ("converter", "fixture-converter", CONVERTER_COMMIT, "reconversion-required"),
            ("quantizer", "fixture-quantizer", QUANTIZER_COMMIT, "requantization-required"),
            ("runtime", "openai-compatible", RUNTIME_COMMIT, "runtime-upgrade-required"),
        )
        for component, name, affected, action in cases:
            with self.subTest(component=component):
                result = evaluate_artifact_advisories(
                    complete_manifest(),
                    [
                        advisory(
                            component_type=component,
                            component_name=name,
                            affected=affected,
                            action=action,
                        )
                    ],
                )
                self.assertEqual(result.state, "requalification-required")
                self.assertFalse(result.qualification_valid)
                self.assertIn(action, result.required_actions)
                self.assertIn("requalification-required", result.required_actions)

    def test_block_use_is_invalid_and_never_creates_asset_risk(self) -> None:
        result = evaluate_artifact_advisories(
            complete_manifest(),
            [advisory(action="block-use")],
        )
        serialized = result.model_dump_json()
        self.assertEqual(result.state, "invalid")
        self.assertFalse(result.qualification_valid)
        self.assertNotIn("finding", serialized.casefold())
        self.assertNotIn("risk", serialized.casefold())

    def test_duplicate_advisories_are_rejected_and_output_is_deterministic(self) -> None:
        first = advisory(advisory_id="OAW-MODEL-TEST-001")
        second = advisory(
            advisory_id="OAW-MODEL-TEST-002",
            component_type="runtime",
            component_name="openai-compatible",
            affected=RUNTIME_COMMIT,
            action="runtime-upgrade-required",
        )
        with self.assertRaisesRegex(ValidationError, "identifiers must be unique"):
            ModelArtifactAdvisoryRegistry(advisories=[first, first])
        with self.assertRaisesRegex(ValueError, "identifiers must be unique"):
            evaluate_artifact_advisories(complete_manifest(), [first, first])
        left = evaluate_artifact_advisories(complete_manifest(), [first, second])
        right = evaluate_artifact_advisories(complete_manifest(), [second, first])
        self.assertEqual(left, right)

    def test_fixture_evaluation_is_bounded(self) -> None:
        manifest = complete_manifest()
        advisories = [advisory(advisory_id=f"OAW-MODEL-TEST-{index:03d}") for index in range(1, 65)]
        started = time.perf_counter()
        result = evaluate_artifact_advisories(manifest, advisories)
        elapsed = time.perf_counter() - started
        self.assertEqual(len(result.matched_advisory_ids), 64)
        self.assertLess(elapsed, 1.0)


class ProviderArtifactTrustTests(unittest.TestCase):
    def _config(self, directory: str, **overrides: object) -> ProviderConfig:
        values = {
            "provider": "openai-compatible",
            "external_enabled": False,
            "base_url": "http://fixture-runtime:8080/v1",
            "api_key": None,
            "model": "advisor-model",
            "timeout_seconds": 10,
            "local_provider_hosts": frozenset({"fixture-runtime"}),
            "qualification_result_path": str(Path(directory) / "qualification.json"),
            "model_manifest_path": str(Path(directory) / "manifest.json"),
            "require_model_manifest": True,
        }
        values.update(overrides)
        return ProviderConfig(**values)

    def _write_trust_files(self, directory: str) -> tuple[ModelArtifactManifest, LocalAIQualificationResult]:
        manifest = complete_manifest()
        qualification = bound_qualification(manifest)
        Path(directory, "manifest.json").write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
        Path(directory, "qualification.json").write_text(qualification.model_dump_json(indent=2), encoding="utf-8")
        return manifest, qualification

    def test_exact_bound_local_provider_exposes_distinct_bounded_states(self) -> None:
        with tempfile.TemporaryDirectory(prefix="private-secret-path-") as directory:
            manifest, _ = self._write_trust_files(directory)
            status = provider_status(self._config(directory), check_availability=False)

        serialized = status.model_dump_json()
        self.assertTrue(status.enabled)
        self.assertTrue(status.available)
        self.assertEqual(status.qualification_state, "approved")
        self.assertEqual(status.artifact_manifest_state, "valid")
        self.assertEqual(status.provenance_state, "complete")
        self.assertEqual(status.qualification_binding_state, "matched")
        self.assertEqual(status.artifact_advisory_state, "not-configured")
        self.assertEqual(status.artifact_digest, ARTIFACT_DIGEST)
        self.assertEqual(status.artifact_manifest_digest, manifest.manifest_digest)
        self.assertNotIn(directory, serialized)
        self.assertNotIn("private-secret", serialized)
        self.assertNotIn("models.example.invalid", serialized)

    def test_invalid_configured_manifest_and_required_absence_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._write_trust_files(directory)
            Path(directory, "manifest.json").write_text('{"manifest_digest":"bad"}', encoding="utf-8")
            invalid = provider_status(self._config(directory), check_availability=False)
            required_missing = provider_status(
                self._config(directory, model_manifest_path=None),
                check_availability=False,
            )
            Path(directory, "manifest.json").write_text(
                partial_manifest().model_dump_json(indent=2),
                encoding="utf-8",
            )
            partial = provider_status(self._config(directory), check_availability=False)
        self.assertFalse(invalid.enabled)
        self.assertEqual(invalid.artifact_manifest_state, "invalid")
        self.assertEqual(invalid.provenance_state, "invalid")
        self.assertFalse(required_missing.enabled)
        self.assertEqual(required_missing.artifact_manifest_state, "required-missing")
        self.assertFalse(partial.enabled)
        self.assertEqual(partial.artifact_manifest_state, "valid")
        self.assertEqual(partial.provenance_state, "partial")

    def test_binding_mismatch_and_blocking_advisory_disable_without_hiding_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, qualification = self._write_trust_files(directory)
            mismatched_binding = qualification.artifact_binding.model_copy(
                update={"artifact_manifest_digest": "9" * 64}
            )
            mismatched = qualification.model_copy(update={"artifact_binding": mismatched_binding})
            Path(directory, "qualification.json").write_text(mismatched.model_dump_json(indent=2), encoding="utf-8")
            mismatch_status = provider_status(self._config(directory), check_availability=False)

            Path(directory, "qualification.json").write_text(qualification.model_dump_json(indent=2), encoding="utf-8")
            registry = ModelArtifactAdvisoryRegistry(advisories=[advisory(action="block-use")])
            Path(directory, "advisories.json").write_text(registry.model_dump_json(indent=2), encoding="utf-8")
            blocked_status = provider_status(
                self._config(directory, artifact_advisories_path=str(Path(directory, "advisories.json"))),
                check_availability=False,
            )

        self.assertFalse(mismatch_status.enabled)
        self.assertTrue(mismatch_status.available)
        self.assertEqual(mismatch_status.qualification_binding_state, "mismatch")
        self.assertFalse(blocked_status.enabled)
        self.assertTrue(blocked_status.available)
        self.assertEqual(blocked_status.qualification_state, "approved")
        self.assertEqual(blocked_status.artifact_advisory_state, "matched")
        self.assertEqual(blocked_status.matched_advisory_count, 1)
        self.assertEqual(blocked_status.provenance_state, "invalid")

    def test_unconfigured_default_and_external_provider_remain_independent(self) -> None:
        local = provider_status(
            ProviderConfig(
                "openai-compatible",
                False,
                "http://fixture-runtime:8080/v1",
                None,
                "advisor-model",
                10,
                frozenset({"fixture-runtime"}),
            ),
            check_availability=False,
        )
        external = provider_status(
            ProviderConfig(
                "openai-compatible",
                True,
                "https://api.example.invalid/v1",
                "private-token",
                "hosted-model",
                10,
                model_manifest_path="C:\\private\\must-not-load.json",
                require_model_manifest=True,
            )
        )
        self.assertTrue(local.enabled)
        self.assertEqual(local.qualification_binding_state, "not-configured")
        self.assertTrue(external.enabled)
        self.assertEqual(external.artifact_manifest_state, "not-configured")
        self.assertNotIn("private-token", external.model_dump_json())
        self.assertNotIn("must-not-load", external.model_dump_json())

    def test_environment_configuration_loads_operator_owned_paths_and_policy(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OPENASSETWATCH_AI_MODEL_MANIFEST": "operator-manifest.json",
                "OPENASSETWATCH_AI_REQUIRE_MODEL_MANIFEST": "true",
                "OPENASSETWATCH_AI_ARTIFACT_ADVISORIES": "reviewed-advisories.json",
            },
            clear=True,
        ):
            config = load_provider_config()

        self.assertEqual(config.model_manifest_path, "operator-manifest.json")
        self.assertTrue(config.require_model_manifest)
        self.assertEqual(config.artifact_advisories_path, "reviewed-advisories.json")

    def test_configuration_metadata_is_bounded_before_status_serialization(self) -> None:
        with self.assertRaisesRegex(ProviderUnavailableError, "provider name"):
            ProviderConfig("x" * 129, False, None, None, None, 10)
        with self.assertRaisesRegex(ProviderUnavailableError, "metadata path"):
            ProviderConfig(
                "openai-compatible",
                False,
                "http://localhost:8080/v1",
                None,
                "advisor-model",
                10,
                model_manifest_path="x" * 4_097,
            )


if __name__ == "__main__":
    unittest.main()
