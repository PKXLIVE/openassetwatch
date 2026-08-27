from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

from app.local_ai import LocalAIHardwareMetadata, LocalAIModelMetadata, LocalAIRuntimeMetadata


REPO_ROOT = Path(__file__).resolve().parents[2]
QUALIFICATION_SCRIPT = REPO_ROOT / "scripts" / "qualify_local_ai.py"


def load_qualification_module():
    spec = importlib.util.spec_from_file_location("qualify_local_ai", QUALIFICATION_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load qualify_local_ai.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeQualificationClient:
    model = "advisor-model"

    def __init__(
        self,
        module,
        *,
        invented_reference: str | None = None,
        unsafe_tool: bool = False,
        followed_injection: bool = False,
    ) -> None:
        self.module = module
        self.invented_reference = invented_reference
        self.unsafe_tool = unsafe_tool
        self.followed_injection = followed_injection

    def result(self, payload, duration_ms: float = 4.0):
        raw = json.dumps(payload).encode("utf-8")
        return self.module.HTTPResult(payload=payload, raw=raw, duration_ms=duration_ms)

    def models(self):
        return self.result(
            {
                "object": "list",
                "data": [
                    {
                        "id": self.model,
                        "object": "model",
                        "meta": {"size": 4096},
                    }
                ],
            }
        )

    def health(self):
        return self.result({"status": "ok"})

    def chat(self, *, messages, response_format=None, tools=None):
        del messages
        if tools is not None:
            name = "run_shell" if self.unsafe_tool else "get_asset_evidence"
            arguments = {"command": "whoami"} if self.unsafe_tool else {"asset_id": "asset-alpha"}
            return self.result(
                {
                    "choices": [
                        {
                            "message": {
                                "content": None,
                                "tool_calls": [
                                    {
                                        "type": "function",
                                        "function": {
                                            "name": name,
                                            "arguments": json.dumps(arguments),
                                        },
                                    }
                                ],
                            }
                        }
                    ]
                }
            )
        if response_format is None:
            return self.result({"choices": [{"message": {"content": "42"}}]})
        evidence_ids = [
            "evidence:asset-alpha",
            "evidence:finding-alpha",
            "evidence:vulnerability-alpha",
        ]
        if self.invented_reference == "evidence":
            evidence_ids.append("evidence:invented")
        asset_ids = ["asset-alpha"]
        finding_ids = ["finding-alpha"]
        vulnerability_ids = ["CVE-2026-1111"]
        if self.invented_reference == "asset":
            asset_ids.append("asset-invented")
        if self.invented_reference == "finding":
            finding_ids.append("finding-invented")
        if self.invented_reference == "vulnerability":
            vulnerability_ids.append("CVE-2099-9999")
        content = {
            "answer": "The deterministic finding and vulnerability evidence support an advisory review.",
            "evidence_ids": evidence_ids,
            "asset_ids": asset_ids,
            "finding_ids": finding_ids,
            "vulnerability_ids": vulnerability_ids,
            "recommended_actions": ["Review the cited deterministic evidence."],
            "advisory_only": True,
            "executed_actions": ["ran a shell"] if self.followed_injection else [],
            "authority_claims": [
                "deterministic-classification-engine",
                "deterministic-findings-risk-engine",
                "deterministic-vulnerability-matcher",
            ],
            "requested_tool_calls": ["shell"] if self.followed_injection else [],
            "untrusted_instructions_followed": self.followed_injection,
        }
        return self.result(
            {"choices": [{"message": {"content": json.dumps(content)}}]},
            duration_ms=8.0,
        )

    def stream(self):
        return (
            b'data: {"object":"chat.completion.chunk","choices":[]}\n\ndata: [DONE]\n\n',
            3.0,
        )


def metadata(*, runtime_type: str = "openai-compatible", architecture: str = "generic"):
    runtime = LocalAIRuntimeMetadata(
        runtime_id="runtime-test",
        runtime_type=runtime_type,
        runtime_version="test-version",
        runtime_commit="c49ebdbd5c9f01ec242369f9e7f7967855f80cba",
        base_url="http://127.0.0.1:8080/v1",
        backend="ROCm" if runtime_type == "ROCmFPX" else "test",
        hardware_architecture=architecture,
        hardware=LocalAIHardwareMetadata(
            vendor="AMD" if runtime_type == "ROCmFPX" else "test",
            device_name="AMD Radeon AI PRO R9700" if runtime_type == "ROCmFPX" else "test-device",
            architecture=architecture,
            backend="ROCm" if runtime_type == "ROCmFPX" else "test",
        ),
    )
    model = LocalAIModelMetadata(
        model_name="advisor-model",
        model_digest="sha256:" + "a" * 64,
        quantization="ROCmFP4" if runtime_type == "ROCmFPX" else "test-quant",
        quant_profile="coherent",
        source="operator-supplied",
        license="unknown",
    )
    return runtime, model


class LocalAIQualificationHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_qualification_module()

    def test_mocked_advisor_qualification_passes_all_required_gates(self) -> None:
        runtime, model = metadata()

        result = self.module.run_qualification(
            FakeQualificationClient(self.module),
            runtime=runtime,
            model=model,
        )

        self.assertTrue(result.advisor_approved)
        self.assertEqual(result.summary.failed, 0)
        self.assertEqual(result.model.model_size_bytes, 4096)
        self.assertTrue(result.runtime.capabilities["structured_output"])
        self.assertTrue(result.runtime.capabilities["tool_calling"])
        self.assertTrue(result.runtime.capabilities["streaming"])
        self.assertIsNone(result.runtime.capabilities["reasoning"])
        self.assertIsNone(result.runtime.metrics.request_count)

    def test_invented_evidence_identifier_rejects_advisor_approval(self) -> None:
        runtime, model = metadata()

        result = self.module.run_qualification(
            FakeQualificationClient(self.module, invented_reference="evidence"),
            runtime=runtime,
            model=model,
        )

        evidence_test = next(item for item in result.tests if item.test_id == "evidence_grounding")
        self.assertEqual(evidence_test.status, "failed")
        self.assertFalse(result.advisor_approved)

    def test_invented_asset_finding_and_cve_each_reject_approval(self) -> None:
        for reference, test_id in (
            ("asset", "asset_grounding"),
            ("finding", "finding_grounding"),
            ("vulnerability", "vulnerability_grounding"),
        ):
            with self.subTest(reference=reference):
                runtime, model = metadata()
                result = self.module.run_qualification(
                    FakeQualificationClient(
                        self.module,
                        invented_reference=reference,
                    ),
                    runtime=runtime,
                    model=model,
                )

                gate = next(item for item in result.tests if item.test_id == test_id)
                self.assertEqual(gate.status, "failed")
                self.assertFalse(result.advisor_approved)

    def test_following_hostile_evidence_rejects_prompt_injection_and_advisory_gates(self) -> None:
        runtime, model = metadata()

        result = self.module.run_qualification(
            FakeQualificationClient(self.module, followed_injection=True),
            runtime=runtime,
            model=model,
        )

        states = {item.test_id: item.status for item in result.tests}
        self.assertEqual(states["prompt_injection_resistance"], "failed")
        self.assertEqual(states["advisory_only"], "failed")
        self.assertFalse(result.advisor_approved)

    def test_detected_unsafe_tool_call_is_a_required_failure(self) -> None:
        runtime, model = metadata()

        result = self.module.run_qualification(
            FakeQualificationClient(self.module, unsafe_tool=True),
            runtime=runtime,
            model=model,
        )

        tool_test = next(item for item in result.tests if item.test_id == "tool_calling")
        self.assertTrue(tool_test.required)
        self.assertEqual(tool_test.status, "failed")
        self.assertFalse(result.advisor_approved)

    def test_rocmfpx_r9700_requires_gfx1201_provenance(self) -> None:
        invalid_runtime, invalid_model = metadata(runtime_type="ROCmFPX", architecture="gfx1200")
        valid_runtime, valid_model = metadata(runtime_type="ROCmFPX", architecture="gfx1201")

        invalid = self.module.run_qualification(
            FakeQualificationClient(self.module),
            runtime=invalid_runtime,
            model=invalid_model,
        )
        valid = self.module.run_qualification(
            FakeQualificationClient(self.module),
            runtime=valid_runtime,
            model=valid_model,
        )

        self.assertFalse(invalid.advisor_approved)
        self.assertEqual(
            next(item for item in invalid.tests if item.test_id == "runtime_provenance").status,
            "failed",
        )
        self.assertTrue(valid.advisor_approved)

    def test_parser_has_no_model_path_or_runtime_launch_option(self) -> None:
        option_strings = {
            option
            for action in self.module.build_parser()._actions
            for option in action.option_strings
        }

        self.assertNotIn("--model-path", option_strings)
        self.assertNotIn("--download-model", option_strings)
        self.assertNotIn("--launch-server", option_strings)
        self.assertIn("--base-url", option_strings)
        self.assertIn("--model", option_strings)
        self.assertIn("--output", option_strings)

    def test_bounded_decoder_rejects_oversized_and_malformed_provider_output(self) -> None:
        with self.assertRaises(self.module.QualificationRequestError):
            self.module._decode_json_bytes(b'{"too":"large"}', limit=4)
        with self.assertRaises(self.module.QualificationRequestError):
            self.module._decode_json_bytes(b"not-json", limit=64)


if __name__ == "__main__":
    unittest.main()
