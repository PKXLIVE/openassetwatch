from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_SCRIPT = REPO_ROOT / "scripts" / "demo_asset_classification.py"


def load_demo_module():
    spec = importlib.util.spec_from_file_location(
        "demo_asset_classification",
        DEMO_SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load demo_asset_classification.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AssetClassificationDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.demo = load_demo_module()

    def test_demo_is_deterministic_and_synthetic(self) -> None:
        first = self.demo.build_demo()
        second = self.demo.build_demo()

        self.assertEqual(first, second)
        self.assertTrue(first["synthetic_only"])
        self.assertEqual(first["schema_version"], "oaw.classification-demo.v1")

    def test_demo_covers_home_office_lab_conflict_and_reclassification(self) -> None:
        result = self.demo.build_demo()

        self.assertEqual(result["sites"]["home"]["category"], "printer")
        self.assertEqual(result["sites"]["office"]["category"], "workstation")
        self.assertEqual(result["sites"]["lab"]["status"], "conflicting")
        self.assertEqual(result["conflict"]["status"], "conflicting")
        self.assertEqual(
            {value for item in result["conflict"]["values"] for value in item.values()},
            {"server", "printer"},
        )
        self.assertEqual(
            result["reclassification"],
            {
                "asset_id": "asset-lab-reclassified-demo",
                "initial_category": "printer",
                "final_category": "server",
                "history_count": 1,
                "changed_assets": 1,
            },
        )

    def test_demo_ai_explanation_cites_authoritative_classification_evidence(self) -> None:
        ai = self.demo.build_demo()["ai_evidence"]

        self.assertTrue(ai["advisory_only"])
        self.assertEqual(
            ai["classification_authority"],
            "deterministic-classification-engine",
        )
        self.assertIn("asset_classification", ai["tools_used"])
        self.assertTrue(any(value.startswith("cls_") for value in ai["evidence_ids"]))
        self.assertTrue(any(value.startswith("cev_") for value in ai["evidence_ids"]))


if __name__ == "__main__":
    unittest.main()
