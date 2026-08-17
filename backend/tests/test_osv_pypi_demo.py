from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class OsvPypiOfflineDemoTests(unittest.TestCase):
    def test_offline_demo_exercises_signed_lifecycle_and_ai_evidence(self) -> None:
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "demo_osv_pypi_publisher.py")],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["status"], "offline-demo-complete")
        self.assertEqual(result["publisher"]["signature_status"], "verified")
        self.assertEqual(result["publisher"]["first_mode"], "full")
        self.assertEqual(result["publisher"]["second_mode"], "incremental")
        self.assertTrue(result["publisher"]["digests_changed"])
        self.assertEqual(result["lifecycle"]["approved_state"], "approved")
        self.assertEqual(result["lifecycle"]["first_activation"], "completed")
        self.assertEqual(result["lifecycle"]["second_activation"], "completed")
        self.assertEqual(result["lifecycle"]["rollback"], "completed")
        self.assertEqual(result["deterministic_outcomes"]["initial_match"], "affected")
        self.assertEqual(result["deterministic_outcomes"]["updated_match"], "fixed")
        self.assertGreater(result["deterministic_outcomes"]["initial_risk"], 0)
        self.assertEqual(result["deterministic_outcomes"]["updated_risk"], 0)
        for tool_name in (
            "advisory_feed_status",
            "advisory_feed_preview",
            "advisory_activation_impact",
        ):
            self.assertIn(tool_name, result["ai_evidence"]["selected_tools"])
        self.assertIn(
            result["ai_evidence"]["server_issued_run_id"],
            result["ai_evidence"]["evidence_ids"],
        )
        self.assertIn(
            result["ai_evidence"]["server_issued_catalog_id"],
            result["ai_evidence"]["evidence_ids"],
        )


if __name__ == "__main__":
    unittest.main()
