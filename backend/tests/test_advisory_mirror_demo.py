from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class AdvisoryMirrorOfflineDemoTests(unittest.TestCase):
    def test_demo_covers_publication_hub_lifecycle_findings_risk_and_ai(self) -> None:
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "demo_advisory_mirror.py")],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["status"], "offline-mirror-demo-complete")
        self.assertEqual(result["publisher"]["first_mode"], "full")
        self.assertEqual(result["publisher"]["second_mode"], "incremental")
        self.assertTrue(result["publisher"]["digests_changed"])
        self.assertEqual(result["publication"]["first"]["status"], "mirror-complete")
        self.assertEqual(result["publication"]["second"]["status"], "mirror-complete")
        self.assertEqual(result["publication"]["index_signature_status"], "verified")
        self.assertEqual(result["publication"]["retained_sequences"], [1, 2])
        self.assertGreaterEqual(result["local_http"]["request_count"], 10)
        self.assertTrue(result["local_http"]["fixed_paths_only"])
        self.assertFalse(result["local_http"]["public_network_used"])
        self.assertEqual(result["hub_lifecycle"]["first_sync_state"], "pending_approval")
        self.assertEqual(result["hub_lifecycle"]["first_approval_state"], "approved")
        self.assertEqual(result["hub_lifecycle"]["first_activation"], "completed")
        self.assertEqual(result["hub_lifecycle"]["second_sync_state"], "pending_approval")
        self.assertEqual(result["hub_lifecycle"]["second_activation"], "completed")
        self.assertEqual(result["hub_lifecycle"]["offline_sync_state"], "failed")
        self.assertTrue(result["hub_lifecycle"]["last_known_good_preserved"])
        self.assertEqual(result["hub_lifecycle"]["offline_rollback"], "completed")
        self.assertEqual(result["deterministic_outcomes"]["initial_match"], "affected")
        self.assertGreater(result["deterministic_outcomes"]["initial_findings"], 0)
        self.assertGreater(result["deterministic_outcomes"]["initial_risk"], 0)
        self.assertEqual(result["deterministic_outcomes"]["updated_match"], "fixed")
        self.assertEqual(result["deterministic_outcomes"]["updated_findings"], 0)
        self.assertEqual(result["deterministic_outcomes"]["updated_risk"], 0)
        self.assertFalse(result["private_key_persisted"])
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
