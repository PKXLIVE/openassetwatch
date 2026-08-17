from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path

from app.ai_advisor import ReadOnlyHubTools, build_tool_context, select_tools


NOW = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
INDEX = Path(__file__).resolve().parents[1] / "app" / "static" / "index.html"


def advisory_tools(state: str = "pending_approval") -> ReadOnlyHubTools:
    return ReadOnlyHubTools(
        sites=[],
        sensors=[],
        assets=[],
        advisory_feed_evidence=[
            {
                "run_id": "afrun_" + "a" * 32,
                "catalog_id": "afcat_" + "b" * 32,
                "source_id": "openassetwatch-synthetic-signed",
                "state": state,
                "catalog_version": "synthetic-2026.1",
                "catalog_sequence": 1,
                "publisher_key_id": "oaw-synthetic-ed25519-2026-01",
                "manifest_digest": "c" * 64,
                "payload_digest": "d" * 64,
                "signature_status": "verified",
                "license_identifier": "Apache-2.0",
                "license_status": "approved",
                "attribution_status": "present",
                "reevaluation_status": "completed",
                "created_at": NOW,
                "completed_at": NOW,
                "preview": {
                    "added_advisories": 1,
                    "updated_advisories": 0,
                    "withdrawn_advisories": 0,
                    "known_exploited_count": 0,
                    "changed_advisory_ids": ["OAW-SYNTH-2026-0001"],
                    "expected_match_impact": {"changed_advisory_count": 1},
                },
            }
        ],
        now=NOW,
    )


class AdvisoryFeedAiTests(unittest.TestCase):
    def test_pending_preview_is_read_only_bounded_and_cited(self) -> None:
        tools = advisory_tools()
        result = tools.run("advisory_feed_preview")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["items"][0]["signature_status"], "verified")
        context, selected, evidence = build_tool_context(
            tools,
            question="Explain the pending advisory feed preview and signature status",
            site_id=None,
            asset_id=None,
        )
        self.assertIn("advisory_feed_preview", selected)
        self.assertIn("advisory_feed_status", selected)
        evidence_ids = {item.evidence_id for item in evidence}
        self.assertIn("afrun_" + "a" * 32, evidence_ids)
        self.assertIn("afcat_" + "b" * 32, evidence_ids)
        self.assertEqual(context["tool_results"]["advisory_feed_preview"]["count"], 1)

    def test_activation_impact_is_selected_and_mutations_are_not_allowlisted(self) -> None:
        selected = select_tools("Why did risk change after activation and which assets are newly affected?")
        self.assertIn("advisory_activation_impact", selected)
        for forbidden in ("sync", "approve", "reject", "activate", "rollback", "change_keyring"):
            self.assertNotIn(forbidden, ReadOnlyHubTools.allowlist)
            with self.assertRaisesRegex(ValueError, "allowlisted"):
                advisory_tools("activated").run(forbidden)


class AdvisoryFeedUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.page = INDEX.read_text(encoding="utf-8")

    def test_settings_contains_bounded_advisory_controls_and_states(self) -> None:
        for value in (
            "Advisory Intelligence",
            'id="advisory-load"',
            'id="advisory-sync"',
            'id="advisory-approve"',
            'id="advisory-reject"',
            'id="advisory-activate"',
            "pending_approval",
            "rollback",
        ):
            self.assertIn(value, self.page)

    def test_feed_values_render_as_text_and_no_secret_storage_is_added(self) -> None:
        advisory_script = self.page[self.page.index("function appendAdvisoryRow"):]
        self.assertIn("textContent", advisory_script)
        self.assertNotIn("innerHTML", advisory_script)
        self.assertNotIn("localStorage", advisory_script)
        self.assertNotIn("sessionStorage", advisory_script)
        self.assertIn("Feed-supplied values are rendered as text only", advisory_script)

    def test_responsive_settings_grid_remains_present(self) -> None:
        self.assertIn(".settings-grid", self.page)
        self.assertIn("@media", self.page)


if __name__ == "__main__":
    unittest.main()
