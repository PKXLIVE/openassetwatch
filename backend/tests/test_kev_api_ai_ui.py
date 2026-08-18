from __future__ import annotations

import os
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.ai_advisor import (
    DeterministicDemoProvider,
    ReadOnlyHubTools,
    build_tool_context,
    select_tools,
)
from app.main import (
    ADMIN_TOKEN_ENV,
    admin_evaluate_kev,
    api_asset_kev_records,
    api_kev_records,
    api_kev_status,
)


NOW = datetime(2099, 1, 4, 12, 0, tzinfo=timezone.utc)
INDEX = Path(__file__).resolve().parents[1] / "app" / "static" / "index.html"
MATCH_ID = "vmt_" + "1" * 32
COMPONENT_ID = "cmp_" + "2" * 32
ADVISORY_ID = "adv_" + "3" * 32
KEV_RECORD_ID = "kev_" + "4" * 64


def kev_tools(*, ransomware_status: str = "Unknown") -> ReadOnlyHubTools:
    return ReadOnlyHubTools(
        sites=[{"site_id": "site-kev", "name": "Synthetic KEV Site"}],
        sensors=[],
        assets=[],
        components=[
            {
                "component_id": COMPONENT_ID,
                "site_id": "site-kev",
                "asset_id": "asset-kev",
                "component_type": "application",
                "ecosystem": "generic",
                "name": "Fictional Component",
                "version": "1.0.0",
                "source_type": "endpoint-collector",
                "source_id": "agent-kev",
                "freshness": "fresh",
                "confidence": 1.0,
                "active": True,
                "observed_at": NOW,
            }
        ],
        vulnerability_matches=[
            {
                "match_id": MATCH_ID,
                "site_id": "site-kev",
                "asset_id": "asset-kev",
                "component_id": COMPONENT_ID,
                "advisory_id": ADVISORY_ID,
                "match_status": "affected",
                "match_confidence": 1.0,
                "installed_version": "1.0.0",
                "fixed_version": "2.0.0",
                "affected_range": "<2.0.0",
                "component_name": "Fictional Component",
                "ecosystem": "generic",
                "severity": "high",
                "known_exploited": False,
                "source": "Synthetic Advisory Laboratory",
                "source_record_id": "OAW-SYNTH-2099-0001",
                "catalog_version": "synthetic-2099.1",
                "source_license": "Apache-2.0",
                "provenance": "Fictional test data.",
                "aliases": ["CVE-2099-10001"],
                "references": [],
                "component_freshness": "fresh",
                "evaluated_at": NOW,
                "reason_codes": ["installed-version-in-affected-range"],
                "kev": {
                    "status": "known_exploited",
                    "source_id": "cisa-kev-official",
                    "freshness": "fresh",
                    "catalog_version": "2099.01.03",
                    "exact_cve_aliases": ["CVE-2099-10001"],
                    "records": [
                        {
                            "kev_record_id": KEV_RECORD_ID,
                            "cve_id": "CVE-2099-10001",
                            "priority_status": "known_exploited",
                            "vendor_project": "Fictional Vendor",
                            "product": "Fictional Component",
                            "date_added": "2099-01-01",
                            "required_action": "Review the fictional component.",
                            "cisa_due_date": "2099-01-31",
                            "ransomware_campaign_status": ransomware_status,
                            "source_freshness": "fresh",
                            "adjusted_weight": 12.0,
                        }
                    ],
                },
            }
        ],
        kev_status={
            "status": "available",
            "source_id": "cisa-kev-official",
            "freshness": "fresh",
            "active_catalog": {
                "import_id": "kevimp_" + "5" * 32,
                "catalog_version": "2099.01.03",
                "catalog_date_released": NOW,
                "payload_sha256": "6" * 64,
            },
            "current_factor_count": 1,
            "current_match_count": 1,
        },
        now=NOW,
    )


class KevApiTests(unittest.TestCase):
    def test_read_endpoints_require_configured_token_and_forward_bounded_filters(self) -> None:
        with patch.dict(os.environ, {ADMIN_TOKEN_ENV: "unit-test-admin"}, clear=True):
            with self.assertRaises(HTTPException) as raised:
                api_kev_status(admin_token=None)
            self.assertEqual(raised.exception.status_code, 401)

            store = Mock()
            store.list_records.return_value = {
                "items": [], "total": 0, "limit": 25, "offset": 10, "truncated": False
            }
            with patch("app.main._kev_store", return_value=store):
                response = api_kev_records(
                    cve="cve-2099-10001",
                    vendor_project="Fictional Vendor",
                    ransomware_status="Unknown",
                    date_added_from=None,
                    due_date_to=None,
                    site_id="site-kev",
                    asset_id="asset-kev",
                    currently_affected=True,
                    priority="known_exploited",
                    limit=25,
                    offset=10,
                    admin_token="unit-test-admin",
                )
            self.assertEqual(response["limit"], 25)
            self.assertEqual(store.list_records.call_args.kwargs["site_id"], "site-kev")
            self.assertTrue(store.list_records.call_args.kwargs["currently_affected"])

    def test_asset_lookup_and_mutation_fail_closed_without_secret(self) -> None:
        store = Mock()
        store.asset_records.return_value = {"items": [], "total": 0, "limit": 20, "offset": 0}
        with patch.dict(os.environ, {}, clear=True), patch("app.main._kev_store", return_value=store):
            with self.assertRaises(HTTPException) as read_error:
                api_asset_kev_records(
                    asset_id="asset-kev",
                    site_id="site-kev",
                    limit=20,
                    admin_token=None,
                )
            self.assertEqual(read_error.exception.status_code, 503)
            store.asset_records.assert_not_called()
            with self.assertRaises(HTTPException) as raised:
                admin_evaluate_kev(admin_token=None)
            self.assertEqual(raised.exception.status_code, 503)


class KevAiTests(unittest.TestCase):
    def test_kev_tools_are_read_only_site_scoped_and_cite_server_ids(self) -> None:
        tools = kev_tools()
        selected = select_tools("Explain this KEV record, risk, and CISA due date")
        for tool_name in ("kev_records_for_matches", "kev_catalog_status", "kev_risk_contribution"):
            self.assertIn(tool_name, selected)
        result = tools.run("kev_records_for_matches", site_id="site-kev", asset_id="asset-kev")
        self.assertEqual(result["items"][0]["match_id"], MATCH_ID)
        context, _, evidence = build_tool_context(
            tools,
            question="Explain this KEV vulnerability, risk, and CISA due date",
            site_id="site-kev",
            asset_id="asset-kev",
        )
        answer = DeterministicDemoProvider().generate(
            question="Explain this KEV vulnerability, risk, and CISA due date",
            context=context,
        )
        self.assertIn(MATCH_ID, answer.answer)
        self.assertIn(ADVISORY_ID, answer.answer)
        self.assertIn(KEV_RECORD_ID, answer.answer)
        self.assertIn("unconfirmed, not No", answer.answer)
        self.assertIn("not a local SLA", answer.answer)
        self.assertIn("does not establish local exploitation", answer.answer)
        self.assertIn(KEV_RECORD_ID, answer.evidence_ids)
        self.assertIn(KEV_RECORD_ID, {item.evidence_id for item in evidence})
        for forbidden in ("activate", "rollback", "evaluate", "patch", "execute_required_action"):
            self.assertNotIn(forbidden, ReadOnlyHubTools.allowlist)
            with self.assertRaisesRegex(ValueError, "allowlisted"):
                tools.run(forbidden, site_id="site-kev")

    def test_known_ransomware_means_cisa_confirmation_not_local_activity(self) -> None:
        context, _, _ = build_tool_context(
            kev_tools(ransomware_status="Known"),
            question="Explain the KEV ransomware vulnerability",
            site_id="site-kev",
            asset_id="asset-kev",
        )
        answer = DeterministicDemoProvider().generate(
            question="Explain the KEV ransomware vulnerability",
            context=context,
        )
        self.assertIn("CISA reports confirmed ransomware campaign use", answer.answer)
        self.assertIn("active ransomware", answer.answer)
        self.assertIn("does not establish", answer.answer)

    def test_shared_kev_record_remains_global_and_risk_binding_stays_on_match(self) -> None:
        first = kev_tools()
        second_match = deepcopy(first.vulnerability_matches[0])
        second_match.update(
            match_id="vmt_" + "7" * 32,
            site_id="site-other",
            asset_id="asset-other",
            component_id="cmp_" + "8" * 32,
        )
        finding_other = {
            "finding_id": "fnd_other",
            "rule_id": "vulnerable-component",
            "category": "vulnerability",
            "title": "Other finding",
            "severity": "high",
            "confidence": 1.0,
            "status": "active",
            "site_id": "site-other",
            "asset_id": "asset-other",
            "evidence_observed_at": NOW,
            "evidence_freshness": "fresh",
            "evidence": [{"evidence_type": "vulnerability-match", "evidence_ref": second_match["match_id"]}],
        }
        finding_first = {
            **finding_other,
            "finding_id": "fnd_first",
            "title": "First finding",
            "site_id": "site-kev",
            "asset_id": "asset-kev",
            "evidence": [{"evidence_type": "vulnerability-match", "evidence_ref": MATCH_ID}],
        }
        tools = ReadOnlyHubTools(
            sites=[{"site_id": "site-kev"}, {"site_id": "site-other"}],
            sensors=[],
            assets=[],
            components=first.components,
            vulnerability_matches=[first.vulnerability_matches[0], second_match],
            findings=[finding_other, finding_first],
            asset_risks=[
                {"site_id": "site-other", "asset_id": "asset-other", "score": 91, "factors": []},
                {"site_id": "site-kev", "asset_id": "asset-kev", "score": 42, "factors": []},
            ],
            now=NOW,
        )
        context, _, evidence = build_tool_context(
            tools,
            question="Explain the KEV vulnerability risk contribution",
            site_id=None,
            asset_id=None,
        )
        kev_evidence = [item for item in evidence if item.evidence_id == KEV_RECORD_ID]
        self.assertEqual(len(kev_evidence), 1)
        self.assertIsNone(kev_evidence[0].site_id)
        self.assertIsNone(kev_evidence[0].asset_id)
        answer = DeterministicDemoProvider().generate(
            question="Explain the KEV vulnerability risk contribution",
            context=context,
        )
        self.assertIn(MATCH_ID, answer.answer)
        self.assertIn("fnd_first", answer.answer)
        self.assertNotIn("fnd_other contributes", answer.answer)


class KevUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.page = INDEX.read_text(encoding="utf-8")

    def test_ui_labels_semantics_and_uses_text_only_rendering(self) -> None:
        for value in (
            "Known Exploited",
            "Known Ransomware Campaign",
            "CISA KEV due date",
            "unconfirmed (not No)",
            "Local exploitation, compromise, and active ransomware are not established",
            "CISA guidance (text only, not executed)",
        ):
            self.assertIn(value, self.page)
        render = self.page[self.page.index("function renderAssetDetail"):self.page.index("function renderCollectors")]
        self.assertIn("kevGuidance.textContent", render)
        self.assertNotIn("innerHTML", render)

    def test_existing_responsive_dashboard_structure_is_preserved(self) -> None:
        self.assertIn(".settings-grid", self.page)
        self.assertIn("@media", self.page)
        self.assertIn('id="kev-status"', self.page)


if __name__ == "__main__":
    unittest.main()
