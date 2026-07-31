from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from fastapi import BackgroundTasks, HTTPException
from pydantic import ValidationError

from app.finding_contracts import FindingEvaluateRequest, FindingSuppressRequest
from app.finding_service import evaluate_site_best_effort
from app.finding_store import SqlFindingStore
from app.main import (
    admin_acknowledge_finding,
    admin_evaluate_findings,
    admin_suppress_finding,
    api_asset_risk,
    api_finding,
    api_finding_rules,
    api_findings,
    api_risk_summary,
    api_site_risk,
    _queue_site_evaluation,
)


NOW = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
FINDING_ID = "fnd_" + "a" * 32


class FindingApiTests(unittest.TestCase):
    def setUp(self) -> None:
        environment = patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": "test-admin-token"})
        environment.start()
        self.addCleanup(environment.stop)

    def test_read_endpoints_require_admin_authentication(self) -> None:
        calls = (
            lambda: api_findings(admin_token=None),
            lambda: api_finding(FINDING_ID, admin_token=None),
            lambda: api_risk_summary(admin_token=None),
            lambda: api_asset_risk("asset-a", site_id="site-a", admin_token=None),
            lambda: api_site_risk("site-a", admin_token=None),
            lambda: api_finding_rules(admin_token=None),
        )

        for call in calls:
            with self.subTest(call=call):
                with self.assertRaises(HTTPException) as raised:
                    call()
                self.assertEqual(raised.exception.status_code, 401)

    def test_findings_filters_and_pagination_are_forwarded_to_bounded_store(self) -> None:
        store = Mock()
        store.list_findings.return_value = {
            "items": [],
            "total": 0,
            "limit": 25,
            "offset": 10,
            "truncated": False,
        }
        with patch("app.main._finding_store", return_value=store):
            response = api_findings(
                site_id="site-a",
                asset_id="asset-a",
                sensor_id=None,
                status="active",
                severity="high",
                rule_id="security-coverage-gap",
                category="coverage",
                updated_after=NOW,
                updated_before=NOW,
                limit=25,
                offset=10,
                admin_token="test-admin-token",
            )

        self.assertEqual(response["items"], [])
        self.assertEqual(store.list_findings.call_args.kwargs["limit"], 25)
        self.assertEqual(store.list_findings.call_args.kwargs["offset"], 10)
        self.assertEqual(store.list_findings.call_args.kwargs["category"], "coverage")
        self.assertEqual(store.list_findings.call_args.kwargs["updated_after"], NOW)

    def test_findings_time_filter_requires_timezone_and_order(self) -> None:
        common = {
            "site_id": None,
            "asset_id": None,
            "sensor_id": None,
            "status": None,
            "severity": None,
            "rule_id": None,
            "category": None,
            "limit": 25,
            "offset": 0,
            "admin_token": "test-admin-token",
        }
        with self.assertRaises(HTTPException) as naive:
            api_findings(
                **common,
                updated_after=datetime(2026, 7, 30, 12, 0),
                updated_before=None,
            )
        self.assertEqual(naive.exception.status_code, 400)

        with self.assertRaises(HTTPException) as reversed_range:
            api_findings(
                **common,
                updated_after=NOW,
                updated_before=datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc),
            )
        self.assertEqual(reversed_range.exception.status_code, 400)

    def test_finding_filter_values_remain_bound_sql_parameters(self) -> None:
        hostile = "coverage' OR TRUE --"
        where, params = SqlFindingStore._finding_filters(
            site_id="site-a",
            asset_id=None,
            sensor_id=None,
            status=None,
            severity=None,
            rule_id=hostile,
            category=None,
            updated_after=None,
            updated_before=None,
        )

        self.assertNotIn(hostile, where)
        self.assertEqual(params["rule_id"], hostile)

    def test_admin_evaluation_forwards_only_validated_scope_and_rules(self) -> None:
        result = Mock()
        result.as_dict.return_value = {"run_id": "frun_test"}
        payload = FindingEvaluateRequest(
            site_id="site-a",
            asset_id="asset-a",
            rule_ids=["unknown-asset"],
            requested_by="reviewer",
        )
        with patch("app.main.evaluate_findings", return_value=result) as evaluate:
            response = admin_evaluate_findings(payload, admin_token="test-admin-token")

        self.assertEqual(response["run_id"], "frun_test")
        self.assertEqual(evaluate.call_args.kwargs["site_id"], "site-a")
        self.assertEqual(evaluate.call_args.kwargs["rule_ids"], ["unknown-asset"])

    def test_asset_scope_without_site_is_rejected_by_contract(self) -> None:
        with self.assertRaises(ValidationError):
            FindingEvaluateRequest(asset_id="asset-a")

    def test_sensor_scope_is_bounded_to_sensor_health_rule(self) -> None:
        with self.assertRaises(ValidationError):
            FindingEvaluateRequest(
                site_id="site-a",
                sensor_id="sensor-a",
                rule_ids=["unknown-asset"],
            )
        payload = FindingEvaluateRequest(site_id="site-a", sensor_id="sensor-a")
        result = Mock()
        result.as_dict.return_value = {"run_id": "frun_sensor"}
        with patch("app.main.evaluate_findings", return_value=result) as evaluate:
            admin_evaluate_findings(payload, admin_token="test-admin-token")

        self.assertEqual(evaluate.call_args.kwargs["sensor_id"], "sensor-a")

    def test_suppression_requires_timezone_and_future_expiry(self) -> None:
        with self.assertRaises(ValidationError):
            FindingSuppressRequest(actor="reviewer", reason="test", until=datetime(2026, 8, 1))

        payload = FindingSuppressRequest(actor="reviewer", reason="test", until=NOW)
        with self.assertRaises(HTTPException) as raised:
            admin_suppress_finding(payload, FINDING_ID, admin_token="test-admin-token")
        self.assertEqual(raised.exception.status_code, 400)

    def test_acknowledgement_and_suppression_are_admin_mutations(self) -> None:
        for call in (
            lambda: admin_acknowledge_finding(
                payload=Mock(actor="reviewer"),
                finding_id=FINDING_ID,
                admin_token=None,
            ),
            lambda: admin_suppress_finding(
                payload=Mock(actor="reviewer", reason="test", until=None),
                finding_id=FINDING_ID,
                admin_token=None,
            ),
        ):
            with self.subTest(call=call):
                with self.assertRaises(HTTPException) as raised:
                    call()
                self.assertEqual(raised.exception.status_code, 401)

    def test_admin_mutations_fail_closed_when_admin_secret_is_unconfigured(self) -> None:
        with patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": ""}):
            with self.assertRaises(HTTPException) as raised:
                admin_evaluate_findings(
                    FindingEvaluateRequest(site_id="site-a"),
                    admin_token=None,
                )

        self.assertEqual(raised.exception.status_code, 503)

    def test_rule_registry_explicitly_reports_vlan_movement_as_deferred(self) -> None:
        response = api_finding_rules(admin_token="test-admin-token")

        self.assertEqual(len(response["rules"]), 7)
        self.assertTrue(any("VLAN movement" in value for value in response["deferred_rules"]))

    def test_post_ingestion_evaluation_is_queued_after_response(self) -> None:
        background = BackgroundTasks()

        _queue_site_evaluation(background, site_id="site-a")

        self.assertEqual(len(background.tasks), 1)
        self.assertEqual(
            background.tasks[0].kwargs,
            {"site_id": "site-a", "sensor_id": None},
        )

    def test_sensor_check_in_can_queue_only_the_affected_sensor(self) -> None:
        background = BackgroundTasks()

        _queue_site_evaluation(
            background,
            site_id="site-a",
            sensor_id="sensor-a",
        )

        self.assertEqual(
            background.tasks[0].kwargs,
            {"site_id": "site-a", "sensor_id": "sensor-a"},
        )

    def test_best_effort_evaluation_never_fails_ingestion_caller(self) -> None:
        with (
            patch(
                "app.finding_service.evaluate_findings",
                side_effect=RuntimeError("synthetic failure"),
            ),
            self.assertLogs("app.finding_service", level="WARNING") as captured,
        ):
            evaluate_site_best_effort(site_id="site-a", sensor_id="sensor-a")

        self.assertIn("RuntimeError", captured.output[0])
        self.assertNotIn("synthetic failure", captured.output[0])


if __name__ == "__main__":
    unittest.main()
