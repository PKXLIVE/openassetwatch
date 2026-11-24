from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.exc import OperationalError

from app.decision_contracts import FindingDecisionResponse, FindingDecisionTransitionResponse
from app.decision_store import DecisionReconcileResult, transition_cause
from app.decisions import evaluate_decision
from app.finding_service import evaluate_findings
from app.finding_store import InMemoryFindingStore
from app.main import (
    api_decision_rules,
    api_finding_decision,
    api_finding_decision_history,
    api_finding_decisions,
    app,
)
from tests.test_decisions import KEV, MATCH, finding


NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
FINDING_ID = "fnd_" + "a" * 32
TOKEN = "test-admin-token"


def decision_payload(**overrides) -> dict:
    decision = evaluate_decision(finding(evidence=(MATCH, KEV)))
    payload = {
        "schema_version": decision.schema_version,
        "ruleset_version": decision.ruleset_version,
        "finding_id": decision.finding_id,
        "site_id": decision.site_id,
        "asset_id": "asset-a",
        "sensor_id": None,
        "finding_rule_id": decision.finding_rule_id,
        "finding_status": "active",
        "decision_state": decision.decision_state,
        "decision_rule_id": decision.decision_rule_id,
        "action_band": decision.action_band,
        "urgency": decision.urgency,
        "severity": decision.severity,
        "evidence_confidence": decision.evidence_confidence,
        "evidence_confidence_value": decision.evidence_confidence_value,
        "evidence_freshness": decision.evidence_freshness,
        "exploitation_status": decision.exploitation_status,
        "exposure_state": decision.exposure_state,
        "asset_importance": decision.asset_importance,
        "uncertainty_present": decision.uncertainty_present,
        "verification_required": decision.verification_required,
        "prioritization_excluded": decision.prioritization_excluded,
        "reason_codes": list(decision.reason_codes),
        "reasons": [{"code": code, "explanation": "x"} for code in decision.reason_codes],
        "evidence_references": list(decision.evidence_references),
        "input_digest": decision.input_digest,
        "finding_evaluated_at": NOW,
        "evaluated_at": NOW,
        "evaluation_run_id": "frun_" + "c" * 32,
        "revision": 1,
        "projection_state": "current",
        "attention": {"asset_score": 42, "formula_version": "oaw.risk.kev.v1", "finding_contribution": 12.0},
    }
    payload.update(overrides)
    return payload


class DecisionApiTests(unittest.TestCase):
    def setUp(self) -> None:
        environment = patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": TOKEN})
        environment.start()
        self.addCleanup(environment.stop)
        self.store = Mock()
        store_patch = patch("app.main._decision_store", return_value=self.store)
        store_patch.start()
        self.addCleanup(store_patch.stop)

    def test_read_routes_require_admin_authentication(self) -> None:
        calls = (
            lambda: api_decision_rules(admin_token=None),
            lambda: api_finding_decisions(admin_token=None),
            lambda: api_finding_decision(FINDING_ID, admin_token="wrong"),
            lambda: api_finding_decision_history(FINDING_ID, admin_token=None),
        )
        for call in calls:
            with self.subTest(call=call):
                with self.assertRaises(HTTPException) as raised:
                    call()
                self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(self.store.method_calls, [])

    def test_decision_routes_are_read_only(self) -> None:
        routes = {
            (route.path, method)
            for route in app.routes
            if "/decisions" in getattr(route, "path", "")
            for method in route.methods
        }
        self.assertEqual({method for _path, method in routes}, {"GET"})
        self.assertFalse(any("/admin/" in path for path, _method in routes))

    def test_list_forwards_bounded_filters(self) -> None:
        self.store.list_decisions.return_value = {"items": [], "total": 0, "limit": 25, "offset": 5, "truncated": False}
        response = api_finding_decisions(
            site_id="site-a",
            action_band="prioritize",
            decision_state="current",
            limit=25,
            offset=5,
            admin_token=TOKEN,
        )
        self.assertEqual(response["total"], 0)
        self.assertEqual(
            self.store.list_decisions.call_args.kwargs,
            {"site_id": "site-a", "action_band": "prioritize", "decision_state": "current", "limit": 25, "offset": 5},
        )

    def test_invalid_filters_are_bad_requests(self) -> None:
        self.store.list_decisions.side_effect = ValueError("invalid action band")
        with self.assertRaises(HTTPException) as raised:
            api_finding_decisions(
                site_id=None, action_band="urgent", decision_state="current", limit=50, offset=0, admin_token=TOKEN
            )
        self.assertEqual(raised.exception.status_code, 400)

    def test_missing_decision_is_not_found(self) -> None:
        self.store.get_decision.return_value = None
        self.store.list_history.return_value = None
        for call in (
            lambda: api_finding_decision(FINDING_ID, admin_token=TOKEN),
            lambda: api_finding_decision_history(FINDING_ID, limit=50, offset=0, admin_token=TOKEN),
        ):
            with self.assertRaises(HTTPException) as raised:
                call()
            self.assertEqual(raised.exception.status_code, 404)

    def test_database_errors_do_not_leak(self) -> None:
        self.store.get_decision.side_effect = OperationalError("SELECT secret", {}, Exception("password=x"))
        with self.assertRaises(HTTPException) as raised:
            api_finding_decision(FINDING_ID, admin_token=TOKEN)
        self.assertEqual(raised.exception.status_code, 500)
        self.assertNotIn("password", raised.exception.detail)

    def test_ruleset_endpoint_validates_against_contract(self) -> None:
        from app.decision_contracts import DecisionRulesetResponse

        public = DecisionRulesetResponse(**api_decision_rules(admin_token=TOKEN))
        self.assertEqual(public.schema_version, "oaw.decision.v1")
        self.assertEqual([band.band for band in public.action_bands], ["monitor", "plan", "prioritize", "act-now"])


class DecisionContractTests(unittest.TestCase):
    def test_engine_output_round_trips_through_the_response_contract(self) -> None:
        model = FindingDecisionResponse(**decision_payload())
        self.assertEqual(model.action_band, "prioritize")
        self.assertEqual(model.attention.asset_score, 42)

    def test_contract_rejects_unknown_fields_and_values(self) -> None:
        for change in (
            {"action_band": "urgent"},
            {"urgency": "now"},
            {"schema_version": "oaw.decision.v2"},
            {"exposure_state": "safe"},
            {"reason_codes": ["lowercase_code"]},
            {"reason_codes": []},
            {"input_digest": "abc"},
            {"projection_state": "trusted"},
            {"ai_override": "monitor"},
        ):
            with self.subTest(change=change):
                with self.assertRaises(ValidationError):
                    FindingDecisionResponse(**decision_payload(**change))

    def test_history_contract_accepts_initial_and_resolution_transitions(self) -> None:
        base = {
            "finding_id": FINDING_ID,
            "site_id": "site-a",
            "revision": 1,
            "transition_cause": "initial",
            "ruleset_version": "oaw.decision.rules.v1",
            "decision_state": "current",
            "action_band": "plan",
            "urgency": "scheduled",
            "reason_codes": ["VULNERABILITY_CONFIRMED"],
            "input_digest": "0" * 64,
            "finding_evaluated_at": NOW,
            "evaluated_at": NOW,
            "evaluation_run_id": "frun_x",
        }
        FindingDecisionTransitionResponse(**base)
        FindingDecisionTransitionResponse(
            **{
                **base,
                "revision": 2,
                "transition_cause": "finding-resolved",
                "previous_decision_state": "current",
                "previous_action_band": "plan",
                "decision_state": "not-current",
                "action_band": None,
                "urgency": None,
                "reason_codes": ["FINDING_RESOLVED"],
            }
        )

    def test_openapi_decision_schemas_are_closed(self) -> None:
        schemas = app.openapi()["components"]["schemas"]
        for name in ("FindingDecisionResponse", "FindingDecisionTransitionResponse", "DecisionRulesetResponse"):
            with self.subTest(schema=name):
                self.assertFalse(schemas[name]["additionalProperties"])

    def test_transition_causes(self) -> None:
        current = evaluate_decision(finding())
        resolved = evaluate_decision(finding(status="resolved"))
        self.assertEqual(transition_cause(None, current), "initial")
        self.assertEqual(
            transition_cause({"ruleset_version": "oaw.decision.rules.v0", "decision_state": "current"}, current),
            "ruleset-changed",
        )
        stored = {"ruleset_version": current.ruleset_version, "decision_state": "current"}
        self.assertEqual(transition_cause(stored, resolved), "finding-resolved")
        self.assertEqual(
            transition_cause({**stored, "decision_state": "not-current"}, current), "finding-reopened"
        )
        self.assertEqual(transition_cause(stored, current), "inputs-changed")


class EvaluationHookTests(unittest.TestCase):
    sites = [{"site_id": "site-a", "name": "Site A"}]
    sensors: list[dict] = []

    def _evaluate(self, **kwargs):
        return evaluate_findings(
            trigger_type="test",
            requested_by="unit-test",
            now=NOW,
            store=InMemoryFindingStore(),
            sites=self.sites,
            sensors=self.sensors,
            assets=[],
            site_id="site-a",
            rule_ids=["unknown-asset"],
            **kwargs,
        )

    def test_decisions_are_reconciled_once_per_run_in_scope(self) -> None:
        decision_store = Mock()
        decision_store.reconcile_decisions.return_value = DecisionReconcileResult(evaluated=3, changed=2, transitions=1)
        result = self._evaluate(decision_store=decision_store)

        decision_store.reconcile_decisions.assert_called_once()
        kwargs = decision_store.reconcile_decisions.call_args.kwargs
        self.assertEqual(kwargs["site_id"], "site-a")
        self.assertEqual(kwargs["evaluated_at"], NOW)
        self.assertEqual(kwargs["run_id"], result.run_id)
        self.assertEqual((result.decision_evaluated_count, result.decision_transition_count), (3, 1))

    def test_injected_store_without_decision_store_skips_decisions(self) -> None:
        with patch("app.finding_service.SqlDecisionStore") as sql_store:
            result = self._evaluate()
        sql_store.assert_not_called()
        self.assertEqual(result.decision_evaluated_count, 0)

    def test_decision_failure_fails_the_run_visibly(self) -> None:
        decision_store = Mock()
        decision_store.reconcile_decisions.side_effect = ValueError("decision evaluation record limit exceeded")
        store = InMemoryFindingStore()
        with self.assertRaises(ValueError):
            evaluate_findings(
                trigger_type="test",
                now=NOW,
                store=store,
                decision_store=decision_store,
                sites=self.sites,
                sensors=self.sensors,
                assets=[],
                site_id="site-a",
                rule_ids=["unknown-asset"],
            )
        self.assertEqual(next(iter(store.runs.values()))["status"], "failed")


if __name__ == "__main__":
    unittest.main()
