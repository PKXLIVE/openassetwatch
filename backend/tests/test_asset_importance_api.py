"""Asset importance API: authorization, strict contracts, and error mapping."""

from __future__ import annotations

import os
import re
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.exc import OperationalError

from app.asset_importance_contracts import (
    ASSET_ID_PATH_PATTERN,
    AssetImportanceAssignRequest,
    AssetImportanceEventResponse,
    AssetImportanceMutationResponse,
    AssetImportanceResponse,
    AssetImportanceWithdrawRequest,
)
from app.asset_importance_store import AssetImportanceError, project_assignment, project_event
from tests.test_asset_importance import latest_for
from app.main import (
    SITE_ID_PATH_PATTERN,
    admin_assign_asset_importance,
    admin_withdraw_asset_importance,
    api_asset_importance,
    api_asset_importance_history,
    api_asset_importance_list,
    app,
)


NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
TOKEN = "test-admin-token"


def current(importance: str = "critical", revision: int = 1) -> dict:
    row = {
        "site_id": "site-a", "asset_id": "asset-a", "importance": importance,
        "assignment_state": "withdrawn" if importance == "unknown" else "assigned",
        "revision": revision, "reason": "payment gateway", "principal": "api-admin-token",
        "actor_label": "alex", "actor_verification": "unverified", "created_at": NOW,
        "reviewed_at": NOW, "updated_at": NOW,
    }
    return project_assignment("site-a", "asset-a", row, latest_for(row), now=NOW)


def event(previous: str | None, importance: str, revision: int = 1) -> dict:
    event_type = "assigned" if previous is None else "withdrawn" if importance == "unknown" else "changed"
    return project_event(
        {
            "event_id": revision, "site_id": "site-a", "asset_id": "asset-a", "revision": revision,
            "event_type": event_type, "previous_importance": previous, "importance": importance,
            "reason": "r", "principal": "api-admin-token", "actor_label": "alex",
            "actor_verification": "unverified", "occurred_at": NOW,
        }
    )


class AssetImportanceApiTests(unittest.TestCase):
    def setUp(self) -> None:
        environment = patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": TOKEN})
        environment.start()
        self.addCleanup(environment.stop)
        self.store = Mock()
        store_patch = patch("app.main._asset_importance_store", return_value=self.store)
        store_patch.start()
        self.addCleanup(store_patch.stop)
        self.evaluate = Mock()
        evaluate_patch = patch("app.main.evaluate_findings", self.evaluate)
        evaluate_patch.start()
        self.addCleanup(evaluate_patch.stop)

    def _assign(self, **overrides):
        payload = {"actor": "alex", "importance": "critical", "reason": "payment gateway"}
        payload.update(overrides)
        return admin_assign_asset_importance(
            AssetImportanceAssignRequest(**payload), "site-a", "asset-a", admin_token=TOKEN
        )

    def test_every_route_requires_a_configured_admin_token(self) -> None:
        calls = (
            lambda token: api_asset_importance_list(admin_token=token),
            lambda token: api_asset_importance("site-a", "asset-a", admin_token=token),
            lambda token: api_asset_importance_history("site-a", "asset-a", admin_token=token),
            lambda token: admin_assign_asset_importance(
                AssetImportanceAssignRequest(actor="a", importance="high", reason="r"),
                "site-a", "asset-a", admin_token=token,
            ),
            lambda token: admin_withdraw_asset_importance(
                AssetImportanceWithdrawRequest(actor="a", reason="r", expected_revision=1),
                "site-a", "asset-a", admin_token=token,
            ),
        )
        for call in calls:
            for token in (None, "wrong"):
                with self.subTest(call=call, token=token):
                    with self.assertRaises(HTTPException) as raised:
                        call(token)
                    self.assertEqual(raised.exception.status_code, 401)
        with patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": ""}):
            for call in calls:
                with self.assertRaises(HTTPException) as raised:
                    call(TOKEN)
                self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(self.store.method_calls, [])
        self.evaluate.assert_not_called()

    def test_route_surface(self) -> None:
        routes = {
            (route.path, method)
            for route in app.routes
            if "importance" in getattr(route, "path", "")
            for method in getattr(route, "methods", set())
        }
        self.assertEqual(
            routes,
            {
                ("/api/v1/asset-importance", "GET"),
                ("/api/v1/sites/{site_id}/assets/{asset_id:path}/importance", "GET"),
                ("/api/v1/sites/{site_id}/assets/{asset_id:path}/importance/history", "GET"),
                ("/api/v1/admin/sites/{site_id}/assets/{asset_id:path}/importance", "POST"),
                ("/api/v1/admin/sites/{site_id}/assets/{asset_id:path}/importance/withdraw", "POST"),
            },
        )

    def test_asset_ids_containing_slashes_route_unambiguously(self) -> None:
        from starlette.routing import Match

        def resolve(method: str, path: str) -> tuple[str, dict]:
            matches = []
            for route in app.routes:
                if "importance" not in getattr(route, "path", ""):
                    continue
                match, child = route.matches({"type": "http", "method": method, "path": path})
                if match == Match.FULL:
                    matches.append((route.name, child["path_params"]))
            self.assertEqual(len(matches), 1, (method, path, matches))
            return matches[0]

        base = "/api/v1/sites/site-a/assets"
        admin = "/api/v1/admin/sites/site-a/assets"
        for asset_id in ("asset-a", "rack/1", "a/importance", "x/importance/history", "a//b"):
            with self.subTest(asset_id=asset_id):
                self.assertEqual(
                    resolve("GET", f"{base}/{asset_id}/importance"),
                    ("api_asset_importance", {"site_id": "site-a", "asset_id": asset_id}),
                )
                self.assertEqual(
                    resolve("GET", f"{base}/{asset_id}/importance/history"),
                    ("api_asset_importance_history", {"site_id": "site-a", "asset_id": asset_id}),
                )
                self.assertEqual(
                    resolve("POST", f"{admin}/{asset_id}/importance"),
                    ("admin_assign_asset_importance", {"site_id": "site-a", "asset_id": asset_id}),
                )
                self.assertEqual(
                    resolve("POST", f"{admin}/{asset_id}/importance/withdraw"),
                    ("admin_withdraw_asset_importance", {"site_id": "site-a", "asset_id": asset_id}),
                )

    def test_assign_records_and_reevaluates_the_asset(self) -> None:
        self.store.assign.return_value = (current("critical"), event(None, "critical"))
        response = self._assign()
        AssetImportanceMutationResponse.model_validate(response)
        self.assertEqual(response["decision_reevaluation"], "completed")
        self.assertEqual(response["event"]["direction"], "initial")
        kwargs = self.store.assign.call_args.kwargs
        self.assertEqual(
            (kwargs["importance"], kwargs["reason"], kwargs["actor"], kwargs["expected_revision"]),
            ("critical", "payment gateway", "alex", None),
        )
        self.assertEqual(self.store.assign.call_args.args, ("site-a", "asset-a"))
        evaluation = self.evaluate.call_args.kwargs
        self.assertEqual(
            (evaluation["trigger_type"], evaluation["site_id"], evaluation["asset_id"]),
            ("asset-importance-change", "site-a", "asset-a"),
        )

    def test_increase_decrease_and_withdraw_are_reported(self) -> None:
        self.store.assign.return_value = (current("critical", 2), event("high", "critical", 2))
        self.assertEqual(self._assign(expected_revision=1)["event"]["direction"], "raised")
        self.store.assign.return_value = (current("low", 3), event("critical", "low", 3))
        lowered = self._assign(importance="low", expected_revision=2)["event"]
        self.assertEqual((lowered["direction"], lowered["security_sensitive"]), ("lowered", True))
        self.assertEqual(lowered["independent_review"], "recommended-not-enforced")
        self.store.withdraw.return_value = (current("unknown", 4), event("low", "unknown", 4))
        withdrawn = admin_withdraw_asset_importance(
            AssetImportanceWithdrawRequest(actor="alex", reason="decommissioned", expected_revision=3),
            "site-a", "asset-a", admin_token=TOKEN,
        )
        AssetImportanceMutationResponse.model_validate(withdrawn)
        self.assertEqual(withdrawn["importance"]["importance"], "unknown")
        self.assertEqual(withdrawn["importance"]["importance_source"], "unassigned")
        self.assertEqual(withdrawn["event"]["direction"], "withdrawn")
        self.assertEqual(self.evaluate.call_count, 3)

    def test_reevaluation_failure_is_reported_not_hidden(self) -> None:
        self.store.assign.return_value = (current("critical"), event(None, "critical"))
        self.evaluate.side_effect = RuntimeError("boom")
        self.assertEqual(self._assign()["decision_reevaluation"], "failed")

    def test_store_errors_map_to_bounded_statuses(self) -> None:
        for error, status in (
            (AssetImportanceError("asset_not_found", "asset not found in this site"), 404),
            (AssetImportanceError("not_found", "asset has no importance assignment"), 404),
            (AssetImportanceError("conflict", "importance revision does not match expected_revision"), 409),
            (ValueError("importance must be critical, high, standard, or low"), 400),
            (OperationalError("SELECT secret", {}, Exception("password=hunter2")), 500),
        ):
            with self.subTest(status=status):
                self.store.assign.side_effect = error
                with self.assertRaises(HTTPException) as raised:
                    self._assign(expected_revision=1)
                self.assertEqual(raised.exception.status_code, status)
                self.assertNotIn("hunter2", str(raised.exception.detail))
        # A refused mutation never triggers decision reevaluation.
        self.evaluate.assert_not_called()

    def test_missing_asset_and_cross_site_reads_are_not_found(self) -> None:
        self.store.get_importance.return_value = None
        self.store.list_history.return_value = None
        for call in (
            lambda: api_asset_importance("site-b", "asset-a", admin_token=TOKEN),
            lambda: api_asset_importance_history("site-b", "asset-a", admin_token=TOKEN),
        ):
            with self.assertRaises(HTTPException) as raised:
                call()
            self.assertEqual(raised.exception.status_code, 404)

    def test_unknown_importance_read_is_explicit(self) -> None:
        self.store.get_importance.return_value = project_assignment("site-a", "asset-a", None, None, now=NOW)
        item = AssetImportanceResponse.model_validate(api_asset_importance("site-a", "asset-a", admin_token=TOKEN))
        self.assertEqual(
            (item.importance, item.importance_source, item.assignment_state, item.revision),
            ("unknown", "unassigned", "none", None),
        )

    def test_list_rejects_invalid_filters(self) -> None:
        self.store.list_importance.side_effect = ValueError("invalid importance")
        with self.assertRaises(HTTPException) as raised:
            api_asset_importance_list(importance="medium", admin_token=TOKEN)
        self.assertEqual(raised.exception.status_code, 400)


class AssetImportanceContractTests(unittest.TestCase):
    def test_requests_reject_unknown_fields_including_claimed_reviewers(self) -> None:
        base = {"actor": "alex", "importance": "high", "reason": "r"}
        for extra in ({"approver": "bo"}, {"reviewer": "bo"}, {"verified_actor": True}, {"source": "imported"}):
            with self.subTest(extra=extra):
                with self.assertRaises(ValidationError):
                    AssetImportanceAssignRequest(**base, **extra)
                with self.assertRaises(ValidationError):
                    AssetImportanceWithdrawRequest(actor="alex", reason="r", expected_revision=1, **extra)

    def test_requests_reject_invalid_values(self) -> None:
        for overrides in (
            {"importance": "unknown"},
            {"importance": "medium"},
            {"importance": "CRITICAL"},
            {"reason": ""},
            {"reason": "x" * 501},
            {"reason": "bad\x00reason"},
            {"actor": ""},
            {"actor": "a" * 121},
            {"actor": "line\nbreak"},
            {"expected_revision": 0},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValidationError):
                    AssetImportanceAssignRequest(**{"actor": "alex", "importance": "high", "reason": "r", **overrides})
        AssetImportanceAssignRequest(actor="alex", importance="high", reason="x" * 500)
        with self.assertRaises(ValidationError):
            AssetImportanceWithdrawRequest(actor="alex", reason="r")

    def test_path_patterns_accept_ingestion_ids_and_reject_control_characters(self) -> None:
        # Ingestion accepts any 1-160 character asset id, including `/`.
        for value in ("asset-a", "host.example 01", "ÄSSET", "rack/1", "x" * 160):
            self.assertRegex(value, ASSET_ID_PATH_PATTERN)
        for value in ("", "a\x00", "a\n", "a\x7f", "x" * 161):
            self.assertIsNone(re.fullmatch(ASSET_ID_PATH_PATTERN, value))
        self.assertRegex("site-a", SITE_ID_PATH_PATTERN)
        for value in ("site a", "site/a", ""):
            self.assertIsNone(re.fullmatch(SITE_ID_PATH_PATTERN, value))

    def test_responses_are_closed_and_verification_is_fixed(self) -> None:
        item = current()
        with self.assertRaises(ValidationError):
            AssetImportanceResponse.model_validate({**item, "approved_by": "bo"})
        with self.assertRaises(ValidationError):
            AssetImportanceResponse.model_validate({**item, "actor_verification": "verified"})
        with self.assertRaises(ValidationError):
            AssetImportanceEventResponse.model_validate({**event(None, "high"), "event_type": "imported"})
        with self.assertRaises(ValidationError):
            AssetImportanceEventResponse.model_validate({**event(None, "high"), "independent_review": "approved"})

    def test_openapi_importance_schemas_are_closed(self) -> None:
        schemas = app.openapi()["components"]["schemas"]
        for name in (
            "AssetImportanceAssignRequest",
            "AssetImportanceWithdrawRequest",
            "AssetImportanceResponse",
            "AssetImportanceEventResponse",
            "AssetImportanceMutationResponse",
        ):
            with self.subTest(name=name):
                self.assertIs(schemas[name].get("additionalProperties"), False)


if __name__ == "__main__":
    unittest.main()
