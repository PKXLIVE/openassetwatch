"""Remediation verification API: authorization, read-only surface, errors."""

from __future__ import annotations

import os
import unittest
from unittest.mock import Mock, patch

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.exc import OperationalError

from app.main import (
    api_finding_verification,
    api_finding_verification_history,
    api_unverified_work,
    api_verification_rules,
    app,
)
from app.verification import ruleset_public
from app.verification_contracts import VerificationRulesetResponse


TOKEN = "test-admin-token"
FINDING_ID = "fnd_" + "a" * 32


class VerificationApiTests(unittest.TestCase):
    def setUp(self) -> None:
        environment = patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": TOKEN})
        environment.start()
        self.addCleanup(environment.stop)
        self.store = Mock()
        store_patch = patch("app.main._verification_store", return_value=self.store)
        store_patch.start()
        self.addCleanup(store_patch.stop)

    def _calls(self):
        return (
            lambda token: api_verification_rules(admin_token=token),
            lambda token: api_unverified_work(admin_token=token),
            lambda token: api_finding_verification(FINDING_ID, admin_token=token),
            lambda token: api_finding_verification_history(FINDING_ID, admin_token=token),
        )

    def test_every_route_fails_closed(self) -> None:
        for call in self._calls():
            for token in (None, "wrong"):
                with self.assertRaises(HTTPException) as raised:
                    call(token)
                self.assertEqual(raised.exception.status_code, 401)
        with patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": ""}):
            for call in self._calls():
                with self.assertRaises(HTTPException) as raised:
                    call(TOKEN)
                self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(self.store.method_calls, [])

    def test_missing_finding_is_not_found(self) -> None:
        self.store.get_verification.return_value = None
        self.store.list_history.return_value = None
        for call in (
            lambda: api_finding_verification(FINDING_ID, admin_token=TOKEN),
            lambda: api_finding_verification_history(FINDING_ID, admin_token=TOKEN),
        ):
            with self.assertRaises(HTTPException) as raised:
                call()
            self.assertEqual(raised.exception.status_code, 404)

    def test_invalid_filter_is_a_bad_request_and_filters_are_forwarded(self) -> None:
        self.store.list_unverified.side_effect = ValueError("invalid unverified verification state")
        with self.assertRaises(HTTPException) as raised:
            api_unverified_work(verification_state="verified", admin_token=TOKEN)
        self.assertEqual(raised.exception.status_code, 400)
        self.store.list_unverified.side_effect = None
        self.store.list_unverified.return_value = {"items": [], "total": 0, "limit": 5, "offset": 0, "truncated": False}
        api_unverified_work(site_id="site-a", verification_state="still-present", limit=5, offset=0, admin_token=TOKEN)
        self.assertEqual(
            self.store.list_unverified.call_args.kwargs,
            {"site_id": "site-a", "verification_state": "still-present", "limit": 5, "offset": 0},
        )

    def test_database_errors_do_not_leak(self) -> None:
        self.store.get_verification.side_effect = OperationalError("SELECT secret", {}, Exception("password=x"))
        with self.assertRaises(HTTPException) as raised:
            api_finding_verification(FINDING_ID, admin_token=TOKEN)
        self.assertEqual(raised.exception.status_code, 500)
        self.assertEqual(raised.exception.detail, "failed to load finding verification")

    def test_guidance_reports_source_backed_component_versions_only(self) -> None:
        from app.verification_store import SqlVerificationStore

        connection = Mock()
        connection.execute.return_value.mappings.return_value = [
            {"match_id": "vmt_" + "a" * 32, "match_status": "affected", "installed_version": "1.2.0",
             "fixed_version": "1.4.2"}
        ]
        item = {
            "finding": {"rule_id": "vulnerable-component", "site_id": "site-a", "title": "t", "recommendation": "r"},
            "evidence": [
                {"evidence_ref": "vmt_" + "a" * 32, "evidence_type": "vulnerability-match"},
                {"evidence_ref": "adv_x", "evidence_type": "reviewed-advisory"},
            ],
        }
        guidance = SqlVerificationStore._guidance(connection, item)
        self.assertEqual(guidance["components"][0]["fixed_version"], "1.4.2")
        params = connection.execute.call_args.args[1]
        self.assertEqual(params, {"ids": ["vmt_" + "a" * 32], "site_id": "site-a"})
        self.assertTrue(guidance["automated"])
        # A rule with no match evidence issues no component query.
        connection.reset_mock()
        guidance = SqlVerificationStore._guidance(
            connection,
            {"finding": {"rule_id": "identity-conflict", "site_id": "site-a", "title": "t", "recommendation": "r"},
             "evidence": []},
        )
        connection.execute.assert_not_called()
        self.assertFalse(guidance["automated"])

    def test_routes_are_read_only(self) -> None:
        methods = {
            method
            for route in app.routes
            if "verification" in getattr(route, "path", "")
            for method in getattr(route, "methods", set())
        }
        self.assertEqual(methods, {"GET"})

    def test_ruleset_validates_against_contract_and_schemas_are_closed(self) -> None:
        VerificationRulesetResponse.model_validate(ruleset_public())
        with self.assertRaises(ValidationError):
            VerificationRulesetResponse.model_validate({**ruleset_public(), "approved_by": "x"})
        schemas = app.openapi()["components"]["schemas"]
        for name in (
            "FindingVerificationResponse",
            "FindingVerificationSummary",
            "VerificationHistoryResponse",
            "VerificationTransitionResponse",
            "VerificationRulesetResponse",
        ):
            with self.subTest(name=name):
                self.assertIs(schemas[name].get("additionalProperties"), False)


if __name__ == "__main__":
    unittest.main()
