from __future__ import annotations

import ast
import os
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi import HTTPException
from pydantic import ValidationError

from app.finding_work_contracts import (
    WORK_STATUS_TRANSITIONS,
    FindingWorkEventResponse,
    FindingWorkItemCreateRequest,
    FindingWorkItemResponse,
    FindingWorkNoteRequest,
    FindingWorkOwnerRequest,
    FindingWorkReferenceRemoveRequest,
    FindingWorkReferenceRequest,
    FindingWorkStatusRequest,
)
from app.finding_work_store import FindingWorkError, validate_status_transition
from app.main import (
    admin_add_finding_work_note,
    admin_add_finding_work_reference,
    admin_change_finding_work_owner,
    admin_change_finding_work_status,
    admin_create_finding_work_item,
    admin_remove_finding_work_reference,
    api_finding_work_events,
    api_finding_work_item,
    api_finding_work_items,
    app,
)


NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
FINDING_ID = "fnd_" + "a" * 32
WORK_ITEM_ID = "fwi_" + "b" * 32
REFERENCE_ID = "fwr_" + "c" * 32
TOKEN = "test-admin-token"
APP_ROOT = Path(__file__).resolve().parents[1] / "app"


def work_item(**overrides: object) -> dict:
    item = {
        "work_item_id": WORK_ITEM_ID,
        "finding_id": FINDING_ID,
        "site_id": "site-a",
        "work_status": "open",
        "owner": None,
        "revision": 1,
        "finding_status": "active",
        "created_principal": "api-admin-token",
        "created_actor_label": "alex",
        "actor_verification": "unverified",
        "created_at": NOW,
        "updated_at": NOW,
        "references": [],
    }
    item.update(overrides)
    return item


class FindingWorkContractTests(unittest.TestCase):
    def test_actor_label_is_required_and_bounded(self) -> None:
        with self.assertRaises(ValidationError):
            FindingWorkItemCreateRequest()
        with self.assertRaises(ValidationError):
            FindingWorkItemCreateRequest(actor="x" * 121)
        with self.assertRaises(ValidationError):
            FindingWorkItemCreateRequest(actor="alex\nadmin")
        self.assertEqual(FindingWorkItemCreateRequest(actor="  alex  ").actor, "alex")

    def test_unknown_fields_cannot_smuggle_finding_status_risk_or_site(self) -> None:
        for field in ("site_id", "status", "risk_score", "principal", "suppressed"):
            with self.subTest(field=field):
                with self.assertRaises(ValidationError):
                    FindingWorkItemCreateRequest(actor="alex", **{field: "x"})
        with self.assertRaises(ValidationError):
            FindingWorkStatusRequest(
                actor="alex", status="open", expected_revision=1, site_id="site-b"
            )

    def test_owner_kind_and_label_must_be_paired(self) -> None:
        with self.assertRaises(ValidationError):
            FindingWorkItemCreateRequest(actor="alex", owner_kind="team")
        with self.assertRaises(ValidationError):
            FindingWorkOwnerRequest(actor="alex", owner_label="Network Ops", expected_revision=1)
        with self.assertRaises(ValidationError):
            FindingWorkOwnerRequest(
                actor="alex", owner_kind="group", owner_label="x", expected_revision=1
            )
        cleared = FindingWorkOwnerRequest(actor="alex", expected_revision=1)
        self.assertIsNone(cleared.owner_kind)
        self.assertIsNone(cleared.owner_label)

    def test_work_status_vocabulary_excludes_risk_acceptance_and_resolution(self) -> None:
        for status in ("accepted", "risk_accepted", "resolved", "suppressed", "active"):
            with self.subTest(status=status):
                with self.assertRaises(ValidationError):
                    FindingWorkStatusRequest(actor="alex", status=status, expected_revision=1)
        self.assertEqual(
            set(WORK_STATUS_TRANSITIONS),
            {"open", "in_progress", "blocked", "done", "cancelled"},
        )

    def test_mutations_require_a_positive_expected_revision(self) -> None:
        for revision in (None, 0, -1):
            with self.subTest(revision=revision):
                with self.assertRaises(ValidationError):
                    FindingWorkNoteRequest(actor="alex", note="n", expected_revision=revision)
        with self.assertRaises(ValidationError):
            FindingWorkReferenceRemoveRequest(actor="alex")

    def test_reference_labels_are_opaque_and_never_urls(self) -> None:
        accepted = FindingWorkReferenceRequest(
            actor="alex",
            reference_type="ticket",
            reference_system="jira",
            reference_label="OPS-1234",
            expected_revision=1,
        )
        self.assertEqual(accepted.reference_label, "OPS-1234")
        for label in (
            "https://tickets.example.test/OPS-1",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "//example.test/x",
            "OPS/1",
            "<script>",
            "-leading-dash",
            "x" * 121,
        ):
            with self.subTest(label=label):
                with self.assertRaises(ValidationError):
                    FindingWorkReferenceRequest(
                        actor="alex",
                        reference_type="ticket",
                        reference_system="jira",
                        reference_label=label,
                        expected_revision=1,
                    )
        for system in ("Jira", "a" * 41, "jira:cloud", "jira/cloud", "https://x"):
            with self.subTest(system=system):
                with self.assertRaises(ValidationError):
                    FindingWorkReferenceRequest(
                        actor="alex",
                        reference_type="ticket",
                        reference_system=system,
                        reference_label="OPS-1",
                        expected_revision=1,
                    )
        with self.assertRaises(ValidationError):
            FindingWorkReferenceRequest(
                actor="alex",
                reference_type="url",
                reference_system="jira",
                reference_label="OPS-1",
                expected_revision=1,
            )

    def test_notes_allow_lines_but_reject_other_control_characters(self) -> None:
        self.assertEqual(
            FindingWorkNoteRequest(actor="a", note="line one\nline two", expected_revision=1).note,
            "line one\nline two",
        )
        for note in ("bad\x00byte", "bell\x07", "x" * 1001):
            with self.subTest(note=note[:10]):
                with self.assertRaises(ValidationError):
                    FindingWorkNoteRequest(actor="a", note=note, expected_revision=1)

    def test_responses_mark_owner_and_actor_as_unverified(self) -> None:
        response = FindingWorkItemResponse(
            **work_item(owner={"kind": "team", "label": "Net Ops", "verification": "unverified"})
        )
        self.assertEqual(response.owner.verification, "unverified")
        self.assertEqual(response.actor_verification, "unverified")
        self.assertEqual(response.created_principal, "api-admin-token")
        with self.assertRaises(ValidationError):
            FindingWorkItemResponse(
                **work_item(owner={"kind": "team", "label": "Net Ops", "verification": "verified"})
            )
        with self.assertRaises(ValidationError):
            FindingWorkItemResponse(**work_item(created_principal="alex"))
        with self.assertRaises(ValidationError):
            FindingWorkEventResponse(
                event_id=1,
                work_item_id=WORK_ITEM_ID,
                finding_id=FINDING_ID,
                site_id="site-a",
                revision=1,
                event_type="created",
                finding_status="active",
                principal="api-admin-token",
                actor_label="alex",
                actor_verification="authenticated",
                occurred_at=NOW,
            )

    def test_openapi_work_contracts_are_closed(self) -> None:
        schemas = app.openapi()["components"]["schemas"]
        for name in (
            "FindingWorkItemCreateRequest",
            "FindingWorkStatusRequest",
            "FindingWorkOwnerRequest",
            "FindingWorkReferenceRequest",
            "FindingWorkReferenceRemoveRequest",
            "FindingWorkNoteRequest",
            "FindingWorkItemResponse",
            "FindingWorkEventResponse",
        ):
            with self.subTest(schema=name):
                self.assertFalse(schemas[name]["additionalProperties"])


class FindingWorkTransitionTests(unittest.TestCase):
    def test_allowed_transitions(self) -> None:
        for current, targets in WORK_STATUS_TRANSITIONS.items():
            for target in targets:
                with self.subTest(current=current, target=target):
                    validate_status_transition(current, target)

    def test_terminal_states_can_only_reopen_work(self) -> None:
        for terminal in ("done", "cancelled"):
            for target in ("in_progress", "blocked", "done", "cancelled"):
                if target == terminal:
                    continue
                with self.subTest(terminal=terminal, target=target):
                    with self.assertRaises(FindingWorkError) as raised:
                        validate_status_transition(terminal, target)
                    self.assertEqual(raised.exception.kind, "conflict")

    def test_same_status_and_unknown_status_are_conflicts(self) -> None:
        with self.assertRaises(FindingWorkError):
            validate_status_transition("open", "open")
        with self.assertRaises(FindingWorkError):
            validate_status_transition("open", "resolved")


class FindingWorkApiTests(unittest.TestCase):
    def setUp(self) -> None:
        environment = patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": TOKEN})
        environment.start()
        self.addCleanup(environment.stop)
        self.store = Mock()
        store_patch = patch("app.main._finding_work_store", return_value=self.store)
        store_patch.start()
        self.addCleanup(store_patch.stop)

    def _calls(self, token: str | None):
        return (
            lambda: api_finding_work_items(
                site_id=None, work_status=None, limit=50, offset=0, admin_token=token
            ),
            lambda: api_finding_work_item(FINDING_ID, admin_token=token),
            lambda: api_finding_work_events(FINDING_ID, limit=50, offset=0, admin_token=token),
            lambda: admin_create_finding_work_item(
                FindingWorkItemCreateRequest(actor="alex"), FINDING_ID, admin_token=token
            ),
            lambda: admin_change_finding_work_status(
                FindingWorkStatusRequest(actor="alex", status="in_progress", expected_revision=1),
                FINDING_ID,
                admin_token=token,
            ),
            lambda: admin_change_finding_work_owner(
                FindingWorkOwnerRequest(
                    actor="alex", owner_kind="team", owner_label="Net Ops", expected_revision=1
                ),
                FINDING_ID,
                admin_token=token,
            ),
            lambda: admin_add_finding_work_reference(
                FindingWorkReferenceRequest(
                    actor="alex",
                    reference_type="ticket",
                    reference_system="jira",
                    reference_label="OPS-1",
                    expected_revision=1,
                ),
                FINDING_ID,
                admin_token=token,
            ),
            lambda: admin_remove_finding_work_reference(
                FindingWorkReferenceRemoveRequest(actor="alex", expected_revision=2),
                FINDING_ID,
                REFERENCE_ID,
                admin_token=token,
            ),
            lambda: admin_add_finding_work_note(
                FindingWorkNoteRequest(actor="alex", note="checked", expected_revision=1),
                FINDING_ID,
                admin_token=token,
            ),
        )

    def test_every_work_route_requires_the_admin_token(self) -> None:
        for token in (None, "wrong-token"):
            for call in self._calls(token):
                with self.subTest(token=token, call=call):
                    with self.assertRaises(HTTPException) as raised:
                        call()
                    self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(self.store.method_calls, [])

    def test_work_routes_fail_closed_when_admin_secret_is_unconfigured(self) -> None:
        with patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": ""}):
            for call in self._calls(TOKEN):
                with self.subTest(call=call):
                    with self.assertRaises(HTTPException) as raised:
                        call()
                    self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(self.store.method_calls, [])

    def test_mutations_never_trigger_finding_evaluation_or_finding_store(self) -> None:
        for method in (
            "create_work_item",
            "change_status",
            "change_owner",
            "add_reference",
            "remove_reference",
            "add_note",
        ):
            getattr(self.store, method).return_value = work_item()
        with (
            patch("app.main.evaluate_site_best_effort") as best_effort,
            patch("app.main.evaluate_findings") as evaluate,
            patch("app.main._finding_store") as finding_store,
        ):
            for call in self._calls(TOKEN)[3:]:
                call()
        best_effort.assert_not_called()
        evaluate.assert_not_called()
        finding_store.assert_not_called()

    def test_actor_is_forwarded_as_label_and_site_is_never_supplied(self) -> None:
        self.store.create_work_item.return_value = work_item()
        admin_create_finding_work_item(
            FindingWorkItemCreateRequest(actor="alex", owner_kind="person", owner_label="Sam"),
            FINDING_ID,
            admin_token=TOKEN,
        )
        kwargs = self.store.create_work_item.call_args.kwargs
        self.assertEqual(self.store.create_work_item.call_args.args, (FINDING_ID,))
        self.assertEqual(kwargs["actor"], "alex")
        self.assertNotIn("site_id", kwargs)
        self.assertNotIn("principal", kwargs)
        self.assertEqual(kwargs["at"].tzinfo, timezone.utc)

    def test_store_errors_map_to_bounded_http_statuses(self) -> None:
        cases = (
            (FindingWorkError("finding_not_found", "finding not found"), 404),
            (FindingWorkError("not_found", "work item not found"), 404),
            (FindingWorkError("conflict", "work item revision does not match"), 409),
            (ValueError("invalid work status"), 400),
        )
        for error, status_code in cases:
            with self.subTest(error=error):
                self.store.change_status.side_effect = error
                with self.assertRaises(HTTPException) as raised:
                    admin_change_finding_work_status(
                        FindingWorkStatusRequest(
                            actor="alex", status="done", expected_revision=3
                        ),
                        FINDING_ID,
                        admin_token=TOKEN,
                    )
                self.assertEqual(raised.exception.status_code, status_code)

    def test_database_errors_do_not_leak_details(self) -> None:
        from sqlalchemy.exc import OperationalError

        self.store.add_note.side_effect = OperationalError(
            "SELECT secret", {}, Exception("password=hunter2")
        )
        with self.assertRaises(HTTPException) as raised:
            admin_add_finding_work_note(
                FindingWorkNoteRequest(actor="alex", note="n", expected_revision=1),
                FINDING_ID,
                admin_token=TOKEN,
            )
        self.assertEqual(raised.exception.status_code, 500)
        self.assertNotIn("hunter2", raised.exception.detail)
        self.assertNotIn("SELECT", raised.exception.detail)

    def test_missing_work_item_reads_are_not_found(self) -> None:
        self.store.get_work_item.return_value = None
        self.store.list_events.return_value = None
        with self.assertRaises(HTTPException) as item:
            api_finding_work_item(FINDING_ID, admin_token=TOKEN)
        with self.assertRaises(HTTPException) as events:
            api_finding_work_events(FINDING_ID, limit=50, offset=0, admin_token=TOKEN)
        self.assertEqual(item.exception.status_code, 404)
        self.assertEqual(events.exception.status_code, 404)

    def test_create_route_reports_created(self) -> None:
        routes = {
            (route.path, method): route
            for route in app.routes
            if getattr(route, "path", "").startswith("/api/v1/admin/findings/{finding_id}/work-item")
            for method in route.methods
        }
        self.assertEqual(
            routes[("/api/v1/admin/findings/{finding_id}/work-item", "POST")].status_code,
            201,
        )
        self.assertEqual({method for _path, method in routes}, {"POST"})


class FindingWorkBoundaryTests(unittest.TestCase):
    def test_work_store_never_writes_findings_evidence_or_risk_tables(self) -> None:
        source = (APP_ROOT / "finding_work_store.py").read_text(encoding="utf-8")
        sql = " ".join(
            " ".join(node.value.split()).upper()
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        )
        for table in (
            "FINDINGS",
            "FINDING_EVIDENCE",
            "ASSET_RISK_SCORES",
            "SITE_RISK_SCORES",
            "RISK_FACTORS",
        ):
            with self.subTest(table=table):
                self.assertNotIn(f"UPDATE {table} ", sql)
                self.assertNotIn(f"INSERT INTO {table} ", sql)
                self.assertNotIn(f"DELETE FROM {table} ", sql)
        self.assertNotIn("UPDATE FINDING_WORK_EVENTS", sql)
        self.assertNotIn("DELETE FROM FINDING_WORK_EVENTS", sql)

    def test_risk_and_ai_advisor_do_not_read_work_tracking(self) -> None:
        for module in ("risk.py", "finding_service.py", "findings.py", "ai_advisor.py"):
            with self.subTest(module=module):
                source = (APP_ROOT / module).read_text(encoding="utf-8")
                self.assertNotIn("finding_work", source)
                self.assertNotIn("work_item", source)


if __name__ == "__main__":
    unittest.main()
