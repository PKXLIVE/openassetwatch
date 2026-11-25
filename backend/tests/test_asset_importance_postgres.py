"""Gated PostgreSQL tests for audited asset importance (CTEM-GAP-02)."""

from __future__ import annotations

import os
import re
import threading
import unittest
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.pool import NullPool

from app.asset_importance_store import AssetImportanceError, SqlAssetImportanceStore
from app.decision_store import SqlDecisionStore
from app.finding_service import evaluate_findings
from app.finding_store import SqlFindingStore
from app.finding_work_store import SqlFindingWorkStore
from app.schema_migrations import migrate_database_schema
from tests.test_decision_postgres import NOW, vulnerable_asset


ENABLED = os.getenv("OPENASSETWATCH_IMPORTANCE_POSTGRES_TEST") == "1"
DATABASE_NAME = re.compile(r"^openassetwatch_importance_test_[0-9a-f]{16}$")


@unittest.skipUnless(ENABLED, "requires an explicitly isolated disposable PostgreSQL server")
class AssetImportancePostgresTests(unittest.TestCase):
    admin_engine: Engine
    database_engine: Engine
    database_name: str

    def setUp(self) -> None:
        parsed = make_url(os.environ["DATABASE_URL"])
        self.database_name = f"openassetwatch_importance_test_{uuid4().hex[:16]}"
        self.assertRegex(self.database_name, DATABASE_NAME)
        self.admin_engine = create_engine(
            parsed.set(database="postgres"), isolation_level="AUTOCOMMIT", poolclass=NullPool
        )
        with self.admin_engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{self.database_name}"')
        self.database_engine = create_engine(parsed.set(database=self.database_name), poolclass=NullPool)
        self.assertEqual(migrate_database_schema(self.database_engine).current_version, 8)
        self.patchers = [
            patch("app.database.get_engine", return_value=self.database_engine),
            patch("app.database.ensure_database_schema"),
        ]
        for patcher in self.patchers:
            patcher.start()
        with self.database_engine.begin() as connection:
            connection.execute(
                text("INSERT INTO sites (site_id, name) VALUES ('site-a', 'Site A'), ('site-b', 'Site B')")
            )
            connection.execute(
                text(
                    """
                    INSERT INTO control_tower_assets (asset_key, asset_id, site_id, hostname, first_seen_at, last_seen_at)
                    VALUES ('site-a:asset-a', 'asset-a', 'site-a', 'payments-critical-db', :at, :at),
                           ('site-b:asset-b', 'asset-b', 'site-b', 'other', :at, :at)
                    """
                ),
                {"at": NOW},
            )
        self.findings = SqlFindingStore()
        self.decisions = SqlDecisionStore()
        self.importance = SqlAssetImportanceStore()
        self.sites = [{"site_id": "site-a", "name": "Site A"}]
        self.sensors = [
            {
                "agent_id": "agent-a",
                "site_id": "site-a",
                "agent_type": "endpoint-agent",
                "identity_status": "active",
                "last_seen_at": NOW,
            }
        ]

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.database_engine.dispose()
        if not DATABASE_NAME.fullmatch(self.database_name):
            self.fail("refusing to drop a database outside the disposable prefix")
        with self.admin_engine.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": self.database_name},
            )
            connection.exec_driver_sql(f'DROP DATABASE "{self.database_name}"')
        self.admin_engine.dispose()

    # ----------------------------------------------------------------- helpers

    def _evaluate(self, at: datetime, **asset_kwargs):
        return evaluate_findings(
            trigger_type="test",
            requested_by="unit-test",
            now=at,
            store=self.findings,
            decision_store=self.decisions,
            sites=self.sites,
            sensors=self.sensors,
            assets=[vulnerable_asset(at, **asset_kwargs)],
            site_id="site-a",
            rule_ids=["vulnerable-component"],
        )

    def _finding_id(self) -> str:
        items = self.findings.list_findings(site_id="site-a", rule_id="vulnerable-component")["items"]
        self.assertEqual(len(items), 1)
        return items[0]["finding_id"]

    def _rows(self, sql: str, **params: Any) -> list[dict[str, Any]]:
        with self.database_engine.connect() as connection:
            return [dict(row) for row in connection.execute(text(sql), params).mappings()]

    def _assign(self, importance: str, *, expected_revision: int | None = None, at: datetime = NOW, **kwargs):
        return self.importance.assign(
            kwargs.pop("site_id", "site-a"),
            kwargs.pop("asset_id", "asset-a"),
            importance=importance,
            reason=kwargs.pop("reason", f"set to {importance}"),
            actor=kwargs.pop("actor", "alex"),
            expected_revision=expected_revision,
            at=at,
        )

    def _events(self) -> list[dict[str, Any]]:
        history = self.importance.list_history("site-a", "asset-a", limit=200)
        assert history is not None
        return history["items"]

    def _authoritative_snapshot(self) -> dict[str, list[dict[str, Any]]]:
        return {
            table: self._rows(f"SELECT * FROM {table} ORDER BY 1")
            for table in (
                "control_tower_assets",
                "findings",
                "finding_evidence",
                "asset_risk_scores",
                "risk_factors",
                "finding_decisions",
                "finding_decision_history",
                "finding_work_items",
                "finding_work_events",
            )
        }

    # -------------------------------------------------------------------- tests

    def test_missing_importance_is_unknown_and_never_low(self) -> None:
        item = self.importance.get_importance("site-a", "asset-a", now=NOW)
        self.assertEqual(
            (item["importance"], item["importance_source"], item["assignment_state"]),
            ("unknown", "unassigned", "none"),
        )
        self._evaluate(NOW)
        decision = self.decisions.get_decision(self._finding_id())
        self.assertEqual(decision["asset_importance"], "unknown")
        self.assertIn("ASSET_IMPORTANCE_UNKNOWN", decision["reason_codes"])
        self.assertEqual(decision["action_band"], "prioritize")

    def test_critical_assignment_drives_act_now_with_exposure_unknown(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        current, event = self._assign("critical")
        self.assertEqual((current["importance"], current["revision"], current["integrity_state"]), ("critical", 1, "consistent"))
        self.assertEqual((event["event_type"], event["direction"]), ("assigned", "initial"))
        self.assertEqual(current["actor_verification"], "unverified")
        # Before evaluation the stored decision is detectably stale, not current.
        self.assertEqual(self.decisions.get_decision(finding_id)["projection_state"], "stale")

        self._evaluate(NOW + timedelta(minutes=1))
        decision = self.decisions.get_decision(finding_id)
        self.assertEqual(decision["action_band"], "act-now")
        self.assertEqual(decision["decision_rule_id"], "vulnerability-known-exploited-critical-asset")
        self.assertEqual(decision["exposure_state"], "unknown")
        self.assertEqual(decision["asset_importance"], "critical")
        self.assertIn("ASSET_IMPORTANCE_CRITICAL", decision["reason_codes"])
        self.assertIn("EXPOSURE_UNKNOWN", decision["reason_codes"])
        self.assertEqual(decision["projection_state"], "current")
        history = self.decisions.list_history(finding_id)["items"]
        self.assertEqual(
            (history[-1]["transition_cause"], history[-1]["previous_action_band"], history[-1]["action_band"]),
            ("inputs-changed", "prioritize", "act-now"),
        )

    def test_increase_decrease_review_and_withdrawal_history(self) -> None:
        self._assign("standard", reason="initial review")
        self._assign("critical", expected_revision=1, at=NOW + timedelta(minutes=1), reason="payment path")
        self._assign("critical", expected_revision=2, at=NOW + timedelta(minutes=2), reason="annual review")
        self._assign("low", expected_revision=3, at=NOW + timedelta(minutes=3), actor="sam", reason="moved to lab")
        current, withdrawal = self.importance.withdraw(
            "site-a", "asset-a", reason="ownership unclear", actor="sam", expected_revision=4,
            at=NOW + timedelta(minutes=4),
        )
        events = self._events()
        self.assertEqual(
            [(e["revision"], e["event_type"], e["previous_importance"], e["importance"], e["direction"]) for e in events],
            [
                (1, "assigned", None, "standard", "initial"),
                (2, "changed", "standard", "critical", "raised"),
                (3, "reviewed", "critical", "critical", "unchanged"),
                (4, "changed", "critical", "low", "lowered"),
                (5, "withdrawn", "low", "unknown", "withdrawn"),
            ],
        )
        self.assertEqual([e["security_sensitive"] for e in events], [False, False, False, True, True])
        # Withdrawal keeps the prior assignment's actor and reason in history.
        self.assertEqual((events[3]["actor_label"], events[3]["reason"]), ("sam", "moved to lab"))
        self.assertEqual((events[1]["actor_label"], events[1]["reason"]), ("alex", "payment path"))
        self.assertEqual(
            (current["importance"], current["importance_source"], current["assignment_state"], current["revision"]),
            ("unknown", "unassigned", "withdrawn", 5),
        )
        self.assertEqual(withdrawal["event_type"], "withdrawn")
        # Reassignment after withdrawal starts a fresh assigned event.
        _, again = self._assign("high", expected_revision=5, at=NOW + timedelta(minutes=5))
        self.assertEqual((again["event_type"], again["direction"]), ("assigned", "reassigned"))

    def test_withdrawal_makes_decisions_see_unknown(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._assign("critical")
        self._evaluate(NOW + timedelta(minutes=1))
        self.assertEqual(self.decisions.get_decision(finding_id)["action_band"], "act-now")
        self.importance.withdraw(
            "site-a", "asset-a", reason="re-review", actor="alex", expected_revision=1,
            at=NOW + timedelta(minutes=2),
        )
        self._evaluate(NOW + timedelta(minutes=3))
        decision = self.decisions.get_decision(finding_id)
        self.assertEqual(decision["action_band"], "prioritize")
        self.assertEqual(decision["asset_importance"], "unknown")
        self.assertIn("ASSET_IMPORTANCE_UNKNOWN", decision["reason_codes"])
        bands = [item["action_band"] for item in self.decisions.list_history(finding_id)["items"]]
        self.assertEqual(bands, ["prioritize", "act-now", "prioritize"])

    def test_stale_or_missing_revisions_conflict_without_partial_history(self) -> None:
        self._assign("high")
        before = self._rows("SELECT * FROM asset_importance_events ORDER BY event_id")
        before_current = self._rows("SELECT * FROM asset_importance_assignments")
        for kwargs in ({"expected_revision": None}, {"expected_revision": 2}, {"expected_revision": 9}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(AssetImportanceError) as raised:
                    self._assign("critical", **kwargs)
                self.assertEqual(raised.exception.kind, "conflict")
        with self.assertRaises(AssetImportanceError) as raised:
            self.importance.withdraw("site-a", "asset-a", reason="r", actor="a", expected_revision=7, at=NOW)
        self.assertEqual(raised.exception.kind, "conflict")
        with self.assertRaises(AssetImportanceError):
            self._assign("low", asset_id="asset-missing", expected_revision=None)
        self.assertEqual(self._rows("SELECT * FROM asset_importance_events ORDER BY event_id"), before)
        self.assertEqual(self._rows("SELECT * FROM asset_importance_assignments"), before_current)

    def test_concurrent_updates_cannot_silently_overwrite(self) -> None:
        self._assign("standard")
        barrier = threading.Barrier(2)
        outcomes: list[str] = []

        def worker(value: str) -> None:
            barrier.wait()
            try:
                self._assign(value, expected_revision=1, at=NOW + timedelta(minutes=1))
                outcomes.append("ok")
            except AssetImportanceError as exc:
                outcomes.append(exc.kind)

        threads = [threading.Thread(target=worker, args=(value,)) for value in ("critical", "low")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ["conflict", "ok"])
        events = self._events()
        self.assertEqual([event["revision"] for event in events], [1, 2])
        current = self.importance.get_importance("site-a", "asset-a", now=NOW)
        self.assertEqual(current["importance"], events[-1]["importance"])
        self.assertEqual(current["integrity_state"], "consistent")

    def test_concurrent_first_assignments_record_one(self) -> None:
        barrier = threading.Barrier(2)
        outcomes: list[str] = []

        def worker(value: str) -> None:
            barrier.wait()
            try:
                self._assign(value)
                outcomes.append("ok")
            except AssetImportanceError as exc:
                outcomes.append(exc.kind)

        threads = [threading.Thread(target=worker, args=(value,)) for value in ("critical", "low")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ["conflict", "ok"])
        self.assertEqual(len(self._events()), 1)

    def test_site_binding_and_cross_site_denial(self) -> None:
        with self.assertRaises(AssetImportanceError) as raised:
            self._assign("critical", site_id="site-b", asset_id="asset-a")
        self.assertEqual(raised.exception.kind, "asset_not_found")
        self.assertIsNone(self.importance.get_importance("site-b", "asset-a", now=NOW))
        self.assertIsNone(self.importance.list_history("site-b", "asset-a"))
        with self.assertRaises(IntegrityError):
            with self.database_engine.begin() as connection:
                connection.execute(
                    text(
                        """
                        INSERT INTO asset_importance_assignments (
                            site_id, asset_id, importance, assignment_state, source, reason,
                            revision, principal, actor_label, created_at, reviewed_at, updated_at
                        ) VALUES ('site-b', 'asset-a', 'critical', 'assigned', 'operator', 'r',
                                  1, 'api-admin-token', 'x', NOW(), NOW(), NOW())
                        """
                    )
                )
        self._assign("high")
        for statement in (
            "UPDATE asset_importance_assignments SET site_id = 'site-b'",
            "UPDATE asset_importance_assignments SET importance = 'medium'",
            "UPDATE asset_importance_assignments SET importance = 'critical', assignment_state = 'withdrawn'",
            "UPDATE asset_importance_assignments SET importance = 'unknown'",
            "UPDATE asset_importance_assignments SET principal = 'someone-else'",
            "UPDATE asset_importance_assignments SET actor_verification = 'verified'",
            "UPDATE asset_importance_assignments SET source = 'ai'",
        ):
            with self.subTest(statement=statement):
                with self.assertRaises(IntegrityError):
                    with self.database_engine.begin() as connection:
                        connection.execute(text(statement))
        with self.assertRaises(IntegrityError):
            with self.database_engine.begin() as connection:
                connection.execute(
                    text(
                        """
                        INSERT INTO asset_importance_events (
                            site_id, asset_id, revision, event_type, previous_importance, importance,
                            reason, principal, actor_label, occurred_at
                        ) VALUES ('site-a', 'asset-a', 2, 'imported', 'high', 'critical',
                                  'r', 'api-admin-token', 'x', NOW())
                        """
                    )
                )

    def test_history_is_append_only_and_assignments_cascade_only(self) -> None:
        self._assign("high")
        for statement, message in (
            ("UPDATE asset_importance_events SET importance = 'critical'", "append-only"),
            ("DELETE FROM asset_importance_events", "append-only"),
            ("TRUNCATE asset_importance_events", "append-only"),
            ("DELETE FROM asset_importance_assignments", "removed only with their asset"),
        ):
            with self.subTest(statement=statement):
                with self.assertRaises(DBAPIError) as raised:
                    with self.database_engine.begin() as connection:
                        connection.execute(text(statement))
                self.assertIn(message, str(raised.exception.orig))
        with self.database_engine.begin() as connection:
            connection.execute(text("DELETE FROM control_tower_assets WHERE asset_id = 'asset-a'"))
        for table in ("asset_importance_assignments", "asset_importance_events"):
            self.assertEqual(self._rows(f"SELECT COUNT(*) AS n FROM {table}")[0]["n"], 0, table)

    def test_tampered_projection_is_detected_and_cannot_drive_act_now(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._assign("standard")
        # A direct write raises the stored value without any history event.
        with self.database_engine.begin() as connection:
            connection.execute(text("UPDATE asset_importance_assignments SET importance = 'critical'"))
        item = self.importance.get_importance("site-a", "asset-a", now=NOW)
        self.assertEqual(
            (item["importance"], item["integrity_state"], item["recorded_importance"]),
            ("unknown", "inconsistent", "critical"),
        )
        self.assertEqual(self.importance.list_importance(now=NOW)["items"][0]["integrity_state"], "inconsistent")
        self._evaluate(NOW + timedelta(minutes=1))
        decision = self.decisions.get_decision(finding_id)
        self.assertEqual(decision["action_band"], "prioritize")
        self.assertEqual(decision["asset_importance"], "unknown")
        with self.assertRaises(AssetImportanceError) as raised:
            self._assign("critical", expected_revision=1)
        self.assertIn("disagrees with its history", raised.exception.detail)

    def test_importance_changes_never_touch_findings_risk_decisions_or_work(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        work = SqlFindingWorkStore()
        work.create_work_item(
            finding_id, actor="alex", owner_kind=None, owner_label=None, note=None, at=NOW + timedelta(seconds=1)
        )
        before = self._authoritative_snapshot()
        self._assign("critical")
        self.importance.withdraw("site-a", "asset-a", reason="r", actor="a", expected_revision=1, at=NOW)
        self.importance.get_importance("site-a", "asset-a", now=NOW)
        self.importance.list_history("site-a", "asset-a")
        self.importance.list_importance(now=NOW)
        self.assertEqual(self._authoritative_snapshot(), before)

    def test_reevaluation_changes_no_finding_fact_or_score(self) -> None:
        # Evaluation rewrites evidence rows with new surrogate ids on every run,
        # with or without an importance change, so compare evidence content.
        columns = "finding_id, rule_id, severity, confidence, status, evidence_freshness"
        evidence = (
            "SELECT finding_id, evidence_type, evidence_ref, freshness FROM finding_evidence"
            " ORDER BY finding_id, evidence_type, evidence_ref"
        )

        def facts():
            return (
                self._rows(f"SELECT {columns} FROM findings"),
                self._rows(evidence),
                self._rows("SELECT site_id, asset_id, score, formula_version FROM asset_risk_scores"),
            )

        self._evaluate(NOW)
        before = facts()
        self._assign("critical")
        self._evaluate(NOW + timedelta(minutes=1))
        self.assertEqual(facts(), before)
        self.assertEqual(self.decisions.get_decision(self._finding_id())["action_band"], "act-now")

    def test_work_tracking_changes_never_change_importance_or_its_decision(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._assign("critical")
        self._evaluate(NOW + timedelta(minutes=1))
        before = (self._rows("SELECT * FROM finding_decisions"), self._rows("SELECT * FROM asset_importance_events"))
        work = SqlFindingWorkStore()
        item = work.create_work_item(
            finding_id, actor="alex", owner_kind="team", owner_label="Ops", note=None, at=NOW + timedelta(minutes=2)
        )
        work.change_status(
            finding_id, actor="alex", status="done", expected_revision=item["revision"], note="patched",
            at=NOW + timedelta(minutes=3),
        )
        self._evaluate(NOW + timedelta(minutes=4))
        after = (self._rows("SELECT * FROM finding_decisions"), self._rows("SELECT * FROM asset_importance_events"))
        self.assertEqual(after, before)
        self.assertEqual(self.decisions.get_decision(finding_id)["action_band"], "act-now")

    def test_route_records_change_and_runs_asset_scoped_reevaluation(self) -> None:
        from app.asset_importance_contracts import AssetImportanceAssignRequest, AssetImportanceWithdrawRequest
        from app.main import admin_assign_asset_importance, admin_withdraw_asset_importance

        with patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": "t"}):
            assigned = admin_assign_asset_importance(
                AssetImportanceAssignRequest(actor="alex", importance="critical", reason="payments"),
                "site-a", "asset-a", admin_token="t",
            )
            withdrawn = admin_withdraw_asset_importance(
                AssetImportanceWithdrawRequest(actor="alex", reason="re-review", expected_revision=1),
                "site-a", "asset-a", admin_token="t",
            )
        self.assertEqual(assigned["decision_reevaluation"], "completed")
        self.assertEqual(withdrawn["importance"]["importance"], "unknown")
        runs = self._rows(
            "SELECT trigger_type, scope_site_id, scope_asset_id, status FROM finding_evaluation_runs"
            " ORDER BY started_at"
        )
        self.assertEqual(
            runs,
            [{"trigger_type": "asset-importance-change", "scope_site_id": "site-a",
              "scope_asset_id": "asset-a", "status": "completed"}] * 2,
        )

    def test_lowering_removes_only_the_escalation_that_depended_on_critical(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        baseline = self.decisions.get_decision(finding_id)
        self.assertEqual(baseline["action_band"], "prioritize")
        self._assign("critical")
        self._evaluate(NOW + timedelta(minutes=1))
        self.assertEqual(self.decisions.get_decision(finding_id)["action_band"], "act-now")

        bands = []
        for revision, value in enumerate(("high", "standard", "low"), start=1):
            self._assign(value, expected_revision=revision, at=NOW + timedelta(minutes=1 + revision))
            # Until evaluation runs, the stored Act Now is detectably stale.
            self.assertEqual(self.decisions.get_decision(finding_id)["projection_state"], "stale")
            self._evaluate(NOW + timedelta(minutes=10 + revision))
            decision = self.decisions.get_decision(finding_id)
            self.assertEqual(decision["projection_state"], "current")
            self.assertIn(f"ASSET_IMPORTANCE_{value.upper()}", decision["reason_codes"])
            bands.append((decision["action_band"], decision["decision_rule_id"]))
        # The independent known-exploited escalation remains: never below the baseline.
        self.assertEqual(bands, [("prioritize", "vulnerability-known-exploited")] * 3)
        self.importance.withdraw(
            "site-a", "asset-a", reason="re-review", actor="alex", expected_revision=4,
            at=NOW + timedelta(minutes=20),
        )
        self._evaluate(NOW + timedelta(minutes=21))
        withdrawn = self.decisions.get_decision(finding_id)
        self.assertEqual(
            (withdrawn["action_band"], withdrawn["asset_importance"]), ("prioritize", "unknown")
        )
        history = self.decisions.list_history(finding_id)["items"]
        self.assertEqual(
            [(item["revision"], item["previous_action_band"], item["action_band"]) for item in history],
            # initial, critical, high, standard, low, withdrawn: each importance
            # change alters the reason codes, so each is a recorded transition.
            [(1, None, "prioritize"), (2, "prioritize", "act-now"), (3, "act-now", "prioritize"),
             (4, "prioritize", "prioritize"), (5, "prioritize", "prioritize"), (6, "prioritize", "prioritize")],
        )
        self.assertIn("ASSET_IMPORTANCE_UNKNOWN", history[-1]["reason_codes"])
        # Earlier Act Now history is preserved, not rewritten.
        self.assertIn("ASSET_IMPORTANCE_CRITICAL", history[1]["reason_codes"])

    def test_critical_importance_without_exploitation_keeps_the_severity_escalation(self) -> None:
        self._evaluate(NOW, kev=False, severity="critical")
        finding_id = self._finding_id()
        self._assign("critical")
        self._evaluate(NOW + timedelta(minutes=1), kev=False, severity="critical")
        critical = self.decisions.get_decision(finding_id)
        self.assertEqual((critical["action_band"], critical["decision_rule_id"]), ("prioritize", "vulnerability-critical"))
        self._assign("low", expected_revision=1, at=NOW + timedelta(minutes=2))
        self._evaluate(NOW + timedelta(minutes=3), kev=False, severity="critical")
        low = self.decisions.get_decision(finding_id)
        self.assertEqual((low["action_band"], low["decision_rule_id"]), ("prioritize", "vulnerability-critical"))

    def test_failure_inside_a_mutation_rolls_back_record_and_history(self) -> None:
        self._assign("high")
        before = (
            self._rows("SELECT * FROM asset_importance_assignments"),
            self._rows("SELECT * FROM asset_importance_events ORDER BY event_id"),
        )
        with patch.object(SqlAssetImportanceStore, "_append_event", side_effect=RuntimeError("event write failed")):
            with self.assertRaises(RuntimeError):
                self._assign("critical", expected_revision=1, at=NOW + timedelta(minutes=1))
            with self.assertRaises(RuntimeError):
                self.importance.withdraw(
                    "site-a", "asset-a", reason="r", actor="a", expected_revision=1, at=NOW + timedelta(minutes=1)
                )
            with self.assertRaises(RuntimeError):
                self._assign("low", site_id="site-b", asset_id="asset-b")
        after = (
            self._rows("SELECT * FROM asset_importance_assignments"),
            self._rows("SELECT * FROM asset_importance_events ORDER BY event_id"),
        )
        self.assertEqual(after, before)
        self.assertEqual(self.importance.list_history("site-b", "asset-b")["items"], [])

    def test_retried_requests_never_create_duplicate_transitions(self) -> None:
        self._assign("critical")
        with self.assertRaises(AssetImportanceError):
            self._assign("critical")  # retried first assignment
        self._assign("low", expected_revision=1, at=NOW + timedelta(minutes=1))
        with self.assertRaises(AssetImportanceError):
            self._assign("low", expected_revision=1, at=NOW + timedelta(minutes=2))  # retried change
        self.importance.withdraw("site-a", "asset-a", reason="r", actor="a", expected_revision=2,
                                 at=NOW + timedelta(minutes=3))
        for expected in (2, 3):
            with self.assertRaises(AssetImportanceError):
                self.importance.withdraw("site-a", "asset-a", reason="r", actor="a", expected_revision=expected,
                                         at=NOW + timedelta(minutes=4))
        self.assertEqual([event["event_type"] for event in self._events()], ["assigned", "changed", "withdrawn"])

    def test_asset_ids_containing_slashes_are_supported(self) -> None:
        with self.database_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO control_tower_assets (asset_key, asset_id, site_id, first_seen_at, last_seen_at)"
                    " VALUES ('site-a:rack/1', 'rack/1', 'site-a', :at, :at)"
                ),
                {"at": NOW},
            )
        current, _ = self._assign("high", asset_id="rack/1")
        self.assertEqual((current["asset_id"], current["importance"]), ("rack/1", "high"))
        self.assertEqual(self.importance.get_importance("site-a", "rack/1", now=NOW)["importance"], "high")
        self.assertEqual(len(self.importance.list_history("site-a", "rack/1")["items"]), 1)
        self.assertIsNone(self.importance.get_importance("site-a", "rack", now=NOW))

    def test_any_altered_authoritative_field_or_injected_event_fails_safe(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._assign("critical")
        self._evaluate(NOW + timedelta(minutes=1))
        self.assertEqual(self.decisions.get_decision(finding_id)["action_band"], "act-now")
        tampering = (
            "UPDATE asset_importance_assignments SET reason = 'edited without history'",
            "UPDATE asset_importance_assignments SET actor_label = 'someone-else'",
            "UPDATE asset_importance_assignments SET updated_at = updated_at + interval '1 second',"
            " reviewed_at = reviewed_at + interval '1 second'",
        )
        for index, statement in enumerate(tampering, start=1):
            with self.subTest(statement=statement):
                with self.database_engine.begin() as connection:
                    original = dict(
                        connection.execute(text("SELECT * FROM asset_importance_assignments")).mappings().one()
                    )
                    connection.execute(text(statement))
                item = self.importance.get_importance("site-a", "asset-a", now=NOW)
                self.assertEqual((item["importance"], item["integrity_state"]), ("unknown", "inconsistent"))
                # A tampered record is never served as current.
                self.assertEqual(self.decisions.get_decision(finding_id)["projection_state"], "stale")
                self._evaluate(NOW + timedelta(minutes=10 * index))
                self.assertEqual(self.decisions.get_decision(finding_id)["action_band"], "prioritize")
                with self.database_engine.begin() as connection:
                    connection.execute(
                        text(
                            "UPDATE asset_importance_assignments SET reason = :reason, actor_label = :actor,"
                            " updated_at = :updated, reviewed_at = :reviewed"
                        ),
                        {
                            "reason": original["reason"], "actor": original["actor_label"],
                            "updated": original["updated_at"], "reviewed": original["reviewed_at"],
                        },
                    )
                self._evaluate(NOW + timedelta(minutes=10 * index + 5))
                self.assertEqual(self.decisions.get_decision(finding_id)["action_band"], "act-now")
        # An event inserted directly, ahead of the record, also fails safe.
        with self.database_engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO asset_importance_events (
                        site_id, asset_id, revision, event_type, previous_importance, importance,
                        reason, principal, actor_label, occurred_at
                    ) VALUES ('site-a', 'asset-a', 2, 'reviewed', 'critical', 'critical',
                              'injected', 'api-admin-token', 'x', NOW())
                    """
                )
            )
        self.assertEqual(self.importance.get_importance("site-a", "asset-a", now=NOW)["integrity_state"], "inconsistent")
        self._evaluate(NOW + timedelta(minutes=60))
        self.assertEqual(self.decisions.get_decision(finding_id)["asset_importance"], "unknown")

    def test_list_filters_and_bounds(self) -> None:
        self._assign("critical")
        self._assign("low", site_id="site-b", asset_id="asset-b")
        everything = self.importance.list_importance(now=NOW)
        self.assertEqual([item["importance"] for item in everything["items"]], ["critical", "low"])
        self.assertEqual(self.importance.list_importance(site_id="site-b", now=NOW)["total"], 1)
        self.assertEqual(self.importance.list_importance(importance="critical", now=NOW)["total"], 1)
        with self.assertRaises(ValueError):
            self.importance.list_importance(importance="medium", now=NOW)


if __name__ == "__main__":
    unittest.main()
