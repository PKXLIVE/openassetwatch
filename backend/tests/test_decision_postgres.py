from __future__ import annotations

import os
import re
import threading
import unittest
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.pool import NullPool

from app.decision_store import SqlDecisionStore
from app.finding_service import evaluate_findings
from app.finding_store import SqlFindingStore
from app.finding_work_store import SqlFindingWorkStore
from app.schema_migrations import migrate_database_schema


ENABLED = os.getenv("OPENASSETWATCH_DECISION_POSTGRES_TEST") == "1"
DATABASE_NAME = re.compile(r"^openassetwatch_decision_test_[0-9a-f]{16}$")
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
MATCH_ID = "vmt_" + "a" * 32


def kev_record(*, ransomware: bool = False) -> dict[str, Any]:
    return {
        "kev_record_id": "kevr_" + "b" * 32,
        "cve_id": "CVE-2099-0001",
        "ransomware_campaign_status": "Known" if ransomware else "Unknown",
        "cisa_due_date": "2099-01-01",
        "required_action": "Apply vendor update.",
        "source_freshness": "fresh",
    }


def vulnerable_asset(
    at: datetime,
    *,
    status: str = "affected",
    kev: bool = True,
    severity: str = "high",
    asset_id: str = "asset-a",
    match_id: str = MATCH_ID,
) -> dict:
    return {
        "asset_id": asset_id,
        "site_id": "site-a",
        "source_agent_id": "agent-a",
        "mac": None,
        "observed_at": at,
        "last_seen_at": at,
        "first_seen_at": at - timedelta(hours=1),
        "confidence": 0.95,
        "metadata": {"category": "server"},
        "vulnerability_matches": [
            {
                "match_id": match_id,
                "component_id": "cmp_" + "c" * 32,
                "advisory_id": "adv_" + "d" * 32,
                "match_status": status,
                "match_confidence": 1.0,
                "component_name": "example-agent",
                "installed_version": "1.2.0",
                "fixed_version": "1.4.2",
                "severity": severity,
                "known_exploited": False,
                "component_freshness": "fresh",
                "component_last_seen_at": at,
                "evaluated_at": at,
                "kev": {"records": [kev_record()] if kev else []},
            }
        ],
    }


@unittest.skipUnless(ENABLED, "requires an explicitly isolated disposable PostgreSQL server")
class DecisionPostgresTests(unittest.TestCase):
    admin_engine: Engine
    database_engine: Engine
    database_name: str

    def setUp(self) -> None:
        parsed = make_url(os.environ["DATABASE_URL"])
        self.database_name = f"openassetwatch_decision_test_{uuid4().hex[:16]}"
        self.assertRegex(self.database_name, DATABASE_NAME)
        self.admin_engine = create_engine(
            parsed.set(database="postgres"), isolation_level="AUTOCOMMIT", poolclass=NullPool
        )
        with self.admin_engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{self.database_name}"')
        self.database_engine = create_engine(parsed.set(database=self.database_name), poolclass=NullPool)
        self.assertEqual(migrate_database_schema(self.database_engine).current_version, 7)
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
        self.findings = SqlFindingStore()
        self.decisions = SqlDecisionStore()
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

    def _history(self, finding_id: str) -> list[dict[str, Any]]:
        history = self.decisions.list_history(finding_id, limit=200)
        assert history is not None
        return history["items"]

    def _authoritative_snapshot(self) -> dict[str, list[dict[str, Any]]]:
        return {
            table: self._rows(f"SELECT * FROM {table} ORDER BY 1")
            for table in (
                "findings",
                "finding_evidence",
                "asset_risk_scores",
                "risk_factors",
                "finding_work_items",
                "finding_work_events",
            )
        }

    # -------------------------------------------------------------------- tests

    def test_initial_decision_is_persisted_explained_and_reproducible(self) -> None:
        result = self._evaluate(NOW)
        finding_id = self._finding_id()
        decision = self.decisions.get_decision(finding_id)
        assert decision is not None

        self.assertEqual(result.decision_transition_count, 1)
        self.assertEqual(decision["action_band"], "prioritize")
        self.assertEqual(decision["decision_rule_id"], "vulnerability-known-exploited")
        self.assertEqual(decision["exploitation_status"], "known-exploited")
        self.assertEqual(decision["exposure_state"], "unknown")
        self.assertIn("EXPLOITATION_KNOWN", decision["reason_codes"])
        self.assertTrue(all(reason["explanation"] for reason in decision["reasons"]))
        self.assertEqual(decision["projection_state"], "current")
        self.assertEqual(decision["evaluation_run_id"], result.run_id)
        self.assertIsNotNone(decision["attention"]["asset_score"])
        self.assertGreater(decision["attention"]["finding_contribution"], 0)
        history = self._history(finding_id)
        self.assertEqual([(item["revision"], item["transition_cause"]) for item in history], [(1, "initial")])
        self.assertIsNone(history[0]["previous_action_band"])

    def test_unchanged_inputs_write_nothing(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        before = self._rows("SELECT * FROM finding_decisions")
        result = self._evaluate(NOW + timedelta(minutes=1))

        self.assertEqual(result.decision_transition_count, 0)
        self.assertEqual(self._rows("SELECT * FROM finding_decisions"), before)
        self.assertEqual(len(self._history(finding_id)), 1)

    def test_input_change_recomputes_and_records_what_changed(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._evaluate(NOW + timedelta(minutes=1), kev=False)
        decision = self.decisions.get_decision(finding_id)
        assert decision is not None
        history = self._history(finding_id)

        self.assertEqual(decision["action_band"], "plan")
        self.assertEqual(decision["revision"], 2)
        self.assertEqual(history[-1]["transition_cause"], "inputs-changed")
        self.assertEqual((history[-1]["previous_action_band"], history[-1]["action_band"]), ("prioritize", "plan"))
        self.assertIn("EXPLOITATION_KNOWN", history[-1]["previous_reason_codes"])
        self.assertNotIn("EXPLOITATION_KNOWN", history[-1]["reason_codes"])

    def test_resolution_and_reopen_are_recorded_transitions(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._evaluate(NOW + timedelta(minutes=1), status="fixed")
        resolved = self.decisions.get_decision(finding_id)
        assert resolved is not None
        self.assertEqual((resolved["decision_state"], resolved["action_band"]), ("not-current", None))
        self._evaluate(NOW + timedelta(minutes=2))
        causes = [item["transition_cause"] for item in self._history(finding_id)]

        self.assertEqual(causes, ["initial", "finding-resolved", "finding-reopened"])
        self.assertEqual(self.decisions.get_decision(finding_id)["action_band"], "prioritize")

    def test_work_tracking_changes_never_change_a_decision(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        work = SqlFindingWorkStore()
        item = work.create_work_item(
            finding_id, actor="alex", owner_kind="team", owner_label="Ops", note=None,
            at=NOW + timedelta(seconds=1),
        )
        work.change_status(
            finding_id, actor="alex", status="done", expected_revision=item["revision"],
            note="patched", at=NOW + timedelta(seconds=2),
        )
        before = self._rows("SELECT * FROM finding_decisions")
        self._evaluate(NOW + timedelta(minutes=1))

        self.assertEqual(self._rows("SELECT * FROM finding_decisions"), before)
        self.assertEqual(len(self._history(finding_id)), 1)
        self.assertEqual(self.decisions.get_decision(finding_id)["action_band"], "prioritize")

    def test_reads_never_mutate_authoritative_or_work_state(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        SqlFindingWorkStore().create_work_item(
            finding_id, actor="alex", owner_kind=None, owner_label=None, note=None, at=NOW,
        )
        before = self._authoritative_snapshot()
        decisions_before = self._rows("SELECT * FROM finding_decisions")
        self.decisions.get_decision(finding_id)
        self.decisions.list_decisions(site_id="site-a")
        self.decisions.list_history(finding_id)

        self.assertEqual(self._authoritative_snapshot(), before)
        self.assertEqual(self._rows("SELECT * FROM finding_decisions"), decisions_before)

    def test_decision_evaluation_does_not_alter_findings_evidence_or_risk(self) -> None:
        self._evaluate(NOW)
        before = self._authoritative_snapshot()
        self.decisions.reconcile_decisions(
            run_id=self._rows("SELECT run_id FROM finding_evaluation_runs")[0]["run_id"],
            evaluated_at=NOW + timedelta(minutes=5),
            site_id="site-a",
        )
        self.assertEqual(self._authoritative_snapshot(), before)

    def test_older_evaluation_cannot_overwrite_a_newer_decision(self) -> None:
        self._evaluate(NOW + timedelta(minutes=10))
        finding_id = self._finding_id()
        run_id = self._rows("SELECT run_id FROM finding_evaluation_runs")[0]["run_id"]
        with self.database_engine.begin() as connection:
            connection.execute(
                text("UPDATE finding_evidence SET freshness = 'stale' WHERE finding_id = :f"),
                {"f": finding_id},
            )
        result = self.decisions.reconcile_decisions(run_id=run_id, evaluated_at=NOW, site_id="site-a")

        self.assertEqual(result.changed, 0)
        self.assertEqual(len(self._history(finding_id)), 1)

    def test_concurrent_reconciles_record_one_transition(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        run_id = self._rows("SELECT run_id FROM finding_evaluation_runs")[0]["run_id"]
        with self.database_engine.begin() as connection:
            connection.execute(
                text("DELETE FROM finding_evidence WHERE finding_id = :f AND evidence_type LIKE 'kev-%'"),
                {"f": finding_id},
            )
        barrier = threading.Barrier(4)
        errors: list[BaseException] = []

        def worker() -> None:
            barrier.wait()
            try:
                SqlDecisionStore().reconcile_decisions(
                    run_id=run_id, evaluated_at=NOW + timedelta(minutes=1), site_id="site-a"
                )
            except BaseException as exc:  # noqa: BLE001 - surfaced below
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(errors, [])
        self.assertEqual([item["revision"] for item in self._history(finding_id)], [1, 2])

    def test_stale_and_tampered_projections_are_detected(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        with self.database_engine.begin() as connection:
            connection.execute(
                text("UPDATE finding_decisions SET action_band = 'monitor', urgency = 'monitor' WHERE finding_id = :f"),
                {"f": finding_id},
            )
        self.assertEqual(self.decisions.get_decision(finding_id)["projection_state"], "inconsistent")
        with self.database_engine.begin() as connection:
            connection.execute(
                text("UPDATE findings SET severity = 'critical' WHERE finding_id = :f"), {"f": finding_id}
            )
        self.assertEqual(self.decisions.get_decision(finding_id)["projection_state"], "stale")

    def test_ruleset_version_change_is_a_recorded_transition(self) -> None:
        # Decisions recorded under v1 keep their v1 identity in history; the
        # first evaluation under the active v2 ruleset is a recorded transition.
        with patch("app.decisions.DECISION_RULESET_VERSION", "oaw.decision.rules.v1"):
            self._evaluate(NOW)
            finding_id = self._finding_id()
            self.assertEqual(self.decisions.get_decision(finding_id)["projection_state"], "current")
        self.assertEqual(self.decisions.get_decision(finding_id)["projection_state"], "stale")
        self._evaluate(NOW + timedelta(minutes=1))
        history = self._history(finding_id)
        self.assertEqual(
            [(item["transition_cause"], item["ruleset_version"]) for item in history],
            [("initial", "oaw.decision.rules.v1"), ("ruleset-changed", "oaw.decision.rules.v2")],
        )
        self.assertEqual(self.decisions.get_decision(finding_id)["projection_state"], "current")

    def test_suppression_is_an_overlay_transition(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self.findings.suppress(finding_id, actor="alex", reason="maintenance window", until=None, at=NOW)
        self._evaluate(NOW + timedelta(minutes=1))
        decision = self.decisions.get_decision(finding_id)

        self.assertEqual(decision["action_band"], "prioritize")
        self.assertTrue(decision["prioritization_excluded"])
        self.assertIn("SUPPRESSION_ACTIVE", decision["reason_codes"])
        self.assertEqual(self._history(finding_id)[-1]["transition_cause"], "inputs-changed")

    def test_history_is_append_only_except_for_finding_cascade(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        for statement in (
            "UPDATE finding_decision_history SET action_band = 'monitor'",
            "DELETE FROM finding_decision_history",
            "TRUNCATE finding_decision_history",
        ):
            with self.subTest(statement=statement):
                with self.assertRaises(DBAPIError) as raised:
                    with self.database_engine.begin() as connection:
                        connection.execute(text(statement))
                self.assertIn("append-only", str(raised.exception.orig))
        with self.database_engine.begin() as connection:
            connection.execute(text("DELETE FROM sites WHERE site_id = 'site-a'"))
        for table in ("findings", "finding_decisions", "finding_decision_history"):
            self.assertEqual(self._rows(f"SELECT COUNT(*) AS n FROM {table}")[0]["n"], 0, table)
        self.assertIsNone(self.decisions.get_decision(finding_id))

    def test_database_rejects_invalid_or_cross_site_decisions(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        for statement in (
            "UPDATE finding_decisions SET action_band = 'urgent'",
            "UPDATE finding_decisions SET decision_state = 'not-current'",
            "UPDATE finding_decisions SET urgency = NULL",
            "UPDATE finding_decisions SET schema_version = 'oaw.decision.v9'",
            "UPDATE finding_decisions SET reason_codes = '[]'::jsonb",
            "UPDATE finding_decisions SET site_id = 'site-b'",
            "UPDATE finding_decisions SET input_digest = 'not-a-digest'",
        ):
            with self.subTest(statement=statement):
                with self.assertRaises(IntegrityError):
                    with self.database_engine.begin() as connection:
                        connection.execute(text(statement))
        self.assertEqual(self.decisions.get_decision(finding_id)["projection_state"], "current")

    def _evaluate_assets(self, at: datetime, count: int, *, kev: bool = True):
        assets = [
            vulnerable_asset(at, kev=kev, asset_id=f"asset-{index}", match_id="vmt_" + f"{index:x}" * 32)
            for index in range(1, count + 1)
        ]
        return evaluate_findings(
            trigger_type="test",
            requested_by="unit-test",
            now=at,
            store=self.findings,
            decision_store=self.decisions,
            sites=self.sites,
            sensors=self.sensors,
            assets=assets,
            site_id="site-a",
            rule_ids=["vulnerable-component"],
        )

    def _count_statements(self, operation) -> int:
        from sqlalchemy import event

        statements: list[str] = []

        def record(_conn, _cursor, statement, *_args) -> None:
            statements.append(statement)

        event.listen(self.database_engine, "before_cursor_execute", record)
        try:
            operation()
        finally:
            event.remove(self.database_engine, "before_cursor_execute", record)
        return len(statements)

    def test_list_read_uses_a_constant_number_of_queries(self) -> None:
        self._evaluate_assets(NOW, 1)
        one = self._count_statements(lambda: self.decisions.list_decisions(site_id="site-a"))
        self._evaluate_assets(NOW + timedelta(minutes=1), 4)
        listed: dict[str, Any] = {}
        four = self._count_statements(
            lambda: listed.update(self.decisions.list_decisions(site_id="site-a"))
        )

        self.assertEqual(listed["total"], 4)
        self.assertEqual(one, four)
        direct = {
            row["asset_id"]: row["score"]
            for row in self._rows("SELECT asset_id, score FROM asset_risk_scores WHERE site_id = 'site-a'")
        }
        for item in listed["items"]:
            self.assertEqual(item["attention"]["asset_score"], direct[item["asset_id"]])
            self.assertEqual(item["projection_state"], "current")

    def test_record_cap_fails_the_run_without_partial_decisions(self) -> None:
        self._evaluate_assets(NOW, 2)
        before_decisions = self._rows("SELECT * FROM finding_decisions ORDER BY finding_id")
        before_history = self._rows("SELECT * FROM finding_decision_history ORDER BY history_id")
        self.assertEqual(len(before_decisions), 2)

        with patch("app.decision_store.MAX_DECISION_RECORDS", 1):
            with self.assertRaises(ValueError) as raised:
                self._evaluate_assets(NOW + timedelta(minutes=1), 2, kev=False)
        self.assertIn("record limit exceeded", str(raised.exception))

        runs = self._rows("SELECT status, error_code FROM finding_evaluation_runs ORDER BY started_at")
        self.assertEqual(runs[-1], {"status": "failed", "error_code": "ValueError"})
        self.assertEqual(self._rows("SELECT * FROM finding_decisions ORDER BY finding_id"), before_decisions)
        self.assertEqual(self._rows("SELECT * FROM finding_decision_history ORDER BY history_id"), before_history)
        # The findings themselves changed, so reads report the decisions as
        # stale instead of serving an outdated band as current.
        states = {item["projection_state"] for item in self.decisions.list_decisions(site_id="site-a")["items"]}
        self.assertEqual(states, {"stale"})


if __name__ == "__main__":
    unittest.main()
