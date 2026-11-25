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

from app.finding_service import evaluate_findings
from app.finding_store import SqlFindingStore
from app.finding_work_store import FindingWorkError, SqlFindingWorkStore
from app.schema_migrations import migrate_database_schema


ENABLED = os.getenv("OPENASSETWATCH_FINDING_WORK_POSTGRES_TEST") == "1"
DATABASE_NAME = re.compile(r"^openassetwatch_finding_work_test_[0-9a-f]{16}$")
NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)


def asset(category: str, observed_at: datetime, *, asset_id: str = "asset-a") -> dict:
    return {
        "asset_id": asset_id,
        "site_id": "site-a",
        "source_agent_id": "agent-a",
        "mac": None,
        "observed_at": observed_at,
        "last_seen_at": observed_at,
        "first_seen_at": observed_at - timedelta(hours=1),
        "confidence": 0.9,
        "metadata": {"category": category},
    }


@unittest.skipUnless(
    ENABLED,
    "requires an explicitly isolated disposable PostgreSQL server",
)
class FindingWorkPostgresTests(unittest.TestCase):
    admin_engine: Engine
    database_engine: Engine
    database_name: str

    def setUp(self) -> None:
        parsed = make_url(os.environ["DATABASE_URL"])
        self.database_name = f"openassetwatch_finding_work_test_{uuid4().hex[:16]}"
        self.assertRegex(self.database_name, DATABASE_NAME)
        self.admin_engine = create_engine(
            parsed.set(database="postgres"),
            isolation_level="AUTOCOMMIT",
            poolclass=NullPool,
        )
        with self.admin_engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{self.database_name}"')
        self.database_engine = create_engine(
            parsed.set(database=self.database_name),
            poolclass=NullPool,
        )
        migration = migrate_database_schema(self.database_engine)
        self.assertEqual(migration.current_version, 7)
        self.patchers = [
            patch("app.database.get_engine", return_value=self.database_engine),
            patch("app.database.ensure_database_schema"),
        ]
        for patcher in self.patchers:
            patcher.start()
        with self.database_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO sites (site_id, name) VALUES "
                    "('site-a', 'Site A'), ('site-b', 'Site B')"
                )
            )
        self.findings = SqlFindingStore()
        self.work = SqlFindingWorkStore()
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
                    """
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE datname = :database_name
                      AND pid <> pg_backend_pid()
                    """
                ),
                {"database_name": self.database_name},
            )
            connection.exec_driver_sql(f'DROP DATABASE "{self.database_name}"')
        self.admin_engine.dispose()

    # ----------------------------------------------------------------- helpers

    def _evaluate(self, category: str, at: datetime):
        return evaluate_findings(
            trigger_type="test",
            requested_by="unit-test",
            now=at,
            store=self.findings,
            sites=self.sites,
            sensors=self.sensors,
            assets=[asset(category, at)],
            rule_ids=["unknown-asset"],
        )

    def _open_finding(self) -> str:
        result = self._evaluate("unknown", NOW)
        self.assertEqual(result.opened_count, 1)
        items = self.findings.list_findings(site_id="site-a")["items"]
        self.assertEqual(len(items), 1)
        return items[0]["finding_id"]

    def _open_finding_again(self) -> str:
        result = self._evaluate("unknown", NOW + timedelta(minutes=1))
        self.assertEqual(result.opened_count, 1)
        return self.findings.list_findings(site_id="site-a")["items"][0]["finding_id"]

    def _rows(self, sql: str, **params: Any) -> list[dict[str, Any]]:
        with self.database_engine.connect() as connection:
            return [dict(row) for row in connection.execute(text(sql), params).mappings()]

    def _deterministic_state(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "findings": self._rows("SELECT * FROM findings ORDER BY finding_id"),
            "finding_evidence": self._rows(
                "SELECT * FROM finding_evidence ORDER BY evidence_id"
            ),
            "asset_risk_scores": self._rows(
                "SELECT * FROM asset_risk_scores ORDER BY site_id, asset_id"
            ),
            "site_risk_scores": self._rows("SELECT * FROM site_risk_scores ORDER BY site_id"),
            "risk_factors": self._rows("SELECT * FROM risk_factors ORDER BY risk_factor_id"),
            "finding_evaluation_runs": self._rows(
                "SELECT * FROM finding_evaluation_runs ORDER BY run_id"
            ),
        }

    def _events(self, finding_id: str) -> list[dict[str, Any]]:
        events = self.work.list_events(finding_id, limit=200)
        assert events is not None
        return events["items"]

    def _exercise_all_mutations(self, finding_id: str) -> dict[str, Any]:
        item = self.work.create_work_item(
            finding_id,
            actor="alex (self-reported)",
            owner_kind="team",
            owner_label="Network Ops",
            note="initial triage",
            at=NOW + timedelta(seconds=1),
        )
        item = self.work.add_reference(
            finding_id,
            actor="alex",
            reference_type="ticket",
            reference_system="jira",
            reference_label="OPS-1234",
            expected_revision=item["revision"],
            at=NOW + timedelta(seconds=2),
        )
        item = self.work.change_status(
            finding_id,
            actor="sam",
            status="in_progress",
            expected_revision=item["revision"],
            note=None,
            at=NOW + timedelta(seconds=3),
        )
        item = self.work.change_owner(
            finding_id,
            actor="sam",
            owner_kind="person",
            owner_label="Sam R.",
            expected_revision=item["revision"],
            at=NOW + timedelta(seconds=4),
        )
        item = self.work.add_note(
            finding_id,
            actor="sam",
            note="patch scheduled\nfor Friday",
            expected_revision=item["revision"],
            at=NOW + timedelta(seconds=5),
        )
        item = self.work.change_status(
            finding_id,
            actor="sam",
            status="done",
            expected_revision=item["revision"],
            note="work reported complete",
            at=NOW + timedelta(seconds=6),
        )
        return item

    # ------------------------------------------------------------------ tests

    def test_full_lifecycle_is_revisioned_and_audited(self) -> None:
        finding_id = self._open_finding()
        item = self._exercise_all_mutations(finding_id)

        self.assertEqual(item["work_status"], "done")
        self.assertEqual(item["revision"], 6)
        self.assertEqual(item["site_id"], "site-a")
        self.assertEqual(
            item["owner"],
            {"kind": "person", "label": "Sam R.", "verification": "unverified"},
        )
        self.assertEqual(item["created_principal"], "api-admin-token")
        self.assertEqual(item["created_actor_label"], "alex (self-reported)")
        self.assertEqual(item["actor_verification"], "unverified")
        self.assertEqual(item["finding_status"], "active")
        self.assertEqual([ref["reference_label"] for ref in item["references"]], ["OPS-1234"])
        reference_id = item["references"][0]["reference_id"]

        item = self.work.remove_reference(
            finding_id,
            reference_id,
            actor="sam",
            expected_revision=6,
            at=NOW + timedelta(seconds=7),
        )
        item = self.work.change_status(
            finding_id,
            actor="alex",
            status="open",
            expected_revision=item["revision"],
            note="reopened work",
            at=NOW + timedelta(seconds=8),
        )
        self.assertEqual(item["references"], [])
        self.assertEqual(item["revision"], 8)

        events = self._events(finding_id)
        self.assertEqual([event["revision"] for event in events], list(range(1, 9)))
        self.assertEqual(
            [event["event_type"] for event in events],
            [
                "created",
                "reference_added",
                "status_changed",
                "owner_changed",
                "note_added",
                "status_changed",
                "reference_removed",
                "status_changed",
            ],
        )
        self.assertTrue(all(event["principal"] == "api-admin-token" for event in events))
        self.assertTrue(all(event["actor_verification"] == "unverified" for event in events))
        self.assertTrue(all(event["site_id"] == "site-a" for event in events))
        self.assertEqual(events[0]["actor_label"], "alex (self-reported)")
        self.assertEqual(events[0]["note"], "initial triage")
        self.assertEqual((events[2]["from_status"], events[2]["to_status"]), ("open", "in_progress"))
        self.assertEqual(events[1]["reference_id"], reference_id)
        self.assertEqual(events[6]["reference_id"], reference_id)
        listed = self.work.list_work_items(site_id="site-a", work_status="open")
        self.assertEqual([entry["finding_id"] for entry in listed["items"]], [finding_id])
        self.assertEqual(self.work.list_work_items(site_id="site-b")["total"], 0)

    def test_work_tracking_never_changes_finding_status_evidence_or_risk(self) -> None:
        finding_id = self._open_finding()
        before = self._deterministic_state()
        self.assertEqual(len(before["asset_risk_scores"]), 1)

        item = self._exercise_all_mutations(finding_id)
        self.work.remove_reference(
            finding_id,
            item["references"][0]["reference_id"],
            actor="sam",
            expected_revision=item["revision"],
            at=NOW + timedelta(seconds=7),
        )

        self.assertEqual(self._deterministic_state(), before)

        # A later evaluation over identical evidence produces the same score
        # whether or not work is recorded as done.
        self._evaluate("unknown", NOW + timedelta(minutes=1))
        after = self._deterministic_state()
        for table in ("asset_risk_scores", "site_risk_scores"):
            for previous, current in zip(before[table], after[table], strict=True):
                self.assertEqual(previous["score"], current["score"])
                self.assertEqual(previous["band"], current["band"])
                self.assertEqual(previous["finding_count"], current["finding_count"])
        self.assertEqual(after["findings"][0]["status"], "active")

    def test_work_tracking_is_preserved_when_finding_resolves_and_reopens(self) -> None:
        finding_id = self._open_finding()
        item = self._exercise_all_mutations(finding_id)
        events_before = self._events(finding_id)

        resolved = self._evaluate("server", NOW + timedelta(minutes=2))
        self.assertEqual(resolved.resolved_count, 1)
        during = self.work.get_work_item(finding_id)
        assert during is not None
        self.assertEqual(during["finding_status"], "resolved")

        with self.assertRaises(FindingWorkError) as raised:
            SqlFindingWorkStore().create_work_item(
                finding_id,
                actor="alex",
                owner_kind=None,
                owner_label=None,
                note=None,
                at=NOW + timedelta(minutes=2, seconds=30),
            )
        self.assertEqual(raised.exception.kind, "conflict")

        reopened = self._evaluate("unknown", NOW + timedelta(minutes=3))
        self.assertEqual(reopened.reopened_count, 1)

        after = self.work.get_work_item(finding_id)
        assert after is not None
        self.assertEqual(after["finding_status"], "active")
        for key in ("work_item_id", "work_status", "owner", "revision", "references", "site_id"):
            self.assertEqual(after[key], item[key], key)
        self.assertEqual(self._events(finding_id), events_before)
        finding = self.findings.get_finding(finding_id)
        assert finding is not None
        self.assertEqual(finding["reopen_count"], 1)

        # Work stays mutable across the reopen, and the event records the
        # finding status observed at that time without changing it.
        updated = self.work.change_status(
            finding_id,
            actor="sam",
            status="open",
            expected_revision=after["revision"],
            note="finding reopened by fresh evidence",
            at=NOW + timedelta(minutes=4),
        )
        self.assertEqual(updated["work_status"], "open")
        self.assertEqual(self._events(finding_id)[-1]["finding_status"], "active")

    def test_site_is_derived_from_finding_and_enforced_by_the_database(self) -> None:
        finding_id = self._open_finding()
        item = self.work.create_work_item(
            finding_id,
            actor="alex",
            owner_kind=None,
            owner_label=None,
            note=None,
            at=NOW + timedelta(seconds=1),
        )
        self.assertEqual(item["site_id"], "site-a")

        # Direct writes that bind the finding to another site are rejected
        # by the composite foreign keys regardless of application checks.
        statements = (
            (
                """
                UPDATE finding_work_items SET site_id = 'site-b'
                WHERE finding_id = :finding_id
                """,
                {"finding_id": finding_id},
            ),
            (
                """
                INSERT INTO finding_work_references (
                    reference_id, work_item_id, site_id, reference_type,
                    reference_system, reference_label, added_actor_label, added_at
                ) VALUES (
                    :reference_id, :work_item_id, 'site-b', 'ticket', 'jira',
                    'OPS-9', 'mallory', NOW()
                )
                """,
                {"reference_id": "fwr_" + "9" * 32, "work_item_id": item["work_item_id"]},
            ),
            (
                """
                INSERT INTO finding_work_events (
                    work_item_id, finding_id, site_id, revision, event_type,
                    note, finding_status, principal, actor_label, occurred_at
                ) VALUES (
                    :work_item_id, :finding_id, 'site-b', 2, 'note_added',
                    'x', 'active', 'api-admin-token', 'mallory', NOW()
                )
                """,
                {"work_item_id": item["work_item_id"], "finding_id": finding_id},
            ),
            (
                """
                INSERT INTO finding_work_items (
                    work_item_id, finding_id, site_id, work_status, revision,
                    created_principal, created_actor_label, created_at, updated_at
                ) VALUES (
                    :work_item_id, :finding_id, 'site-b', 'open', 1,
                    'api-admin-token', 'mallory', NOW(), NOW()
                )
                """,
                {"work_item_id": "fwi_" + "9" * 32, "finding_id": "fnd_" + "9" * 32},
            ),
        )
        for statement, params in statements:
            with self.subTest(statement=statement.split()[0:3]):
                with self.assertRaises(IntegrityError):
                    with self.database_engine.begin() as connection:
                        connection.execute(text(statement), params)
        self.assertEqual(self.work.get_work_item(finding_id)["site_id"], "site-a")

    def test_database_rejects_verified_claims_other_principals_and_urls(self) -> None:
        finding_id = self._open_finding()
        item = self.work.create_work_item(
            finding_id,
            actor="alex",
            owner_kind="team",
            owner_label="Ops",
            note=None,
            at=NOW + timedelta(seconds=1),
        )
        statements = (
            "UPDATE finding_work_items SET owner_verification = 'verified'",
            "UPDATE finding_work_items SET actor_verification = 'authenticated'",
            "UPDATE finding_work_items SET created_principal = 'alex'",
            "UPDATE finding_work_items SET work_status = 'risk_accepted'",
            "UPDATE finding_work_items SET owner_label = NULL",
        )
        for statement in statements:
            with self.subTest(statement=statement):
                with self.assertRaises(IntegrityError):
                    with self.database_engine.begin() as connection:
                        connection.execute(text(statement))
        for label in ("https://example.test/OPS-1", "a/b", "x:y"):
            with self.subTest(label=label):
                with self.assertRaises(IntegrityError):
                    with self.database_engine.begin() as connection:
                        connection.execute(
                            text(
                                """
                                INSERT INTO finding_work_references (
                                    reference_id, work_item_id, site_id,
                                    reference_type, reference_system,
                                    reference_label, added_actor_label, added_at
                                ) VALUES (
                                    :reference_id, :work_item_id, 'site-a',
                                    'ticket', 'jira', :label, 'alex', NOW()
                                )
                                """
                            ),
                            {
                                "reference_id": "fwr_" + uuid4().hex,
                                "work_item_id": item["work_item_id"],
                                "label": label,
                            },
                        )

    def test_events_are_append_only_except_for_whole_finding_cascade(self) -> None:
        finding_id = self._open_finding()
        self._exercise_all_mutations(finding_id)
        for statement in (
            "UPDATE finding_work_events SET actor_label = 'rewritten'",
            "DELETE FROM finding_work_events",
            "TRUNCATE finding_work_events",
        ):
            with self.subTest(statement=statement):
                with self.assertRaises(DBAPIError) as raised:
                    with self.database_engine.begin() as connection:
                        connection.execute(text(statement))
                self.assertIn("append-only", str(raised.exception.orig))
        self.assertEqual(len(self._events(finding_id)), 6)

        # Deleting the work item alone would cascade away its history, so it
        # is rejected; only removing the whole finding may remove events.
        with self.assertRaises(DBAPIError) as direct_delete:
            with self.database_engine.begin() as connection:
                connection.execute(text("DELETE FROM finding_work_items"))
        self.assertIn("removed only with their finding", str(direct_delete.exception.orig))
        self.assertIsNotNone(self.work.get_work_item(finding_id))
        self.assertEqual(len(self._events(finding_id)), 6)

        with self.database_engine.begin() as connection:
            connection.execute(text("DELETE FROM findings WHERE finding_id = :f"), {"f": finding_id})
        self.assertIsNone(self.work.get_work_item(finding_id))
        self.assertEqual(self._rows("SELECT COUNT(*) AS n FROM finding_work_events")[0]["n"], 0)

        second_finding = self._open_finding_again()
        self._exercise_all_mutations(second_finding)
        with self.database_engine.begin() as connection:
            connection.execute(text("DELETE FROM sites WHERE site_id = 'site-a'"))
        for table in (
            "findings",
            "finding_work_items",
            "finding_work_references",
            "finding_work_events",
        ):
            with self.subTest(table=table):
                self.assertEqual(self._rows(f"SELECT COUNT(*) AS n FROM {table}")[0]["n"], 0)

    def test_stale_revision_and_invalid_transitions_write_nothing(self) -> None:
        finding_id = self._open_finding()
        self.work.create_work_item(
            finding_id,
            actor="alex",
            owner_kind=None,
            owner_label=None,
            note=None,
            at=NOW + timedelta(seconds=1),
        )
        attempts = (
            lambda: self.work.change_status(
                finding_id, actor="a", status="done", expected_revision=2, note=None,
                at=NOW + timedelta(seconds=2),
            ),
            lambda: self.work.change_status(
                finding_id, actor="a", status="open", expected_revision=1, note=None,
                at=NOW + timedelta(seconds=2),
            ),
            lambda: self.work.change_owner(
                finding_id, actor="a", owner_kind=None, owner_label=None,
                expected_revision=1, at=NOW + timedelta(seconds=2),
            ),
            lambda: self.work.remove_reference(
                finding_id, "fwr_" + "0" * 32, actor="a", expected_revision=1,
                at=NOW + timedelta(seconds=2),
            ),
            lambda: self.work.create_work_item(
                finding_id, actor="a", owner_kind=None, owner_label=None, note=None,
                at=NOW + timedelta(seconds=2),
            ),
        )
        for attempt in attempts:
            with self.subTest(attempt=attempt):
                with self.assertRaises(FindingWorkError):
                    attempt()
        item = self.work.get_work_item(finding_id)
        assert item is not None
        self.assertEqual(item["revision"], 1)
        self.assertEqual(len(self._events(finding_id)), 1)

    def test_missing_finding_and_missing_work_item_are_distinct(self) -> None:
        with self.assertRaises(FindingWorkError) as missing_finding:
            self.work.create_work_item(
                "fnd_" + "0" * 32, actor="a", owner_kind=None, owner_label=None,
                note=None, at=NOW,
            )
        self.assertEqual(missing_finding.exception.kind, "finding_not_found")
        finding_id = self._open_finding()
        with self.assertRaises(FindingWorkError) as missing_item:
            self.work.add_note(
                finding_id, actor="a", note="n", expected_revision=1, at=NOW,
            )
        self.assertEqual(missing_item.exception.kind, "not_found")
        self.assertIsNone(self.work.get_work_item(finding_id))
        self.assertIsNone(self.work.list_events(finding_id))

    def test_duplicate_and_excess_references_are_rejected(self) -> None:
        finding_id = self._open_finding()
        item = self.work.create_work_item(
            finding_id, actor="a", owner_kind=None, owner_label=None, note=None,
            at=NOW,
        )
        for index in range(20):
            item = self.work.add_reference(
                finding_id,
                actor="a",
                reference_type="ticket",
                reference_system="jira",
                reference_label=f"OPS-{index}",
                expected_revision=item["revision"],
                at=NOW + timedelta(seconds=index + 1),
            )
        for label in ("OPS-0", "OPS-99"):
            with self.subTest(label=label):
                with self.assertRaises(FindingWorkError) as raised:
                    self.work.add_reference(
                        finding_id,
                        actor="a",
                        reference_type="ticket",
                        reference_system="jira",
                        reference_label=label,
                        expected_revision=item["revision"],
                        at=NOW + timedelta(minutes=1),
                    )
                self.assertEqual(raised.exception.kind, "conflict")
        self.assertEqual(len(self.work.get_work_item(finding_id)["references"]), 20)

    def test_concurrent_writers_with_same_revision_serialize_to_one_change(self) -> None:
        finding_id = self._open_finding()
        self.work.create_work_item(
            finding_id, actor="a", owner_kind=None, owner_label=None, note=None,
            at=NOW,
        )
        barrier = threading.Barrier(4)
        outcomes: list[str] = []
        lock = threading.Lock()

        def writer(index: int) -> None:
            barrier.wait()
            try:
                SqlFindingWorkStore().add_note(
                    finding_id,
                    actor=f"writer-{index}",
                    note=f"note {index}",
                    expected_revision=1,
                    at=NOW + timedelta(seconds=1),
                )
                outcome = "ok"
            except FindingWorkError as exc:
                outcome = exc.kind
            with lock:
                outcomes.append(outcome)

        threads = [threading.Thread(target=writer, args=(index,)) for index in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(sorted(outcomes), ["conflict", "conflict", "conflict", "ok"])
        self.assertEqual([event["revision"] for event in self._events(finding_id)], [1, 2])


if __name__ == "__main__":
    unittest.main()
