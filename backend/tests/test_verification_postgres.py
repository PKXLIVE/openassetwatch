"""Gated PostgreSQL tests for remediation verification (CTEM-GAP-06)."""

from __future__ import annotations

import os
import re
import unittest
from datetime import datetime, timedelta
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
from app.verification_contracts import (
    FindingVerificationResponse,
    UnverifiedWorkListResponse,
    VerificationHistoryResponse,
)
from app.verification_store import SqlVerificationStore
from tests.test_decision_postgres import NOW, vulnerable_asset


ENABLED = os.getenv("OPENASSETWATCH_VERIFICATION_POSTGRES_TEST") == "1"
DATABASE_NAME = re.compile(r"^openassetwatch_verification_test_[0-9a-f]{16}$")
SOURCE_ID = "src_" + "e" * 32


def observed_asset(at: datetime, *, seen: datetime, freshness: str = "fresh", **kwargs) -> dict:
    """An asset evaluated at `at` whose component was last observed at `seen`."""

    asset = vulnerable_asset(at, **kwargs)
    asset["observed_at"] = seen
    asset["last_seen_at"] = seen
    for match in asset["vulnerability_matches"]:
        match["component_last_seen_at"] = seen
        match["component_freshness"] = freshness
    return asset


@unittest.skipUnless(ENABLED, "requires an explicitly isolated disposable PostgreSQL server")
class VerificationPostgresTests(unittest.TestCase):
    admin_engine: Engine
    database_engine: Engine
    database_name: str

    def setUp(self) -> None:
        parsed = make_url(os.environ["DATABASE_URL"])
        self.database_name = f"openassetwatch_verification_test_{uuid4().hex[:16]}"
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
                    "INSERT INTO control_tower_assets (asset_key, asset_id, site_id, first_seen_at, last_seen_at)"
                    " VALUES ('site-a:asset-a', 'asset-a', 'site-a', :at, :at)"
                ),
                {"at": NOW},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO canonical_ingestion_sources (
                        source_id, site_id, source_identity, source_type, adapter_type,
                        authentication_class, source_authority, trust_rank,
                        compatibility_status, first_seen_at, last_seen_at
                    ) VALUES (
                        :source_id, 'site-a', 'agent-a', 'endpoint-agent', 'endpoint-agent',
                        'bound-credential', 'authenticated-endpoint', 90, 'canonical', :at, :at
                    )
                    """
                ),
                {"source_id": SOURCE_ID, "at": NOW},
            )
        self.findings = SqlFindingStore()
        self.decisions = SqlDecisionStore()
        self.verification = SqlVerificationStore()
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
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": self.database_name},
            )
            connection.exec_driver_sql(f'DROP DATABASE "{self.database_name}"')
        self.admin_engine.dispose()

    # ----------------------------------------------------------------- helpers

    def _evaluate(self, at: datetime, asset: dict | None = None, **asset_kwargs):
        return evaluate_findings(
            trigger_type="test",
            requested_by="unit-test",
            now=at,
            store=self.findings,
            decision_store=self.decisions,
            verification_store=self.verification,
            sites=self.sites,
            sensors=self.sensors,
            assets=[asset or vulnerable_asset(at, **asset_kwargs)],
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

    def _report_done(self, finding_id: str, at: datetime) -> dict[str, Any]:
        item = self.work.get_work_item(finding_id)
        if item is None:
            item = self.work.create_work_item(
                finding_id, actor="alex", owner_kind=None, owner_label=None, note=None, at=at - timedelta(seconds=1)
            )
        return self.work.change_status(
            finding_id, actor="alex", status="done", expected_revision=item["revision"], note="patched", at=at
        )

    def _snapshot(self, at: datetime, status: str) -> None:
        collection_id = "col_" + uuid4().hex
        limitations = "[]" if status == "complete" else '["inventory truncated"]'
        with self.database_engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO canonical_inventory_collections (
                        canonical_collection_id, site_id, source_id, adapter_type, route_name,
                        idempotency_key, payload_sha256, schema_version, observed_at, ingested_at,
                        inventory_mode, observed_asset_count, canonical_asset_count, evidence_count,
                        component_count
                    ) VALUES (
                        :cid, 'site-a', :source_id, 'endpoint-agent', 'test', :cid, :sha, 'test.v1',
                        :at, :at, 'complete', 1, 1, 1, 1
                    )
                    """
                ),
                {"cid": collection_id, "source_id": SOURCE_ID, "sha": "f" * 64, "at": at},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO component_source_snapshots (
                        source_snapshot_id, canonical_collection_id, site_id, asset_id,
                        agent_source_id, collection_source_id, platform, collection_status,
                        observed_at, record_count, truncated, error_code, limitations_json
                    ) VALUES (
                        :sid, :cid, 'site-a', 'asset-a', :source_id, 'native-packages', 'linux',
                        :status, :at, :records, :truncated, :error, CAST(:limitations AS JSONB)
                    )
                    """
                ),
                {
                    "sid": "css_" + uuid4().hex,
                    "cid": collection_id,
                    "source_id": SOURCE_ID,
                    "status": status,
                    "at": at,
                    "records": 0 if status in {"failed", "unsupported"} else 5,
                    "truncated": status == "partial",
                    "error": None if status in {"complete", "partial"} else "collector-error",
                    "limitations": limitations,
                },
            )

    def _state(self, finding_id: str) -> dict[str, Any]:
        result = self.verification.get_verification(finding_id)
        assert result is not None
        FindingVerificationResponse.model_validate(result)
        return result

    def _history(self, finding_id: str) -> list[dict[str, Any]]:
        history = self.verification.list_history(finding_id, limit=200)
        assert history is not None
        VerificationHistoryResponse.model_validate(history)
        return history["items"]

    def _authoritative(self) -> dict[str, list[dict[str, Any]]]:
        return {
            table: self._rows(f"SELECT * FROM {table} ORDER BY 1")
            for table in ("findings", "finding_evidence", "asset_risk_scores", "risk_factors",
                          "finding_decisions", "finding_decision_history")
        }

    # -------------------------------------------------------------------- tests

    def test_marking_work_done_records_a_baseline_and_never_resolves(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self.work.create_work_item(
            finding_id, actor="alex", owner_kind=None, owner_label=None, note=None, at=NOW + timedelta(seconds=1)
        )
        before = self._authoritative()
        self._report_done(finding_id, NOW + timedelta(minutes=1))
        self.assertEqual(self._authoritative(), before)
        baseline = self._rows("SELECT * FROM finding_verification_baselines")
        self.assertEqual(len(baseline), 1)
        self.assertEqual((baseline[0]["finding_status"], baseline[0]["finding_rule_id"]), ("active", "vulnerable-component"))
        self.assertEqual(
            {item["evidence_type"] for item in baseline[0]["evidence_references"]},
            {"vulnerability-match", "normalized-component", "reviewed-advisory", "kev-prioritization"},
        )
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "awaiting-evidence")
        self.assertEqual(state["finding_status"], "active")
        self.assertFalse(state["verified"])
        self.assertIn("BASELINE_CAPTURED", state["reason_codes"])
        self.assertEqual(len(state["before_evidence_references"]), 4)
        self.assertEqual(state["after_evidence_references"], [])
        self.assertEqual(state["guidance"]["method_id"], "component-inventory")
        # This harness injects assets, so no stored match row exists to join;
        # guidance reports no component versions rather than inventing them.
        self.assertEqual(state["guidance"]["components"], [])
        self.assertIn("complete inventory", state["guidance"]["resolution_behavior"])
        self.assertEqual(state["record_state"], "not-recorded")
        unverified = self.verification.list_unverified(site_id="site-a")
        UnverifiedWorkListResponse.model_validate(unverified)
        self.assertEqual([item["finding_id"] for item in unverified["items"]], [finding_id])

    def test_later_inventory_still_showing_the_component_is_still_present(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._report_done(finding_id, NOW + timedelta(minutes=1))
        later = NOW + timedelta(hours=2)
        self._snapshot(later, "complete")
        self._evaluate(later, observed_asset(later, seen=later))
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "still-present")
        self.assertEqual(state["collection_completeness"], "complete")
        self.assertIn("EVIDENCE_SINCE_REPORT_STILL_MATCHES", state["reason_codes"])
        self.assertTrue(state["after_evidence_references"])
        self.assertEqual(self.verification.list_unverified(verification_state="still-present")["total"], 1)
        self.assertEqual([item["verification_state"] for item in self._history(finding_id)], ["still-present"])

    def test_fixed_component_on_complete_inventory_verifies(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._report_done(finding_id, NOW + timedelta(minutes=1))
        self._evaluate(NOW + timedelta(minutes=30), observed_asset(NOW + timedelta(minutes=30), seen=NOW))
        self.assertEqual(self._state(finding_id)["verification_state"], "awaiting-evidence")
        later = NOW + timedelta(hours=2)
        self._snapshot(later, "complete")
        self._evaluate(later, observed_asset(later, seen=later, status="fixed"))
        state = self._state(finding_id)
        self.assertEqual(state["finding_status"], "resolved")
        self.assertEqual(state["verification_state"], "verified")
        for code in ("RESOLVED_BY_FRESH_EVIDENCE", "COMPONENT_VERSION_FIXED", "COLLECTION_COMPLETE_AT_RESOLUTION"):
            self.assertIn(code, state["reason_codes"])
        self.assertEqual(state["record_state"], "current")
        self.assertEqual(self.verification.list_unverified()["total"], 0)
        # The affirmative evidence that resolved the finding is retained and
        # returned: the fixed match, its versions, and its collection time.
        (evidence,) = state["resolution_evidence"]
        self.assertEqual(
            (evidence["resolution_basis"], evidence["technical"], evidence["evidence_ref"]),
            ("component-version-fixed", True, "vmt_" + "a" * 32),
        )
        self.assertEqual((evidence["installed_version"], evidence["fixed_version"]), ("1.2.0", "1.4.2"))
        self.assertEqual(evidence["observed_at"], later)
        self.assertEqual(state["after_evidence_references"][0]["evidence_ref"], "vmt_" + "a" * 32)
        self.assertEqual(state["collection_at_resolution"]["collection_status"], "complete")
        stored = self._rows("SELECT * FROM finding_resolution_evidence")
        self.assertEqual(len(stored), 1)
        self.assertEqual((stored[0]["resolved_at"], stored[0]["observed_at"]), (later, later))
        history = self._history(finding_id)
        self.assertEqual(
            [(item["sequence"], item["previous_state"], item["verification_state"]) for item in history],
            [(1, None, "awaiting-evidence"), (2, "awaiting-evidence", "verified")],
        )

    def _verify_after_report(self, *, status: str = "fixed", seen_offset: timedelta = timedelta(hours=2),
                             snapshot_status: str | None = "complete") -> tuple[str, datetime]:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._report_done(finding_id, NOW + timedelta(minutes=1))
        later = NOW + timedelta(hours=2)
        if snapshot_status is not None:
            self._snapshot(later, snapshot_status)
        self._evaluate(later, observed_asset(later, seen=NOW + seen_offset, status=status))
        return finding_id, later

    def test_resolution_before_the_report_is_not_attributable(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        item = self.work.create_work_item(
            finding_id, actor="alex", owner_kind=None, owner_label=None, note=None, at=NOW + timedelta(seconds=1)
        )
        self._snapshot(NOW + timedelta(minutes=30), "complete")
        self._evaluate(NOW + timedelta(minutes=30), observed_asset(NOW + timedelta(minutes=30),
                                                                   seen=NOW + timedelta(minutes=30), status="fixed"))
        self.work.change_status(
            finding_id, actor="alex", status="done", expected_revision=item["revision"], note=None,
            at=NOW + timedelta(hours=1),
        )
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "resolved-before-report")
        self.assertIn("RESOLVED_BEFORE_REPORT", state["reason_codes"])
        self.assertFalse(state["verified"])
        self.assertEqual(self.verification.list_unverified()["total"], 0)

    def test_resolution_after_report_from_evidence_observed_before_it(self) -> None:
        finding_id, _ = self._verify_after_report(seen_offset=timedelta(0))
        state = self._state(finding_id)
        self.assertEqual(state["finding_status"], "resolved")
        self.assertEqual(state["verification_state"], "insufficient-evidence")
        self.assertIn("RESOLUTION_EVIDENCE_PREDATES_REPORT", state["reason_codes"])
        self.assertEqual(state["after_evidence_references"], [])

    def test_incomplete_or_missing_collection_before_resolution_is_insufficient(self) -> None:
        for snapshot_status, code in (
            ("partial", "COLLECTION_INCOMPLETE_AT_RESOLUTION"),
            ("failed", "COLLECTION_INCOMPLETE_AT_RESOLUTION"),
            ("unsupported", "COLLECTION_INCOMPLETE_AT_RESOLUTION"),
            (None, "COLLECTION_NOT_COMPLETE_AT_RESOLUTION"),
        ):
            with self.subTest(snapshot_status=snapshot_status):
                self.tearDown()
                self.setUp()
                finding_id, _ = self._verify_after_report(snapshot_status=snapshot_status)
                state = self._state(finding_id)
                self.assertEqual(state["finding_status"], "resolved")
                self.assertEqual(state["verification_state"], "insufficient-evidence")
                self.assertIn(code, state["reason_codes"])
                self.assertEqual(self.verification.list_unverified()["total"], 1)

    def test_stale_resolution_evidence_is_not_verification(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._report_done(finding_id, NOW + timedelta(minutes=1))
        later = NOW + timedelta(hours=2)
        self._snapshot(later, "complete")
        self._evaluate(later, observed_asset(later, seen=later, status="fixed", freshness="stale"))
        self.assertEqual(self._state(finding_id)["verification_state"], "evidence-stale")

    def test_advisory_withdrawal_is_distinct_from_technical_remediation(self) -> None:
        for status, basis in (("advisory-withdrawn", "advisory-withdrawn"), ("not-affected", "applicability-not-affected")):
            with self.subTest(status=status):
                self.tearDown()
                self.setUp()
                finding_id, _ = self._verify_after_report(status=status)
                state = self._state(finding_id)
                self.assertEqual(state["finding_status"], "resolved")
                self.assertEqual(state["verification_state"], "resolved-by-advisory-change")
                self.assertEqual(state["resolution_evidence"][0]["resolution_basis"], basis)
                self.assertFalse(state["resolution_evidence"][0]["technical"])
                self.assertFalse(state["verified"])

    def test_verified_outcome_survives_later_degraded_collection(self) -> None:
        finding_id, later = self._verify_after_report()
        self.assertEqual(self._state(finding_id)["verification_state"], "verified")
        self._snapshot(later + timedelta(hours=1), "failed")
        self._evaluate(later + timedelta(hours=1, minutes=5),
                       observed_asset(later + timedelta(hours=1, minutes=5), seen=later, status="fixed"))
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "verified")
        self.assertIn("COLLECTION_DEGRADED_SINCE_VERIFICATION", state["reason_codes"])
        self.assertEqual(state["collection_after_resolution"]["collection_status"], "failed")
        states = [item["verification_state"] for item in self._history(finding_id)]
        self.assertEqual(states, ["verified", "verified"])

    def test_resolution_evidence_is_append_only_site_bound_and_cascades(self) -> None:
        finding_id, _ = self._verify_after_report()
        self.assertEqual(len(self._rows("SELECT * FROM finding_resolution_evidence")), 1)
        for statement in (
            "UPDATE finding_resolution_evidence SET resolution_basis = 'component-version-fixed'",
            "DELETE FROM finding_resolution_evidence",
            "TRUNCATE finding_resolution_evidence",
        ):
            with self.subTest(statement=statement):
                with self.assertRaises(DBAPIError) as raised:
                    with self.database_engine.begin() as connection:
                        connection.execute(text(statement))
                self.assertIn("append-only", str(raised.exception.orig))
        for column, value in (("resolution_basis", "'guessed-remediation'"), ("site_id", "'site-b'")):
            with self.subTest(column=column):
                with self.assertRaises(IntegrityError):
                    with self.database_engine.begin() as connection:
                        connection.execute(
                            text(
                                f"""
                                INSERT INTO finding_resolution_evidence (
                                    finding_id, site_id, resolved_at, evaluation_run_id, resolution_basis,
                                    evidence_ref, evidence_type, source, freshness
                                )
                                SELECT finding_id, {value if column == 'site_id' else 'site_id'}, NOW(),
                                       evaluation_run_id,
                                       {value if column == 'resolution_basis' else "'fresh-observation'"},
                                       'x', 'x', 'x', 'fresh'
                                FROM finding_resolution_evidence
                                """
                            )
                        )
        with self.database_engine.begin() as connection:
            connection.execute(text("DELETE FROM findings WHERE finding_id = :f"), {"f": finding_id})
        self.assertEqual(self._rows("SELECT COUNT(*) AS n FROM finding_resolution_evidence")[0]["n"], 0)

    def test_reopened_finding_is_still_present_and_history_is_preserved(self) -> None:
        finding_id, later = self._verify_after_report()
        verified_history = self._history(finding_id)
        evidence_before = self._rows("SELECT * FROM finding_resolution_evidence ORDER BY 1")
        reopened_at = later + timedelta(hours=3)
        self._evaluate(reopened_at, observed_asset(reopened_at, seen=reopened_at, status="affected"))
        state = self._state(finding_id)
        self.assertEqual(state["finding_status"], "active")
        self.assertEqual(state["verification_state"], "still-present")
        self.assertIn("REOPENED_SINCE_REPORT", state["reason_codes"])
        history = self._history(finding_id)
        self.assertEqual(history[: len(verified_history)], verified_history)
        self.assertEqual(history[-1]["previous_state"], "verified")
        # The resolution evidence that once verified it is kept unchanged.
        self.assertEqual(self._rows("SELECT * FROM finding_resolution_evidence ORDER BY 1"), evidence_before)

    def test_partial_collection_after_report_is_insufficient_and_never_resolves(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._report_done(finding_id, NOW + timedelta(minutes=1))
        later = NOW + timedelta(hours=2)
        self._snapshot(later, "partial")
        # The partial inventory did not re-observe the component.
        self._evaluate(later, observed_asset(later, seen=NOW))
        state = self._state(finding_id)
        self.assertEqual(state["finding_status"], "active")
        self.assertEqual(state["verification_state"], "insufficient-evidence")
        self.assertEqual(state["collection_completeness"], "incomplete")
        self.assertEqual(state["collection_since_report"]["collection_status"], "partial")
        self.assertIn("COLLECTION_INCOMPLETE_SINCE_REPORT", state["reason_codes"])

    def test_complete_collection_awaits_evaluation_then_verifies(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._report_done(finding_id, NOW + timedelta(minutes=1))
        later = NOW + timedelta(hours=2)
        self._snapshot(later, "complete")
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "awaiting-evidence")
        self.assertIn("EVALUATION_PENDING", state["reason_codes"])

    def test_stale_later_evidence_is_not_proof(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._report_done(finding_id, NOW + timedelta(minutes=1))
        later = NOW + timedelta(hours=2)
        self._evaluate(later, observed_asset(later, seen=later, freshness="stale"))
        self.assertEqual(self._state(finding_id)["verification_state"], "evidence-stale")

    def test_reopening_work_withdraws_the_report_and_a_new_report_starts_over(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        done = self._report_done(finding_id, NOW + timedelta(minutes=1))
        self._evaluate(NOW + timedelta(minutes=5), observed_asset(NOW + timedelta(minutes=5), seen=NOW))
        self.work.change_status(
            finding_id, actor="sam", status="open", expected_revision=done["revision"], note="not fixed",
            at=NOW + timedelta(minutes=10),
        )
        self.assertEqual(self._state(finding_id)["verification_state"], "report-withdrawn")
        self.assertEqual(self.verification.list_unverified()["total"], 0)
        self._evaluate(NOW + timedelta(minutes=15), observed_asset(NOW + timedelta(minutes=15), seen=NOW))
        again = self._report_done(finding_id, NOW + timedelta(minutes=20))
        state = self._state(finding_id)
        self.assertEqual((state["verification_state"], state["report_revision"]), ("awaiting-evidence", again["revision"]))
        self.assertEqual(len(self._rows("SELECT * FROM finding_verification_baselines")), 2)
        history = self._history(finding_id)
        self.assertEqual(
            [(item["report_revision"], item["verification_state"]) for item in history],
            [(done["revision"], "awaiting-evidence"), (done["revision"], "report-withdrawn")],
        )

    def test_unchanged_reevaluation_writes_no_history(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._report_done(finding_id, NOW + timedelta(minutes=1))
        for minutes in (5, 10, 15):
            self._evaluate(NOW + timedelta(minutes=minutes), observed_asset(NOW + timedelta(minutes=minutes), seen=NOW))
        self.assertEqual(len(self._history(finding_id)), 1)

    def test_identity_conflict_on_the_asset_blocks_attribution(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._report_done(finding_id, NOW + timedelta(minutes=1))
        later = NOW + timedelta(hours=2)
        self._snapshot(later, "complete")
        self._evaluate(later, observed_asset(later, seen=later, status="fixed"))
        with self.database_engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO findings (
                        finding_id, dedupe_key, rule_id, rule_version, engine_version, category,
                        subject_type, site_id, asset_id, title, description, recommendation,
                        severity, confidence, status, evidence_freshness, first_seen_at,
                        last_seen_at, evaluated_at, last_evaluation_run_id
                    )
                    SELECT :fid, :dk, 'identity-conflict', 1, 'oaw.findings.v1', 'identity', 'asset',
                           'site-a', 'asset-a', 't', 'd', 'r', 'high', 0.9, 'active', 'fresh',
                           :at, :at, :at, run_id
                    FROM finding_evaluation_runs ORDER BY started_at DESC LIMIT 1
                    """
                ),
                {"fid": "fnd_" + "c" * 32, "dk": "fdk_" + "c" * 64, "at": later},
            )
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "conflicting-evidence")
        self.assertIn("IDENTITY_CONFLICT_ACTIVE", state["reason_codes"])

    def test_baseline_failure_rolls_back_the_done_transition(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        item = self.work.create_work_item(
            finding_id, actor="alex", owner_kind=None, owner_label=None, note=None, at=NOW + timedelta(seconds=1)
        )
        with patch("app.finding_work_store.capture_baseline", side_effect=RuntimeError("baseline failed")):
            with self.assertRaises(RuntimeError):
                self.work.change_status(
                    finding_id, actor="alex", status="done", expected_revision=item["revision"], note=None,
                    at=NOW + timedelta(minutes=1),
                )
        self.assertEqual(self.work.get_work_item(finding_id)["work_status"], "open")
        self.assertEqual(self._rows("SELECT COUNT(*) AS n FROM finding_work_events")[0]["n"], 1)
        self.assertEqual(self._rows("SELECT COUNT(*) AS n FROM finding_verification_baselines")[0]["n"], 0)

    def test_records_are_append_only_site_bound_and_cascade_with_the_finding(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._report_done(finding_id, NOW + timedelta(minutes=1))
        self._evaluate(NOW + timedelta(minutes=5), observed_asset(NOW + timedelta(minutes=5), seen=NOW))
        for table in ("finding_verification_baselines", "finding_verification_history"):
            for statement in (f"UPDATE {table} SET site_id = 'site-a'", f"DELETE FROM {table}", f"TRUNCATE {table}"):
                with self.subTest(statement=statement):
                    with self.assertRaises(DBAPIError) as raised:
                        with self.database_engine.begin() as connection:
                            connection.execute(text(statement))
                    self.assertIn("append-only", str(raised.exception.orig))
        with self.assertRaises(IntegrityError):
            with self.database_engine.begin() as connection:
                connection.execute(
                    text(
                        """
                        INSERT INTO finding_verification_baselines (
                            work_item_id, finding_id, site_id, report_revision, reported_at,
                            finding_rule_id, finding_status, finding_evidence_freshness,
                            finding_reopen_count, evidence_references
                        )
                        SELECT work_item_id, finding_id, 'site-b', 99, NOW(), 'r', 'active', 'fresh', 0, '[]'::jsonb
                        FROM finding_work_items
                        """
                    )
                )
        with self.assertRaises(IntegrityError):
            with self.database_engine.begin() as connection:
                connection.execute(
                    text(
                        """
                        INSERT INTO finding_verification_history (
                            work_item_id, finding_id, site_id, report_revision, sequence, ruleset_version,
                            previous_state, verification_state, reason_codes, after_evidence_references,
                            finding_status, input_digest, evaluated_at, evaluation_run_id
                        )
                        SELECT work_item_id, finding_id, site_id, 99, 1, 'oaw.verification.rules.v1', NULL,
                               'approved', '["X"]'::jsonb, '[]'::jsonb, 'active', :digest, NOW(),
                               (SELECT run_id FROM finding_evaluation_runs LIMIT 1)
                        FROM finding_work_items
                        """
                    ),
                    {"digest": "a" * 64},
                )
        # Removing the finding cascades through its work item to every
        # verification record; nothing else can remove them.
        with self.database_engine.begin() as connection:
            connection.execute(text("DELETE FROM findings WHERE finding_id = :f"), {"f": finding_id})
        for table in ("finding_verification_baselines", "finding_verification_history", "finding_work_items"):
            self.assertEqual(self._rows(f"SELECT COUNT(*) AS n FROM {table}")[0]["n"], 0, table)

    def test_verification_never_changes_findings_risk_decisions_or_work(self) -> None:
        self._evaluate(NOW)
        finding_id = self._finding_id()
        self._report_done(finding_id, NOW + timedelta(minutes=1))
        later = NOW + timedelta(hours=2)
        # Two identical evaluations, one with verification and one without,
        # produce the same findings, risk, and decisions.
        self._evaluate(later, observed_asset(later, seen=later))
        with_verification = self._authoritative()
        work_before = self._rows("SELECT * FROM finding_work_items")
        self.verification.get_verification(finding_id)
        self.verification.list_unverified()
        self.verification.list_history(finding_id)
        self.assertEqual(self._authoritative(), with_verification)
        self.assertEqual(self._rows("SELECT * FROM finding_work_items"), work_before)
        decision = self.decisions.get_decision(finding_id)
        self.assertEqual(decision["projection_state"], "current")
        self.assertEqual(decision["action_band"], "prioritize")


if __name__ == "__main__":
    unittest.main()
