"""Gated PostgreSQL tests for remediation verification (CTEM-GAP-06).

These run end to end through production persistence and projection: real
advisory, component, source snapshot, presence, and match rows; finding
evaluation that loads its inputs through `list_control_tower_assets` and
`active_match_snapshot`; and verification read through the store. Times are
relative to the database clock because component freshness is computed there.
"""

from __future__ import annotations

import json
import os
import re
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
from app.verification_contracts import (
    FindingVerificationResponse,
    UnverifiedWorkListResponse,
    VerificationHistoryResponse,
)
from app.verification_store import SqlVerificationStore
from app.vulnerability_contracts import VulnerabilityMatchResponse
from app.vulnerability_store import SqlVulnerabilityStore


ENABLED = os.getenv("OPENASSETWATCH_VERIFICATION_POSTGRES_TEST") == "1"
DATABASE_NAME = re.compile(r"^openassetwatch_verification_test_[0-9a-f]{16}$")
SOURCE_ID = "src_" + "e" * 32
MATCH_ID = "vmt_" + "a" * 32
COMPONENT_ID = "cmp_" + "c" * 32
ADVISORY_ID = "adv_" + "d" * 32
OWN_SOURCE = "native-packages"
OTHER_SOURCE = "other-packages"
# Times stay in the recent past of the database clock.
T0 = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=12)


def at(hours: float) -> datetime:
    return T0 + timedelta(hours=hours)


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
        self._seed()
        self.findings = SqlFindingStore()
        self.decisions = SqlDecisionStore()
        self.verification = SqlVerificationStore()
        self.work = SqlFindingWorkStore()

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

    # ------------------------------------------------------------ production rows

    def _exec(self, sql: str, **params: Any) -> None:
        with self.database_engine.begin() as connection:
            connection.execute(text(sql), params)

    def _rows(self, sql: str, **params: Any) -> list[dict[str, Any]]:
        with self.database_engine.connect() as connection:
            return [dict(row) for row in connection.execute(text(sql), params).mappings()]

    def _seed(self) -> None:
        self._exec("INSERT INTO sites (site_id, name) VALUES ('site-a', 'Site A'), ('site-b', 'Site B')")
        self._exec(
            "INSERT INTO control_tower_assets (asset_key, asset_id, site_id, hostname, first_seen_at,"
            " last_seen_at, observed_at, metadata_json)"
            " VALUES ('site-a:asset-a', 'asset-a', 'site-a', 'db01', :t, :t, :t, '{\"category\": \"server\"}')",
            t=at(0),
        )
        self._exec(
            """
            INSERT INTO canonical_ingestion_sources (
                source_id, site_id, source_identity, source_type, adapter_type, authentication_class,
                source_authority, trust_rank, compatibility_status, first_seen_at, last_seen_at
            ) VALUES (:s, 'site-a', 'agent-a', 'endpoint-agent', 'endpoint-agent', 'bound-credential',
                      'authenticated-endpoint', 90, 'canonical', :t, :t)
            """,
            s=SOURCE_ID, t=at(0),
        )
        self._exec(
            """
            INSERT INTO advisory_catalog_imports (
                import_id, catalog_version, source, source_version, source_license, provenance,
                checksum, generated_at, imported_at, advisory_count, status
            ) VALUES ('imp_1', 'v1', 'reviewed', '1', 'reviewed', 'test', :c, :t, :t, 1, 'completed')
            """,
            c="a" * 64, t=at(0),
        )
        self._exec(
            """
            INSERT INTO advisories (
                advisory_id, source, source_record_id, source_version, title, summary, severity,
                known_exploited, published_at, modified_at, current, catalog_import_id, checksum
            ) VALUES (:a, 'reviewed', 'REC-1', '1', 'Example agent flaw', 's', 'high', FALSE,
                      :t, :t, TRUE, 'imp_1', :c)
            """,
            a=ADVISORY_ID, t=at(0), c="b" * 64,
        )
        self._exec(
            """
            INSERT INTO asset_components (
                component_id, asset_id, site_id, component_type, ecosystem, name, normalized_name,
                version, normalized_version, install_scope, source_type, source_id,
                firmware_evidence_type, first_seen_at, last_seen_at, observed_at, freshness,
                confidence, normalization_status, model_version
            ) VALUES (:c, 'asset-a', 'site-a', 'package', 'pypi', 'example-agent', 'example-agent',
                      '1.2.0', '1.2.0', 'system', 'endpoint-collector', :s, 'direct', :t, :t, :t,
                      'fresh', 1.0, 'normalized', 'test')
            """,
            c=COMPONENT_ID, s=SOURCE_ID, t=at(0),
        )
        self._exec(
            "INSERT INTO vulnerability_evaluation_runs (run_id, trigger_type, engine_version, status, started_at)"
            " VALUES ('vrun_1', 'test', 'test', 'completed', :t)",
            t=at(0),
        )
        snapshot = self._inventory(at(0), observed=True, first=True)
        self.first_snapshot = snapshot
        self._exec(
            """
            INSERT INTO vulnerability_matches (
                match_id, asset_id, site_id, component_id, advisory_id, affected_id, match_status,
                match_confidence, installed_version, fixed_version, evaluated_at, reason_codes_json,
                engine_version, last_run_id
            ) VALUES (:m, 'asset-a', 'site-a', :c, :a, 'aff_1', 'affected', 1.0, '1.2.0', '1.4.2',
                      :t, '["installed-version-in-affected-range"]', 'test', 'vrun_1')
            """,
            m=MATCH_ID, c=COMPONENT_ID, a=ADVISORY_ID, t=at(0),
        )

    def _inventory(
        self,
        when: datetime,
        *,
        status: str = "complete",
        source: str = OWN_SOURCE,
        observed: bool = True,
        removed: bool = False,
        version: str | None = None,
        first: bool = False,
    ) -> str:
        """Record one source snapshot and, for the component's own source, its effect."""

        collection_id = "col_" + uuid4().hex
        snapshot_id = "css_" + uuid4().hex
        self._exec(
            """
            INSERT INTO canonical_inventory_collections (
                canonical_collection_id, site_id, source_id, adapter_type, route_name, idempotency_key,
                payload_sha256, schema_version, observed_at, ingested_at, inventory_mode,
                observed_asset_count, canonical_asset_count, evidence_count, component_count
            ) VALUES (:cid, 'site-a', :s, 'endpoint-agent', 'test', :cid, :sha, 'test.v1', :t, :t,
                      'complete', 1, 1, 1, 1)
            """,
            cid=collection_id, s=SOURCE_ID, sha="f" * 64, t=when,
        )
        self._exec(
            """
            INSERT INTO component_source_snapshots (
                source_snapshot_id, canonical_collection_id, site_id, asset_id, agent_source_id,
                collection_source_id, platform, collection_status, observed_at, record_count,
                truncated, error_code, limitations_json
            ) VALUES (:sid, :cid, 'site-a', 'asset-a', :s, :src, 'linux', :status, :t, :n, :tr, :err,
                      CAST(:lim AS JSONB))
            """,
            sid=snapshot_id, cid=collection_id, s=SOURCE_ID, src=source, status=status, t=when,
            n=0 if status in {"failed", "unsupported"} else 5, tr=status == "partial",
            err=None if status in {"complete", "partial"} else "collector-error",
            lim="[]" if status == "complete" else '["inventory truncated"]',
        )
        if source != OWN_SOURCE:
            return snapshot_id
        if first:
            self._exec(
                """
                INSERT INTO component_source_presence (
                    component_id, site_id, asset_id, agent_source_id, collection_source_id,
                    source_record_id, evidence_method, active, first_observed_at, last_observed_at,
                    last_source_snapshot_id
                ) VALUES (:c, 'site-a', 'asset-a', :s, :src, 'pkg:example-agent', 'package-manager',
                          TRUE, :t, :t, :sid)
                """,
                c=COMPONENT_ID, s=SOURCE_ID, src=OWN_SOURCE, t=when, sid=snapshot_id,
            )
        elif removed:
            self._exec(
                "UPDATE component_source_presence SET active = FALSE, not_observed_at = :t,"
                " last_source_snapshot_id = :sid WHERE component_id = :c",
                t=when, sid=snapshot_id, c=COMPONENT_ID,
            )
            self._exec(
                "UPDATE asset_components SET active = FALSE, not_observed_at = :t WHERE component_id = :c",
                t=when, c=COMPONENT_ID,
            )
        elif observed:
            self._exec(
                "UPDATE component_source_presence SET last_observed_at = :t, last_source_snapshot_id = :sid"
                " WHERE component_id = :c",
                t=when, sid=snapshot_id, c=COMPONENT_ID,
            )
            self._exec(
                "UPDATE asset_components SET last_seen_at = :t, observed_at = :t,"
                " normalized_version = COALESCE(:v, normalized_version), version = COALESCE(:v, version)"
                " WHERE component_id = :c",
                t=when, v=version, c=COMPONENT_ID,
            )
        return snapshot_id

    def _match(self, when: datetime, status: str, reason: str, installed: str | None = None) -> None:
        """Persist a matcher result as the vulnerability store would."""

        self._exec(
            """
            UPDATE vulnerability_matches
            SET match_status = :status, reason_codes_json = CAST(:reasons AS JSONB),
                installed_version = COALESCE(:installed, installed_version), evaluated_at = :t,
                resolved_at = CASE WHEN :status IN ('fixed', 'not-affected', 'advisory-withdrawn')
                                   THEN CAST(:t AS TIMESTAMPTZ) ELSE NULL END
            WHERE match_id = :m
            """,
            status=status, reasons=json.dumps([reason]), installed=installed, t=when, m=MATCH_ID,
        )

    def _evaluate(self, when: datetime):
        # No injected inputs: findings load assets and matches through the
        # production projection.
        return evaluate_findings(
            trigger_type="test",
            requested_by="unit-test",
            now=when,
            store=self.findings,
            decision_store=self.decisions,
            verification_store=self.verification,
            site_id="site-a",
            rule_ids=["vulnerable-component"],
        )

    def _finding_id(self) -> str:
        items = self.findings.list_findings(site_id="site-a", rule_id="vulnerable-component")["items"]
        self.assertEqual(len(items), 1)
        return items[0]["finding_id"]

    def _report_done(self, finding_id: str, when: datetime) -> dict[str, Any]:
        item = self.work.get_work_item(finding_id) or self.work.create_work_item(
            finding_id, actor="alex", owner_kind=None, owner_label=None, note=None, at=when - timedelta(seconds=1)
        )
        return self.work.change_status(
            finding_id, actor="alex", status="done", expected_revision=item["revision"], note="patched", at=when
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

    def _reported(self) -> str:
        """An affected finding with remediation reported at T0 + 1h."""

        self._evaluate(at(0.5))
        finding_id = self._finding_id()
        self._report_done(finding_id, at(1))
        return finding_id

    def _upgrade_and_resolve(self, finding_id: str, *, status: str = "complete") -> str:
        snapshot_id = self._inventory(at(2), status=status, version="1.4.2")
        self._match(at(2), "fixed", "at-or-after-fixed-boundary", installed="1.4.2")
        self._evaluate(at(2.5))
        return snapshot_id

    # -------------------------------------------------------------------- tests

    def test_projection_returns_observation_times_and_supporting_snapshot(self) -> None:
        (match,) = SqlVulnerabilityStore().active_match_snapshot(site_id="site-a")
        self.assertEqual(match["component_last_seen_at"], at(0))
        self.assertIsNone(match["component_not_observed_at"])
        self.assertEqual(match["component_source_snapshot_id"], self.first_snapshot)
        # The list route's match contract accepts the new projection fields.
        listed = SqlVulnerabilityStore().list_matches(site_id="site-a")["items"][0]
        VulnerabilityMatchResponse.model_validate({key: value for key, value in listed.items() if key != "kev"})
        self._evaluate(at(0.5))
        finding = self.findings.list_findings(site_id="site-a", rule_id="vulnerable-component")["items"][0]
        self.assertEqual(finding["evidence_observed_at"], at(0))

    def test_marking_work_done_captures_baseline_with_installed_version(self) -> None:
        finding_id = self._reported()
        (baseline,) = self._rows("SELECT * FROM finding_verification_baselines")
        self.assertEqual(baseline["match_versions"][0]["installed_version"], "1.2.0")
        self.assertEqual(baseline["finding_status"], "active")
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "awaiting-evidence")
        self.assertEqual(state["finding_status"], "active")
        unverified = self.verification.list_unverified(site_id="site-a")
        UnverifiedWorkListResponse.model_validate(unverified)
        self.assertEqual(unverified["total"], 1)

    def test_version_upgrade_on_the_components_complete_inventory_verifies(self) -> None:
        finding_id = self._reported()
        snapshot_id = self._upgrade_and_resolve(finding_id)
        state = self._state(finding_id)
        self.assertEqual((state["finding_status"], state["verification_state"]), ("resolved", "verified"))
        for code in ("COMPONENT_VERSION_FIXED", "COLLECTION_COMPLETE_AT_RESOLUTION", "RESOLVED_BY_FRESH_EVIDENCE"):
            self.assertIn(code, state["reason_codes"])
        (evidence,) = state["resolution_evidence"]
        self.assertEqual(
            (evidence["resolution_basis"], evidence["evidence_ref"], evidence["installed_version"],
             evidence["fixed_version"], evidence["supporting_snapshot_id"], evidence["observed_at"]),
            ("component-version-fixed", MATCH_ID, "1.4.2", "1.4.2", snapshot_id, at(2)),
        )
        self.assertEqual(state["collection_at_resolution"]["snapshot_id"], snapshot_id)
        self.assertEqual(state["after_evidence_references"][0]["evidence_ref"], MATCH_ID)
        self.assertEqual(self.verification.list_unverified()["total"], 0)

    def test_confirmed_removal_verifies_from_the_removal_snapshot(self) -> None:
        finding_id = self._reported()
        snapshot_id = self._inventory(at(2), removed=True)
        self._match(at(2), "fixed", "component-removal-confirmed-by-complete-inventory")
        self._evaluate(at(2.5))
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "verified")
        self.assertIn("COMPONENT_REMOVED", state["reason_codes"])
        self.assertNotIn("COMPONENT_VERSION_FIXED", state["reason_codes"])
        (evidence,) = state["resolution_evidence"]
        self.assertEqual((evidence["resolution_basis"], evidence["observed_at"]), ("component-removed", at(2)))
        self.assertEqual(evidence["supporting_snapshot_id"], snapshot_id)

    def test_fixed_status_without_a_version_change_is_an_advisory_revision(self) -> None:
        finding_id = self._reported()
        self._inventory(at(2))  # re-observed, still 1.2.0
        self._match(at(2), "fixed", "at-or-after-fixed-boundary")
        self._evaluate(at(2.5))
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "resolved-by-advisory-change")
        self.assertIn("FIXED_BOUNDARY_REVISED", state["reason_codes"])
        self.assertFalse(state["verified"])

    def test_unrelated_complete_inventory_cannot_establish_completeness(self) -> None:
        finding_id = self._reported()
        self._inventory(at(1.9), source=OTHER_SOURCE)  # complete, but another source
        self._upgrade_and_resolve(finding_id, status="partial")
        state = self._state(finding_id)
        self.assertEqual(state["finding_status"], "resolved")
        self.assertEqual(state["verification_state"], "insufficient-evidence")
        self.assertIn("COLLECTION_INCOMPLETE_AT_RESOLUTION", state["reason_codes"])
        self.assertEqual(state["collection_at_resolution"]["collection_status"], "partial")

    def test_failed_or_unsupported_own_collection_never_verifies(self) -> None:
        for status in ("failed", "unsupported"):
            with self.subTest(status=status):
                self.tearDown()
                self.setUp()
                finding_id = self._reported()
                self._inventory(at(2), status=status, observed=False)
                state = self._state(finding_id)
                self.assertEqual(state["verification_state"], "insufficient-evidence")
                self.assertEqual(state["collection_since_report"]["collection_status"], status)

    def test_other_source_inventory_does_not_count_for_an_unresolved_finding(self) -> None:
        finding_id = self._reported()
        self._inventory(at(2), source=OTHER_SOURCE)
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "awaiting-evidence")
        self.assertIsNone(state["collection_since_report"])
        self.assertNotIn("COLLECTION_COMPLETE_SINCE_REPORT", state["reason_codes"])

    def test_resolution_before_the_report_is_not_attributable(self) -> None:
        self._evaluate(at(0.5))
        finding_id = self._finding_id()
        item = self.work.create_work_item(
            finding_id, actor="alex", owner_kind=None, owner_label=None, note=None, at=at(0.6)
        )
        self._inventory(at(0.7), version="1.4.2")
        self._match(at(0.7), "fixed", "at-or-after-fixed-boundary", installed="1.4.2")
        self._evaluate(at(0.8))
        self.work.change_status(finding_id, actor="alex", status="done", expected_revision=item["revision"],
                                note=None, at=at(1))
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "resolved-before-report")
        self.assertEqual(self.verification.list_unverified()["total"], 0)

    def test_resolution_after_report_from_evidence_collected_before_it(self) -> None:
        self._evaluate(at(0.5))
        finding_id = self._finding_id()
        self._inventory(at(0.8), version="1.4.2")  # upgrade observed, not yet matched
        self._report_done(finding_id, at(1))
        self._match(at(2), "fixed", "at-or-after-fixed-boundary", installed="1.4.2")
        self._evaluate(at(2.5))
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "insufficient-evidence")
        self.assertIn("RESOLUTION_EVIDENCE_PREDATES_REPORT", state["reason_codes"])

    def test_advisory_withdrawal_is_distinct_from_remediation(self) -> None:
        finding_id = self._reported()
        self._inventory(at(2))
        self._match(at(2), "advisory-withdrawn", "advisory-withdrawn-or-superseded")
        self._evaluate(at(2.5))
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "resolved-by-advisory-change")
        self.assertEqual(state["resolution_evidence"][0]["resolution_basis"], "advisory-withdrawn")
        self.assertFalse(state["resolution_evidence"][0]["technical"])

    def test_verified_outcome_survives_later_degraded_collection(self) -> None:
        finding_id = self._reported()
        self._upgrade_and_resolve(finding_id)
        self._inventory(at(4), status="failed", observed=False)
        self._evaluate(at(4.5))
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "verified")
        self.assertIn("COLLECTION_DEGRADED_SINCE_VERIFICATION", state["reason_codes"])
        self.assertEqual(state["collection_after_resolution"]["collection_status"], "failed")
        self.assertEqual([item["verification_state"] for item in self._history(finding_id)][-2:], ["verified", "verified"])

    def test_reopened_finding_keeps_history_and_resolution_evidence(self) -> None:
        finding_id = self._reported()
        self._upgrade_and_resolve(finding_id)
        verified = self._history(finding_id)
        evidence = self._rows("SELECT * FROM finding_resolution_evidence ORDER BY 1")
        self._inventory(at(4), version="1.2.0")  # downgraded
        self._match(at(4), "affected", "installed-version-in-affected-range", installed="1.2.0")
        self._evaluate(at(4.5))
        state = self._state(finding_id)
        self.assertEqual((state["finding_status"], state["verification_state"]), ("active", "still-present"))
        self.assertIn("REOPENED_SINCE_REPORT", state["reason_codes"])
        history = self._history(finding_id)
        self.assertEqual(history[: len(verified)], verified)
        self.assertEqual(self._rows("SELECT * FROM finding_resolution_evidence ORDER BY 1"), evidence)

    def test_reopened_work_withdraws_the_report(self) -> None:
        finding_id = self._reported()
        done = self.work.get_work_item(finding_id)
        self.work.change_status(finding_id, actor="sam", status="open", expected_revision=done["revision"],
                                note="not fixed", at=at(1.5))
        self.assertEqual(self._state(finding_id)["verification_state"], "report-withdrawn")

    def test_baseline_failure_rolls_back_the_done_transition(self) -> None:
        self._evaluate(at(0.5))
        finding_id = self._finding_id()
        item = self.work.create_work_item(
            finding_id, actor="alex", owner_kind=None, owner_label=None, note=None, at=at(0.6)
        )
        with patch("app.finding_work_store.capture_baseline", side_effect=RuntimeError("baseline failed")):
            with self.assertRaises(RuntimeError):
                self.work.change_status(finding_id, actor="alex", status="done",
                                        expected_revision=item["revision"], note=None, at=at(1))
        self.assertEqual(self.work.get_work_item(finding_id)["work_status"], "open")
        self.assertEqual(self._rows("SELECT COUNT(*) AS n FROM finding_verification_baselines")[0]["n"], 0)

    def test_records_are_append_only_site_bound_and_cascade(self) -> None:
        finding_id = self._reported()
        self._upgrade_and_resolve(finding_id)
        for table in ("finding_verification_baselines", "finding_verification_history", "finding_resolution_evidence"):
            for statement in (f"UPDATE {table} SET site_id = site_id", f"DELETE FROM {table}", f"TRUNCATE {table}"):
                with self.subTest(statement=statement):
                    with self.assertRaises(DBAPIError) as raised:
                        self._exec(statement)
                    self.assertIn("append-only", str(raised.exception.orig))
        with self.assertRaises(IntegrityError):
            self._exec(
                "INSERT INTO finding_resolution_evidence (finding_id, site_id, resolved_at, evaluation_run_id,"
                " resolution_basis, evidence_ref, evidence_type, source, freshness)"
                " SELECT finding_id, 'site-b', NOW(), evaluation_run_id, 'component-removed', 'x', 'x', 'x', 'fresh'"
                " FROM finding_resolution_evidence"
            )
        with self.assertRaises(IntegrityError):
            self._exec(
                "INSERT INTO finding_resolution_evidence (finding_id, site_id, resolved_at, evaluation_run_id,"
                " resolution_basis, evidence_ref, evidence_type, source, freshness)"
                " SELECT finding_id, site_id, NOW(), evaluation_run_id, 'guessed', 'x', 'x', 'x', 'fresh'"
                " FROM finding_resolution_evidence"
            )
        self._exec("DELETE FROM findings WHERE finding_id = :f", f=finding_id)
        for table in ("finding_verification_baselines", "finding_verification_history", "finding_resolution_evidence"):
            self.assertEqual(self._rows(f"SELECT COUNT(*) AS n FROM {table}")[0]["n"], 0, table)

    def _real_collection(self, when: datetime, source: str, status: str, version: str | None) -> str:
        """Ingest one native source collection through production persistence."""

        import hashlib

        from app.component_intelligence import ComponentSourceSnapshot, NormalizedComponent
        from app.component_store import persist_authenticated_endpoint_source_presence, persist_components

        collection_id = "col_" + uuid4().hex
        self._exec(
            """
            INSERT INTO canonical_inventory_collections (
                canonical_collection_id, site_id, source_id, adapter_type, route_name, idempotency_key,
                payload_sha256, schema_version, observed_at, ingested_at, inventory_mode,
                observed_asset_count, canonical_asset_count, evidence_count, component_count,
                evaluation_state
            ) VALUES (:cid, 'site-a', :s, 'endpoint-agent', 'test', :cid, :sha, 'test.v1', :t, :t,
                      'complete', 1, 1, 1, 1, 'running')
            """,
            cid=collection_id, s=SOURCE_ID, sha="f" * 64, t=when,
        )
        digest = hashlib.sha256(
            "\x00".join((collection_id, "site-a", "asset-a", SOURCE_ID, source)).encode("utf-8")
        ).hexdigest()[:32]
        snapshot = ComponentSourceSnapshot(
            source_snapshot_id=f"css_{digest}", canonical_collection_id=collection_id, site_id="site-a",
            asset_id="asset-a", agent_source_id=SOURCE_ID, collection_source_id=source, platform="linux",
            collection_status=status, observed_at=when, record_count=0 if version is None else 1,
            truncated=status == "partial", error_code=None,
            limitations=() if status == "complete" else ("inventory truncated",),
        )
        components = []
        if version is not None:
            components.append(
                NormalizedComponent(
                    component_id=COMPONENT_ID, asset_id="asset-a", site_id="site-a", component_type="package",
                    ecosystem="pypi", namespace=None, vendor=None, name="example-agent",
                    normalized_name="example-agent", version=version, normalized_version=version,
                    architecture=None, package_manager=None, canonical_identifier=None, cpe_hint=None,
                    install_scope="system", source_type="endpoint-collector", source_id=SOURCE_ID,
                    firmware_evidence_type="direct", evidence_ids=(), observed_at=when, first_seen_at=at(0),
                    last_seen_at=when, freshness="fresh", confidence=1.0, normalization_status="normalized",
                    metadata={}, inventory_complete=status == "complete", collection_source_id=source,
                    source_record_id="pkg:example-agent", evidence_method="package-manager",
                )
            )
        with self.database_engine.begin() as connection:
            if components:
                persist_components(connection, components=components)
            persist_authenticated_endpoint_source_presence(
                connection, components=components, source_snapshots=[snapshot]
            )
        return snapshot.source_snapshot_id

    def test_partial_version_source_and_later_complete_omission_elsewhere_never_verify(self) -> None:
        # Two reviewed sources report the same canonical component. The partial
        # source supplies the new version; the other source's later complete
        # inventory omits it. That complete inventory neither supplied the
        # version nor established canonical absence (the component is still
        # present elsewhere), so it cannot support verification.
        finding_id = self._reported()
        self._real_collection(at(1.2), "linux-rpm", "complete", "1.2.0")
        partial = self._real_collection(at(1.5), "linux-dpkg", "partial", "1.4.2")
        omitting = self._real_collection(at(2), "linux-rpm", "complete", None)
        self._match(at(2), "fixed", "at-or-after-fixed-boundary", installed="1.4.2")
        (match,) = SqlVulnerabilityStore().active_match_snapshot(site_id="site-a")
        self.assertTrue(match["component_active"])
        self.assertNotEqual(match["component_source_snapshot_id"], omitting)
        self.assertEqual(match["component_source_snapshot_id"], partial)
        self._evaluate(at(2.5))
        state = self._state(finding_id)
        self.assertEqual(state["finding_status"], "resolved")
        self.assertNotEqual(state["verification_state"], "verified")
        self.assertEqual(state["verification_state"], "insufficient-evidence")
        self.assertIn("COLLECTION_INCOMPLETE_AT_RESOLUTION", state["reason_codes"])

    def test_ambiguous_supporting_observation_is_insufficient(self) -> None:
        # Two sources observe the component at the same instant: the exact
        # supporting collection cannot be established, so none is chosen.
        finding_id = self._reported()
        self._real_collection(at(2), "linux-rpm", "complete", "1.4.2")
        self._real_collection(at(2), "linux-dpkg", "complete", "1.4.2")
        self._match(at(2), "fixed", "at-or-after-fixed-boundary", installed="1.4.2")
        (match,) = SqlVulnerabilityStore().active_match_snapshot(site_id="site-a")
        self.assertIsNone(match["component_source_snapshot_id"])
        self._evaluate(at(2.5))
        state = self._state(finding_id)
        self.assertEqual(state["verification_state"], "insufficient-evidence")
        self.assertIn("COLLECTION_NOT_COMPLETE_AT_RESOLUTION", state["reason_codes"])

    def test_verification_never_changes_findings_risk_decisions_or_work(self) -> None:
        finding_id = self._reported()
        self._upgrade_and_resolve(finding_id)
        tables = ("findings", "finding_evidence", "asset_risk_scores", "finding_decisions",
                  "finding_decision_history", "finding_work_items", "vulnerability_matches")
        before = {table: self._rows(f"SELECT * FROM {table} ORDER BY 1") for table in tables}
        self.verification.get_verification(finding_id)
        self.verification.list_unverified()
        self.verification.list_history(finding_id)
        self.assertEqual({table: self._rows(f"SELECT * FROM {table} ORDER BY 1") for table in tables}, before)


if __name__ == "__main__":
    unittest.main()
