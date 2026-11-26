"""Gated PostgreSQL tests for security outcome metrics (CTEM-GAP-09).

History is produced by production code: finding evaluation (findings,
decisions, decision history, verification history and runs), work tracking
(work events and baselines), and the verification store. The remediation
verification harness supplies the inventory and match rows those paths read.
Metrics are read through `SqlOutcomeMetricsStore`, the same path the API uses.
"""

from __future__ import annotations

import os
import unittest
from datetime import timedelta
from typing import Any
from unittest.mock import patch

from tests import test_verification_postgres as gap06

from app.finding_service import evaluate_findings
from app.outcome_metrics_contracts import MetricResultResponse
from app.outcome_metrics_store import SqlOutcomeMetricsStore

ENABLED = os.getenv("OPENASSETWATCH_OUTCOME_METRICS_POSTGRES_TEST") == "1"
at = gap06.at


@unittest.skipUnless(ENABLED, "requires an explicitly isolated disposable PostgreSQL server")
class OutcomeMetricsPostgresTests(unittest.TestCase):
    def setUp(self) -> None:
        # Reuse the verification harness (disposable database, production
        # writers, inventory and match helpers) without re-running its tests.
        self.h = gap06.VerificationPostgresTests("test_projection_returns_observation_times_and_supporting_snapshot")
        self.h.setUp()
        # Histories are written at fixed times in the recent past; record the
        # sources as having started before them, as on a long-running system.
        self.h._exec("UPDATE public.oaw_schema_migrations SET applied_at = :t", t=at(-48))
        self.metrics = SqlOutcomeMetricsStore()

    def tearDown(self) -> None:
        self.h.tearDown()

    def m(self, metric_id: str, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("site_id", "site-a")
        return self.metrics.compute(metric_id, now=at(10), **kwargs)

    def window(self, metric_id: str, start: float = 0, end: float = 10, **kwargs: Any) -> dict[str, Any]:
        return self.m(metric_id, start=at(start), end=at(end), **kwargs)

    def _verified_report(self) -> str:
        finding_id = self.h._reported()  # evaluated at 0.5h, reported at 1h
        self.h._upgrade_and_resolve(finding_id)  # resolved and verified at 2.5h
        return finding_id

    def _site_b_finding(self) -> None:
        self.h._exec(
            "INSERT INTO control_tower_assets (asset_key, asset_id, site_id, hostname, first_seen_at,"
            " last_seen_at, observed_at, metadata_json)"
            " VALUES ('site-b:asset-b', 'asset-b', 'site-b', 'db02', :t, :t, :t, '{\"category\": \"server\"}')",
            t=at(0),
        )
        self.h._exec(
            """
            INSERT INTO asset_components (
                component_id, asset_id, site_id, component_type, ecosystem, name, normalized_name,
                version, normalized_version, install_scope, source_type, source_id,
                firmware_evidence_type, first_seen_at, last_seen_at, observed_at, freshness,
                confidence, normalization_status, model_version
            ) VALUES (:c, 'asset-b', 'site-b', 'package', 'pypi', 'example-agent', 'example-agent',
                      '1.2.0', '1.2.0', 'system', 'endpoint-collector', :s, 'direct', :t, :t, :t,
                      'fresh', 1.0, 'normalized', 'test')
            """,
            c="cmp_" + "9" * 32, s=gap06.SOURCE_ID, t=at(0),
        )
        self.h._exec(
            """
            INSERT INTO vulnerability_matches (
                match_id, asset_id, site_id, component_id, advisory_id, affected_id, match_status,
                match_confidence, installed_version, fixed_version, evaluated_at, reason_codes_json,
                engine_version, last_run_id
            ) VALUES (:m, 'asset-b', 'site-b', :c, :a, 'aff_1', 'affected', 1.0, '1.2.0', '1.4.2',
                      :t, '["installed-version-in-affected-range"]', 'test', 'vrun_1')
            """,
            m="vmt_" + "9" * 32, c="cmp_" + "9" * 32, a=gap06.ADVISORY_ID, t=at(0),
        )
        evaluate_findings(trigger_type="test", requested_by="unit-test", now=at(0.5), store=self.h.findings,
                          decision_store=self.h.decisions, verification_store=self.h.verification,
                          site_id="site-b", rule_ids=["vulnerable-component"])
        (item,) = self.h.findings.list_findings(site_id="site-b", rule_id="vulnerable-component")["items"]
        self.h._report_done(item["finding_id"], at(1))

    def _band(self) -> str:
        (row,) = self.h._rows("SELECT action_band FROM finding_decision_history WHERE revision = 1"
                              " AND site_id = 'site-a'")
        return row["action_band"]

    # ----------------------------------------------------------------- tests

    def test_verified_remediation_metrics_from_production_history(self) -> None:
        self._verified_report()
        self.assertEqual(self.window("remediation.reports")["total"]["value"], 1)
        verified = self.window("remediation.verified")
        self.assertEqual((verified["status"], verified["total"]["value"]), ("measured", 1))
        rate = self.window("remediation.verification-rate")["total"]
        self.assertEqual((rate["numerator"], rate["denominator"], rate["value"]), (1, 1, 1.0))
        from_report = self.window("remediation.time-to-verified-from-report")["total"]
        self.assertEqual((from_report["count"], from_report["value"]), (1, 1.5))  # 1h -> 2.5h
        states = {item["dimensions"]["verification_state"]: item["value"]
                  for item in self.window("remediation.outcomes-by-state")["breakdown"]}
        self.assertEqual((states["verified"], states["not-recorded"]), (1, 0))
        self.assertEqual(self.m("remediation.done-unverified")["total"]["value"], 0)

    def test_band_time_and_open_backlog_come_from_recorded_history(self) -> None:
        self._verified_report()
        band = self._band()
        episodes = self.window("findings.band-episode-duration")
        cell = {item["dimensions"]["action_band"]: item for item in episodes["breakdown"]}[band]
        self.assertEqual((cell["count"], cell["value"]), (1, 2.0))  # 0.5h -> resolved at 2.5h
        self.assertEqual(episodes["status"], "measured")
        open_now = self.m("findings.open-by-band")
        self.assertEqual((open_now["status"], open_now["total"]["value"]), ("measured", 0))
        # A window before the finding existed is a measured zero, not missing data.
        early = self.window("findings.band-transitions", start=-20, end=-10)
        self.assertEqual((early["status"], early["total"]["value"]), ("measured", 0))

    def test_reopened_after_verification_and_still_done_work(self) -> None:
        finding_id = self._verified_report()
        self.h._inventory(at(4), version="1.2.0")  # downgraded
        self.h._match(at(4), "affected", "installed-version-in-affected-range", installed="1.2.0")
        self.h._evaluate(at(4.5))
        reopened = self.window("findings.reopened")
        self.assertEqual(reopened["total"]["value"], 1)
        after = {item["dimensions"]["after_verification"]: item["value"] for item in reopened["breakdown"]}
        self.assertEqual(after, {"yes": 1, "no": 0})
        done = self.m("remediation.done-unverified")
        states = {item["dimensions"]["verification_state"]: item["value"] for item in done["breakdown"]}
        self.assertEqual((done["total"]["value"], states["still-present"]), (1, 1))
        # The report was verified at 2.5h; as of a window ending at 3h it still is.
        self.assertEqual(self.window("remediation.verification-rate", end=3)["total"]["value"], 1.0)
        self.assertEqual(self.window("remediation.verification-rate")["total"]["value"], 0.0)
        self.assertEqual(self.h.findings.get_finding(finding_id)["status"], "active")

    def test_repeated_reports_are_counted_once_each(self) -> None:
        finding_id = self.h._reported()  # report 1 at 1h
        item = self.h.work.get_work_item(finding_id)
        self.h.work.change_status(finding_id, actor="sam", status="open", expected_revision=item["revision"],
                                  note="not yet", at=at(1.5))
        self.h._evaluate(at(1.6))  # records the withdrawal
        self.h._report_done(finding_id, at(2))  # report 2
        self.h._evaluate(at(2.2))
        outcomes = self.window("remediation.outcomes-by-state")
        states = {cell["dimensions"]["verification_state"]: cell["value"] for cell in outcomes["breakdown"]}
        self.assertEqual(outcomes["total"]["value"], 2)
        self.assertEqual((states["report-withdrawn"], states["awaiting-evidence"]), (1, 1))
        self.assertEqual(self.window("remediation.reports")["total"]["value"], 2)
        rate = self.window("remediation.verification-rate")["total"]
        self.assertEqual((rate["numerator"], rate["denominator"], rate["value"]), (0, 1, 0.0))

    def test_report_superseded_without_an_evaluation_is_withdrawn(self) -> None:
        finding_id = self.h._reported()  # report at 1h, evaluated only at 0.5h
        item = self.h.work.get_work_item(finding_id)
        self.h.work.change_status(finding_id, actor="sam", status="open", expected_revision=item["revision"],
                                  note="not yet", at=at(1.5))
        self.h._report_done(finding_id, at(2))  # no evaluation between the two reports
        self.h._evaluate(at(2.2))
        states = {cell["dimensions"]["verification_state"]: cell["value"]
                  for cell in self.window("remediation.outcomes-by-state")["breakdown"]}
        self.assertEqual((states["report-withdrawn"], states["not-recorded"], states["awaiting-evidence"]), (1, 0, 1))
        self.assertEqual(self.window("quality.unmeasurable-outcomes")["total"]["value"], 0)

    def test_episode_that_began_before_the_window_keeps_its_recorded_start(self) -> None:
        self._verified_report()  # one episode: 0.5h -> 2.5h
        band = self._band()
        result = self.window("findings.band-episode-duration", start=2, end=10)
        cell = {item["dimensions"]["action_band"]: item for item in result["breakdown"]}[band]
        self.assertEqual((cell["count"], cell["value"]), (1, 2.0))
        before = self.window("findings.band-episode-duration", start=0, end=2)
        self.assertEqual((before["status"], before["coverage"]["ongoing_episodes"]), ("not-measured", 1))

    def test_advisory_change_is_never_verified_remediation(self) -> None:
        finding_id = self.h._reported()
        self.h._inventory(at(2))
        self.h._match(at(2), "advisory-withdrawn", "advisory-withdrawn-or-superseded")
        self.h._evaluate(at(2.5))
        self.assertEqual(self.h.findings.get_finding(finding_id)["status"], "resolved")
        verified = self.window("remediation.verified")
        self.assertEqual((verified["status"], verified["total"]["value"]), ("measured", 0))
        rate = self.window("remediation.verification-rate")
        self.assertEqual((rate["status"], rate["total"]["numerator"], rate["total"]["denominator"]),
                         ("measured", 0, 1))
        duration = self.window("remediation.time-to-verified-from-report")
        self.assertEqual((duration["status"], duration["total"]["value"]), ("not-measured", None))

    def test_failed_verification_runs_are_visible_and_degrade_verification_metrics(self) -> None:
        finding_id = self.h._reported()
        self.h._inventory(at(2), version="1.4.2")
        self.h._match(at(2), "fixed", "at-or-after-fixed-boundary", installed="1.4.2")
        with patch("app.verification_store.evaluate_verification", side_effect=RuntimeError("engine fault")):
            self.h._evaluate(at(2.5))
        coverage = self.window("quality.verification-run-coverage")
        statuses = {cell["dimensions"]["verification_status"]: cell["value"] for cell in coverage["breakdown"]}
        self.assertEqual(statuses["failed"], 1)
        self.assertEqual(statuses["completed"], coverage["total"]["value"] - 1)
        with patch("app.finding_service.calculate_risk", side_effect=RuntimeError("risk fault")):
            with self.assertRaises(RuntimeError):
                self.h._evaluate(at(3))
        failed = {cell["dimensions"]["verification_status"]: cell["value"]
                  for cell in self.window("quality.verification-run-coverage")["breakdown"]}
        self.assertEqual(failed["evaluation-failed"], 1)
        verified = self.window("remediation.verified")
        self.assertEqual((verified["status"], verified["total"]["value"]), ("partial", 0))
        self.assertIn("VERIFICATION_RUNS_DEGRADED", verified["status_reasons"])
        self.assertEqual(self.h.findings.get_finding(finding_id)["status"], "resolved")

    def test_history_starting_after_the_window_is_reported(self) -> None:
        self._verified_report()
        self.h._exec("UPDATE public.oaw_schema_migrations SET applied_at = :t", t=at(2))
        partial = self.window("remediation.reports")
        self.assertEqual(partial["status"], "partial")
        self.assertIn("HISTORY_STARTS_AFTER_WINDOW_START", partial["status_reasons"])
        none = self.window("remediation.reports", start=0, end=1.5)
        self.assertEqual((none["status"], none["total"]["value"]), ("not-measured", None))
        self.h._exec("UPDATE public.oaw_schema_migrations SET applied_at = NOW() + INTERVAL '1 day'")
        coverage = self.m("quality.history-coverage")
        cells = {cell["dimensions"]["source"]: cell for cell in coverage["breakdown"]}
        self.assertEqual((cells["decision-history"]["value"], cells["decision-history"]["denominator"]), (1, 1))
        self.assertEqual(coverage["status"], "partial")

    def test_sites_are_isolated(self) -> None:
        self._verified_report()
        self._site_b_finding()
        self.assertEqual(self.window("remediation.reports")["total"]["value"], 1)
        self.assertEqual(self.window("remediation.reports", site_id="site-b")["total"]["value"], 1)
        self.assertEqual(self.window("remediation.reports", site_id=None)["total"]["value"], 2)
        self.assertEqual(self.m("findings.open-by-band")["total"]["value"], 0)
        self.assertEqual(self.m("findings.open-by-band", site_id="site-b")["total"]["value"], 1)
        self.assertEqual(self.window("remediation.verified", site_id="site-b")["total"]["value"], 0)
        self.assertEqual(self.m("remediation.done-unverified", site_id="site-b")["total"]["value"], 1)
        self.assertEqual(self.m("findings.open-by-band", site_id="site-unknown")["total"]["value"], 0)

    def test_row_bound_makes_results_unavailable(self) -> None:
        self._verified_report()
        with patch("app.outcome_metrics_store.MAX_METRIC_ROWS", 0):
            result = self.window("remediation.reports")
        self.assertEqual((result["status"], result["total"]["value"]), ("unavailable", None))

    def test_every_metric_runs_and_reads_nothing_it_writes(self) -> None:
        from app.outcome_metrics import METRIC_DEFINITIONS

        self._verified_report()
        tables = ("findings", "finding_decisions", "finding_decision_history", "finding_work_items",
                  "finding_work_events", "finding_verification_history", "finding_verification_runs",
                  "finding_evaluation_runs", "oaw_schema_migrations")
        before = {table: self.h._rows(f"SELECT * FROM {table} ORDER BY 1") for table in tables}
        for definition in METRIC_DEFINITIONS:
            with self.subTest(metric=definition.metric_id):
                if definition.time_semantics == "window":
                    result = self.window(definition.metric_id)
                else:
                    result = self.m(definition.metric_id)
                self.assertIn(result["status"], {"measured", "partial", "not-measured"})
                self.assertEqual(result["metric_id"], definition.metric_id)
                self.assertEqual(result["source_freshness"][0]["source"], "finding-evaluation")
                MetricResultResponse.model_validate(result)
        self.assertEqual({table: self.h._rows(f"SELECT * FROM {table} ORDER BY 1") for table in tables}, before)


if __name__ == "__main__":
    unittest.main()
