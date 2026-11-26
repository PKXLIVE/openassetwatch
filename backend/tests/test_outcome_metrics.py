"""Security outcome metrics (CTEM-GAP-09): catalog, windows, and calculations.

Expected values are worked out by hand from the fixtures below, not by
re-running the implementation's own logic.
"""

from __future__ import annotations

import ast
import re
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.outcome_metrics import (
    CATALOG_VERSION,
    METRIC_DEFINITIONS,
    METRICS_BY_ID,
    STATUS_REASONS,
    UNITS,
    MetricFilters,
    MetricInputs,
    catalog_public,
    compute_metric,
    percentile,
    resolve_window,
    validate_filters,
)

UTC = timezone.utc
T = datetime(2026, 11, 1, tzinfo=UTC)
NOW = T + timedelta(days=2)
WINDOW = (T, T + timedelta(hours=24))
SINCE = {
    "work-events": T - timedelta(days=90),
    "decision-history": T - timedelta(days=60),
    "verification-history": T - timedelta(days=30),
    "verification-runs": T - timedelta(days=30),
}


def h(hours: float) -> datetime:
    return T + timedelta(hours=hours)


def run(metric_id: str, inputs: MetricInputs, *, window=WINDOW, now=NOW, **filters):
    definition = METRICS_BY_ID[metric_id]
    resolved = resolve_window(
        definition,
        start=window[0] if definition.time_semantics == "window" else None,
        end=window[1] if definition.time_semantics == "window" else None,
        now=now,
    )
    return compute_metric(definition, window=resolved, filters=MetricFilters(**filters), inputs=inputs, now=now)


def by_dims(result) -> dict[tuple[tuple[str, str], ...], dict]:
    return {tuple(sorted(item["dimensions"].items())): item for item in result["breakdown"]}


def inputs(**values) -> MetricInputs:
    values.setdefault("recording_since", SINCE)
    return MetricInputs(**values)


# ------------------------------------------------------------------ fixtures


def decision_rows():
    # Finding A: plan from 0h (reason change at 2h keeps the band), act-now at
    # 5h, resolved at 9h. Created after decision history began.
    # Finding B: created before decision history began, so its first band
    # episode has an unknown start; plan at 1h, monitor at 3h, still open.
    # Finding C: two rows at the same instant (revision orders them): plan for
    # 0h, then prioritize until resolved at 6h.
    # Finding D: an episode that ended before the window starts.
    created_after = T - timedelta(days=1)
    created_before = T - timedelta(days=90)
    rows = [
        ("fnd_a", 1, h(0), "current", "plan", None, "initial", created_after),
        ("fnd_a", 2, h(2), "current", "plan", "plan", "inputs-changed", created_after),
        ("fnd_a", 3, h(5), "current", "act-now", "plan", "inputs-changed", created_after),
        ("fnd_a", 4, h(9), "not-current", None, "act-now", "finding-resolved", created_after),
        ("fnd_b", 1, h(1), "current", "plan", None, "initial", created_before),
        ("fnd_b", 2, h(3), "current", "monitor", "plan", "inputs-changed", created_before),
        ("fnd_c", 2, h(4), "current", "prioritize", "plan", "inputs-changed", created_after),
        ("fnd_c", 1, h(4), "current", "plan", None, "initial", created_after),
        ("fnd_c", 3, h(6), "not-current", None, "prioritize", "finding-resolved", created_after),
        ("fnd_d", 1, h(-10), "current", "plan", None, "initial", created_after),
        ("fnd_d", 2, h(-5), "not-current", None, "plan", "finding-resolved", created_after),
    ]
    keys = ("finding_id", "revision", "evaluated_at", "decision_state", "action_band", "previous_action_band",
            "transition_cause", "finding_created_at")
    return [dict(zip(keys, row)) for row in rows]


def report_rows():
    keys = ("work_item_id", "finding_id", "revision", "occurred_at", "finding_first_seen_at")
    return [
        dict(zip(keys, row))
        for row in (
            ("fwi_1", "fnd_1", 3, h(1), h(-48)),   # R1: verified at 5h
            ("fwi_1", "fnd_1", 6, h(10), h(-48)),  # R2: a repeated report, insufficient evidence
            ("fwi_2", "fnd_2", 2, h(2), h(-10)),   # R3: advisory change
            ("fwi_3", "fnd_3", 2, h(3), h(-10)),   # R4: never recorded
            ("fwi_4", "fnd_4", 2, h(4), h(-10)),   # R5: withdrawn
            ("fwi_5", "fnd_5", 2, h(-5), h(-30)),  # R6: reported before the window, verified inside it
        )
    ]


def history_rows():
    keys = ("work_item_id", "report_revision", "sequence", "verification_state", "evaluated_at")
    return [
        dict(zip(keys, row))
        for row in (
            ("fwi_1", 3, 1, "awaiting-evidence", h(1)),
            ("fwi_1", 3, 2, "verified", h(5)),
            ("fwi_1", 6, 1, "awaiting-evidence", h(10)),
            ("fwi_1", 6, 2, "insufficient-evidence", h(12)),
            ("fwi_2", 2, 1, "resolved-by-advisory-change", h(3)),
            ("fwi_4", 2, 1, "awaiting-evidence", h(4)),
            ("fwi_4", 2, 2, "report-withdrawn", h(6)),
            ("fwi_5", 2, 1, "awaiting-evidence", h(-5)),
            ("fwi_5", 2, 2, "verified", h(2)),
            # Recorded after the window end: never visible to this window.
            ("fwi_2", 2, 2, "verified", h(30)),
        )
    ]


def remediation_inputs(**extra) -> MetricInputs:
    return inputs(reports=report_rows(), verification_history=history_rows(), **extra)


# ------------------------------------------------------------------ catalog


class CatalogTests(unittest.TestCase):
    def test_every_definition_is_complete_versioned_and_unit_consistent(self) -> None:
        ids = [item.metric_id for item in METRIC_DEFINITIONS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 16)
        for item in METRIC_DEFINITIONS:
            with self.subTest(metric=item.metric_id):
                self.assertRegex(item.metric_id, r"^[a-z]+(\.[a-z][a-z0-9-]*)+$")
                self.assertGreaterEqual(item.version, 1)
                for text in (item.display_name, item.description, item.purpose, item.population,
                             item.counting_grain, item.freshness_requirement, item.missing_data_behavior):
                    self.assertTrue(text.strip())
                self.assertIn(item.unit, UNITS)
                self.assertTrue(item.source_records and item.required_evidence and item.limitations)
                self.assertIn(item.time_semantics, {"current", "window"})
                self.assertIn(item.value_kind, {"count", "ratio", "duration"})
                self.assertEqual(item.value_kind == "ratio", item.numerator is not None)
                self.assertEqual(item.value_kind == "ratio", item.denominator is not None)
                self.assertEqual(item.value_kind == "duration", item.unit == "hours")
                self.assertTrue(set(item.filters) <= {"site_id", "action_band", "verification_state"})
                self.assertIn("site_id", item.filters)

    def test_catalog_lists_every_metric_with_its_version(self) -> None:
        public = catalog_public()
        self.assertEqual(public["catalog_version"], CATALOG_VERSION)
        self.assertEqual([item["metric_id"] for item in public["metrics"]], sorted(METRICS_BY_ID))
        self.assertTrue(all(item["version"] >= 1 for item in public["metrics"]))
        self.assertTrue(public["status_reasons"])
        self.assertTrue(all(re.fullmatch(r"[A-Z][A-Z0-9_]+", code) for code in STATUS_REASONS))

    def test_verified_metrics_never_count_advisory_or_before_report_outcomes(self) -> None:
        for metric_id in ("remediation.verified", "remediation.verification-rate"):
            text = (METRICS_BY_ID[metric_id].description + " ".join(METRICS_BY_ID[metric_id].limitations)).lower()
            self.assertIn("advisory", text)


# ------------------------------------------------------------------ windows and filters


class WindowAndFilterTests(unittest.TestCase):
    def test_window_defaults_to_the_last_30_days_in_utc(self) -> None:
        window = resolve_window(METRICS_BY_ID["remediation.reports"], start=None, end=None, now=NOW)
        self.assertEqual((window.start, window.end), (NOW - timedelta(days=30), NOW))

    def test_invalid_windows_are_rejected(self) -> None:
        definition = METRICS_BY_ID["remediation.reports"]
        for start, end in (
            (T, T),  # empty
            (h(5), h(1)),  # reversed
            (T - timedelta(days=367), T),  # too long
            (T, NOW + timedelta(hours=1)),  # in the future
            (datetime(2026, 11, 1), T + timedelta(days=1)),  # naive
        ):
            with self.subTest(start=start, end=end):
                with self.assertRaises(ValueError):
                    resolve_window(definition, start=start, end=end, now=NOW)

    def test_current_metrics_reject_a_time_window(self) -> None:
        with self.assertRaises(ValueError):
            resolve_window(METRICS_BY_ID["findings.open-by-band"], start=T, end=None, now=NOW)
        window = resolve_window(METRICS_BY_ID["findings.open-by-band"], start=None, end=None, now=NOW)
        self.assertEqual((window.start, window.end), (None, NOW))

    def test_unsupported_or_invalid_filters_are_rejected(self) -> None:
        for metric_id, filters in (
            ("remediation.reports", MetricFilters(action_band="plan")),
            ("findings.open-by-band", MetricFilters(verification_state="verified")),
            ("findings.open-by-band", MetricFilters(action_band="urgent")),
            ("remediation.outcomes-by-state", MetricFilters(verification_state="done")),
            ("findings.open-by-band", MetricFilters(site_id="")),
        ):
            with self.subTest(metric=metric_id, filters=filters):
                with self.assertRaises(ValueError):
                    validate_filters(METRICS_BY_ID[metric_id], filters)
        validate_filters(METRICS_BY_ID["findings.open-by-band"], MetricFilters(site_id="site-a", action_band="plan"))

    def test_percentile_interpolates_between_closest_ranks(self) -> None:
        self.assertEqual(percentile([4.0, 1.0, 3.0, 2.0], 0.5), 2.5)
        self.assertAlmostEqual(percentile([1.0, 2.0, 3.0, 4.0], 0.9), 3.7)
        self.assertEqual(percentile([7.0], 0.9), 7.0)


# ------------------------------------------------------------------ findings and bands


class FindingMetricTests(unittest.TestCase):
    def test_open_findings_by_band_counts_each_finding_once(self) -> None:
        rows = [
            {"finding_id": "fnd_1", "action_band": "act-now", "first_seen_at": h(-30), "evidence_freshness": "fresh"},
            {"finding_id": "fnd_2", "action_band": "plan", "first_seen_at": h(-20), "evidence_freshness": "stale"},
            {"finding_id": "fnd_3", "action_band": "plan", "first_seen_at": h(-10), "evidence_freshness": "fresh"},
            {"finding_id": "fnd_4", "action_band": None, "first_seen_at": h(-5), "evidence_freshness": "unknown"},
        ]
        result = run("findings.open-by-band", inputs(open_findings=rows))
        self.assertEqual((result["status"], result["total"]["value"]), ("measured", 4))
        bands = {item["dimensions"]["action_band"]: item["value"] for item in result["breakdown"]}
        self.assertEqual(bands, {"act-now": 1, "prioritize": 0, "plan": 2, "monitor": 0, "no-current-decision": 1})
        filtered = run("findings.open-by-band", inputs(open_findings=rows), action_band="plan")
        self.assertEqual(filtered["total"]["value"], 2)
        freshness = run("quality.evidence-freshness", inputs(open_findings=rows))
        self.assertEqual({item["dimensions"]["evidence_freshness"]: item["value"] for item in freshness["breakdown"]},
                         {"fresh": 2, "aging": 0, "stale": 1, "unknown": 1})

    def test_measured_zero_is_distinct_from_not_measured(self) -> None:
        zero = run("findings.open-by-band", inputs(open_findings=[]))
        self.assertEqual((zero["status"], zero["total"]["value"]), ("measured", 0))
        empty = run("findings.backlog-age-by-band", inputs(open_findings=[]))
        self.assertEqual((empty["status"], empty["total"]["value"], empty["total"]["count"]), ("not-measured", None, 0))
        self.assertIn("NO_POPULATION", empty["status_reasons"])

    def test_backlog_age_is_measured_from_first_detection(self) -> None:
        now = T
        rows = [
            {"finding_id": "fnd_1", "action_band": "plan", "first_seen_at": now - timedelta(hours=10), "evidence_freshness": "fresh"},
            {"finding_id": "fnd_2", "action_band": "plan", "first_seen_at": now - timedelta(hours=20), "evidence_freshness": "fresh"},
            {"finding_id": "fnd_3", "action_band": "act-now", "first_seen_at": now - timedelta(hours=30), "evidence_freshness": "fresh"},
        ]
        result = run("findings.backlog-age-by-band", inputs(open_findings=rows), now=now)
        plan = {item["dimensions"]["action_band"]: item for item in result["breakdown"]}["plan"]
        self.assertEqual((plan["count"], plan["value"], plan["p90"], plan["max"]), (2, 15.0, 19.0, 20.0))
        self.assertEqual((result["total"]["count"], result["total"]["value"]), (3, 20.0))

    def test_band_episodes_come_from_recorded_transitions_only(self) -> None:
        result = run("findings.band-episode-duration", inputs(decision_history=decision_rows()))
        bands = {item["dimensions"]["action_band"]: item for item in result["breakdown"]}
        # A: plan 0h-5h (the 2h reason change keeps the episode) and act-now 5h-9h.
        # C: plan 0h at 4h (same instant, by revision), prioritize 4h-6h.
        # B's plan episode (1h-3h) starts with the first row of a finding that
        # existed before history began: its true start is unknown, so excluded.
        # D's episode ended before the window.
        self.assertEqual((bands["plan"]["count"], bands["plan"]["value"], bands["plan"]["max"]), (2, 2.5, 5.0))
        self.assertEqual((bands["act-now"]["count"], bands["act-now"]["value"]), (1, 4.0))
        self.assertEqual((bands["prioritize"]["count"], bands["prioritize"]["value"]), (1, 2.0))
        self.assertEqual((bands["monitor"]["count"], bands["monitor"]["value"]), (0, None))
        self.assertEqual(result["coverage"]["ongoing_episodes"], 1)  # B in monitor
        self.assertEqual(result["coverage"]["left_censored_episodes"], 1)
        self.assertEqual(result["status"], "partial")
        self.assertIn("EPISODE_START_UNRECORDED", result["status_reasons"])
        only_plan = run("findings.band-episode-duration", inputs(decision_history=decision_rows()), action_band="plan")
        self.assertEqual(only_plan["total"]["count"], 2)

    def test_band_transitions_count_recorded_band_changes(self) -> None:
        result = run("findings.band-transitions", inputs(decision_history=decision_rows()))
        self.assertEqual(result["total"]["value"], 3)
        cells = by_dims(result)
        self.assertEqual(cells[(("direction", "escalation"), ("from_band", "plan"), ("to_band", "act-now"))]["value"], 1)
        self.assertEqual(cells[(("direction", "escalation"), ("from_band", "plan"), ("to_band", "prioritize"))]["value"], 1)
        self.assertEqual(cells[(("direction", "de-escalation"), ("from_band", "plan"), ("to_band", "monitor"))]["value"], 1)

    def test_reopened_findings_are_distinct_and_attributed_by_prior_verification(self) -> None:
        rows = [
            {"finding_id": "fnd_x", "revision": 3, "evaluated_at": h(10), "decision_state": "current", "action_band": "plan",
             "previous_action_band": None, "transition_cause": "finding-reopened", "finding_created_at": h(-100)},
            {"finding_id": "fnd_x", "revision": 5, "evaluated_at": h(20), "decision_state": "current", "action_band": "plan",
             "previous_action_band": None, "transition_cause": "finding-reopened", "finding_created_at": h(-100)},
            {"finding_id": "fnd_y", "revision": 2, "evaluated_at": h(12), "decision_state": "current", "action_band": "plan",
             "previous_action_band": None, "transition_cause": "finding-reopened", "finding_created_at": h(-100)},
            {"finding_id": "fnd_z", "revision": 2, "evaluated_at": h(30), "decision_state": "current", "action_band": "plan",
             "previous_action_band": None, "transition_cause": "finding-reopened", "finding_created_at": h(-100)},
        ]
        # X was verified at 15h, before its second reopen; Y only after its reopen.
        # W reopened in the same run as a ruleset change: the transition is
        # recorded as ruleset-changed, but the decision went not-current -> current.
        rows.append({"finding_id": "fnd_w", "revision": 4, "evaluated_at": h(8), "decision_state": "current",
                     "action_band": "plan", "previous_action_band": None, "previous_decision_state": "not-current",
                     "transition_cause": "ruleset-changed", "finding_created_at": h(-100)})
        verified = {"fnd_x": [h(15)], "fnd_y": [h(13)]}
        result = run("findings.reopened", inputs(decision_history=rows, verified_times=verified))
        self.assertEqual(result["total"]["value"], 3)
        after = {item["dimensions"]["after_verification"]: item["value"] for item in result["breakdown"]}
        self.assertEqual(after, {"yes": 1, "no": 2})


# ------------------------------------------------------------------ remediation outcomes


class RemediationMetricTests(unittest.TestCase):
    def test_reports_count_each_completion_report_in_the_window(self) -> None:
        result = run("remediation.reports", remediation_inputs())
        self.assertEqual((result["status"], result["total"]["value"]), ("measured", 5))

    def test_outcomes_use_the_latest_recorded_state_as_of_the_window_end(self) -> None:
        result = run("remediation.outcomes-by-state", remediation_inputs())
        states = {item["dimensions"]["verification_state"]: item["value"] for item in result["breakdown"]}
        self.assertEqual(states["verified"], 1)
        self.assertEqual(states["insufficient-evidence"], 1)
        # The verified row recorded after the window end is not visible.
        self.assertEqual(states["resolved-by-advisory-change"], 1)
        self.assertEqual(states["report-withdrawn"], 1)
        self.assertEqual(states["not-recorded"], 1)
        self.assertEqual(states["awaiting-evidence"], 0)
        self.assertEqual(result["total"]["value"], 5)
        self.assertEqual(result["status"], "partial")
        self.assertIn("OUTCOME_NOT_RECORDED", result["status_reasons"])
        only = run("remediation.outcomes-by-state", remediation_inputs(), verification_state="verified")
        self.assertEqual(only["total"]["value"], 1)

    def test_verified_outcomes_count_each_report_once_and_exclude_advisory_changes(self) -> None:
        result = run("remediation.verified", remediation_inputs())
        # R1 (verified at 5h) and R6 (reported earlier, verified at 2h). R1 has
        # two history rows and is still counted once; R3's advisory change and
        # its later verified row (after the window) are not counted.
        self.assertEqual(result["total"]["value"], 2)

    def test_verification_rate_has_an_explicit_denominator(self) -> None:
        result = run("remediation.verification-rate", remediation_inputs())
        total = result["total"]
        # Reports in the window with a recorded outcome other than withdrawn:
        # R1 (verified), R2 (insufficient), R3 (advisory change). R4 has no
        # recorded outcome and is reported as a coverage gap.
        self.assertEqual((total["numerator"], total["denominator"]), (1, 3))
        self.assertAlmostEqual(total["value"], 1 / 3)
        self.assertEqual(result["coverage"]["not_recorded"], 1)
        self.assertEqual(result["status"], "partial")
        none = run("remediation.verification-rate", inputs(reports=[], verification_history=[]))
        self.assertEqual((none["status"], none["total"]["value"], none["total"]["denominator"]), ("not-measured", None, 0))

    def test_time_to_verified_resolution(self) -> None:
        from_report = run("remediation.time-to-verified-from-report", remediation_inputs())
        # R1: 1h -> 5h = 4h; R6: -5h -> 2h = 7h.
        self.assertEqual((from_report["total"]["count"], from_report["total"]["value"]), (2, 5.5))
        from_detection = run("remediation.time-to-verified-from-detection", remediation_inputs())
        # R1: -48h -> 5h = 53h; R6: -30h -> 2h = 32h.
        self.assertEqual((from_detection["total"]["count"], from_detection["total"]["value"], from_detection["total"]["max"]),
                         (2, 42.5, 53.0))

    def test_unmeasurable_outcomes(self) -> None:
        result = run("quality.unmeasurable-outcomes", remediation_inputs())
        reasons = {item["dimensions"]["verification_state"]: item["value"] for item in result["breakdown"]}
        self.assertEqual(result["total"]["value"], 2)
        self.assertEqual((reasons["insufficient-evidence"], reasons["not-recorded"]), (1, 1))

    def test_report_superseded_before_any_evaluation_is_withdrawn_not_unrecorded(self) -> None:
        # Work marked done at 1h, reopened at 2h, done again at 3h, with no
        # evaluation in between: the first report never got a history row.
        # The recorded work event that left done withdraws it.
        reports = [
            {"work_item_id": "fwi_9", "finding_id": "fnd_9", "revision": 2, "occurred_at": h(1),
             "finding_first_seen_at": h(-10), "left_done_at": h(2)},
            {"work_item_id": "fwi_9", "finding_id": "fnd_9", "revision": 4, "occurred_at": h(3),
             "finding_first_seen_at": h(-10), "left_done_at": None},
        ]
        history = [{"work_item_id": "fwi_9", "report_revision": 4, "sequence": 1,
                    "verification_state": "insufficient-evidence", "evaluated_at": h(4)}]
        values = inputs(reports=reports, verification_history=history)
        states = {item["dimensions"]["verification_state"]: item["value"]
                  for item in run("remediation.outcomes-by-state", values)["breakdown"]}
        self.assertEqual((states["report-withdrawn"], states["not-recorded"], states["insufficient-evidence"]), (1, 0, 1))
        rate = run("remediation.verification-rate", values)
        self.assertEqual((rate["status"], rate["total"]["denominator"]), ("measured", 1))
        self.assertEqual(run("quality.unmeasurable-outcomes", values)["total"]["value"], 1)
        # A report that left done only after the window end is not withdrawn in it.
        later = [dict(reports[0], left_done_at=h(30))]
        result = run("remediation.outcomes-by-state", inputs(reports=later))
        self.assertEqual(result["total"]["value"], 1)
        self.assertIn("OUTCOME_NOT_RECORDED", result["status_reasons"])

    def test_verified_counts_are_partial_when_reports_have_no_recorded_outcome(self) -> None:
        reports = [{"work_item_id": "fwi_8", "finding_id": "fnd_8", "revision": 2, "occurred_at": h(1),
                    "finding_first_seen_at": h(-10)}]
        for metric_id in ("remediation.verified", "remediation.time-to-verified-from-report",
                          "remediation.time-to-verified-from-detection"):
            with self.subTest(metric=metric_id):
                result = run(metric_id, inputs(reports=reports))
                self.assertIn("OUTCOME_NOT_RECORDED", result["status_reasons"])
                self.assertNotEqual(result["status"], "measured")

    def test_done_but_unverified_work_items(self) -> None:
        items = [
            {"work_item_id": "fwi_1", "finding_id": "fnd_1", "report_revision": 6, "verification_state": "insufficient-evidence"},
            {"work_item_id": "fwi_2", "finding_id": "fnd_2", "report_revision": 2, "verification_state": "verified"},
            {"work_item_id": "fwi_3", "finding_id": "fnd_3", "report_revision": 2, "verification_state": None},
        ]
        result = run("remediation.done-unverified", inputs(done_items=items))
        self.assertEqual(result["total"]["value"], 2)
        states = {item["dimensions"]["verification_state"]: item["value"] for item in result["breakdown"]}
        self.assertEqual((states["insufficient-evidence"], states["not-recorded"], states.get("verified")), (1, 1, None))


# ------------------------------------------------------------------ measurement quality and states


class MeasurementStateTests(unittest.TestCase):
    def test_history_starting_inside_or_after_the_window_is_not_hidden(self) -> None:
        late = dict(SINCE, **{"work-events": h(12)})
        partial = run("remediation.reports", remediation_inputs(recording_since=late))
        self.assertEqual(partial["status"], "partial")
        self.assertIn("HISTORY_STARTS_AFTER_WINDOW_START", partial["status_reasons"])
        after = dict(SINCE, **{"work-events": h(30)})
        none = run("remediation.reports", remediation_inputs(recording_since=after))
        self.assertEqual((none["status"], none["total"]["value"]), ("not-measured", None))
        self.assertIn("NO_HISTORY_IN_WINDOW", none["status_reasons"])
        missing = dict(SINCE, **{"work-events": None})
        unavailable = run("remediation.reports", remediation_inputs(recording_since=missing))
        self.assertEqual((unavailable["status"], unavailable["total"]["value"]), ("unavailable", None))
        self.assertIn("SOURCE_NOT_AVAILABLE", unavailable["status_reasons"])

    def test_row_limit_makes_a_result_unavailable_rather_than_wrong(self) -> None:
        result = run("remediation.reports", remediation_inputs(truncated=True))
        self.assertEqual((result["status"], result["total"]["value"]), ("unavailable", None))
        self.assertIn("ROW_LIMIT_EXCEEDED", result["status_reasons"])
        self.assertEqual(result["breakdown"], [])

    def test_failed_or_incomplete_verification_runs_degrade_verification_metrics(self) -> None:
        result = run("remediation.verified", remediation_inputs(degraded_verification_runs=2))
        self.assertEqual(result["status"], "partial")
        self.assertIn("VERIFICATION_RUNS_DEGRADED", result["status_reasons"])
        self.assertEqual(result["coverage"]["degraded_verification_runs"], 2)
        # Metrics that do not read verification history are unaffected.
        self.assertEqual(run("remediation.reports", remediation_inputs(degraded_verification_runs=2))["status"], "measured")

    def test_verification_run_coverage(self) -> None:
        runs = [{"run_id": f"frun_{i}", "started_at": h(i), "run_status": "completed", "verification_status": status}
                for i, status in enumerate(("completed", "completed", "failed", "incomplete", None))]
        # A failed evaluation run never reached verification at all.
        runs.append({"run_id": "frun_9", "started_at": h(9), "run_status": "failed", "verification_status": None})
        result = run("quality.verification-run-coverage", inputs(evaluation_runs=runs))
        statuses = {item["dimensions"]["verification_status"]: item["value"] for item in result["breakdown"]}
        self.assertEqual(result["total"]["value"], 6)
        self.assertEqual(statuses, {"completed": 2, "incomplete": 1, "failed": 1, "not-recorded": 1,
                                    "evaluation-failed": 1})
        self.assertEqual(result["status"], "measured")

    def test_history_coverage_reports_findings_older_than_each_source(self) -> None:
        rows = [
            {"source": "decision-history", "findings_total": 10, "findings_before": 4},
            {"source": "verification-history", "findings_total": 10, "findings_before": 0},
        ]
        result = run("quality.history-coverage", inputs(history_coverage=rows))
        cells = {item["dimensions"]["source"]: item for item in result["breakdown"]}
        self.assertEqual((cells["decision-history"]["value"], cells["decision-history"]["denominator"]), (4, 10))
        self.assertEqual(cells["verification-history"]["value"], 0)
        self.assertEqual(result["total"]["value"], 4)


class BoundaryTests(unittest.TestCase):
    def test_metric_modules_are_read_only(self) -> None:
        root = Path(__file__).resolve().parents[1] / "app"
        sql = (root / "outcome_metrics_store.py").read_text(encoding="utf-8").upper()
        writes = re.findall(
            r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|TRUNCATE\s+\w|ALTER\s+\w|DROP\s+\w|CREATE\s+\w|GRANT\s)",
            sql,
        )
        self.assertEqual(writes, [])
        self.assertIn("SET TRANSACTION READ ONLY", sql)
        engine = ast.parse((root / "outcome_metrics.py").read_text(encoding="utf-8"))
        imported = {
            node.module if isinstance(node, ast.ImportFrom) else alias.name
            for node in ast.walk(engine)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in (node.names if isinstance(node, ast.Import) else [None])
        }
        self.assertFalse({"sqlalchemy", "requests", "httpx", "socket"} & {str(item).split(".")[0] for item in imported})


if __name__ == "__main__":
    unittest.main()
