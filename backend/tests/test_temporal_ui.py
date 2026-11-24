from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = REPO_ROOT / "backend" / "app" / "static" / "index.html"


class TemporalUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dashboard = DASHBOARD.read_text(encoding="utf-8")

    def test_environment_trends_is_a_read_only_navigation_view(self) -> None:
        expected = (
            'href="#environment-trends"',
            'id="environment-trends" class="view-section"',
            "Environment Trends",
            "observed + expected context",
            'id="trend-site"',
            'id="trend-metric"',
            'id="trend-window"',
            'id="load-temporal-trend"',
            'id="temporal-trend-chart"',
            'id="temporal-trend-buckets"',
            "/api/v1/temporal/metrics",
            "/api/v1/temporal/signals",
            "/api/v1/temporal/expectations",
            "/api/v1/temporal/deviation-assessments",
            'id="temporal-deviation-assessment"',
            'id="trend-deviation-state"',
            'id="trend-deviation-persistence"',
            'id="trend-deviation-provenance"',
        )
        for value in expected:
            with self.subTest(value=value):
                self.assertIn(value, self.dashboard)

    def test_metric_options_come_from_the_server_registry(self) -> None:
        self.assertIn("async function loadTemporalRegistry()", self.dashboard)
        self.assertIn("renderTemporalMetricOptions(metrics)", self.dashboard)
        self.assertIn("metric.metric_key", self.dashboard)
        self.assertNotIn(
            '<option value="site.assets.new.count">',
            self.dashboard,
        )

    def test_rendering_distinguishes_zero_missing_incomplete_and_stale(self) -> None:
        presentation = self.dashboard.split(
            "function temporalPointPresentation(signal)",
            1,
        )[1].split("function temporalNumericValue", 1)[0]
        self.assertIn('label: "Incomplete"', presentation)
        self.assertIn("signal.data_quality === \"incomplete\"", presentation)
        self.assertIn(
            "signal.value === null || signal.value === undefined",
            presentation,
        )
        self.assertIn('label: "Missing"', presentation)
        self.assertIn("!signal.complete", presentation)
        self.assertIn('signal.freshness === "stale"', presentation)
        self.assertIn('label: "Stale"', presentation)
        self.assertIn('label: "Observed"', presentation)
        self.assertNotIn("signal.value || 0", self.dashboard)

    def test_missing_buckets_break_chart_segments_instead_of_becoming_zero(self) -> None:
        chart = self.dashboard.split("function renderTemporalChart(series, expectation)", 1)[1].split(
            "function renderTemporalSeries",
            1,
        )[0]
        self.assertIn("if (value === null)", chart)
        self.assertIn("previous = null", chart)
        self.assertIn("Every requested bucket is missing", chart)

    def test_series_request_is_site_scoped_bounded_and_daily(self) -> None:
        loader = self.dashboard.split("async function loadTemporalTrend()", 1)[1].split(
            "function setupTemporalTrends",
            1,
        )[0]
        self.assertIn("site_id: siteId", loader)
        self.assertIn('granularity: "daily"', loader)
        self.assertIn("target_start: window.targetStart", loader)
        self.assertNotIn("Promise.all", loader)
        self.assertIn("[30, 90].includes", loader)
        self.assertIn("advisorHeaders()", loader)
        self.assertNotIn("tenant_id", loader)
        self.assertNotIn("group_by", loader)
        self.assertIn("assessmentTargetStart", loader)
        self.assertIn("endpoints.temporalDeviation", loader)
        series_index = loader.index("endpoints.temporalSignals")
        expectation_index = loader.index("endpoints.temporalExpectation")
        deviation_index = loader.index("endpoints.temporalDeviation")
        self.assertLess(series_index, expectation_index)
        self.assertLess(expectation_index, deviation_index)
        self.assertIn("let deviationAvailable = false", loader)
        self.assertIn("Assessment unavailable; observed history and expected context remain visible.", loader)
        for forbidden in (
            "direction:",
            "persistence:",
            "confidence_threshold",
            "quality_threshold",
            "method:",
            "formula:",
            "severity:",
            "risk:",
        ):
            self.assertNotIn(forbidden, loader)

    def test_untrusted_values_are_rendered_as_text(self) -> None:
        self.assertNotIn("innerHTML", self.dashboard)
        self.assertNotIn("insertAdjacentHTML", self.dashboard)
        self.assertIn("title.textContent", self.dashboard)
        self.assertIn("option.textContent", self.dashboard)

    def test_expected_range_is_visible_without_phase_three_authority(self) -> None:
        section = self.dashboard.split(
            '<section id="environment-trends"',
            1,
        )[1].split('<section id="assets"', 1)[0]
        self.assertIn("Expected ranges", section)
        self.assertIn('id="trend-expected-range"', section)
        self.assertIn('id="trend-expectation-method"', section)
        self.assertIn('id="trend-expectation-confidence"', section)
        self.assertIn('id="trend-expectation-quality"', section)
        self.assertIn("analytical context only", section)
        self.assertIn("current open UTC bucket never enters baseline history", section)
        chart = self.dashboard.split(
            "function renderTemporalChart(series, expectation)",
            1,
        )[1].split("function renderTemporalSeries", 1)[0]
        self.assertIn('class: "expected-band"', chart)
        self.assertIn("expectation.lower", chart)
        self.assertIn("expectation.upper", chart)
        self.assertNotIn("anomaly-indicator", section)
        self.assertNotIn("deviation-indicator", section)

    def test_deviation_assessment_uses_latest_closed_bucket_and_neutral_states(self) -> None:
        window = self.dashboard.split("function temporalUtcWindow(days)", 1)[1].split(
            "function temporalPointPresentation",
            1,
        )[0]
        self.assertIn("assessmentTargetStart", window)
        self.assertIn("assessmentTargetStart.setUTCDate(assessmentTargetStart.getUTCDate() - 1)", window)

        renderer = self.dashboard.split(
            "function temporalDeviationStateText(stateValue)",
            1,
        )[1].split("async function loadTemporalRegistry", 1)[0]
        for state in (
            "blocked",
            "within-range",
            "outside-policy-direction",
            "pending-persistence",
            "candidate",
        ):
            self.assertIn(f'"{state}"', renderer)
        for phrase in (
            "Assessment unavailable",
            "Within expected historical range",
            "Outside expected range",
            "Persistence requirement not yet met",
            "Review candidate",
            "Above expected range",
            "Below expected range",
        ):
            self.assertIn(phrase, renderer)

    def test_blocked_assessment_does_not_fabricate_distance_or_provenance(self) -> None:
        renderer = self.dashboard.split(
            "function renderTemporalDeviationAssessment(assessment",
            1,
        )[1].split("async function loadTemporalRegistry", 1)[0]
        self.assertIn('setText("trend-deviation-distance", "not available")', renderer)
        self.assertIn('setText("trend-deviation-relative", "not available")', renderer)
        self.assertIn("Observation and expectation provenance are unavailable", renderer)
        self.assertIn("assessment.distance_beyond_bound !== null", renderer)
        self.assertIn("assessment.relative_change !== null", renderer)

    def test_deviation_language_is_non_authoritative_and_has_no_automatic_action(self) -> None:
        section = self.dashboard.split(
            '<section id="temporal-deviation-assessment"',
            1,
        )[1].split('<section id="assets"', 1)[0]
        lower = section.lower()
        self.assertIn("deterministic investigation context", lower)
        for prohibited in (
            "confirmed anomaly",
            "alert",
            "incident",
            "breach",
            "malicious",
            "compromised",
            "attack detected",
            "critical",
            "high severity",
            "remediation required",
        ):
            self.assertNotIn(prohibited, lower)
        loader = self.dashboard.split("async function loadTemporalTrend()", 1)[1].split(
            "function setupTemporalTrends",
            1,
        )[0]
        self.assertNotIn("setInterval", loader)
        self.assertNotIn("setTimeout", loader)
        self.assertNotIn("POST", loader)
        self.assertNotIn("save", loader.lower())
        self.assertNotIn("openInvestigation", loader)


if __name__ == "__main__":
    unittest.main()
