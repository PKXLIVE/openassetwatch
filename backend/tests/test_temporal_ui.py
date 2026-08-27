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
            "observed history only",
            'id="trend-site"',
            'id="trend-metric"',
            'id="trend-window"',
            'id="load-temporal-trend"',
            'id="temporal-trend-chart"',
            'id="temporal-trend-buckets"',
            "/api/v1/temporal/metrics",
            "/api/v1/temporal/signals",
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
        chart = self.dashboard.split("function renderTemporalChart(series)", 1)[1].split(
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
        self.assertIn("[30, 90].includes", loader)
        self.assertIn("advisorHeaders()", loader)
        self.assertNotIn("tenant_id", loader)
        self.assertNotIn("group_by", loader)

    def test_untrusted_values_are_rendered_as_text(self) -> None:
        self.assertNotIn("innerHTML", self.dashboard)
        self.assertNotIn("insertAdjacentHTML", self.dashboard)
        self.assertIn("title.textContent", self.dashboard)
        self.assertIn("option.textContent", self.dashboard)

    def test_phase_two_and_three_visuals_are_explicitly_absent(self) -> None:
        section = self.dashboard.split(
            '<section id="environment-trends"',
            1,
        )[1].split('<section id="assets"', 1)[0]
        self.assertIn("Expected ranges", section)
        self.assertIn("not implemented", section)
        self.assertNotIn("expected-band", section)
        self.assertNotIn("anomaly-indicator", section)


if __name__ == "__main__":
    unittest.main()
