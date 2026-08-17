from __future__ import annotations

import unittest
from datetime import datetime, timezone

from app.risk import (
    FORMULA_VERSION,
    RiskConfig,
    calculate_risk,
    load_risk_config,
)


NOW = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)


def finding(
    finding_id: str,
    *,
    asset_id: str | None,
    severity: str,
    confidence: float = 1.0,
    freshness: str = "fresh",
    category: str = "coverage",
    site_id: str = "site-a",
    status: str = "active",
) -> dict:
    return {
        "finding_id": finding_id,
        "site_id": site_id,
        "asset_id": asset_id,
        "title": finding_id,
        "severity": severity,
        "confidence": confidence,
        "evidence_freshness": freshness,
        "category": category,
        "status": status,
    }


class DeterministicRiskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sites = [{"site_id": "site-a", "name": "Site A"}]
        self.assets = [
            {"site_id": "site-a", "asset_id": "asset-a", "observed_at": NOW},
            {"site_id": "site-a", "asset_id": "asset-b", "observed_at": NOW},
        ]

    def test_severity_confidence_and_freshness_are_independent_inputs(self) -> None:
        findings = [
            finding("fresh-high", asset_id="asset-a", severity="high", confidence=1.0),
            finding(
                "stale-high",
                asset_id="asset-b",
                severity="high",
                confidence=0.5,
                freshness="stale",
            ),
        ]

        asset_scores, _ = calculate_risk(sites=self.sites, assets=self.assets, findings=findings)
        by_asset = {item.asset_id: item for item in asset_scores}

        self.assertGreater(by_asset["asset-a"].score, by_asset["asset-b"].score)
        self.assertEqual(by_asset["asset-a"].factors[0].severity, "high")
        self.assertEqual(by_asset["asset-b"].factors[0].freshness, "stale")

    def test_duplicate_category_contributions_diminish_and_cap(self) -> None:
        findings = [
            finding(f"coverage-{index}", asset_id="asset-a", severity="critical")
            for index in range(8)
        ]

        asset_scores, _ = calculate_risk(sites=self.sites, assets=self.assets, findings=findings)
        score = next(item for item in asset_scores if item.asset_id == "asset-a")

        self.assertLessEqual(score.score, 30)
        adjusted = [factor.adjusted_weight for factor in score.factors]
        self.assertGreater(adjusted[0], adjusted[1])
        self.assertEqual(sum(adjusted), 30.0)

    def test_suppressed_and_resolved_findings_do_not_contribute(self) -> None:
        findings = [
            finding("active", asset_id="asset-a", severity="medium"),
            finding("suppressed", asset_id="asset-a", severity="critical", status="suppressed"),
            finding("resolved", asset_id="asset-a", severity="critical", status="resolved"),
        ]

        asset_scores, _ = calculate_risk(sites=self.sites, assets=self.assets, findings=findings)
        score = next(item for item in asset_scores if item.asset_id == "asset-a")

        self.assertEqual(score.finding_count, 1)
        self.assertEqual([factor.finding_id for factor in score.factors], ["active"])

    def test_site_score_is_portfolio_based_not_a_blind_sum(self) -> None:
        findings = [
            finding("high-a", asset_id="asset-a", severity="critical", category="identity"),
            finding("high-b", asset_id="asset-b", severity="critical", category="identity"),
        ]

        asset_scores, site_scores = calculate_risk(
            sites=self.sites,
            assets=self.assets,
            findings=findings,
        )
        site_score = site_scores[0]

        self.assertLessEqual(site_score.score, max(item.score for item in asset_scores))
        self.assertNotEqual(site_score.score, sum(item.score for item in asset_scores))
        self.assertEqual([factor.label for factor in site_score.factors[:3]], [
            "Highest asset risk",
            "Upper-quartile asset risk",
            "Top-ten asset risk average",
        ])

    def test_site_sensor_finding_breakdown_uses_actual_headroom_contribution(self) -> None:
        findings = [
            finding(
                "sensor-stale",
                asset_id=None,
                severity="medium",
                category="freshness",
            )
        ]

        _, site_scores = calculate_risk(
            sites=self.sites,
            assets=self.assets,
            findings=findings,
        )
        site_score = site_scores[0]
        direct = [factor for factor in site_score.factors if factor.factor_type == "site-finding"]

        self.assertEqual(site_score.score, 5)
        self.assertEqual(len(direct), 1)
        self.assertAlmostEqual(direct[0].adjusted_weight, 4.9)

    def test_repeated_calculation_is_reproducible(self) -> None:
        findings = [
            finding("inventory", asset_id="asset-a", severity="medium", category="inventory"),
            finding("coverage", asset_id="asset-a", severity="high", category="coverage"),
        ]

        first = calculate_risk(sites=self.sites, assets=self.assets, findings=findings)
        second = calculate_risk(sites=self.sites, assets=self.assets, findings=list(reversed(findings)))

        self.assertEqual(first, second)
        self.assertTrue(all(item.formula_version == FORMULA_VERSION for item in first[0]))

    def test_environment_weights_are_bounded(self) -> None:
        config = load_risk_config(
            {
                "OPENASSETWATCH_RISK_WEIGHT_CRITICAL": "999",
                "OPENASSETWATCH_RISK_WEIGHT_HIGH": "not-a-number",
                "OPENASSETWATCH_RISK_CAP_IDENTITY": "-1",
            }
        )

        self.assertEqual(config.severity_weights["critical"], 60.0)
        self.assertEqual(config.severity_weights["high"], 25.0)
        self.assertEqual(config.category_caps["identity"], 0.0)

    def test_custom_config_remains_deterministic(self) -> None:
        config = RiskConfig(
            severity_weights={"critical": 10, "high": 8, "medium": 5, "low": 2, "informational": 1},
            category_caps={"coverage": 12, "other": 8},
        )
        findings = [finding("coverage", asset_id="asset-a", severity="critical")]

        asset_scores, _ = calculate_risk(
            sites=self.sites,
            assets=self.assets,
            findings=findings,
            config=config,
        )

        self.assertEqual(asset_scores[0].score, 10)


if __name__ == "__main__":
    unittest.main()
