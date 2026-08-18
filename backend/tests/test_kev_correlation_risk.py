from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path

from app.findings import evaluate_rules
from app.kev_catalog import normalize_cisa_kev_catalog, parse_cisa_kev_bytes
from app.kev_correlation import (
    correlate_current_affected_match,
    correlate_current_affected_matches,
    exact_cve_aliases,
)
from app.risk import FORMULA_VERSION, KEV_CATEGORY_CAP, KEV_FORMULA_VERSION, calculate_risk


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cisa-kev" / "catalog-v1.json"
NOW = datetime(2099, 1, 3, 12, 0, tzinfo=timezone.utc)


def kev_records():
    return normalize_cisa_kev_catalog(parse_cisa_kev_bytes(FIXTURE.read_bytes())).records


def match(*, status: str = "affected", aliases=None, match_id: str = "match-1") -> dict:
    return {
        "match_id": match_id,
        "advisory_id": "adv-1",
        "match_status": status,
        "aliases": aliases if aliases is not None else ["CVE-2099-10001"],
    }


class ExactKevCorrelationTests(unittest.TestCase):
    def test_exact_and_lowercase_cve_aliases_correlate_once(self) -> None:
        value = match(aliases=["cve-2099-10001", "CVE-2099-10001", "GHSA-fictional"])
        correlations = correlate_current_affected_match(value, kev_records())

        self.assertEqual(len(correlations), 1)
        self.assertEqual(correlations[0].cve_id, "CVE-2099-10001")
        self.assertEqual(correlations[0].priority_status, "known_exploited_ransomware")
        self.assertEqual(exact_cve_aliases(value["aliases"]), ("CVE-2099-10001",))

    def test_fuzzy_vendor_product_cpe_ghsa_and_fixed_matches_do_not_correlate(self) -> None:
        variants = [
            match(aliases=["GHSA-fictional"], match_id="ghsa"),
            {**match(aliases=[], match_id="vendor"), "vendor": "Fictional Aster Works", "product": "Synthetic Orbit Service"},
            match(aliases=["cpe:2.3:a:fictional:orbit:*"], match_id="cpe"),
            match(status="fixed", match_id="fixed"),
            match(status="identity-uncertain", match_id="uncertain"),
        ]
        self.assertTrue(all(not correlate_current_affected_match(value, kev_records()) for value in variants))

    def test_two_advisories_share_alias_without_amplifying_each_match(self) -> None:
        first = correlate_current_affected_match(match(match_id="match-a"), kev_records())
        second = correlate_current_affected_match({**match(match_id="match-b"), "advisory_id": "adv-2"}, kev_records())
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)

    def test_batch_correlation_rejects_duplicate_logical_matches_and_limits(self) -> None:
        values = [match(match_id="match-a"), match(match_id="match-b")]
        correlations = correlate_current_affected_matches(values, kev_records())
        self.assertEqual(len(correlations), 2)
        with self.assertRaisesRegex(ValueError, "duplicate logical match"):
            correlate_current_affected_matches([values[0], values[0]], kev_records())
        with self.assertRaisesRegex(ValueError, "reviewed limit"):
            correlate_current_affected_matches(values, kev_records(), maximum_matches=1)


class KevFindingRiskTests(unittest.TestCase):
    def _finding(self, *, ransomware: bool, freshness: str = "fresh", index: int = 1) -> dict:
        return {
            "finding_id": f"finding-{index}",
            "rule_id": "vulnerable-component",
            "site_id": "site-a",
            "asset_id": "asset-a",
            "title": "KEV-prioritized vulnerable component",
            "severity": "medium",
            "confidence": 1.0,
            "evidence_freshness": "fresh",
            "category": "vulnerability",
            "status": "active",
            "evidence": [
                {"evidence_ref": f"match-{index}", "evidence_type": "vulnerability-match", "freshness": "fresh"},
                {
                    "evidence_ref": f"kev-{index}",
                    "evidence_type": "kev-prioritization-ransomware" if ransomware else "kev-prioritization",
                    "freshness": freshness,
                },
            ],
        }

    def test_ransomware_is_higher_stale_is_degraded_and_cap_is_bounded(self) -> None:
        sites = [{"site_id": "site-a"}]
        assets = [{"site_id": "site-a", "asset_id": "asset-a", "observed_at": NOW}]
        regular, regular_sites = calculate_risk(sites=sites, assets=assets, findings=[self._finding(ransomware=False)])
        ransomware, _ = calculate_risk(sites=sites, assets=assets, findings=[self._finding(ransomware=True)])
        stale, _ = calculate_risk(sites=sites, assets=assets, findings=[self._finding(ransomware=True, freshness="stale")])
        many, _ = calculate_risk(
            sites=sites,
            assets=assets,
            findings=[self._finding(ransomware=True, index=index) for index in range(1, 8)],
        )

        def kev_total(result):
            return sum(factor.adjusted_weight for factor in result[0].factors if factor.factor_type == "kev-priority")

        self.assertGreater(kev_total(ransomware), kev_total(regular))
        self.assertGreater(kev_total(ransomware), kev_total(stale))
        self.assertLessEqual(kev_total(many), KEV_CATEGORY_CAP)
        self.assertEqual(regular[0].formula_version, KEV_FORMULA_VERSION)
        self.assertEqual(regular_sites[0].formula_version, KEV_FORMULA_VERSION)

    def test_no_kev_evidence_does_not_reduce_existing_risk(self) -> None:
        sites = [{"site_id": "site-a"}]
        assets = [{"site_id": "site-a", "asset_id": "asset-a", "observed_at": NOW}]
        base = self._finding(ransomware=False)
        base["evidence"] = base["evidence"][:1]
        without, _ = calculate_risk(sites=sites, assets=assets, findings=[base])
        with_kev, _ = calculate_risk(sites=sites, assets=assets, findings=[self._finding(ransomware=False)])
        self.assertGreaterEqual(with_kev[0].score, without[0].score)
        self.assertEqual(without[0].formula_version, FORMULA_VERSION)
        self.assertEqual(with_kev[0].formula_version, KEV_FORMULA_VERSION)

    def test_existing_finding_is_enriched_without_second_logical_finding(self) -> None:
        record = kev_records()[1]
        asset = {
            "site_id": "site-a",
            "asset_id": "asset-a",
            "observed_at": NOW,
            "vulnerability_matches": [
                {
                    "match_id": "match-unknown-ransomware",
                    "component_id": "component-a",
                    "advisory_id": "advisory-a",
                    "match_status": "affected",
                    "match_confidence": 1.0,
                    "component_name": "Synthetic Compass Agent",
                    "installed_version": "1.0",
                    "evaluated_at": NOW,
                    "component_freshness": "fresh",
                    "severity": "medium",
                    "kev": {
                        "records": [
                            {
                                **record.model_dump(mode="python"),
                                "source_freshness": "fresh",
                                "adjusted_weight": 12.0,
                            }
                        ]
                    },
                }
            ],
        }
        snapshot = evaluate_rules(sites=[{"site_id": "site-a"}], sensors=[], assets=[asset], now=NOW, rule_ids=("vulnerable-component",))
        self.assertEqual(len(snapshot.candidates), 1)
        finding = snapshot.candidates[0]
        self.assertEqual(finding.rule_version, 2)
        self.assertIn("does not establish exploitation or compromise", finding.description)
        self.assertIn("CISA KEV due date", finding.recommendation)
        self.assertNotIn("ransomware: No", finding.recommendation)


if __name__ == "__main__":
    unittest.main()
