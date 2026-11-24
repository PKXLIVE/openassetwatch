from __future__ import annotations

import ast
import dataclasses
import inspect
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import decisions
from app.decisions import (
    ACTION_BANDS,
    CONFIDENCE_HIGH_MIN,
    CONFIDENCE_LOW_MIN,
    CONFIDENCE_MEDIUM_MIN,
    DECISION_RULES,
    DECISION_RULESET_VERSION,
    DECISION_SCHEMA_VERSION,
    REASON_CODE_CATALOG,
    REASON_CODE_ORDER,
    RULE_FAMILY_REASON,
    DecisionEvidence,
    DecisionInput,
    band_rank,
    confidence_band,
    decision_input_from_records,
    evaluate_decision,
    input_digest,
    lifecycle_class,
    ruleset_public,
)
from app.findings import RULE_REGISTRY


NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
APP_ROOT = Path(__file__).resolve().parents[1] / "app"
KEV = DecisionEvidence("kevr_" + "1" * 32, "kev-prioritization", "fresh")
KEV_RANSOMWARE = DecisionEvidence("kevr_" + "2" * 32, "kev-prioritization-ransomware", "fresh")
MATCH = DecisionEvidence("vmt_" + "3" * 32, "vulnerability-match", "fresh")


def finding(**overrides) -> DecisionInput:
    values = {
        "finding_id": "fnd_" + "a" * 32,
        "site_id": "site-a",
        "rule_id": "vulnerable-component",
        "subject_type": "asset",
        "category": "vulnerability",
        "severity": "high",
        "confidence": 0.95,
        "evidence_freshness": "fresh",
        "status": "active",
        "finding_evaluated_at": NOW,
        "evidence": (MATCH,),
    }
    values.update(overrides)
    return DecisionInput(**values)


class DecisionRuleTests(unittest.TestCase):
    def test_known_exploited_confirmed_vulnerability_is_prioritize_not_act_now(self) -> None:
        decision = evaluate_decision(finding(evidence=(MATCH, KEV)))

        self.assertEqual(decision.action_band, "prioritize")
        self.assertEqual(decision.decision_rule_id, "vulnerability-known-exploited")
        self.assertEqual(decision.urgency, "expedited")
        self.assertEqual(decision.exploitation_status, "known-exploited")
        self.assertEqual(decision.exposure_state, "unknown")
        self.assertEqual(decision.asset_importance, "unknown")
        self.assertIn("EXPLOITATION_KNOWN", decision.reason_codes)
        self.assertIn("EXPOSURE_UNKNOWN", decision.reason_codes)
        self.assertIn("ASSET_IMPORTANCE_UNKNOWN", decision.reason_codes)

    def test_known_exploited_overrides_lower_severity(self) -> None:
        for severity in ("informational", "low", "medium"):
            with self.subTest(severity=severity):
                decision = evaluate_decision(finding(severity=severity, evidence=(MATCH, KEV)))
                self.assertEqual(decision.action_band, "prioritize")

    def test_ransomware_evidence_adds_reason_without_a_new_band(self) -> None:
        decision = evaluate_decision(finding(evidence=(MATCH, KEV_RANSOMWARE)))

        self.assertEqual(decision.action_band, "prioritize")
        self.assertIn("EXPLOITATION_RANSOMWARE_KNOWN", decision.reason_codes)

    def test_vulnerability_severity_boundaries(self) -> None:
        expected = {
            "critical": ("prioritize", "vulnerability-critical"),
            "high": ("plan", "vulnerability-confirmed"),
            "medium": ("plan", "vulnerability-confirmed"),
            "low": ("plan", "vulnerability-confirmed"),
            "informational": ("monitor", "vulnerability-informational"),
        }
        for severity, (band, rule_id) in expected.items():
            with self.subTest(severity=severity):
                decision = evaluate_decision(finding(severity=severity))
                self.assertEqual((decision.action_band, decision.decision_rule_id), (band, rule_id))

    def test_kev_evidence_on_a_non_vulnerability_finding_is_ignored(self) -> None:
        decision = evaluate_decision(
            finding(rule_id="asset-stale", category="health", severity="low", evidence=(KEV,))
        )

        self.assertNotIn("EXPLOITATION_KNOWN", decision.reason_codes)
        self.assertEqual(decision.exploitation_status, "not-applicable")

    def test_identity_and_version_gaps_need_verification(self) -> None:
        for rule_id in ("component-version-unavailable", "advisory-identity-uncertain"):
            with self.subTest(rule_id=rule_id):
                decision = evaluate_decision(
                    finding(rule_id=rule_id, severity="informational", confidence=0.9)
                )
                self.assertEqual(decision.action_band, "plan")
                self.assertEqual(decision.urgency, "verification-required")
                self.assertEqual(decision.evidence_confidence, "insufficient")
                self.assertTrue(decision.verification_required)

    def test_conflicts_are_prioritized_for_human_review(self) -> None:
        for rule_id in ("classification-conflict", "identity-conflict"):
            with self.subTest(rule_id=rule_id):
                decision = evaluate_decision(
                    finding(rule_id=rule_id, category="identity", severity="high", confidence=0.6)
                )
                self.assertEqual(decision.action_band, "prioritize")
                self.assertEqual(decision.evidence_confidence, "conflicted")
                self.assertEqual(decision.urgency, "verification-required")
                self.assertIn("EVIDENCE_CONFLICTED", decision.reason_codes)

    def test_collection_gaps_restore_evidence_rather_than_look_safe(self) -> None:
        for rule_id in ("asset-stale", "sensor-stale", "unknown-asset", "passive-only-asset"):
            with self.subTest(rule_id=rule_id):
                subject = "sensor" if rule_id == "sensor-stale" else "asset"
                decision = evaluate_decision(
                    finding(rule_id=rule_id, category="coverage", subject_type=subject, severity="low")
                )
                self.assertEqual(decision.action_band, "plan")
                self.assertEqual(decision.urgency, "verification-required")
                self.assertEqual(decision.decision_rule_id, "collection-gap")

    def test_security_coverage_gap_uses_severity_default(self) -> None:
        expected = {"critical": "prioritize", "high": "prioritize", "medium": "plan", "low": "plan"}
        for severity, band in expected.items():
            with self.subTest(severity=severity):
                decision = evaluate_decision(
                    finding(rule_id="security-coverage-gap", category="coverage", severity=severity)
                )
                self.assertEqual(decision.action_band, band)
                self.assertEqual(decision.decision_rule_id, "severity-default")

    def test_informational_coverage_gap_with_complete_evidence_may_monitor(self) -> None:
        decision = evaluate_decision(
            finding(rule_id="security-coverage-gap", category="coverage", severity="informational")
        )

        self.assertEqual(decision.action_band, "monitor")
        self.assertEqual(decision.urgency, "monitor")
        self.assertFalse(decision.uncertainty_present)

    def test_unmapped_finding_rule_fails_safe_to_plan(self) -> None:
        decision = evaluate_decision(
            finding(rule_id="future-rule", category="future", severity="informational")
        )

        self.assertEqual(decision.action_band, "plan")
        self.assertEqual(decision.decision_rule_id, "unmapped-finding-rule")
        self.assertIn("DECISION_RULE_UNMAPPED", decision.reason_codes)
        self.assertTrue(decision.verification_required)

    def test_every_registered_finding_rule_has_a_reviewed_mapping(self) -> None:
        registered = {rule.rule_id for rule in RULE_REGISTRY}
        self.assertEqual(registered - set(RULE_FAMILY_REASON), set())

    def test_no_rule_in_this_version_produces_act_now(self) -> None:
        self.assertNotIn("act-now", {rule.action_band for rule in DECISION_RULES})
        for rule_id in sorted(RULE_FAMILY_REASON):
            for severity in ("critical", "high"):
                for evidence in ((MATCH,), (MATCH, KEV_RANSOMWARE)):
                    decision = evaluate_decision(
                        finding(rule_id=rule_id, severity=severity, evidence=evidence)
                    )
                    self.assertNotEqual(decision.action_band, "act-now")


class MissingAndUncertainEvidenceTests(unittest.TestCase):
    def test_stale_or_unknown_freshness_never_lowers_to_monitor(self) -> None:
        for freshness, reason in (("stale", "EVIDENCE_STALE"), ("unknown", "EVIDENCE_FRESHNESS_UNKNOWN")):
            with self.subTest(freshness=freshness):
                decision = evaluate_decision(
                    finding(severity="informational", evidence_freshness=freshness)
                )
                self.assertEqual(decision.action_band, "plan")
                self.assertIn(reason, decision.reason_codes)
                self.assertIn("UNCERTAINTY_FLOOR_APPLIED", decision.reason_codes)
                self.assertTrue(decision.uncertainty_present)
                self.assertEqual(decision.urgency, "verification-required")

    def test_uncertainty_never_lowers_a_higher_band(self) -> None:
        certain = evaluate_decision(finding(evidence=(MATCH, KEV)))
        uncertain = evaluate_decision(
            finding(evidence=(MATCH, KEV), evidence_freshness="stale", confidence=0.1)
        )

        self.assertEqual(certain.action_band, uncertain.action_band)
        self.assertNotIn("UNCERTAINTY_FLOOR_APPLIED", uncertain.reason_codes)

    def test_stale_known_exploited_catalog_still_counts_but_is_flagged(self) -> None:
        stale = DecisionEvidence("kevr_" + "4" * 32, "kev-prioritization", "stale")
        decision = evaluate_decision(finding(evidence=(MATCH, stale)))

        self.assertEqual(decision.action_band, "prioritize")
        self.assertIn("EXPLOITATION_SOURCE_STALE", decision.reason_codes)
        self.assertTrue(decision.uncertainty_present)

    def test_confidence_band_boundaries(self) -> None:
        cases = (
            (1.0, "high"),
            (CONFIDENCE_HIGH_MIN, "high"),
            (CONFIDENCE_HIGH_MIN - 0.0001, "medium"),
            (CONFIDENCE_MEDIUM_MIN, "medium"),
            (CONFIDENCE_MEDIUM_MIN - 0.0001, "low"),
            (CONFIDENCE_LOW_MIN, "low"),
            (CONFIDENCE_LOW_MIN - 0.0001, "insufficient"),
            (0.0, "insufficient"),
        )
        for value, band in cases:
            with self.subTest(value=value):
                self.assertEqual(confidence_band("vulnerable-component", value), band)

    def test_low_confidence_is_uncertainty_and_requires_verification(self) -> None:
        decision = evaluate_decision(finding(confidence=0.5))

        self.assertEqual(decision.evidence_confidence, "low")
        self.assertIn("CONFIDENCE_LOW", decision.reason_codes)
        self.assertTrue(decision.verification_required)
        self.assertEqual(decision.action_band, "plan")

    def test_missing_context_is_unknown_never_safe(self) -> None:
        decision = evaluate_decision(finding(severity="low"))

        self.assertEqual(decision.exposure_state, "unknown")
        self.assertEqual(decision.asset_importance, "unknown")
        self.assertEqual(decision.exploitation_status, "unknown")
        self.assertNotIn(decision.exposure_state, {"not-reachable", "segmented"})

    def test_non_asset_findings_mark_context_not_applicable(self) -> None:
        decision = evaluate_decision(
            finding(rule_id="sensor-stale", category="health", subject_type="sensor", severity="medium")
        )

        self.assertEqual(decision.asset_importance, "not-applicable")
        self.assertEqual(decision.exposure_state, "not-applicable")


UNCERTAINTY_REASONS = frozenset(
    {
        "EVIDENCE_STALE",
        "EVIDENCE_FRESHNESS_UNKNOWN",
        "CONFIDENCE_LOW",
        "EXPLOITATION_SOURCE_STALE",
        "UNCERTAINTY_FLOOR_APPLIED",
    }
)
UNDERLYING_UNCERTAINTY_REASONS = UNCERTAINTY_REASONS - {"UNCERTAINTY_FLOOR_APPLIED"}
FACT_FIELDS = ("exploitation_status", "exposure_state", "asset_importance", "severity", "finding_rule_id")


def _uncertainty_grid():
    """Every rule, severity, exploitation evidence, and lifecycle with certain evidence."""

    rules = sorted(RULE_FAMILY_REASON) + ["future-rule"]
    for rule_id in rules:
        subject = "sensor" if rule_id == "sensor-stale" else "asset"
        category = (
            "vulnerability"
            if rule_id in {"vulnerable-component", "component-version-unavailable", "advisory-identity-uncertain"}
            else "coverage"
        )
        for severity in ("informational", "low", "medium", "high", "critical"):
            for kev in ((), (KEV,), (KEV_RANSOMWARE,)):
                for status in ("active", "suppressed"):
                    yield {
                        "rule_id": rule_id,
                        "subject_type": subject,
                        "category": category,
                        "severity": severity,
                        "status": status,
                        "confidence": 0.95,
                        "evidence_freshness": "fresh",
                        "evidence": (MATCH, *kev),
                    }


def _uncertainty_variants(base: dict):
    yield {**base, "evidence_freshness": "stale"}
    yield {**base, "evidence_freshness": "unknown"}
    yield {**base, "confidence": 0.5}
    yield {**base, "confidence": 0.1}
    # Stale known-exploited catalog evidence is uncertainty only where that
    # evidence is a decision input: a confirmed vulnerable component.
    if base["rule_id"] == "vulnerable-component" and any(
        item.evidence_type.startswith("kev-") for item in base["evidence"]
    ):
        yield {
            **base,
            "evidence": tuple(
                DecisionEvidence(item.evidence_ref, item.evidence_type, "stale")
                if item.evidence_type.startswith("kev-")
                else item
                for item in base["evidence"]
            ),
        }
    yield {**base, "evidence_freshness": "stale", "confidence": 0.1}


class UncertaintyInvariantTests(unittest.TestCase):
    """Uncertainty may prevent an unsafe low band but must never create a fact."""

    def _pairs(self):
        for base in _uncertainty_grid():
            certain = evaluate_decision(finding(**base))
            for variant in _uncertainty_variants(base):
                yield base, certain, variant, evaluate_decision(finding(**variant))

    def test_uncertainty_never_changes_a_security_fact(self) -> None:
        for base, certain, variant, uncertain in self._pairs():
            for field in FACT_FIELDS:
                self.assertEqual(
                    getattr(uncertain, field), getattr(certain, field), (base, variant, field)
                )

    def test_uncertainty_adds_only_uncertainty_reasons_and_removes_none(self) -> None:
        for base, certain, variant, uncertain in self._pairs():
            added = set(uncertain.reason_codes) - set(certain.reason_codes)
            removed = set(certain.reason_codes) - set(uncertain.reason_codes)
            self.assertLessEqual(added, UNCERTAINTY_REASONS, (base, variant))
            self.assertEqual(removed, set(), (base, variant))

    def test_uncertainty_raises_at_most_from_monitor_to_plan(self) -> None:
        for base, certain, variant, uncertain in self._pairs():
            expected = "plan" if certain.action_band == "monitor" else certain.action_band
            self.assertEqual(uncertain.action_band, expected, (base, variant))
            self.assertNotEqual(uncertain.action_band, "act-now")
            self.assertTrue(uncertain.verification_required, (base, variant))

    def test_floor_always_carries_its_underlying_reason(self) -> None:
        floored = 0
        for base, _certain, variant, uncertain in self._pairs():
            if "UNCERTAINTY_FLOOR_APPLIED" in uncertain.reason_codes:
                floored += 1
                self.assertEqual(uncertain.action_band, "plan")
                self.assertTrue(
                    set(uncertain.reason_codes) & UNDERLYING_UNCERTAINTY_REASONS, (base, variant)
                )
        self.assertGreater(floored, 0)

    def test_maximum_band_from_uncertainty_alone_is_plan(self) -> None:
        # Start from findings that are Monitor with certain evidence, then add
        # every kind of uncertainty at once. Nothing else differs.
        reached = set()
        for base in _uncertainty_grid():
            if evaluate_decision(finding(**base)).action_band != "monitor":
                continue
            for variant in _uncertainty_variants(base):
                reached.add(evaluate_decision(finding(**variant)).action_band)
        self.assertEqual(reached, {"plan"})

    def test_catalog_evidence_is_not_an_input_outside_confirmed_vulnerabilities(self) -> None:
        stale = DecisionEvidence(KEV.evidence_ref, KEV.evidence_type, "stale")
        for rule_id in sorted(set(RULE_FAMILY_REASON) - {"vulnerable-component"}):
            with self.subTest(rule_id=rule_id):
                fresh = evaluate_decision(finding(rule_id=rule_id, category="coverage", evidence=(MATCH, KEV)))
                aged = evaluate_decision(finding(rule_id=rule_id, category="coverage", evidence=(MATCH, stale)))
                self.assertEqual(fresh.outcome(), aged.outcome())
                self.assertNotIn("EXPLOITATION_KNOWN", aged.reason_codes)
                self.assertNotIn("EXPLOITATION_SOURCE_STALE", aged.reason_codes)

    def test_uncertainty_never_asserts_exploitation_exposure_or_importance(self) -> None:
        for _base, _certain, _variant, uncertain in self._pairs():
            if uncertain.exploitation_status == "known-exploited":
                self.assertTrue(
                    any(item.evidence_type.startswith("kev-") for item in finding(**_variant).evidence)
                )
            self.assertIn(uncertain.exposure_state, {"unknown", "not-applicable"})
            self.assertIn(uncertain.asset_importance, {"unknown", "not-applicable"})
            self.assertNotEqual(uncertain.exploitation_status, "no-known-exploitation")


class GovernanceOverlayTests(unittest.TestCase):
    def test_acknowledgement_does_not_change_the_decision(self) -> None:
        active = evaluate_decision(finding(status="active", evidence=(MATCH, KEV)))
        acknowledged = evaluate_decision(finding(status="acknowledged", evidence=(MATCH, KEV)))

        self.assertEqual(dataclasses.asdict(active), dataclasses.asdict(acknowledged))
        self.assertEqual(lifecycle_class("acknowledged"), "current")

    def test_suppression_keeps_the_band_and_marks_exclusion(self) -> None:
        active = evaluate_decision(finding(evidence=(MATCH, KEV)))
        suppressed = evaluate_decision(finding(status="suppressed", evidence=(MATCH, KEV)))

        self.assertEqual(suppressed.action_band, active.action_band)
        self.assertTrue(suppressed.prioritization_excluded)
        self.assertIn("SUPPRESSION_ACTIVE", suppressed.reason_codes)
        self.assertNotEqual(suppressed.input_digest, active.input_digest)

    def test_resolved_finding_has_no_band(self) -> None:
        decision = evaluate_decision(finding(status="resolved", evidence=(MATCH, KEV)))

        self.assertEqual(decision.decision_state, "not-current")
        self.assertIsNone(decision.action_band)
        self.assertIsNone(decision.urgency)
        self.assertEqual(decision.reason_codes, ("FINDING_RESOLVED",))

    def test_unknown_status_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            evaluate_decision(finding(status="in_progress"))


class DeterminismAndContractTests(unittest.TestCase):
    def test_identical_inputs_produce_identical_decisions(self) -> None:
        first = evaluate_decision(finding(evidence=(MATCH, KEV, KEV_RANSOMWARE)))
        second = evaluate_decision(finding(evidence=(KEV_RANSOMWARE, MATCH, KEV)))

        self.assertEqual(first, second)
        self.assertEqual(first.input_digest, second.input_digest)

    def test_reason_codes_follow_catalog_order_with_multiple_drivers(self) -> None:
        decision = evaluate_decision(
            finding(
                status="suppressed",
                severity="critical",
                confidence=0.3,
                evidence_freshness="stale",
                evidence=(MATCH, KEV_RANSOMWARE),
            )
        )

        self.assertGreaterEqual(len(decision.reason_codes), 8)
        self.assertEqual(
            list(decision.reason_codes),
            sorted(decision.reason_codes, key=REASON_CODE_ORDER.__getitem__),
        )
        self.assertEqual(len(decision.reason_codes), len(set(decision.reason_codes)))

    def test_digest_changes_only_with_decision_inputs(self) -> None:
        base = finding()
        self.assertEqual(input_digest(base), input_digest(finding()))
        for change in (
            {"severity": "critical"},
            {"confidence": 0.5},
            {"evidence_freshness": "aging"},
            {"status": "suppressed"},
            {"evidence": (MATCH, KEV)},
        ):
            with self.subTest(change=change):
                self.assertNotEqual(input_digest(base), input_digest(finding(**change)))
        self.assertEqual(
            input_digest(base),
            input_digest(finding(finding_evaluated_at=NOW + timedelta(hours=1))),
        )

    def test_input_has_no_score_or_work_tracking_field(self) -> None:
        fields = {field.name for field in dataclasses.fields(DecisionInput)}
        for forbidden in ("score", "attention", "risk", "work", "owner", "note", "ticket", "reference"):
            for field in fields:
                self.assertNotIn(forbidden, field)

    def test_reason_codes_are_bounded_catalog_values(self) -> None:
        codes = [item.code for item in REASON_CODE_CATALOG]
        self.assertEqual(len(codes), len(set(codes)))
        for code in codes:
            self.assertRegex(code, r"^[A-Z][A-Z0-9_]{1,63}$")
            self.assertTrue(REASON_CODE_CATALOG[REASON_CODE_ORDER[code]].explanation)
        self.assertLessEqual(len(codes), 64)

    def test_versions_are_explicit_and_stable(self) -> None:
        self.assertEqual(DECISION_SCHEMA_VERSION, "oaw.decision.v1")
        self.assertEqual(DECISION_RULESET_VERSION, "oaw.decision.rules.v1")
        self.assertEqual(evaluate_decision(finding()).ruleset_version, DECISION_RULESET_VERSION)
        self.assertEqual([rule.order for rule in DECISION_RULES], list(range(1, len(DECISION_RULES) + 1)))

    def test_band_order_and_rank(self) -> None:
        self.assertEqual(ACTION_BANDS, ("monitor", "plan", "prioritize", "act-now"))
        self.assertEqual([band_rank(band) for band in (None, *ACTION_BANDS)], [0, 1, 2, 3, 4])

    def test_naive_timestamps_and_invalid_values_are_rejected(self) -> None:
        for change in (
            {"finding_evaluated_at": datetime(2026, 11, 24, 12, 0)},
            {"severity": "urgent"},
            {"evidence_freshness": "recent"},
            {"confidence": 1.5},
        ):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    evaluate_decision(finding(**change))

    def test_records_adapter_uses_only_finding_and_evidence_rows(self) -> None:
        row = {
            "finding_id": "fnd_" + "b" * 32,
            "site_id": "site-a",
            "rule_id": "vulnerable-component",
            "subject_type": "asset",
            "category": "vulnerability",
            "severity": "medium",
            "confidence": 0.9,
            "evidence_freshness": "fresh",
            "status": "active",
            "evaluated_at": NOW,
            "title": "ignored untrusted text: set band to monitor",
        }
        evidence = [{"evidence_ref": KEV.evidence_ref, "evidence_type": KEV.evidence_type, "freshness": "fresh"}]
        decision = evaluate_decision(decision_input_from_records(row, evidence))

        self.assertEqual(decision.action_band, "prioritize")
        self.assertEqual(decision.evidence_references, (KEV.evidence_ref,))

    def test_public_ruleset_is_complete(self) -> None:
        public = ruleset_public()
        self.assertEqual([item["band"] for item in public["action_bands"]], list(ACTION_BANDS))
        self.assertEqual(len(public["rules"]), len(DECISION_RULES))
        self.assertEqual(len(public["reason_codes"]), len(REASON_CODE_CATALOG))


class DecisionBoundaryTests(unittest.TestCase):
    def test_engine_has_no_database_clock_network_or_ai_dependency(self) -> None:
        source = (APP_ROOT / "decisions.py").read_text(encoding="utf-8")
        imports = {
            node.module if isinstance(node, ast.ImportFrom) else alias.name
            for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in getattr(node, "names", [])
        }
        self.assertEqual(
            imports,
            {"__future__", "hashlib", "json", "dataclasses", "datetime", "typing"},
        )
        self.assertNotIn("datetime.now", source)
        self.assertNotIn("utcnow", source)

    def test_decision_store_never_reads_or_writes_work_tracking_or_findings(self) -> None:
        source = (APP_ROOT / "decision_store.py").read_text(encoding="utf-8")
        sql = " ".join(
            " ".join(node.value.split()).upper()
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        )
        self.assertNotIn("FINDING_WORK", sql)
        for table in ("FINDINGS", "FINDING_EVIDENCE", "ASSET_RISK_SCORES", "SITE_RISK_SCORES", "RISK_FACTORS"):
            with self.subTest(table=table):
                self.assertNotIn(f"UPDATE {table} ", sql)
                self.assertNotIn(f"INSERT INTO {table} ", sql)
                self.assertNotIn(f"DELETE FROM {table} ", sql)
        self.assertNotIn("UPDATE FINDING_DECISION_HISTORY", sql)
        self.assertNotIn("DELETE FROM FINDING_DECISION_HISTORY", sql)

    def test_ai_advisor_and_risk_do_not_touch_decisions(self) -> None:
        for module in ("ai_advisor.py", "local_ai.py", "risk.py", "findings.py"):
            with self.subTest(module=module):
                source = (APP_ROOT / module).read_text(encoding="utf-8")
                self.assertNotIn("decision_store", source)
                self.assertNotIn("from .decisions", source)

    def test_evaluate_decision_signature_takes_one_input(self) -> None:
        self.assertEqual(list(inspect.signature(evaluate_decision).parameters), ["value"])
        self.assertIs(decisions.evaluate_decision, evaluate_decision)


if __name__ == "__main__":
    unittest.main()
