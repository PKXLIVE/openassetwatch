"""Asset importance (CTEM-GAP-02): pure rules and decision ruleset v2."""

from __future__ import annotations

import ast
import hashlib
import json
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import decisions
from app.asset_importance import (
    ASSIGNABLE_IMPORTANCE,
    EFFECTIVE_IMPORTANCE,
    IMPORTANCE_REVIEW_INTERVAL,
    ImportanceRuleError,
    assignment_event_type,
    direction,
    effective_source,
    review_state,
    validate_assignable,
)
from app.asset_importance_store import project_assignment, project_event
from app.decisions import (
    DECISION_RULESET_V1,
    DECISION_RULESET_V2,
    DecisionEvidence,
    DecisionInput,
    evaluate_decision,
    evaluate_decision_with_ruleset,
    input_digest_for_ruleset,
)


NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
APP_ROOT = Path(__file__).resolve().parents[1] / "app"
MATCH = DecisionEvidence("vmt_" + "3" * 32, "vulnerability-match", "fresh")
KEV = DecisionEvidence("kevr_" + "1" * 32, "kev-prioritization", "fresh")
KEV_STALE = DecisionEvidence("kevr_" + "1" * 32, "kev-prioritization", "stale")
REACHABILITY_CODES = {"EXPOSURE_INTERNET_REACHABLE", "EXPOSURE_EXTERNALLY_REACHABLE", "EXPOSURE_INTERNALLY_REACHABLE"}


def latest_for(row: dict) -> dict:
    """The event the store writes together with `row`."""

    return {
        "revision": row["revision"],
        "importance": row["importance"],
        "reason": row["reason"],
        "principal": row["principal"],
        "actor_label": row["actor_label"],
        "actor_verification": row["actor_verification"],
        "occurred_at": row["updated_at"],
    }


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


class ImportanceVocabularyTests(unittest.TestCase):
    def test_assignable_values_and_order(self) -> None:
        self.assertEqual(ASSIGNABLE_IMPORTANCE, ("low", "standard", "high", "critical"))
        self.assertEqual(EFFECTIVE_IMPORTANCE[-1], "unknown")
        for value in ASSIGNABLE_IMPORTANCE:
            self.assertEqual(validate_assignable(value), value)
        for value in ("unknown", "not-applicable", "CRITICAL", "medium", "", "none"):
            with self.subTest(value=value):
                with self.assertRaises(ImportanceRuleError):
                    validate_assignable(value)

    def test_unknown_is_unassigned_never_low(self) -> None:
        self.assertEqual(effective_source("unknown"), "unassigned")
        self.assertEqual(effective_source("low"), "operator-assigned")
        projected = project_assignment("site-a", "asset-a", None, None, now=NOW)
        self.assertEqual(projected["importance"], "unknown")
        self.assertEqual(projected["importance_source"], "unassigned")
        self.assertEqual(projected["assignment_state"], "none")
        self.assertIsNone(projected["revision"])

    def test_event_classification(self) -> None:
        self.assertEqual(assignment_event_type(None, "high"), "assigned")
        self.assertEqual(assignment_event_type("unknown", "high"), "assigned")
        self.assertEqual(assignment_event_type("high", "high"), "reviewed")
        self.assertEqual(assignment_event_type("high", "critical"), "changed")
        self.assertEqual(assignment_event_type("critical", "low"), "changed")
        with self.assertRaises(ImportanceRuleError):
            assignment_event_type("bogus", "high")
        with self.assertRaises(ImportanceRuleError):
            assignment_event_type(None, "unknown")

    def test_direction_distinguishes_increase_decrease_and_withdrawal(self) -> None:
        self.assertEqual(direction(None, "standard"), "initial")
        self.assertEqual(direction("standard", "critical"), "raised")
        self.assertEqual(direction("critical", "standard"), "lowered")
        self.assertEqual(direction("high", "high"), "unchanged")
        self.assertEqual(direction("critical", "unknown"), "withdrawn")
        self.assertEqual(direction("unknown", "low"), "reassigned")

    def test_lowering_and_withdrawal_are_security_sensitive_without_claimed_approval(self) -> None:
        base = {
            "event_id": 1, "site_id": "site-a", "asset_id": "asset-a", "revision": 2,
            "event_type": "changed", "reason": "r", "principal": "api-admin-token",
            "actor_label": "alex", "actor_verification": "unverified", "occurred_at": NOW,
        }
        lowered = project_event({**base, "previous_importance": "critical", "importance": "low"})
        raised = project_event({**base, "previous_importance": "low", "importance": "critical"})
        withdrawn = project_event(
            {**base, "event_type": "withdrawn", "previous_importance": "high", "importance": "unknown"}
        )
        for event in (lowered, withdrawn):
            self.assertTrue(event["security_sensitive"])
            self.assertEqual(event["independent_review"], "recommended-not-enforced")
        self.assertFalse(raised["security_sensitive"])
        self.assertEqual(raised["independent_review"], "not-required")
        for event in (lowered, raised, withdrawn):
            self.assertNotIn("approver", " ".join(event))
            self.assertEqual(event["actor_verification"], "unverified")

    def test_review_state(self) -> None:
        self.assertEqual(review_state("unknown", NOW, NOW), "not-applicable")
        self.assertEqual(review_state("high", None, NOW), "not-applicable")
        self.assertEqual(review_state("high", NOW, NOW + timedelta(days=1)), "current")
        self.assertEqual(review_state("high", NOW, NOW + IMPORTANCE_REVIEW_INTERVAL), "review-due")
        with self.assertRaises(ValueError):
            review_state("high", datetime(2026, 1, 1), NOW)

    def test_projection_fails_safe_when_record_disagrees_with_history(self) -> None:
        row = {
            "site_id": "site-a", "asset_id": "asset-a", "importance": "critical",
            "assignment_state": "assigned", "revision": 3, "reason": "r",
            "principal": "api-admin-token", "actor_label": "alex",
            "actor_verification": "unverified", "created_at": NOW, "reviewed_at": NOW,
            "updated_at": NOW,
        }
        written = latest_for(row)
        consistent = project_assignment("site-a", "asset-a", row, written, now=NOW)
        self.assertEqual((consistent["importance"], consistent["integrity_state"]), ("critical", "consistent"))
        for latest in (
            None,
            {**written, "revision": 2},
            {**written, "importance": "low"},
            {**written, "reason": "edited without history"},
            {**written, "actor_label": "someone-else"},
            {**written, "principal": "other"},
            {**written, "occurred_at": NOW - timedelta(seconds=1)},
        ):
            with self.subTest(latest=latest):
                projected = project_assignment("site-a", "asset-a", row, latest, now=NOW)
                self.assertEqual(projected["importance"], "unknown")
                self.assertEqual(projected["integrity_state"], "inconsistent")
                self.assertEqual(projected["recorded_importance"], "critical")

    def test_withdrawn_projection_is_unknown(self) -> None:
        row = {
            "site_id": "site-a", "asset_id": "asset-a", "importance": "unknown",
            "assignment_state": "withdrawn", "revision": 2, "reason": "decommissioned",
            "principal": "api-admin-token", "actor_label": "alex",
            "actor_verification": "unverified", "created_at": NOW, "reviewed_at": NOW,
            "updated_at": NOW,
        }
        projected = project_assignment("site-a", "asset-a", row, latest_for(row), now=NOW)
        self.assertEqual(projected["importance"], "unknown")
        self.assertEqual(projected["importance_source"], "unassigned")
        self.assertEqual(projected["integrity_state"], "consistent")
        self.assertEqual(projected["review_state"], "not-applicable")


class CriticalAssetRuleTests(unittest.TestCase):
    """Ruleset v2 Act Now: every canonical predicate must hold."""

    def test_known_exploited_critical_asset_is_act_now_and_exposure_stays_unknown(self) -> None:
        decision = evaluate_decision(finding(evidence=(MATCH, KEV), asset_importance="critical"))
        self.assertEqual(decision.ruleset_version, DECISION_RULESET_V2)
        self.assertEqual(decision.decision_rule_id, "vulnerability-known-exploited-critical-asset")
        self.assertEqual((decision.action_band, decision.urgency), ("act-now", "immediate"))
        self.assertEqual(decision.exposure_state, "unknown")
        self.assertEqual(decision.asset_importance, "critical")
        self.assertEqual(decision.exploitation_status, "known-exploited")
        for code in ("EXPLOITATION_KNOWN", "ASSET_IMPORTANCE_CRITICAL", "EXPOSURE_UNKNOWN"):
            self.assertIn(code, decision.reason_codes)
        self.assertNotIn("ASSET_IMPORTANCE_UNKNOWN", decision.reason_codes)
        self.assertFalse(set(decision.reason_codes) & REACHABILITY_CODES)

    def test_unknown_importance_cannot_produce_act_now(self) -> None:
        decision = evaluate_decision(finding(evidence=(MATCH, KEV)))
        self.assertEqual(decision.action_band, "prioritize")
        self.assertEqual(decision.decision_rule_id, "vulnerability-known-exploited")
        self.assertIn("ASSET_IMPORTANCE_UNKNOWN", decision.reason_codes)

    def test_non_critical_importance_cannot_satisfy_the_critical_predicate(self) -> None:
        for importance in ("high", "standard", "low"):
            with self.subTest(importance=importance):
                decision = evaluate_decision(finding(evidence=(MATCH, KEV), asset_importance=importance))
                self.assertEqual(decision.action_band, "prioritize")
                self.assertIn(f"ASSET_IMPORTANCE_{importance.upper()}", decision.reason_codes)
                self.assertNotIn("ASSET_IMPORTANCE_CRITICAL", decision.reason_codes)

    def test_missing_known_exploited_evidence_cannot_satisfy_the_rule(self) -> None:
        for severity in ("critical", "high", "medium", "low", "informational"):
            with self.subTest(severity=severity):
                decision = evaluate_decision(finding(severity=severity, asset_importance="critical"))
                self.assertNotEqual(decision.action_band, "act-now")
                self.assertNotIn("EXPLOITATION_KNOWN", decision.reason_codes)
                self.assertEqual(decision.exploitation_status, "unknown")

    def test_non_confirmed_vulnerability_findings_cannot_satisfy_the_rule(self) -> None:
        for rule_id in sorted(set(decisions.RULE_FAMILY_REASON) - {"vulnerable-component"}) + ["future-rule"]:
            with self.subTest(rule_id=rule_id):
                decision = evaluate_decision(
                    finding(rule_id=rule_id, severity="critical", evidence=(MATCH, KEV), asset_importance="critical")
                )
                self.assertNotEqual(decision.action_band, "act-now")
                self.assertNotIn("EXPLOITATION_KNOWN", decision.reason_codes)
        # A vulnerable-component rule on a non-asset subject carries no importance.
        sensor = evaluate_decision(
            finding(subject_type="sensor", evidence=(MATCH, KEV), asset_importance="critical")
        )
        self.assertEqual(sensor.asset_importance, "not-applicable")
        self.assertNotEqual(sensor.action_band, "act-now")

    def test_explicitly_ruled_out_exposure_prevents_the_rule(self) -> None:
        # No current input produces a ruled-out exposure; the predicate is
        # exercised directly so a future exposure model cannot widen the rule.
        value = finding(evidence=(MATCH, KEV), asset_importance="critical")
        self.assertEqual(decisions.EXPOSURE_RULED_OUT_STATES, frozenset({"not-reachable"}))
        rule_id, band, _ = decisions._select_rule(value, True, critical_asset=True, exposure="not-reachable")
        self.assertEqual((rule_id, band), ("vulnerability-known-exploited", "prioritize"))
        # `segmented` limits reachability but does not rule alternate paths
        # out, so it is not treated as `not-reachable`.
        for exposure in ("unknown", "segmented", "internally-reachable", "externally-reachable", "internet-reachable"):
            with self.subTest(exposure=exposure):
                rule_id, band, _ = decisions._select_rule(value, True, critical_asset=True, exposure=exposure)
                self.assertEqual(band, "act-now")
        # Without critical importance, no exposure state reaches Act Now.
        for exposure in ("unknown", "segmented", "internet-reachable"):
            _, band, _ = decisions._select_rule(value, True, critical_asset=False, exposure=exposure)
            self.assertEqual(band, "prioritize")

    def test_uncertainty_never_manufactures_act_now_and_flags_verification(self) -> None:
        stale = evaluate_decision(finding(evidence=(MATCH, KEV_STALE), asset_importance="critical"))
        self.assertEqual(stale.action_band, "act-now")
        self.assertEqual(stale.urgency, "verification-required")
        self.assertIn("EXPLOITATION_SOURCE_STALE", stale.reason_codes)
        for change in (
            {"evidence_freshness": "stale"},
            {"evidence_freshness": "unknown"},
            {"confidence": 0.1},
        ):
            with self.subTest(change=change):
                uncertain = evaluate_decision(finding(asset_importance="critical", **change))
                self.assertNotEqual(uncertain.action_band, "act-now")
                self.assertEqual(uncertain.asset_importance, "critical")

    def test_importance_never_lowers_a_band(self) -> None:
        base = {"rule_id": "vulnerable-component", "subject_type": "asset", "category": "vulnerability"}
        for severity in ("critical", "high", "medium", "low", "informational"):
            for evidence in ((MATCH,), (MATCH, KEV)):
                unknown = evaluate_decision(finding(severity=severity, evidence=evidence, **base))
                for importance in ("low", "standard", "high", "critical"):
                    assigned = evaluate_decision(
                        finding(severity=severity, evidence=evidence, asset_importance=importance, **base)
                    )
                    self.assertGreaterEqual(
                        decisions.band_rank(assigned.action_band), decisions.band_rank(unknown.action_band)
                    )
                    if importance != "critical":
                        self.assertEqual(assigned.action_band, unknown.action_band)

    def test_act_now_requires_every_predicate_exhaustively(self) -> None:
        for rule_id in sorted(decisions.RULE_FAMILY_REASON) + ["future-rule"]:
            for subject in ("asset", "sensor", "site"):
                for category in ("vulnerability", "coverage"):
                    for importance in decisions.ASSET_IMPORTANCE_INPUTS:
                        for evidence in ((MATCH,), (MATCH, KEV), (MATCH, KEV_STALE)):
                            for status in ("active", "acknowledged", "suppressed", "resolved"):
                                decision = evaluate_decision(
                                    finding(
                                        rule_id=rule_id, subject_type=subject, category=category,
                                        asset_importance=importance, evidence=evidence, status=status,
                                    )
                                )
                                expected = (
                                    rule_id == "vulnerable-component"
                                    and subject == "asset"
                                    and category == "vulnerability"
                                    and importance == "critical"
                                    and len(evidence) == 2
                                    and status != "resolved"
                                )
                                self.assertEqual(decision.action_band == "act-now", expected)
                                if decision.action_band == "act-now":
                                    self.assertIn("EXPLOITATION_KNOWN", decision.reason_codes)
                                    self.assertIn("ASSET_IMPORTANCE_CRITICAL", decision.reason_codes)
                                    self.assertEqual(decision.exposure_state, "unknown")

    def test_v2_is_deterministic_and_digest_covers_importance(self) -> None:
        first = evaluate_decision(finding(evidence=(MATCH, KEV), asset_importance="critical"))
        second = evaluate_decision(finding(evidence=(MATCH, KEV), asset_importance="critical"))
        self.assertEqual(first, second)
        digests = {
            input_digest_for_ruleset(finding(asset_importance=value), DECISION_RULESET_V2)
            for value in decisions.ASSET_IMPORTANCE_INPUTS
        }
        self.assertEqual(len(digests), len(decisions.ASSET_IMPORTANCE_INPUTS))
        # Non-asset findings ignore importance entirely.
        sensor = {
            input_digest_for_ruleset(
                finding(rule_id="sensor-stale", subject_type="sensor", category="coverage", asset_importance=value),
                DECISION_RULESET_V2,
            )
            for value in decisions.ASSET_IMPORTANCE_INPUTS
        }
        self.assertEqual(len(sensor), 1)

    def test_invalid_importance_and_ruleset_are_rejected(self) -> None:
        for value in ("not-applicable", "medium", "CRITICAL"):
            with self.assertRaises(ValueError):
                evaluate_decision(finding(asset_importance=value))
        with self.assertRaises(ValueError):
            evaluate_decision_with_ruleset(finding(), "oaw.decision.rules.v9")

    def test_records_adapter_reads_importance_and_defaults_unknown(self) -> None:
        row = {
            "finding_id": "fnd_" + "b" * 32, "site_id": "site-a", "rule_id": "vulnerable-component",
            "subject_type": "asset", "category": "vulnerability", "severity": "high",
            "confidence": 0.9, "evidence_freshness": "fresh", "status": "active", "evaluated_at": NOW,
        }
        evidence = [{"evidence_ref": KEV.evidence_ref, "evidence_type": KEV.evidence_type, "freshness": "fresh"}]
        self.assertEqual(decisions.decision_input_from_records(row, evidence).asset_importance, "unknown")
        self.assertEqual(
            decisions.decision_input_from_records({**row, "asset_importance": None}, evidence).asset_importance,
            "unknown",
        )
        critical = decisions.decision_input_from_records({**row, "asset_importance": "critical"}, evidence)
        self.assertEqual(evaluate_decision(critical).action_band, "act-now")


def _v1_universe():
    """Deterministic generator of the recorded v1 compatibility universe."""

    rules = sorted(decisions.RULE_FAMILY_REASON) + ["future-rule"]
    for rule_id in rules:
        for subject in ("asset", "sensor", "site"):
            for category in ("vulnerability", "coverage"):
                for severity in decisions.FINDING_SEVERITIES:
                    for confidence in (0.95, 0.7, 0.5, 0.1):
                        for fresh in decisions.FRESHNESS_VALUES:
                            for status in ("active", "acknowledged", "suppressed", "resolved"):
                                for kev in (
                                    (),
                                    ("kev-prioritization", "fresh"),
                                    ("kev-prioritization-ransomware", "stale"),
                                    ("kev-prioritization", "unknown"),
                                ):
                                    evidence = [MATCH]
                                    if kev:
                                        evidence.append(DecisionEvidence("kevr_" + "1" * 32, kev[0], kev[1]))
                                    yield DecisionInput(
                                        finding_id="fnd_" + "a" * 32, site_id="site-a", rule_id=rule_id,
                                        subject_type=subject, category=category, severity=severity,
                                        confidence=confidence, evidence_freshness=fresh, status=status,
                                        finding_evaluated_at=NOW, evidence=tuple(evidence),
                                    )


class V1CompatibilityTests(unittest.TestCase):
    """`oaw.decision.rules.v1` stays bit-identical to the merged GAP-01 engine."""

    # Recorded from main 0e51ef1 before ruleset v2 existed.
    V1_UNIVERSE_SIZE = 84_480
    V1_UNIVERSE_DIGEST = "015c7183e526a026d6d0d0fd31eb0d7cef286e31d10fe1e81ee0ad7083adfd1c"
    V1_REPRESENTATIVE = (
        ({}, "5223a3ecb981a0c2fe48ab3d2e1b4a4e6455e2aa973c8eb0983a098543a2c8bb", "plan"),
        ({"evidence": (MATCH, KEV)}, "da13e15995ee3c2f65b5781e55e6c3b9e452e316a522366f6c025105b41c470b", "prioritize"),
        (
            {"rule_id": "sensor-stale", "subject_type": "sensor", "category": "coverage", "severity": "medium"},
            "0fd5a58ba1d1dbd87f9a3926298ab725fd208910adb6ba529773c3ff14c93567",
            "plan",
        ),
    )

    def test_v1_universe_is_bit_identical(self) -> None:
        rows = []
        for value in _v1_universe():
            item = asdict(evaluate_decision_with_ruleset(value, DECISION_RULESET_V1))
            item["finding_evaluated_at"] = item["finding_evaluated_at"].isoformat()
            rows.append(item)
        blob = json.dumps(rows, sort_keys=True).encode()
        self.assertEqual(len(rows), self.V1_UNIVERSE_SIZE)
        self.assertEqual(hashlib.sha256(blob).hexdigest(), self.V1_UNIVERSE_DIGEST)

    def test_v1_representative_digests_and_importance_is_ignored(self) -> None:
        for overrides, digest, band in self.V1_REPRESENTATIVE:
            for importance in decisions.ASSET_IMPORTANCE_INPUTS:
                with self.subTest(overrides=overrides, importance=importance):
                    decision = evaluate_decision_with_ruleset(
                        finding(asset_importance=importance, **overrides), DECISION_RULESET_V1
                    )
                    self.assertEqual(decision.input_digest, digest)
                    self.assertEqual(decision.action_band, band)
                    self.assertEqual(decision.ruleset_version, DECISION_RULESET_V1)


class ImportanceBoundaryTests(unittest.TestCase):
    def _imports(self, module: str) -> set[str]:
        source = (APP_ROOT / module).read_text(encoding="utf-8")
        return {
            node.module if isinstance(node, ast.ImportFrom) else alias.name
            for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in getattr(node, "names", [])
        }

    def test_pure_module_has_no_database_network_model_or_clock_dependency(self) -> None:
        self.assertEqual(self._imports("asset_importance.py"), {"__future__", "datetime", "typing"})
        source = (APP_ROOT / "asset_importance.py").read_text(encoding="utf-8")
        self.assertNotIn("datetime.now", source)
        self.assertNotIn("utcnow", source)

    def test_ai_and_scoring_modules_cannot_reach_importance(self) -> None:
        for module in ("ai_advisor.py", "local_ai.py", "local_ai_transport.py", "risk.py", "findings.py",
                       "classification.py", "finding_work_store.py"):
            with self.subTest(module=module):
                source = (APP_ROOT / module).read_text(encoding="utf-8")
                self.assertNotIn("asset_importance", source)

    def test_importance_store_writes_only_importance_tables(self) -> None:
        source = (APP_ROOT / "asset_importance_store.py").read_text(encoding="utf-8")
        sql = " ".join(
            " ".join(node.value.split()).upper()
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        )
        import re

        written = set(re.findall(r"INSERT INTO ([A-Z_]+)", sql))
        written |= set(re.findall(r"DELETE FROM ([A-Z_]+)", sql))
        written |= set(re.findall(r"(?<!FOR )UPDATE ([A-Z_]+) SET", sql))
        self.assertNotRegex(sql, r"(?<!FOR )UPDATE (?!ASSET_IMPORTANCE_ASSIGNMENTS SET)[A-Z_]+ SET")
        self.assertEqual(written, {"ASSET_IMPORTANCE_ASSIGNMENTS", "ASSET_IMPORTANCE_EVENTS"})
        self.assertNotIn("FINDING_WORK", sql)
        self.assertNotIn("FINDING_DECISION", sql)

    def test_importance_inputs_never_derive_from_names_software_or_scores(self) -> None:
        source = (APP_ROOT / "asset_importance_store.py").read_text(encoding="utf-8").lower()
        for column in ("hostname", "metadata_json", "asset_components", "risk_scores", "severity", "category"):
            self.assertNotIn(column, source)


if __name__ == "__main__":
    unittest.main()
