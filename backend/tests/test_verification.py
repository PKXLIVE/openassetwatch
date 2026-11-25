"""Remediation verification (CTEM-GAP-06): pure engine and boundaries."""

from __future__ import annotations

import ast
import itertools
import re
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import verification
from app.findings import RULE_REGISTRY
from app.verification import (
    REASON_CODE_CATALOG,
    REASON_CODE_ORDER,
    UNVERIFIED_STATES,
    VERIFICATION_METHODS,
    CollectionSnapshot,
    EvidenceReference,
    FindingState,
    RemediationReport,
    VerificationInput,
    evaluate_verification,
    input_digest,
    ruleset_public,
)


REPORTED = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
BEFORE = REPORTED - timedelta(hours=2)
AFTER = REPORTED + timedelta(hours=2)
APP_ROOT = Path(__file__).resolve().parents[1] / "app"
MATCH_BEFORE = EvidenceReference("vmt_" + "a" * 32, "vulnerability-match", "fresh", BEFORE)
MATCH_AFTER = EvidenceReference("vmt_" + "a" * 32, "vulnerability-match", "fresh", AFTER)


def finding(**overrides) -> FindingState:
    values = {
        "finding_id": "fnd_" + "1" * 32,
        "site_id": "site-a",
        "rule_id": "vulnerable-component",
        "subject_type": "asset",
        "status": "active",
        "evidence_observed_at": BEFORE,
        "evidence_freshness": "fresh",
        "evaluated_at": BEFORE,
        "resolved_at": None,
        "reopen_count": 0,
        "evidence": (MATCH_BEFORE,),
    }
    values.update(overrides)
    return FindingState(**values)


def report(**overrides) -> RemediationReport:
    values = {
        "report_revision": 2,
        "reported_at": REPORTED,
        "work_status": "done",
        "baseline_captured": True,
        "baseline_reopen_count": 0,
        "baseline_evidence": (MATCH_BEFORE,),
    }
    values.update(overrides)
    return RemediationReport(**values)


def snapshot(status: str, at: datetime = AFTER) -> CollectionSnapshot:
    return CollectionSnapshot("css_" + "b" * 32, status, at)


def verify(finding_state=None, report_value="default", **kwargs):
    return evaluate_verification(
        VerificationInput(
            finding=finding_state or finding(),
            report=report() if report_value == "default" else report_value,
            **kwargs,
        )
    )


class VerificationStateTests(unittest.TestCase):
    def test_no_report_is_not_reported_and_guidance_only(self) -> None:
        outcome = verify(report_value=None)
        self.assertEqual(outcome.verification_state, "not-reported")
        self.assertEqual(outcome.reason_codes, ("WORK_NOT_DONE",))
        self.assertEqual(outcome.method_id, "component-inventory")

    def test_done_work_alone_is_never_verification(self) -> None:
        outcome = verify()
        self.assertEqual(outcome.verification_state, "awaiting-evidence")
        self.assertIn("REMEDIATION_REPORTED", outcome.reason_codes)
        self.assertIn("NO_EVIDENCE_SINCE_REPORT", outcome.reason_codes)
        self.assertIn(outcome.verification_state, UNVERIFIED_STATES)

    def test_deterministic_resolution_after_report_verifies(self) -> None:
        outcome = verify(
            finding(status="resolved", resolved_at=AFTER, evaluated_at=AFTER, evidence_observed_at=AFTER,
                    evidence=(MATCH_AFTER,)),
            collection_since_report=snapshot("complete"),
            collection_recorded=True,
        )
        self.assertEqual(outcome.verification_state, "verified")
        self.assertIn("RESOLVED_BY_FRESH_EVIDENCE", outcome.reason_codes)
        self.assertIn("COLLECTION_COMPLETE_SINCE_REPORT", outcome.reason_codes)
        self.assertEqual(outcome.collection_completeness, "complete")
        self.assertEqual(outcome.after_evidence_references, (MATCH_AFTER,))

    def test_resolution_before_report_is_verified_but_labelled(self) -> None:
        outcome = verify(finding(status="resolved", resolved_at=BEFORE))
        self.assertEqual(outcome.verification_state, "verified")
        self.assertIn("RESOLVED_BEFORE_REPORT", outcome.reason_codes)
        self.assertNotIn("RESOLVED_BY_FRESH_EVIDENCE", outcome.reason_codes)

    def test_later_evidence_that_still_matches_is_still_present(self) -> None:
        outcome = verify(finding(evidence_observed_at=AFTER, evaluated_at=AFTER, evidence=(MATCH_AFTER,)))
        self.assertEqual(outcome.verification_state, "still-present")
        self.assertIn("EVIDENCE_SINCE_REPORT_STILL_MATCHES", outcome.reason_codes)
        self.assertEqual(outcome.after_evidence_references, (MATCH_AFTER,))

    def test_reopen_after_report_is_reported(self) -> None:
        outcome = verify(finding(evidence_observed_at=AFTER, reopen_count=1, evaluated_at=AFTER))
        self.assertEqual(outcome.verification_state, "still-present")
        self.assertIn("REOPENED_SINCE_REPORT", outcome.reason_codes)

    def test_stale_and_unknown_later_evidence_are_not_proof(self) -> None:
        stale = verify(finding(evidence_observed_at=AFTER, evidence_freshness="stale"))
        unknown = verify(finding(evidence_observed_at=AFTER, evidence_freshness="unknown"))
        self.assertEqual((stale.verification_state, unknown.verification_state), ("evidence-stale", "insufficient-evidence"))
        self.assertIn("EVIDENCE_STALE", stale.reason_codes)
        self.assertIn("EVIDENCE_FRESHNESS_UNKNOWN", unknown.reason_codes)
        old_stale = verify(finding(evidence_freshness="stale"))
        self.assertEqual(old_stale.verification_state, "awaiting-evidence")
        self.assertIn("EVIDENCE_STALE", old_stale.reason_codes)

    def test_partial_failed_or_unsupported_collection_is_insufficient(self) -> None:
        for status in ("partial", "failed", "unsupported"):
            with self.subTest(status=status):
                outcome = verify(collection_since_report=snapshot(status), collection_recorded=True)
                self.assertEqual(outcome.verification_state, "insufficient-evidence")
                self.assertEqual(outcome.collection_completeness, "incomplete")
                self.assertIn("COLLECTION_INCOMPLETE_SINCE_REPORT", outcome.reason_codes)

    def test_complete_collection_not_yet_evaluated_is_pending(self) -> None:
        outcome = verify(collection_since_report=snapshot("complete"), collection_recorded=True)
        self.assertEqual(outcome.verification_state, "awaiting-evidence")
        self.assertIn("EVALUATION_PENDING", outcome.reason_codes)
        # After evaluation that did not resolve or re-observe, it is still awaiting.
        evaluated = verify(
            finding(evaluated_at=AFTER + timedelta(minutes=1)),
            collection_since_report=snapshot("complete"),
            collection_recorded=True,
        )
        self.assertNotIn("EVALUATION_PENDING", evaluated.reason_codes)
        self.assertEqual(evaluated.verification_state, "awaiting-evidence")

    def test_completeness_labels(self) -> None:
        self.assertEqual(verify().collection_completeness, "not-recorded")
        self.assertEqual(verify(collection_recorded=True).collection_completeness, "none-since-report")
        coverage = verify(finding(rule_id="security-coverage-gap"), collection_since_report=snapshot("partial"))
        self.assertEqual(coverage.collection_completeness, "not-applicable")

    def test_identity_conflict_blocks_attribution(self) -> None:
        resolved = verify(finding(status="resolved", resolved_at=AFTER), identity_conflict_active=True)
        self.assertEqual(resolved.verification_state, "conflicting-evidence")
        self.assertIn("IDENTITY_CONFLICT_ACTIVE", resolved.reason_codes)
        active = verify(identity_conflict_active=True)
        self.assertEqual(active.verification_state, "awaiting-evidence")
        self.assertIn("IDENTITY_CONFLICT_ACTIVE", active.reason_codes)

    def test_rules_without_automatic_path_need_manual_review(self) -> None:
        for rule_id in ("identity-conflict", "future-rule"):
            with self.subTest(rule_id=rule_id):
                outcome = verify(finding(rule_id=rule_id, evidence_observed_at=AFTER))
                self.assertEqual(outcome.verification_state, "manual-review-required")
                self.assertFalse(outcome.automated)
                self.assertIn("NOT_AUTOMATICALLY_VERIFIABLE", outcome.reason_codes)

    def test_suppression_never_verifies(self) -> None:
        outcome = verify(finding(status="suppressed"))
        self.assertNotEqual(outcome.verification_state, "verified")
        self.assertIn("SUPPRESSION_ACTIVE", outcome.reason_codes)

    def test_reopened_work_withdraws_the_report(self) -> None:
        for status in ("open", "in_progress", "blocked", "cancelled"):
            with self.subTest(status=status):
                outcome = verify(finding(status="resolved", resolved_at=AFTER), report(work_status=status))
                self.assertEqual(outcome.verification_state, "report-withdrawn")
                self.assertIn("REPORT_WITHDRAWN", outcome.reason_codes)

    def test_missing_baseline_is_explicit(self) -> None:
        outcome = verify(report_value=report(baseline_captured=False, baseline_reopen_count=None, baseline_evidence=()))
        self.assertIn("BASELINE_NOT_CAPTURED", outcome.reason_codes)
        self.assertNotIn("BASELINE_CAPTURED", outcome.reason_codes)


class VerificationInvariantTests(unittest.TestCase):
    """Exhaustive: only deterministic resolution can produce `verified`."""

    def test_verified_requires_deterministic_resolution(self) -> None:
        rules = sorted(VERIFICATION_METHODS) + ["future-rule"]
        statuses = ("active", "acknowledged", "suppressed", "resolved")
        freshness = ("fresh", "aging", "stale", "unknown")
        observed = (None, BEFORE, AFTER)
        collections = (None, "complete", "partial", "failed", "unsupported")
        work = ("done", "open")
        count = 0
        for rule_id, status, fresh, seen, collected, work_status, conflict in itertools.product(
            rules, statuses, freshness, observed, collections, work, (False, True)
        ):
            outcome = verify(
                finding(
                    rule_id=rule_id,
                    status=status,
                    evidence_freshness=fresh,
                    evidence_observed_at=seen,
                    resolved_at=AFTER if status == "resolved" else None,
                ),
                report(work_status=work_status),
                collection_since_report=snapshot(collected) if collected else None,
                collection_recorded=collected is not None,
                identity_conflict_active=conflict,
            )
            count += 1
            expected = status == "resolved" and work_status == "done" and not conflict
            self.assertEqual(outcome.verification_state == "verified", expected)
            if outcome.verification_state == "verified":
                self.assertTrue(
                    {"RESOLVED_BY_FRESH_EVIDENCE", "RESOLVED_BEFORE_REPORT"} & set(outcome.reason_codes)
                )
            # Absence of evidence or incomplete collection never verifies.
            if status != "resolved":
                self.assertNotEqual(outcome.verification_state, "verified")
            self.assertEqual(
                list(outcome.reason_codes), sorted(outcome.reason_codes, key=REASON_CODE_ORDER.__getitem__)
            )
        self.assertEqual(count, 11 * 4 * 4 * 3 * 5 * 2 * 2)

    def test_identical_inputs_are_identical_and_digest_tracks_inputs(self) -> None:
        base = VerificationInput(finding=finding(), report=report())
        self.assertEqual(evaluate_verification(base), evaluate_verification(base))
        self.assertEqual(input_digest(base), input_digest(VerificationInput(finding=finding(), report=report())))
        for changed in (
            VerificationInput(finding=finding(status="resolved", resolved_at=AFTER), report=report()),
            VerificationInput(finding=finding(), report=report(work_status="open")),
            VerificationInput(finding=finding(), report=report(), collection_since_report=snapshot("partial")),
            VerificationInput(finding=finding(), report=report(), identity_conflict_active=True),
            VerificationInput(finding=finding(evidence_observed_at=AFTER), report=report()),
        ):
            self.assertNotEqual(input_digest(base), input_digest(changed))

    def test_invalid_inputs_are_rejected(self) -> None:
        for bad in (
            finding(status="closed"),
            finding(evidence_freshness="recent"),
            finding(evaluated_at=datetime(2026, 1, 1)),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    verify(bad)
        with self.assertRaises(ValueError):
            verify(collection_since_report=snapshot("weird"))


class VerificationCatalogTests(unittest.TestCase):
    def test_every_finding_rule_has_a_reviewed_method(self) -> None:
        self.assertEqual({rule.rule_id for rule in RULE_REGISTRY}, set(VERIFICATION_METHODS))

    def test_reason_codes_are_bounded_and_explained(self) -> None:
        codes = [item.code for item in REASON_CODE_CATALOG]
        self.assertEqual(len(codes), len(set(codes)))
        for item in REASON_CODE_CATALOG:
            self.assertRegex(item.code, r"^[A-Z][A-Z0-9_]{1,63}$")
            self.assertTrue(item.explanation)

    def test_no_method_claims_active_retesting_or_unsupported_evidence(self) -> None:
        for method in VERIFICATION_METHODS.values():
            text_value = f"{method.evidence_source} {method.comparable_evidence}".lower()
            for word in ("scan", "probe", "retest", "exploit", "reachab", "firewall"):
                self.assertNotIn(word, text_value)

    def test_public_ruleset_lists_methods_and_limits(self) -> None:
        public = ruleset_public()
        self.assertEqual(public["ruleset_version"], "oaw.verification.rules.v1")
        self.assertEqual(len(public["methods"]), len(VERIFICATION_METHODS))
        self.assertTrue(all(item["resolution_behavior"] for item in public["methods"]))
        self.assertNotIn("verified", public["unverified_states"])


class VerificationBoundaryTests(unittest.TestCase):
    def _sql(self, module: str) -> str:
        source = (APP_ROOT / module).read_text(encoding="utf-8")
        return " ".join(
            " ".join(node.value.split()).upper()
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        )

    def test_engine_has_no_database_network_model_or_clock_dependency(self) -> None:
        source = (APP_ROOT / "verification.py").read_text(encoding="utf-8")
        imports = {
            node.module if isinstance(node, ast.ImportFrom) else alias.name
            for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in getattr(node, "names", [])
        }
        self.assertEqual(imports, {"__future__", "hashlib", "json", "dataclasses", "datetime", "typing", "findings"})
        self.assertNotIn("datetime.now", source)
        self.assertNotIn("utcnow", source)

    def test_store_writes_only_verification_tables(self) -> None:
        sql = self._sql("verification_store.py")
        written = set(re.findall(r"INSERT INTO ([A-Z_]+)", sql))
        written |= set(re.findall(r"DELETE FROM ([A-Z_]+)", sql))
        written |= set(re.findall(r"(?<!FOR )UPDATE ([A-Z_]+) SET", sql))
        self.assertEqual(written, {"FINDING_VERIFICATION_BASELINES", "FINDING_VERIFICATION_HISTORY"})

    def test_decisions_risk_findings_and_ai_never_read_verification(self) -> None:
        for module in ("decisions.py", "decision_store.py", "risk.py", "findings.py", "finding_store.py",
                       "ai_advisor.py", "local_ai.py", "asset_importance_store.py"):
            with self.subTest(module=module):
                source = (APP_ROOT / module).read_text(encoding="utf-8")
                self.assertNotIn("verification_store", source)
                self.assertNotIn("from .verification", source)
                self.assertNotIn("finding_verification_", source)

    def test_no_route_can_set_a_verification_outcome(self) -> None:
        from app.main import app

        routes = {
            (route.path, method)
            for route in app.routes
            if "verification" in getattr(route, "path", "")
            for method in getattr(route, "methods", set())
        }
        self.assertEqual(
            routes,
            {
                ("/api/v1/verification/rules", "GET"),
                ("/api/v1/verification/unverified-work", "GET"),
                ("/api/v1/findings/{finding_id}/verification", "GET"),
                ("/api/v1/findings/{finding_id}/verification/history", "GET"),
            },
        )


if __name__ == "__main__":
    unittest.main()
