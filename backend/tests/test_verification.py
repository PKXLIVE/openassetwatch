"""Remediation verification (CTEM-GAP-06): pure engine and boundaries."""

from __future__ import annotations

import ast
import dataclasses
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
    NOT_ATTRIBUTABLE_STATES,
    CollectionSnapshot,
    EvidenceReference,
    FindingState,
    RemediationReport,
    ResolutionProof,
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
        # The vulnerable version installed when work was marked done.
        "baseline_match_versions": (("vmt_" + "a" * 32, "1.2.0"),),
    }
    values.update(overrides)
    return RemediationReport(**values)


def snapshot(status: str, at: datetime = AFTER) -> CollectionSnapshot:
    return CollectionSnapshot("css_" + "b" * 32, status, at)


def proof(
    basis: str = "component-version-fixed",
    *,
    at: datetime = AFTER,
    freshness: str = "fresh",
    installed: str | None = "1.4.2",
    supporting: CollectionSnapshot | None = None,
) -> ResolutionProof:
    # An upgrade from the report-time 1.2.0 to the fixed 1.4.2.
    return ResolutionProof(
        basis=basis,
        evidence_ref="vmt_" + "a" * 32,
        evidence_type="vulnerability-match",
        source="deterministic-vulnerability-matcher",
        observed_at=at,
        freshness=freshness,
        installed_version=installed,
        fixed_version="1.4.2",
        supporting_snapshot=supporting,
    )


RESOLVED_AFTER = AFTER + timedelta(minutes=5)


def resolved(**overrides) -> FindingState:
    values = {"status": "resolved", "resolved_at": RESOLVED_AFTER, "evaluated_at": RESOLVED_AFTER}
    values.update(overrides)
    return finding(**values)


def verify(finding_state=None, report_value="default", **kwargs):
    # Test convenience: `collection_at_resolution` becomes the supporting
    # snapshot of every proof that has none, as the store binds it.
    at_resolution = kwargs.pop("collection_at_resolution", None)
    if at_resolution is not None and kwargs.get("resolution_evidence"):
        kwargs["resolution_evidence"] = tuple(
            item if item.supporting_snapshot is not None else dataclasses.replace(item, supporting_snapshot=at_resolution)
            for item in kwargs["resolution_evidence"]
        )
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

    def test_fixed_component_on_complete_post_report_inventory_verifies(self) -> None:
        outcome = verify(
            resolved(),
            resolution_evidence=(proof(),),
            collection_at_resolution=snapshot("complete"),
            collection_recorded=True,
        )
        self.assertEqual(outcome.verification_state, "verified")
        for code in ("RESOLVED_BY_FRESH_EVIDENCE", "COMPONENT_VERSION_FIXED", "COLLECTION_COMPLETE_AT_RESOLUTION"):
            self.assertIn(code, outcome.reason_codes)
        self.assertEqual(outcome.collection_completeness, "complete")
        # The after-evidence is the recorded resolution evidence, not the old
        # finding evidence that described the condition.
        self.assertEqual(
            outcome.after_evidence_references,
            (EvidenceReference("vmt_" + "a" * 32, "vulnerability-match", "fresh", AFTER),),
        )

    def test_a_resolution_timestamp_alone_is_not_verification(self) -> None:
        outcome = verify(resolved(), collection_at_resolution=snapshot("complete"), collection_recorded=True)
        self.assertEqual(outcome.verification_state, "insufficient-evidence")
        self.assertIn("RESOLUTION_EVIDENCE_UNAVAILABLE", outcome.reason_codes)
        self.assertEqual(outcome.after_evidence_references, ())

    def test_resolution_before_report_is_not_attributable(self) -> None:
        outcome = verify(
            resolved(resolved_at=BEFORE),
            resolution_evidence=(proof(at=BEFORE),),
            collection_at_resolution=None,
        )
        self.assertEqual(outcome.verification_state, "resolved-before-report")
        self.assertIn("RESOLVED_BEFORE_REPORT", outcome.reason_codes)
        self.assertNotIn("RESOLVED_BY_FRESH_EVIDENCE", outcome.reason_codes)
        self.assertIn(outcome.verification_state, NOT_ATTRIBUTABLE_STATES)
        self.assertNotIn(outcome.verification_state, UNVERIFIED_STATES)

    def test_resolution_after_report_using_evidence_observed_before_it(self) -> None:
        outcome = verify(
            resolved(),
            resolution_evidence=(proof(at=BEFORE),),
            collection_at_resolution=snapshot("complete"),
            collection_recorded=True,
        )
        self.assertEqual(outcome.verification_state, "insufficient-evidence")
        self.assertIn("RESOLUTION_EVIDENCE_PREDATES_REPORT", outcome.reason_codes)

    def test_stale_or_unknown_resolution_evidence_is_not_proof(self) -> None:
        stale = verify(resolved(), resolution_evidence=(proof(freshness="stale"),),
                       collection_at_resolution=snapshot("complete"))
        unknown = verify(resolved(), resolution_evidence=(proof(freshness="unknown"),),
                         collection_at_resolution=snapshot("complete"))
        self.assertEqual(stale.verification_state, "evidence-stale")
        self.assertEqual(unknown.verification_state, "insufficient-evidence")
        self.assertIn("EVIDENCE_FRESHNESS_UNKNOWN", unknown.reason_codes)

    def test_component_resolution_needs_a_complete_collection_before_resolution(self) -> None:
        for status in ("partial", "failed", "unsupported"):
            with self.subTest(status=status):
                outcome = verify(resolved(), resolution_evidence=(proof(),), collection_at_resolution=snapshot(status),
                                 collection_recorded=True)
                self.assertEqual(outcome.verification_state, "insufficient-evidence")
                self.assertIn("COLLECTION_INCOMPLETE_AT_RESOLUTION", outcome.reason_codes)
        for recorded in (True, False):
            with self.subTest(recorded=recorded):
                outcome = verify(resolved(), resolution_evidence=(proof(),), collection_recorded=recorded)
                self.assertEqual(outcome.verification_state, "insufficient-evidence")
                self.assertIn("COLLECTION_NOT_COMPLETE_AT_RESOLUTION", outcome.reason_codes)
        # Methods without a component collection check rely on rule freshness.
        coverage = verify(
            resolved(rule_id="security-coverage-gap"),
            resolution_evidence=(proof("healthy-coverage"),),
        )
        self.assertEqual(coverage.verification_state, "verified")
        self.assertIn("OBSERVATION_CONFIRMS_CHANGE", coverage.reason_codes)

    def test_advisory_withdrawal_and_applicability_are_not_remediation(self) -> None:
        for basis, code in (
            ("advisory-withdrawn", "ADVISORY_WITHDRAWN"),
            ("applicability-not-affected", "APPLICABILITY_REVISED"),
            ("advisory-identity-reviewed", "ADVISORY_IDENTITY_REVIEWED"),
        ):
            with self.subTest(basis=basis):
                outcome = verify(resolved(), resolution_evidence=(proof(basis),),
                                 collection_at_resolution=snapshot("complete"))
                self.assertEqual(outcome.verification_state, "resolved-by-advisory-change")
                self.assertIn(code, outcome.reason_codes)
                self.assertNotIn("RESOLVED_BY_FRESH_EVIDENCE", outcome.reason_codes)
                self.assertIn(outcome.verification_state, NOT_ATTRIBUTABLE_STATES)

    def test_later_degraded_collection_keeps_a_verified_outcome(self) -> None:
        for status in ("partial", "failed", "unsupported"):
            with self.subTest(status=status):
                outcome = verify(
                    resolved(),
                    resolution_evidence=(proof(),),
                    collection_at_resolution=snapshot("complete"),
                    collection_after_resolution=snapshot(status, RESOLVED_AFTER + timedelta(hours=1)),
                    collection_recorded=True,
                )
                self.assertEqual(outcome.verification_state, "verified")
                self.assertIn("COLLECTION_DEGRADED_SINCE_VERIFICATION", outcome.reason_codes)
                self.assertEqual(outcome.collection_completeness, "complete")

    def test_manual_only_and_unknown_methods_never_verify_a_resolution(self) -> None:
        for rule_id in ("identity-conflict", "future-rule"):
            with self.subTest(rule_id=rule_id):
                outcome = verify(resolved(rule_id=rule_id), resolution_evidence=(proof("fresh-observation"),))
                self.assertEqual(outcome.verification_state, "manual-review-required")

    def test_confirmed_removal_verifies_from_its_removal_snapshot(self) -> None:
        outcome = verify(
            resolved(),
            resolution_evidence=(proof("component-removed", installed="1.2.0"),),
            collection_at_resolution=snapshot("complete"),
        )
        self.assertEqual(outcome.verification_state, "verified")
        self.assertIn("COMPONENT_REMOVED", outcome.reason_codes)
        self.assertNotIn("COMPONENT_VERSION_FIXED", outcome.reason_codes)

    def test_fixed_status_with_an_unchanged_version_is_an_advisory_revision(self) -> None:
        outcome = verify(
            resolved(),
            resolution_evidence=(proof(installed="1.2.0"),),
            collection_at_resolution=snapshot("complete"),
        )
        self.assertEqual(outcome.verification_state, "resolved-by-advisory-change")
        self.assertIn("FIXED_BOUNDARY_REVISED", outcome.reason_codes)

    def test_version_upgrade_needs_a_report_time_version(self) -> None:
        for report_value in (report(baseline_match_versions=()), report(baseline_match_versions=(("vmt_" + "a" * 32, None),))):
            with self.subTest(report_value=report_value):
                outcome = verify(resolved(), report_value, resolution_evidence=(proof(),),
                                 collection_at_resolution=snapshot("complete"))
                self.assertEqual(outcome.verification_state, "insufficient-evidence")
                self.assertIn("VERSION_CHANGE_UNCONFIRMED", outcome.reason_codes)

    def test_unattributed_fixed_status_claims_nothing(self) -> None:
        outcome = verify(resolved(), resolution_evidence=(proof("match-fixed-unattributed"),),
                         collection_at_resolution=snapshot("complete"))
        self.assertEqual(outcome.verification_state, "insufficient-evidence")
        self.assertIn("RESOLUTION_BASIS_UNCONFIRMED", outcome.reason_codes)

    def test_supporting_evidence_must_fall_in_the_report_to_resolution_window(self) -> None:
        late = RESOLVED_AFTER + timedelta(hours=1)
        outcome = verify(resolved(), resolution_evidence=(proof(at=late),), collection_at_resolution=snapshot("complete"))
        self.assertEqual(outcome.verification_state, "insufficient-evidence")
        self.assertIn("RESOLUTION_EVIDENCE_OUTSIDE_WINDOW", outcome.reason_codes)
        for snap_at in (BEFORE, late):
            with self.subTest(snap_at=snap_at):
                outcome = verify(resolved(), resolution_evidence=(proof(),),
                                 collection_at_resolution=snapshot("complete", snap_at))
                self.assertEqual(outcome.verification_state, "insufficient-evidence")
                self.assertIn("COLLECTION_NOT_COMPLETE_AT_RESOLUTION", outcome.reason_codes)

    def test_unknown_resolution_basis_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            verify(resolved(), resolution_evidence=(proof("guessed-remediation"),))

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

    def test_verified_requires_every_evidence_condition(self) -> None:
        """`verified` iff every independently stated requirement holds.

        The expectation is written from the requirements, not from the
        implementation: an automatic method, a resolution after the report,
        technical resolution evidence collected after the report that is
        fresh or aging, a complete pre-resolution collection for component
        methods, work still done, and no identity conflict. A later degraded
        collection never changes the result.
        """

        rules = sorted(VERIFICATION_METHODS) + ["future-rule"]
        statuses = ("active", "suppressed", "resolved")
        resolutions = (None, BEFORE, RESOLVED_AFTER)
        proofs = (
            None,
            ("component-version-fixed", AFTER, "fresh"),
            ("component-version-fixed", AFTER, "stale"),
            ("component-version-fixed", AFTER, "unknown"),
            ("component-version-fixed", BEFORE, "fresh"),
            ("fresh-observation", AFTER, "aging"),
            ("advisory-withdrawn", AFTER, "fresh"),
            ("applicability-not-affected", AFTER, "fresh"),
        )
        at_resolution = (None, "complete", "partial", "failed")
        after_resolution = (None, "failed")
        count = 0
        for rule_id, status, resolved_at, proof_spec, at_status, after_status, work_status, conflict in itertools.product(
            rules, statuses, resolutions, proofs, at_resolution, after_resolution, ("done", "open"), (False, True)
        ):
            if (status == "resolved") != (resolved_at is not None):
                continue
            outcome = verify(
                finding(rule_id=rule_id, status=status, resolved_at=resolved_at),
                report(work_status=work_status),
                resolution_evidence=() if proof_spec is None else (proof(proof_spec[0], at=proof_spec[1], freshness=proof_spec[2]),),
                collection_at_resolution=snapshot(at_status) if at_status else None,
                collection_after_resolution=snapshot(after_status, RESOLVED_AFTER + timedelta(hours=1))
                if after_status
                else None,
                collection_recorded=at_status is not None,
                identity_conflict_active=conflict,
            )
            count += 1
            method = VERIFICATION_METHODS.get(rule_id)
            component_method = method is not None and method.collection_check == "component-source-snapshot"
            expected = (
                status == "resolved"
                and work_status == "done"
                and not conflict
                and method is not None
                and method.automated
                and resolved_at > REPORTED
                and proof_spec is not None
                and proof_spec[0] in {"component-version-fixed", "fresh-observation"}
                and proof_spec[1] > REPORTED
                and proof_spec[2] in {"fresh", "aging"}
                and (not component_method or at_status == "complete")
            )
            self.assertEqual(
                outcome.verification_state == "verified",
                expected,
                (rule_id, status, resolved_at, proof_spec, at_status, after_status, work_status, conflict),
            )
            if outcome.verification_state == "verified":
                self.assertIn("RESOLVED_BY_FRESH_EVIDENCE", outcome.reason_codes)
                self.assertTrue(outcome.after_evidence_references)
            if status != "resolved":
                self.assertNotEqual(outcome.verification_state, "verified")
            if proof_spec is not None and proof_spec[0].startswith(("advisory", "applicability")) and status == "resolved":
                self.assertNotEqual(outcome.verification_state, "verified")
            self.assertEqual(
                list(outcome.reason_codes), sorted(outcome.reason_codes, key=REASON_CODE_ORDER.__getitem__)
            )
        self.assertEqual(count, 11 * (2 * 1 + 1 * 2) * 8 * 4 * 2 * 2 * 2)

    def test_unresolved_findings_never_verify_whatever_the_later_evidence(self) -> None:
        for rule_id, status, fresh, seen, collected in itertools.product(
            sorted(VERIFICATION_METHODS) + ["future-rule"],
            ("active", "acknowledged", "suppressed"),
            ("fresh", "aging", "stale", "unknown"),
            (None, BEFORE, AFTER),
            (None, "complete", "partial", "failed", "unsupported"),
        ):
            outcome = verify(
                finding(rule_id=rule_id, status=status, evidence_freshness=fresh, evidence_observed_at=seen),
                collection_since_report=snapshot(collected) if collected else None,
                collection_recorded=collected is not None,
                resolution_evidence=(proof(),),
            )
            self.assertNotIn(outcome.verification_state, {"verified", *NOT_ATTRIBUTABLE_STATES})

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


class ResolutionEvidenceDerivationTests(unittest.TestCase):
    """The finding lifecycle records why a resolution happened, from its own inputs."""

    def _snapshot(self, status: str, **match_overrides):
        from app.findings import evaluate_rules

        match = {
            "match_id": "vmt_" + "a" * 32,
            "component_id": "cmp_" + "c" * 32,
            "advisory_id": "adv_" + "d" * 32,
            "match_status": status,
            "match_confidence": 1.0,
            "installed_version": "1.4.2",
            "fixed_version": "1.4.2",
            "component_freshness": "fresh",
            "component_last_seen_at": AFTER,
            "evaluated_at": AFTER,
        }
        match.update(match_overrides)
        asset = {
            "asset_id": "asset-a",
            "site_id": "site-a",
            "observed_at": AFTER,
            "last_seen_at": AFTER,
            "metadata": {"category": "server"},
            "vulnerability_matches": [match],
        }
        return evaluate_rules(
            sites=[{"site_id": "site-a"}],
            sensors=[],
            assets=[asset],
            now=AFTER + timedelta(minutes=1),
            rule_ids=["vulnerable-component", "asset-stale"],
        )

    def test_fixed_match_basis_comes_from_the_matcher_reason(self) -> None:
        snapshot_id = "css_" + "e" * 32
        removed_at = AFTER + timedelta(seconds=30)
        for reasons, basis, observed in (
            (["at-or-after-fixed-boundary"], "component-version-fixed", AFTER),
            (["component-removal-confirmed-by-complete-inventory"], "component-removed", removed_at),
            (["reviewed-identity-match"], "match-fixed-unattributed", AFTER),
            ([], "match-fixed-unattributed", AFTER),
        ):
            with self.subTest(reasons=reasons):
                snapshot_value = self._snapshot(
                    "fixed",
                    reason_codes=reasons,
                    component_not_observed_at=removed_at,
                    component_source_snapshot_id=snapshot_id,
                )
                (dedupe,) = snapshot_value.resolution_eligible_dedupe_keys
                (evidence,) = snapshot_value.resolution_evidence[dedupe]
                self.assertEqual(evidence.basis, basis)
                self.assertEqual(evidence.evidence_ref, "vmt_" + "a" * 32)
                self.assertEqual((evidence.installed_version, evidence.fixed_version), ("1.4.2", "1.4.2"))
                # Removal is observed when the complete inventory omitted it.
                self.assertEqual(evidence.observed_at, observed)
                self.assertEqual(evidence.supporting_snapshot_id, snapshot_id)

    def test_advisory_changes_are_recorded_as_advisory_bases(self) -> None:
        for status, basis in (("advisory-withdrawn", "advisory-withdrawn"), ("not-affected", "applicability-not-affected")):
            with self.subTest(status=status):
                snapshot_value = self._snapshot(status)
                (dedupe,) = snapshot_value.resolution_eligible_dedupe_keys
                self.assertEqual(snapshot_value.resolution_evidence[dedupe][0].basis, basis)

    def test_affected_match_records_nothing(self) -> None:
        snapshot_value = self._snapshot("affected")
        self.assertEqual(snapshot_value.resolution_eligible_dedupe_keys, frozenset())
        self.assertFalse(any(key.startswith("fdk") for key in snapshot_value.resolution_evidence))

    def test_subject_rules_record_their_fresh_observation(self) -> None:
        from app.findings import resolution_evidence_key

        snapshot_value = self._snapshot("affected")
        key = ("asset-stale", "asset", "site-a", "asset-a")
        self.assertIn(key, snapshot_value.resolution_eligible)
        (evidence,) = snapshot_value.resolution_evidence[resolution_evidence_key(key)]
        self.assertEqual((evidence.basis, evidence.evidence_type), ("fresh-observation", "asset-observation"))
        self.assertTrue(evidence.evidence_ref.startswith("ev_"))


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
