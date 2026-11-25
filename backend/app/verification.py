"""Evidence-based remediation verification (CTEM-GAP-06).

Verification answers, for one finding:

- what condition needs verification;
- what evidence would establish that it changed;
- whether comparable evidence arrived since remediation was reported;
- whether that evidence supports the reported outcome.

It is a deterministic read model over existing authorities:

    work item marked done      -> the remediation report (a claim)
    deterministic finding run  -> the only path that resolves a finding
    finding evidence + source  -> the comparable "after" evidence
    collection snapshots       -> whether later collection was complete

Verification never resolves a finding, changes work status, or feeds the
decision layer or the Operational Attention Score. A work item marked done is
a claim, not proof. Absence of an observation never establishes resolution:
only the deterministic finding lifecycle, which already requires fresh,
affirmative, complete evidence, can mark a finding resolved.

This module has no database, clock, network, or model dependency.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Literal, Mapping, Sequence

from .findings import (
    ADVISORY_RESOLUTION_BASES,
    TECHNICAL_RESOLUTION_BASES,
    UNATTRIBUTED_RESOLUTION_BASES,
)


VERIFICATION_SCHEMA_VERSION = "oaw.verification.v1"
VERIFICATION_RULESET_VERSION = "oaw.verification.rules.v1"
MAX_VERIFICATION_EVIDENCE_REFERENCES = 8

VerificationState = Literal[
    "not-reported",
    "awaiting-evidence",
    "insufficient-evidence",
    "evidence-stale",
    "still-present",
    "conflicting-evidence",
    "manual-review-required",
    "verified",
    "resolved-before-report",
    "resolved-by-advisory-change",
    "report-withdrawn",
]
# States that can be recorded in history (a remediation report exists).
RECORDED_STATES: tuple[str, ...] = (
    "awaiting-evidence",
    "insufficient-evidence",
    "evidence-stale",
    "still-present",
    "conflicting-evidence",
    "manual-review-required",
    "verified",
    "resolved-before-report",
    "resolved-by-advisory-change",
    "report-withdrawn",
)
VERIFICATION_STATES: tuple[str, ...] = ("not-reported", *RECORDED_STATES)
# Closed without evidence that the reported work caused the change: the
# finding resolved before the report, or a reviewed advisory change removed it.
NOT_ATTRIBUTABLE_STATES = frozenset({"resolved-before-report", "resolved-by-advisory-change"})
# Reported work that still needs evidence or a person's review.
UNVERIFIED_STATES = frozenset(RECORDED_STATES) - {"verified", "report-withdrawn"} - NOT_ATTRIBUTABLE_STATES
CollectionCompleteness = Literal["complete", "incomplete", "none-since-report", "not-recorded", "not-applicable"]

FRESH_ENOUGH = frozenset({"fresh", "aging"})
CONFLICT_RULES = frozenset({"classification-conflict", "identity-conflict"})
COLLECTION_STATUSES = frozenset({"complete", "partial", "unsupported", "failed"})


@dataclass(frozen=True)
class VerificationMethod:
    method_id: str
    evidence_source: str
    comparable_evidence: str
    collection_check: Literal["component-source-snapshot", "finding-freshness"]
    automated: bool


# Reviewed mapping from finding rule to how its outcome can be verified. The
# evidence named here is what the platform already collects and evaluates; no
# method relies on active retesting. A rule missing from this table is held for
# manual review instead of being treated as verifiable.
VERIFICATION_METHODS: dict[str, VerificationMethod] = {
    "vulnerable-component": VerificationMethod(
        "component-inventory",
        "authenticated endpoint software inventory",
        "A later complete inventory showing the component removed or at a version the advisory "
        "does not affect, or a reviewed advisory change to not-affected or withdrawn.",
        "component-source-snapshot",
        True,
    ),
    "component-version-unavailable": VerificationMethod(
        "component-inventory",
        "authenticated endpoint software inventory",
        "A later complete inventory reporting a usable version for the component.",
        "component-source-snapshot",
        True,
    ),
    "advisory-identity-uncertain": VerificationMethod(
        "component-identity",
        "authenticated endpoint software inventory and reviewed advisory catalog",
        "A later complete inventory or reviewed catalog that makes the component identity precise.",
        "component-source-snapshot",
        True,
    ),
    "security-coverage-gap": VerificationMethod(
        "endpoint-coverage-status",
        "authenticated endpoint inventory",
        "A later endpoint-origin observation that no longer reports the coverage gap.",
        "finding-freshness",
        True,
    ),
    "asset-stale": VerificationMethod(
        "fresh-observation",
        "any authenticated collection for the asset",
        "A fresh normalized observation of the asset.",
        "finding-freshness",
        True,
    ),
    "sensor-stale": VerificationMethod(
        "sensor-check-in",
        "authenticated sensor check-in",
        "A current authenticated check-in from the sensor.",
        "finding-freshness",
        True,
    ),
    "unknown-asset": VerificationMethod(
        "classification",
        "deterministic classification of collected evidence",
        "Fresh evidence that yields a recognized classification.",
        "finding-freshness",
        True,
    ),
    "passive-only-asset": VerificationMethod(
        "managed-evidence",
        "authenticated endpoint inventory",
        "A fresh normalized record that is no longer passive-only.",
        "finding-freshness",
        True,
    ),
    "classification-conflict": VerificationMethod(
        "classification",
        "deterministic classification of collected evidence",
        "Deterministic reevaluation reporting a fresh non-conflicting classification.",
        "finding-freshness",
        True,
    ),
    "identity-conflict": VerificationMethod(
        "manual-identity-review",
        "inventory merge history and sensor provenance",
        "Identity conflicts do not resolve automatically; a person must review merge evidence.",
        "finding-freshness",
        False,
    ),
}
UNMAPPED_METHOD = VerificationMethod(
    "manual-review",
    "not defined for this finding rule",
    "No reviewed verification method exists for this finding rule.",
    "finding-freshness",
    False,
)


@dataclass(frozen=True)
class ReasonCodeDefinition:
    code: str
    explanation: str


# Catalog order is the stable output order.
REASON_CODE_CATALOG: tuple[ReasonCodeDefinition, ...] = (
    ReasonCodeDefinition("WORK_NOT_DONE", "No work item for this finding is marked done."),
    ReasonCodeDefinition("REPORT_WITHDRAWN", "Work was marked done earlier and has since been reopened."),
    ReasonCodeDefinition("REMEDIATION_REPORTED", "A work item marked done reports remediation. A report is a claim, not proof."),
    ReasonCodeDefinition("BASELINE_CAPTURED", "Evidence present when remediation was reported was recorded for comparison."),
    ReasonCodeDefinition("BASELINE_NOT_CAPTURED", "No evidence was recorded at report time, so before-and-after comparison is limited."),
    ReasonCodeDefinition("RESOLVED_BY_FRESH_EVIDENCE", "Deterministic evaluation resolved the finding from fresh affirmative evidence collected after the report."),
    ReasonCodeDefinition("RESOLVED_BEFORE_REPORT", "The finding was resolved before remediation was reported, so the resolution is not evidence that the reported work caused it."),
    ReasonCodeDefinition("COMPONENT_REMOVED", "A complete inventory after the report confirmed the component is no longer installed."),
    ReasonCodeDefinition("COMPONENT_VERSION_FIXED", "A later observation shows the component at or after the fixed boundary, at a different version than at report time."),
    ReasonCodeDefinition("FIXED_BOUNDARY_REVISED", "The match became fixed while the installed version stayed the same, so the advisory boundary changed, not the software."),
    ReasonCodeDefinition("VERSION_CHANGE_UNCONFIRMED", "The report-time condition (an affected installed version, or a missing version) was not recorded consistently with the component, so a version change after the report cannot be confirmed."),
    ReasonCodeDefinition("RESOLUTION_BASIS_UNCONFIRMED", "The match became fixed for a reason the matcher did not identify as removal or a version change."),
    ReasonCodeDefinition("COMPONENT_VERSION_COLLECTED", "A later observation supplied a usable component version."),
    ReasonCodeDefinition("OBSERVATION_CONFIRMS_CHANGE", "A later authorized observation shows the condition the rule detects has ended."),
    ReasonCodeDefinition("ADVISORY_WITHDRAWN", "The reviewed advisory was withdrawn. Nothing changed on the asset."),
    ReasonCodeDefinition("APPLICABILITY_REVISED", "The deterministic match became not-affected. That is an applicability change, not confirmed remediation."),
    ReasonCodeDefinition("ADVISORY_IDENTITY_REVIEWED", "Component identity was resolved through catalog review, not by a change on the asset."),
    ReasonCodeDefinition("RESOLUTION_EVIDENCE_UNAVAILABLE", "No affirmative resolution evidence was recorded for this resolution, for example because the match result and the component state it cited described different observations."),
    ReasonCodeDefinition("RESOLUTION_EVIDENCE_PREDATES_REPORT", "The evidence that resolved the finding was collected before remediation was reported."),
    ReasonCodeDefinition("RESOLUTION_EVIDENCE_OUTSIDE_WINDOW", "The resolving evidence was not collected between the report and the resolution."),
    ReasonCodeDefinition("EVIDENCE_SINCE_REPORT_STILL_MATCHES", "Evidence observed after the report still matches the finding rule."),
    ReasonCodeDefinition("REOPENED_SINCE_REPORT", "The finding reopened after remediation was reported."),
    ReasonCodeDefinition("NO_EVIDENCE_SINCE_REPORT", "No comparable evidence has been observed since remediation was reported."),
    ReasonCodeDefinition("EVALUATION_PENDING", "Newer collection exists but deterministic evaluation has not run on it yet."),
    ReasonCodeDefinition("COLLECTION_COMPLETE_SINCE_REPORT", "A complete collection was received after the report."),
    ReasonCodeDefinition("COLLECTION_INCOMPLETE_SINCE_REPORT", "Collection after the report was partial, failed, or unsupported. It cannot prove the condition ended."),
    ReasonCodeDefinition("COLLECTION_COMPLETE_AT_RESOLUTION", "The collection that observed the component between the report and the resolution was complete."),
    ReasonCodeDefinition("COLLECTION_INCOMPLETE_AT_RESOLUTION", "The newest collection before the resolution was partial, failed, or unsupported."),
    ReasonCodeDefinition("COLLECTION_NOT_COMPLETE_AT_RESOLUTION", "No complete collection between the report and the resolution was recorded."),
    ReasonCodeDefinition("COLLECTION_DEGRADED_SINCE_VERIFICATION", "Collection after the verified resolution was partial, failed, or unsupported. The earlier verification stands."),
    ReasonCodeDefinition("EVIDENCE_STALE", "The latest comparable evidence is stale."),
    ReasonCodeDefinition("EVIDENCE_FRESHNESS_UNKNOWN", "The age of the latest comparable evidence is unknown."),
    ReasonCodeDefinition("IDENTITY_CONFLICT_ACTIVE", "An active identity or classification conflict on this asset prevents attributing the outcome."),
    ReasonCodeDefinition("NOT_AUTOMATICALLY_VERIFIABLE", "This finding rule has no automatic verification path; a person must review the evidence."),
    ReasonCodeDefinition("SUPPRESSION_ACTIVE", "The finding is suppressed. Suppression does not prove the condition ended."),
)
REASON_CODE_ORDER: dict[str, int] = {item.code: index for index, item in enumerate(REASON_CODE_CATALOG)}
REASON_CODE_EXPLANATIONS: dict[str, str] = {item.code: item.explanation for item in REASON_CODE_CATALOG}


@dataclass(frozen=True)
class EvidenceReference:
    evidence_ref: str
    evidence_type: str
    freshness: str
    observed_at: datetime | None


@dataclass(frozen=True)
class ResolutionProof:
    """Affirmative evidence recorded by the finding lifecycle at resolution."""

    basis: str
    evidence_ref: str
    evidence_type: str
    source: str
    observed_at: datetime | None
    freshness: str
    installed_version: str | None = None
    fixed_version: str | None = None
    # The component source snapshot that observed the component or confirmed
    # its removal; None when the projection did not identify one.
    supporting_snapshot: CollectionSnapshot | None = None


@dataclass(frozen=True)
class CollectionSnapshot:
    snapshot_id: str
    collection_status: str
    observed_at: datetime


@dataclass(frozen=True)
class FindingState:
    finding_id: str
    site_id: str
    rule_id: str
    subject_type: str
    status: str
    evidence_observed_at: datetime | None
    evidence_freshness: str
    evaluated_at: datetime
    resolved_at: datetime | None
    reopen_count: int
    evidence: tuple[EvidenceReference, ...] = ()


@dataclass(frozen=True)
class RemediationReport:
    """The latest work-status change to `done`, and its captured baseline."""

    report_revision: int
    reported_at: datetime
    work_status: str
    baseline_captured: bool
    baseline_reopen_count: int | None = None
    baseline_evidence: tuple[EvidenceReference, ...] = ()
    # (match_id, installed version) captured when work was marked done; the
    # version is None unless it describes an open, consistent condition.
    baseline_match_versions: tuple[tuple[str, str | None], ...] = ()
    # Whether the baseline shows the component's version was still missing at
    # report time (see `report_time_version_unknown`).
    baseline_version_unknown: bool = False


@dataclass(frozen=True)
class VerificationInput:
    finding: FindingState
    report: RemediationReport | None
    # Newest snapshot after the report from the collection sources that
    # report the finding's component (component methods only).
    collection_since_report: CollectionSnapshot | None = None
    # Whether the asset has any recorded component source snapshot at all.
    collection_recorded: bool = False
    # Whether an identity or classification conflict finding is current on the
    # same asset.
    identity_conflict_active: bool = False
    # Affirmative evidence recorded for the finding's current resolution, each
    # with the exact snapshot that supported it.
    resolution_evidence: tuple[ResolutionProof, ...] = ()
    # Newest snapshot after the resolution from the same collection source as
    # the supporting snapshot.
    collection_after_resolution: CollectionSnapshot | None = None


@dataclass(frozen=True)
class VerificationOutcome:
    schema_version: str
    ruleset_version: str
    finding_id: str
    site_id: str
    finding_rule_id: str
    verification_state: VerificationState
    method_id: str
    automated: bool
    collection_completeness: CollectionCompleteness
    reason_codes: tuple[str, ...]
    after_evidence_references: tuple[EvidenceReference, ...]
    input_digest: str

    def outcome(self) -> tuple[Any, ...]:
        """Fields whose change is a material verification transition."""

        return (self.ruleset_version, self.verification_state, self.reason_codes)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("verification timestamps must include a timezone")
    return value.astimezone(timezone.utc)


def method_for(rule_id: str) -> VerificationMethod:
    return VERIFICATION_METHODS.get(rule_id, UNMAPPED_METHOD)


def _ordered(codes: Iterable[str]) -> tuple[str, ...]:
    unique = set(codes)
    if unique - set(REASON_CODE_ORDER):
        raise ValueError("reason code is not in the reviewed catalog")
    return tuple(sorted(unique, key=REASON_CODE_ORDER.__getitem__))


def _after(evidence: Sequence[EvidenceReference], reported_at: datetime) -> tuple[EvidenceReference, ...]:
    later = [item for item in evidence if item.observed_at is not None and _utc(item.observed_at) > reported_at]
    later.sort(key=lambda item: (item.evidence_ref, item.evidence_type))
    return tuple(later[:MAX_VERIFICATION_EVIDENCE_REFERENCES])


def _completeness(value: VerificationInput, method: VerificationMethod) -> CollectionCompleteness:
    """Completeness of the collection that decides the outcome.

    For a resolved finding that is the collection before the resolution, so a
    later failed collection cannot undo a verified outcome. Otherwise it is the
    newest collection since the report.
    """

    for snapshot in (
        value.collection_since_report,
        value.collection_after_resolution,
        *(item.supporting_snapshot for item in value.resolution_evidence),
    ):
        if snapshot is not None and snapshot.collection_status not in COLLECTION_STATUSES:
            raise ValueError("unsupported collection status")
    if method.collection_check != "component-source-snapshot":
        return "not-applicable"
    if value.finding.status == "resolved":
        snapshots = [
            item.supporting_snapshot
            for item in value.resolution_evidence
            if item.supporting_snapshot is not None and _in_window(item.supporting_snapshot.observed_at, value)
        ]
        if any(item.collection_status == "complete" for item in snapshots):
            return "complete"
        if snapshots:
            return "incomplete"
        return "none-since-report" if value.collection_recorded else "not-recorded"
    deciding = value.collection_since_report
    if deciding is not None:
        return "complete" if deciding.collection_status == "complete" else "incomplete"
    return "none-since-report" if value.collection_recorded else "not-recorded"


def _in_window(at: datetime | None, value: VerificationInput) -> bool:
    """True when `at` lies after the report and at or before the resolution."""

    if at is None or value.report is None or value.finding.resolved_at is None:
        return False
    return _utc(value.report.reported_at) < _utc(at) <= _utc(value.finding.resolved_at)


def _proof_payload(items: Sequence[ResolutionProof]) -> list[list[Any]]:
    return sorted(
        [
            item.basis,
            item.evidence_ref,
            item.evidence_type,
            item.source,
            _iso(item.observed_at),
            item.freshness,
            item.installed_version,
            item.fixed_version,
            _snapshot_payload(item.supporting_snapshot),
        ]
        for item in items
    )


def _snapshot_payload(item: CollectionSnapshot | None) -> list[Any] | None:
    return None if item is None else [item.snapshot_id, item.collection_status, _iso(item.observed_at)]


_BASIS_REASON = {
    "component-removed": "COMPONENT_REMOVED",
    "component-version-fixed": "COMPONENT_VERSION_FIXED",
    "match-fixed-unattributed": "RESOLUTION_BASIS_UNCONFIRMED",
    "component-version-available": "COMPONENT_VERSION_COLLECTED",
    "applicability-not-affected": "APPLICABILITY_REVISED",
    "advisory-withdrawn": "ADVISORY_WITHDRAWN",
    "advisory-identity-reviewed": "ADVISORY_IDENTITY_REVIEWED",
}


def _basis_reason(basis: str) -> str:
    return _BASIS_REASON.get(basis, "OBSERVATION_CONFIRMS_CHANGE")


def _evidence_payload(items: Sequence[EvidenceReference]) -> list[list[Any]]:
    return sorted(
        [item.evidence_ref, item.evidence_type, item.freshness, _iso(item.observed_at)] for item in items
    )


def _iso(value: datetime | None) -> str | None:
    utc = _utc(value)
    return utc.isoformat() if utc is not None else None


def input_digest(value: VerificationInput) -> str:
    """SHA-256 over the exact normalized inputs and ruleset version."""

    finding = value.finding
    report = value.report
    payload = {
        "ruleset_version": VERIFICATION_RULESET_VERSION,
        "finding": {
            "finding_id": finding.finding_id,
            "site_id": finding.site_id,
            "rule_id": finding.rule_id,
            "subject_type": finding.subject_type,
            "status": finding.status,
            "evidence_observed_at": _iso(finding.evidence_observed_at),
            "evidence_freshness": finding.evidence_freshness,
            "evaluated_at": _iso(finding.evaluated_at),
            "resolved_at": _iso(finding.resolved_at),
            "reopen_count": int(finding.reopen_count),
            "evidence": _evidence_payload(finding.evidence),
        },
        "report": None
        if report is None
        else {
            "report_revision": report.report_revision,
            "reported_at": _iso(report.reported_at),
            "work_status": report.work_status,
            "baseline_captured": report.baseline_captured,
            "baseline_reopen_count": report.baseline_reopen_count,
            "baseline_match_versions": sorted([list(pair) for pair in report.baseline_match_versions]),
            "baseline_version_unknown": report.baseline_version_unknown,
        },
        "collection_since_report": _snapshot_payload(value.collection_since_report),
        "collection_after_resolution": _snapshot_payload(value.collection_after_resolution),
        "collection_recorded": value.collection_recorded,
        "identity_conflict_active": value.identity_conflict_active,
        "resolution_evidence": _proof_payload(value.resolution_evidence),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def evaluate_verification(value: VerificationInput) -> VerificationOutcome:
    """Deterministically verify one finding. Identical inputs give identical output."""

    finding = value.finding
    if finding.status not in {"active", "acknowledged", "resolved", "suppressed"}:
        raise ValueError("unsupported finding status for verification")
    if finding.evidence_freshness not in {"fresh", "aging", "stale", "unknown"}:
        raise ValueError("unsupported evidence freshness for verification")
    _utc(finding.evaluated_at)
    method = method_for(finding.rule_id)
    completeness = _completeness(value, method)
    digest = input_digest(value)
    common = {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "ruleset_version": VERIFICATION_RULESET_VERSION,
        "finding_id": finding.finding_id,
        "site_id": finding.site_id,
        "finding_rule_id": finding.rule_id,
        "method_id": method.method_id,
        "automated": method.automated,
        "collection_completeness": completeness,
        "input_digest": digest,
    }
    report = value.report

    if report is None:
        return VerificationOutcome(
            **common,
            verification_state="not-reported",
            reason_codes=("WORK_NOT_DONE",),
            after_evidence_references=(),
        )

    reported_at = _utc(report.reported_at)
    assert reported_at is not None
    reasons: list[str] = ["REMEDIATION_REPORTED"]
    reasons.append("BASELINE_CAPTURED" if report.baseline_captured else "BASELINE_NOT_CAPTURED")
    after = _after(finding.evidence, reported_at)

    if report.work_status != "done":
        reasons.append("REPORT_WITHDRAWN")
        return VerificationOutcome(
            **common,
            verification_state="report-withdrawn",
            reason_codes=_ordered(reasons),
            after_evidence_references=after,
        )

    if finding.status == "resolved":
        return _resolved_outcome(value, method, completeness, reported_at, reasons, common)

    if completeness == "complete":
        reasons.append("COLLECTION_COMPLETE_SINCE_REPORT")
    elif completeness == "incomplete":
        reasons.append("COLLECTION_INCOMPLETE_SINCE_REPORT")
    if finding.status == "suppressed":
        reasons.append("SUPPRESSION_ACTIVE")

    # The finding is not resolved. Nothing below can produce `verified`.
    if not method.automated:
        reasons.append("NOT_AUTOMATICALLY_VERIFIABLE")
        state = "manual-review-required"
    else:
        observed_at = _utc(finding.evidence_observed_at)
        reopened = (
            report.baseline_reopen_count is not None
            and int(finding.reopen_count) > int(report.baseline_reopen_count)
        )
        if reopened:
            reasons.append("REOPENED_SINCE_REPORT")
        evidence_since_report = observed_at is not None and observed_at > reported_at
        if evidence_since_report and finding.evidence_freshness in FRESH_ENOUGH:
            reasons.append("EVIDENCE_SINCE_REPORT_STILL_MATCHES")
            state = "still-present"
        elif evidence_since_report and finding.evidence_freshness == "stale":
            reasons.append("EVIDENCE_STALE")
            state = "evidence-stale"
        elif evidence_since_report:
            reasons.append("EVIDENCE_FRESHNESS_UNKNOWN")
            state = "insufficient-evidence"
        elif completeness == "incomplete":
            # Later collection arrived but was partial or failed: it cannot
            # prove the condition ended.
            reasons.append("NO_EVIDENCE_SINCE_REPORT")
            state = "insufficient-evidence"
        elif (
            completeness == "complete"
            and value.collection_since_report is not None
            and _utc(value.collection_since_report.observed_at) > _utc(finding.evaluated_at)
        ):
            reasons.extend(("NO_EVIDENCE_SINCE_REPORT", "EVALUATION_PENDING"))
            state = "awaiting-evidence"
        elif finding.evidence_freshness == "stale":
            reasons.extend(("NO_EVIDENCE_SINCE_REPORT", "EVIDENCE_STALE"))
            state = "awaiting-evidence"
        else:
            reasons.append("NO_EVIDENCE_SINCE_REPORT")
            state = "awaiting-evidence"
    if value.identity_conflict_active and state != "manual-review-required":
        reasons.append("IDENTITY_CONFLICT_ACTIVE")
    return VerificationOutcome(
        **common,
        verification_state=state,
        reason_codes=_ordered(reasons),
        after_evidence_references=after,
    )


def _resolved_outcome(
    value: VerificationInput,
    method: VerificationMethod,
    completeness: CollectionCompleteness,
    reported_at: datetime,
    reasons: list[str],
    common: Mapping[str, Any],
) -> VerificationOutcome:
    """Decide a resolved finding.

    A historical resolution is not proof that the reported work caused the
    change. `verified` needs all of:

    - an automatic verification method for the rule;
    - no identity or classification conflict on the asset;
    - a resolution after the report;
    - recorded affirmative evidence with a technical basis (a change on the
      asset, not a reviewed advisory or applicability change);
    - that evidence collected after the report and fresh or aging;
    - for component methods, a complete collection between the report and the
      resolution.

    A later failed or partial collection does not undo a verified outcome; it
    adds `COLLECTION_DEGRADED_SINCE_VERIFICATION`.
    """

    finding = value.finding
    resolved_at = _utc(finding.resolved_at)
    proofs = value.resolution_evidence
    known = TECHNICAL_RESOLUTION_BASES | ADVISORY_RESOLUTION_BASES | UNATTRIBUTED_RESOLUTION_BASES
    if any(item.basis not in known for item in proofs):
        raise ValueError("unsupported resolution basis")
    after = tuple(
        sorted(
            (
                EvidenceReference(item.evidence_ref, item.evidence_type, item.freshness, item.observed_at)
                for item in proofs
                if _in_window(item.observed_at, value)
            ),
            key=lambda item: (item.evidence_ref, item.evidence_type),
        )
    )[:MAX_VERIFICATION_EVIDENCE_REFERENCES]

    def outcome(state: VerificationState) -> VerificationOutcome:
        return VerificationOutcome(
            **common,
            verification_state=state,
            reason_codes=_ordered(reasons),
            after_evidence_references=after,
        )

    if not method.automated:
        reasons.append("NOT_AUTOMATICALLY_VERIFIABLE")
        return outcome("manual-review-required")
    if value.identity_conflict_active:
        reasons.append("IDENTITY_CONFLICT_ACTIVE")
        return outcome("conflicting-evidence")
    if resolved_at is None or resolved_at <= reported_at:
        reasons.append("RESOLVED_BEFORE_REPORT")
        return outcome("resolved-before-report")
    if not proofs:
        reasons.append("RESOLUTION_EVIDENCE_UNAVAILABLE")
        return outcome("insufficient-evidence")
    reasons.extend(_basis_reason(item.basis) for item in proofs)

    # A `fixed` match by version counts as an upgrade only when the installed
    # version actually changed since the report. The same version with a
    # `fixed` status means the advisory's fixed boundary was revised.
    baseline_versions = dict(value.report.baseline_match_versions) if value.report else {}
    confirmed: list[ResolutionProof] = []
    boundary_revised = version_unconfirmed = False
    for item in proofs:
        if item.basis not in TECHNICAL_RESOLUTION_BASES:
            continue
        if item.basis == "component-version-available" and not (value.report and value.report.baseline_version_unknown):
            # The version must still have been missing when work was reported.
            version_unconfirmed = True
            continue
        if item.basis == "component-version-fixed":
            before = baseline_versions.get(item.evidence_ref)
            if item.evidence_ref not in baseline_versions or before is None or item.installed_version is None:
                version_unconfirmed = True
                continue
            if before == item.installed_version:
                boundary_revised = True
                continue
        confirmed.append(item)
    if not confirmed:
        if boundary_revised:
            reasons.append("FIXED_BOUNDARY_REVISED")
            return outcome("resolved-by-advisory-change")
        if version_unconfirmed:
            reasons.append("VERSION_CHANGE_UNCONFIRMED")
            if any(
                item.basis in {"component-version-fixed", "component-version-available"}
                and item.observed_at is not None
                and _utc(item.observed_at) <= reported_at
                for item in proofs
            ):
                reasons.append("RESOLUTION_EVIDENCE_PREDATES_REPORT")
            return outcome("insufficient-evidence")
        if any(item.basis in UNATTRIBUTED_RESOLUTION_BASES for item in proofs):
            return outcome("insufficient-evidence")
        return outcome("resolved-by-advisory-change")

    in_window = [item for item in confirmed if _in_window(item.observed_at, value)]
    if not in_window:
        if any(item.observed_at is not None and _utc(item.observed_at) <= reported_at for item in confirmed):
            reasons.append("RESOLUTION_EVIDENCE_PREDATES_REPORT")
        else:
            reasons.append("RESOLUTION_EVIDENCE_OUTSIDE_WINDOW")
        return outcome("insufficient-evidence")
    fresh = [item for item in in_window if item.freshness in FRESH_ENOUGH]
    if not fresh:
        if any(item.freshness == "stale" for item in in_window):
            reasons.append("EVIDENCE_STALE")
            return outcome("evidence-stale")
        reasons.append("EVIDENCE_FRESHNESS_UNKNOWN")
        return outcome("insufficient-evidence")
    if method.collection_check == "component-source-snapshot":
        # The supporting snapshot must be the one that observed this component
        # (or confirmed its removal), complete, and inside the report-to-
        # resolution window. Another complete inventory on the asset is not
        # enough.
        supported = [
            item
            for item in fresh
            if item.supporting_snapshot is not None
            and item.supporting_snapshot.collection_status == "complete"
            and _in_window(item.supporting_snapshot.observed_at, value)
        ]
        if not supported:
            incomplete = any(
                item.supporting_snapshot is not None
                and _in_window(item.supporting_snapshot.observed_at, value)
                for item in fresh
            )
            reasons.append(
                "COLLECTION_INCOMPLETE_AT_RESOLUTION" if incomplete else "COLLECTION_NOT_COMPLETE_AT_RESOLUTION"
            )
            return outcome("insufficient-evidence")
        reasons.append("COLLECTION_COMPLETE_AT_RESOLUTION")
        later = value.collection_after_resolution
        if later is not None and later.collection_status != "complete":
            reasons.append("COLLECTION_DEGRADED_SINCE_VERIFICATION")
    reasons.append("RESOLVED_BY_FRESH_EVIDENCE")
    return outcome("verified")


def report_time_version(entry: Mapping[str, Any]) -> str | None:
    """The installed version a baseline match entry establishes, or None.

    A baseline describes the condition at report time only when the match
    still showed the component affected and was computed from the component
    state recorded with it. A match that was already fixed, not affected, or
    stale against the component is not a usable "before" version.
    """

    installed = entry.get("installed_version")
    if (
        entry.get("match_status") != "affected"
        or entry.get("component_active") is not True
        or not isinstance(installed, str)
        or not installed
        or installed != entry.get("component_version")
    ):
        return None
    return installed


def report_time_version_unknown(entries: Sequence[Mapping[str, Any]]) -> bool:
    """Whether baseline match entries show the component version still missing.

    Every entry must be a `version-unknown` match computed from a present
    component that itself recorded no version.
    """

    return bool(entries) and all(
        entry.get("match_status") == "version-unknown"
        and entry.get("installed_version") is None
        and entry.get("component_version") is None
        and entry.get("component_active") is True
        for entry in entries
    )


def proofs_from_records(rows: Sequence[Mapping[str, Any]]) -> tuple[ResolutionProof, ...]:
    return tuple(
        ResolutionProof(
            basis=str(row["resolution_basis"]),
            evidence_ref=str(row["evidence_ref"]),
            evidence_type=str(row["evidence_type"]),
            source=str(row["source"]),
            observed_at=row.get("observed_at"),
            freshness=str(row["freshness"]),
            installed_version=row.get("installed_version"),
            fixed_version=row.get("fixed_version"),
            supporting_snapshot=CollectionSnapshot(
                snapshot_id=str(row["supporting_snapshot_id"]),
                collection_status=str(row["snapshot_status"]),
                observed_at=row["snapshot_observed_at"],
            )
            if row.get("supporting_snapshot_id") and row.get("snapshot_status")
            else None,
        )
        for row in rows
    )


def evidence_from_records(rows: Sequence[Mapping[str, Any]]) -> tuple[EvidenceReference, ...]:
    return tuple(
        EvidenceReference(
            evidence_ref=str(row["evidence_ref"]),
            evidence_type=str(row["evidence_type"]),
            freshness=str(row["freshness"]),
            observed_at=row.get("observed_at"),
        )
        for row in rows
    )


def evidence_to_json(items: Sequence[EvidenceReference]) -> list[dict[str, Any]]:
    return [
        {
            "evidence_ref": item.evidence_ref,
            "evidence_type": item.evidence_type,
            "freshness": item.freshness,
            "observed_at": _iso(item.observed_at),
        }
        for item in items
    ]


def evidence_from_json(items: Sequence[Mapping[str, Any]] | None) -> tuple[EvidenceReference, ...]:
    result = []
    for item in items or ():
        observed = item.get("observed_at")
        result.append(
            EvidenceReference(
                evidence_ref=str(item["evidence_ref"]),
                evidence_type=str(item["evidence_type"]),
                freshness=str(item["freshness"]),
                observed_at=datetime.fromisoformat(observed) if isinstance(observed, str) else observed,
            )
        )
    return tuple(result)


def ruleset_public() -> dict[str, Any]:
    from .findings import RULES_BY_ID

    return {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "ruleset_version": VERIFICATION_RULESET_VERSION,
        "states": list(VERIFICATION_STATES),
        "unverified_states": sorted(UNVERIFIED_STATES),
        "not_attributable_states": sorted(NOT_ATTRIBUTABLE_STATES),
        "methods": [
            {
                "finding_rule_id": rule_id,
                "method_id": method.method_id,
                "evidence_source": method.evidence_source,
                "comparable_evidence": method.comparable_evidence,
                "collection_check": method.collection_check,
                "automated": method.automated,
                "resolution_behavior": RULES_BY_ID[rule_id].resolution_behavior if rule_id in RULES_BY_ID else None,
            }
            for rule_id, method in sorted(VERIFICATION_METHODS.items())
        ],
        "reason_codes": [{"code": item.code, "explanation": item.explanation} for item in REASON_CODE_CATALOG],
        "limitations": [
            "A work item marked done is a remediation claim; only deterministic finding evaluation "
            "on fresh, affirmative evidence resolves a finding.",
            "A resolution counts as verified remediation only with recorded technical evidence "
            "collected after the report and, for software, a complete collection before the resolution.",
            "Advisory withdrawal and applicability changes resolve findings without remediation "
            "evidence and are reported separately.",
            "Verification waits for the next authorized collection; it never retests actively.",
            "Absence of an observation, or a partial or failed collection, never establishes resolution.",
        ],
    }
