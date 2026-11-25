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
    "report-withdrawn",
)
VERIFICATION_STATES: tuple[str, ...] = ("not-reported", *RECORDED_STATES)
# Every state except `verified` means reported work is not yet verified.
UNVERIFIED_STATES = frozenset(RECORDED_STATES) - {"verified", "report-withdrawn"}
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
    ReasonCodeDefinition("RESOLVED_BY_FRESH_EVIDENCE", "Deterministic evaluation resolved the finding from fresh affirmative evidence after the report."),
    ReasonCodeDefinition("RESOLVED_BEFORE_REPORT", "The finding was already resolved by fresh evidence before remediation was reported."),
    ReasonCodeDefinition("EVIDENCE_SINCE_REPORT_STILL_MATCHES", "Evidence observed after the report still matches the finding rule."),
    ReasonCodeDefinition("REOPENED_SINCE_REPORT", "The finding reopened after remediation was reported."),
    ReasonCodeDefinition("NO_EVIDENCE_SINCE_REPORT", "No comparable evidence has been observed since remediation was reported."),
    ReasonCodeDefinition("EVALUATION_PENDING", "Newer collection exists but deterministic evaluation has not run on it yet."),
    ReasonCodeDefinition("COLLECTION_COMPLETE_SINCE_REPORT", "A complete collection was received after the report."),
    ReasonCodeDefinition("COLLECTION_INCOMPLETE_SINCE_REPORT", "Collection after the report was partial, failed, or unsupported. It cannot prove the condition ended."),
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


@dataclass(frozen=True)
class VerificationInput:
    finding: FindingState
    report: RemediationReport | None
    # Newest component source snapshot for the asset observed after the report
    # (component methods only); None when no such snapshot exists.
    collection_since_report: CollectionSnapshot | None = None
    # Whether the asset has any recorded component source snapshot at all.
    collection_recorded: bool = False
    # Whether an identity or classification conflict finding is current on the
    # same asset.
    identity_conflict_active: bool = False


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
    if method.collection_check != "component-source-snapshot":
        return "not-applicable"
    if value.collection_since_report is not None:
        if value.collection_since_report.collection_status not in COLLECTION_STATUSES:
            raise ValueError("unsupported collection status")
        return "complete" if value.collection_since_report.collection_status == "complete" else "incomplete"
    return "none-since-report" if value.collection_recorded else "not-recorded"


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
        },
        "collection_since_report": None
        if value.collection_since_report is None
        else [
            value.collection_since_report.snapshot_id,
            value.collection_since_report.collection_status,
            _iso(value.collection_since_report.observed_at),
        ],
        "collection_recorded": value.collection_recorded,
        "identity_conflict_active": value.identity_conflict_active,
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

    if completeness == "complete":
        reasons.append("COLLECTION_COMPLETE_SINCE_REPORT")
    elif completeness == "incomplete":
        reasons.append("COLLECTION_INCOMPLETE_SINCE_REPORT")
    if finding.status == "suppressed":
        reasons.append("SUPPRESSION_ACTIVE")

    resolved_at = _utc(finding.resolved_at)
    if finding.status == "resolved":
        # Resolution comes only from the deterministic finding lifecycle, which
        # already requires fresh, affirmative, complete evidence.
        if value.identity_conflict_active:
            reasons.append("IDENTITY_CONFLICT_ACTIVE")
            state: VerificationState = "conflicting-evidence"
        else:
            reasons.append(
                "RESOLVED_BEFORE_REPORT"
                if resolved_at is not None and resolved_at <= reported_at
                else "RESOLVED_BY_FRESH_EVIDENCE"
            )
            state = "verified"
        return VerificationOutcome(
            **common,
            verification_state=state,
            reason_codes=_ordered(reasons),
            after_evidence_references=after,
        )

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
            "Verification waits for the next authorized collection; it never retests actively.",
            "Absence of an observation, or a partial or failed collection, never establishes resolution.",
        ],
    }
