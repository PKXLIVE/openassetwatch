"""Deterministic finding decision layer (`oaw.decision.v1` contract).

Two rulesets exist. `oaw.decision.rules.v1` is kept exactly reproducible so
historical decisions keep their meaning. `oaw.decision.rules.v2` is active: it
adds operator-assigned asset importance as an input and one Act Now rule
(known exploitation on a critical asset when exposure is not ruled out).

The decision layer answers "what should receive attention now, and why" for one
deterministic finding. It sits beside the Operational Attention Score
(`oaw.risk.v1`) and never replaces it:

    evidence -> finding -> Operational Attention Score
             -> deterministic decision (action band, urgency, reason codes)
             -> human work (finding work tracking)

Everything here is a pure function of one finding's authoritative fields and
its server-issued evidence. It reads no clock, database, network, model, or
work-tracking state. The ordered rule table and reason-code catalog are
reviewed product code; external text can never select or define them.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Literal, Mapping, Sequence


DECISION_SCHEMA_VERSION = "oaw.decision.v1"
DECISION_RULESET_V1 = "oaw.decision.rules.v1"
DECISION_RULESET_V2 = "oaw.decision.rules.v2"
SUPPORTED_DECISION_RULESETS = (DECISION_RULESET_V1, DECISION_RULESET_V2)
# The active ruleset. Earlier versions stay evaluable for reproduction only.
DECISION_RULESET_VERSION = DECISION_RULESET_V2
MAX_DECISION_EVIDENCE_REFERENCES = 8

ActionBand = Literal["monitor", "plan", "prioritize", "act-now"]
Urgency = Literal["immediate", "expedited", "scheduled", "monitor", "verification-required"]
DecisionState = Literal["current", "not-current"]
EvidenceConfidence = Literal["high", "medium", "low", "insufficient", "conflicted"]
ExploitationStatus = Literal[
    "known-exploited",
    "public-exploit-evidence",
    "no-known-exploitation",
    "unknown",
    "not-applicable",
]
ExposureState = Literal[
    "internet-reachable",
    "externally-reachable",
    "internally-reachable",
    "segmented",
    "not-reachable",
    "unknown",
    "not-applicable",
]
AssetImportance = Literal["critical", "high", "standard", "low", "unknown", "not-applicable"]
# Effective importance an input may carry. `unknown` means no operator
# assignment; it is never read as low and never satisfies a critical rule.
ASSET_IMPORTANCE_INPUTS = ("critical", "high", "standard", "low", "unknown")
# Exposure states that affirmatively rule exposure out. Only `not-reachable`
# does. `segmented` means reachability is limited, not that alternate paths are
# ruled out, so it does not block the critical-asset rule. Whether a reviewed
# segmentation control should lower a critical-asset Act Now is a policy
# decision for the exposure model (CTEM-GAP-03); no current input produces any
# of these states.
EXPOSURE_RULED_OUT_STATES = frozenset({"not-reachable"})

# Ascending order of attention. The display names are product copy.
ACTION_BANDS: tuple[ActionBand, ...] = ("monitor", "plan", "prioritize", "act-now")
ACTION_BAND_LABELS: dict[str, str] = {
    "monitor": "Monitor",
    "plan": "Plan",
    "prioritize": "Prioritize",
    "act-now": "Act Now",
}
URGENCY_FOR_BAND: dict[str, Urgency] = {
    "act-now": "immediate",
    "prioritize": "expedited",
    "plan": "scheduled",
    "monitor": "monitor",
}
FINDING_SEVERITIES = ("informational", "low", "medium", "high", "critical")
FRESHNESS_VALUES = ("fresh", "aging", "stale", "unknown")

# Numeric finding confidence is a deterministic implementation weight, not a
# calibrated probability. These versioned thresholds only translate it into a
# readable band.
CONFIDENCE_HIGH_MIN = 0.85
CONFIDENCE_MEDIUM_MIN = 0.65
CONFIDENCE_LOW_MIN = 0.40

KEV_EVIDENCE_TYPES = frozenset({"kev-prioritization", "kev-prioritization-ransomware"})
KEV_RANSOMWARE_EVIDENCE_TYPE = "kev-prioritization-ransomware"

# Finding rule families. A finding rule that is not listed here fails safe to
# `plan` with verification required; it is never treated as safe.
VULNERABILITY_RULE = "vulnerable-component"
IDENTITY_OR_VERSION_GAP_RULES = frozenset({"component-version-unavailable", "advisory-identity-uncertain"})
CONFLICT_RULES = frozenset({"classification-conflict", "identity-conflict"})
COLLECTION_GAP_RULES = frozenset({"asset-stale", "sensor-stale", "unknown-asset", "passive-only-asset"})
SEVERITY_DEFAULT_RULES = frozenset({"security-coverage-gap"})
RULE_FAMILY_REASON: dict[str, str] = {
    "vulnerable-component": "VULNERABILITY_CONFIRMED",
    "component-version-unavailable": "VERSION_UNKNOWN",
    "advisory-identity-uncertain": "IDENTITY_UNCERTAIN",
    "classification-conflict": "EVIDENCE_CONFLICTED",
    "identity-conflict": "EVIDENCE_CONFLICTED",
    "security-coverage-gap": "SECURITY_CONTROL_COVERAGE_GAP",
    "passive-only-asset": "ASSET_UNMANAGED",
    "unknown-asset": "ASSET_UNCLASSIFIED",
    "asset-stale": "COLLECTION_STALE",
    "sensor-stale": "COLLECTION_STALE",
}


@dataclass(frozen=True)
class ReasonCodeDefinition:
    code: str
    source: str
    explanation: str


# Catalog order is the stable output order of reason codes.
REASON_CODE_CATALOG: tuple[ReasonCodeDefinition, ...] = (
    ReasonCodeDefinition(
        "FINDING_RESOLVED",
        "findings.status",
        "Fresh affirmative evidence resolved the finding, so no action band applies.",
    ),
    ReasonCodeDefinition(
        "SUPPRESSION_ACTIVE",
        "findings.status",
        "An audited suppression excludes this finding from current prioritization. "
        "The band is still shown; suppression does not prove the condition is gone.",
    ),
    ReasonCodeDefinition(
        "EXPLOITATION_KNOWN",
        "finding_evidence (known-exploited catalog)",
        "A reviewed known-exploited catalog lists an exact vulnerability alias for this "
        "finding. Exploitation of this specific asset is not established.",
    ),
    ReasonCodeDefinition(
        "EXPLOITATION_RANSOMWARE_KNOWN",
        "finding_evidence (known-exploited catalog)",
        "The known-exploited catalog also records use in ransomware campaigns.",
    ),
    ReasonCodeDefinition(
        "EXPLOITATION_SOURCE_STALE",
        "finding_evidence.freshness",
        "The known-exploited catalog evidence is stale or of unknown age. It still counts, "
        "but the catalog should be refreshed.",
    ),
    ReasonCodeDefinition(
        "VULNERABILITY_CONFIRMED",
        "findings.rule_id",
        "Deterministic matching confirmed that an installed component version is affected "
        "by a reviewed advisory.",
    ),
    ReasonCodeDefinition(
        "SECURITY_CONTROL_COVERAGE_GAP",
        "findings.rule_id",
        "Fresh evidence shows an expected security control is missing or not healthy.",
    ),
    ReasonCodeDefinition(
        "EVIDENCE_CONFLICTED",
        "findings.rule_id",
        "Strong sources disagree about this asset. A person should resolve the conflict.",
    ),
    ReasonCodeDefinition(
        "IDENTITY_UNCERTAIN",
        "findings.rule_id",
        "Product identity is too uncertain to confirm whether an advisory applies.",
    ),
    ReasonCodeDefinition(
        "VERSION_UNKNOWN",
        "findings.rule_id",
        "The installed version is unknown, so applicability cannot be confirmed.",
    ),
    ReasonCodeDefinition(
        "ASSET_UNMANAGED",
        "findings.rule_id",
        "The asset is seen only passively; no managed endpoint evidence exists.",
    ),
    ReasonCodeDefinition(
        "ASSET_UNCLASSIFIED",
        "findings.rule_id",
        "The asset type is not yet established.",
    ),
    ReasonCodeDefinition(
        "COLLECTION_STALE",
        "findings.rule_id",
        "Expected collection stopped arriving. Restore evidence before drawing conclusions.",
    ),
    ReasonCodeDefinition(
        "DECISION_RULE_UNMAPPED",
        "findings.rule_id",
        "This finding rule has no reviewed decision mapping yet, so it is held for planning "
        "and verification rather than treated as safe.",
    ),
    ReasonCodeDefinition("SEVERITY_CRITICAL", "findings.severity", "Technical severity is critical."),
    ReasonCodeDefinition("SEVERITY_HIGH", "findings.severity", "Technical severity is high."),
    ReasonCodeDefinition("SEVERITY_MEDIUM", "findings.severity", "Technical severity is medium."),
    ReasonCodeDefinition("SEVERITY_LOW", "findings.severity", "Technical severity is low."),
    ReasonCodeDefinition(
        "SEVERITY_INFORMATIONAL",
        "findings.severity",
        "Technical severity is informational.",
    ),
    ReasonCodeDefinition(
        "EXPOSURE_UNKNOWN",
        "exposure model (not yet available)",
        "Reachability is not established from current evidence. It is not assumed to be safe.",
    ),
    ReasonCodeDefinition(
        "ASSET_IMPORTANCE_CRITICAL",
        "asset_importance_assignments",
        "An operator assigned critical importance to this asset. This is an audited "
        "assertion, not discovered evidence.",
    ),
    ReasonCodeDefinition(
        "ASSET_IMPORTANCE_HIGH",
        "asset_importance_assignments",
        "An operator assigned high importance to this asset.",
    ),
    ReasonCodeDefinition(
        "ASSET_IMPORTANCE_STANDARD",
        "asset_importance_assignments",
        "An operator assigned standard importance to this asset.",
    ),
    ReasonCodeDefinition(
        "ASSET_IMPORTANCE_LOW",
        "asset_importance_assignments",
        "An operator assigned low importance to this asset. Low importance never lowers "
        "an action band.",
    ),
    ReasonCodeDefinition(
        "ASSET_IMPORTANCE_UNKNOWN",
        "asset_importance_assignments",
        "Asset importance has not been assigned by an operator. It is not assumed to be low.",
    ),
    ReasonCodeDefinition(
        "EVIDENCE_STALE",
        "findings.evidence_freshness",
        "The supporting evidence is stale.",
    ),
    ReasonCodeDefinition(
        "EVIDENCE_FRESHNESS_UNKNOWN",
        "findings.evidence_freshness",
        "The age of the supporting evidence is unknown.",
    ),
    ReasonCodeDefinition(
        "CONFIDENCE_LOW",
        "findings.confidence",
        "Evidence confidence is low or insufficient for a product-specific conclusion.",
    ),
    ReasonCodeDefinition(
        "UNCERTAINTY_FLOOR_APPLIED",
        "decision ruleset",
        "Uncertain evidence kept this finding at Plan. Missing or stale evidence never "
        "lowers a finding to Monitor.",
    ),
)
REASON_CODE_ORDER: dict[str, int] = {item.code: index for index, item in enumerate(REASON_CODE_CATALOG)}
REASON_CODE_EXPLANATIONS: dict[str, str] = {item.code: item.explanation for item in REASON_CODE_CATALOG}


@dataclass(frozen=True)
class DecisionRuleDefinition:
    rule_id: str
    order: int
    condition: str
    action_band: ActionBand | None
    verification_required: bool


_RULE_RESOLVED = DecisionRuleDefinition("finding-resolved", 1, "Finding status is resolved.", None, False)
_RULE_KNOWN_EXPLOITED = DecisionRuleDefinition(
    "vulnerability-known-exploited",
    2,
    "Confirmed vulnerable component with known-exploited catalog evidence; exposure and "
    "importance are unknown, so the result is at least Prioritize.",
    "prioritize",
    False,
)
_RULE_KNOWN_EXPLOITED_CRITICAL_ASSET = DecisionRuleDefinition(
    "vulnerability-known-exploited-critical-asset",
    2,
    "Confirmed vulnerable component with known-exploited catalog evidence on an asset an "
    "operator assigned critical importance, and exposure is not affirmatively ruled out.",
    "act-now",
    False,
)


def _renumbered(rules: Sequence[DecisionRuleDefinition]) -> tuple[DecisionRuleDefinition, ...]:
    return tuple(
        DecisionRuleDefinition(rule.rule_id, order, rule.condition, rule.action_band, rule.verification_required)
        for order, rule in enumerate(rules, start=1)
    )


# Ordered rule table for `oaw.decision.rules.v1`. The first matching rule
# selects the band; the uncertainty floor is applied afterwards. No v1 rule
# yields `act-now`: the approved Act Now conditions need confirmed exposure,
# asset importance, compromise, or safety evidence, none of which v1 reads.
DECISION_RULES_V1: tuple[DecisionRuleDefinition, ...] = (
    _RULE_RESOLVED,
    _RULE_KNOWN_EXPLOITED,
    DecisionRuleDefinition(
        "vulnerability-critical",
        3,
        "Confirmed vulnerable component with critical severity; exposure is not ruled out.",
        "prioritize",
        False,
    ),
    DecisionRuleDefinition(
        "vulnerability-confirmed",
        4,
        "Confirmed vulnerable component with high, medium, or low severity.",
        "plan",
        False,
    ),
    DecisionRuleDefinition(
        "vulnerability-informational",
        5,
        "Confirmed vulnerable component with informational severity.",
        "monitor",
        False,
    ),
    DecisionRuleDefinition(
        "identity-or-version-gap",
        6,
        "Version or product identity is too uncertain to confirm applicability.",
        "plan",
        True,
    ),
    DecisionRuleDefinition(
        "evidence-conflict",
        7,
        "Strong sources disagree about asset classification or identity.",
        "prioritize",
        True,
    ),
    DecisionRuleDefinition(
        "collection-gap",
        8,
        "Collection is stale, the asset is unclassified, or only passive evidence exists.",
        "plan",
        True,
    ),
    DecisionRuleDefinition(
        "severity-default",
        9,
        "Other reviewed finding rules: critical or high is Prioritize, medium or low is Plan, "
        "informational is Monitor.",
        None,
        False,
    ),
    DecisionRuleDefinition(
        "unmapped-finding-rule",
        10,
        "A finding rule without a reviewed mapping is held at Plan with verification required.",
        "plan",
        True,
    ),
)

# `oaw.decision.rules.v2` is v1 with one rule inserted ahead of the
# known-exploited Prioritize rule. Every other rule keeps its meaning; asset
# importance never lowers a band.
_RULE_KNOWN_EXPLOITED_V2 = DecisionRuleDefinition(
    "vulnerability-known-exploited",
    3,
    "Confirmed vulnerable component with known-exploited catalog evidence where asset "
    "importance is not an operator-assigned critical value (including unknown); exposure "
    "is unknown, so the result is at least Prioritize.",
    "prioritize",
    False,
)
DECISION_RULES_V2: tuple[DecisionRuleDefinition, ...] = _renumbered(
    (
        DECISION_RULES_V1[0],
        _RULE_KNOWN_EXPLOITED_CRITICAL_ASSET,
        _RULE_KNOWN_EXPLOITED_V2,
        *DECISION_RULES_V1[2:],
    )
)
RULES_BY_RULESET: dict[str, tuple[DecisionRuleDefinition, ...]] = {
    DECISION_RULESET_V1: DECISION_RULES_V1,
    DECISION_RULESET_V2: DECISION_RULES_V2,
}
# The active rule table.
DECISION_RULES = DECISION_RULES_V2


@dataclass(frozen=True)
class DecisionEvidence:
    evidence_ref: str
    evidence_type: str
    freshness: str


@dataclass(frozen=True)
class DecisionInput:
    finding_id: str
    site_id: str
    rule_id: str
    subject_type: str
    category: str
    severity: str
    confidence: float
    evidence_freshness: str
    status: str
    finding_evaluated_at: datetime
    evidence: tuple[DecisionEvidence, ...] = ()
    # Effective operator-assigned importance of the finding's asset, or
    # `unknown`. Read by `oaw.decision.rules.v2` only; v1 ignores it.
    asset_importance: str = "unknown"


@dataclass(frozen=True)
class FindingDecision:
    schema_version: str
    ruleset_version: str
    finding_id: str
    site_id: str
    finding_rule_id: str
    decision_state: DecisionState
    decision_rule_id: str
    action_band: ActionBand | None
    urgency: Urgency | None
    severity: str
    evidence_confidence: EvidenceConfidence
    evidence_confidence_value: float
    evidence_freshness: str
    exploitation_status: ExploitationStatus
    exposure_state: ExposureState
    asset_importance: AssetImportance
    uncertainty_present: bool
    verification_required: bool
    prioritization_excluded: bool
    reason_codes: tuple[str, ...]
    evidence_references: tuple[str, ...]
    input_digest: str
    finding_evaluated_at: datetime

    def outcome(self) -> tuple[Any, ...]:
        """The fields whose change is a material decision transition."""

        return (
            self.ruleset_version,
            self.decision_state,
            self.action_band,
            self.urgency,
            self.reason_codes,
        )


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("decision timestamps must include a timezone")
    return value.astimezone(timezone.utc)


def lifecycle_class(status: str) -> str:
    """Acknowledgement records review only, so it decides like an active finding."""

    if status in {"active", "acknowledged"}:
        return "current"
    if status in {"suppressed", "resolved"}:
        return status
    raise ValueError("unsupported finding status for decision evaluation")


def confidence_band(rule_id: str, confidence: float) -> EvidenceConfidence:
    if rule_id in CONFLICT_RULES:
        return "conflicted"
    if rule_id in IDENTITY_OR_VERSION_GAP_RULES:
        return "insufficient"
    if confidence >= CONFIDENCE_HIGH_MIN:
        return "high"
    if confidence >= CONFIDENCE_MEDIUM_MIN:
        return "medium"
    if confidence >= CONFIDENCE_LOW_MIN:
        return "low"
    return "insufficient"


def _validated(value: DecisionInput) -> DecisionInput:
    if value.severity not in FINDING_SEVERITIES:
        raise ValueError("unsupported finding severity for decision evaluation")
    if value.evidence_freshness not in FRESHNESS_VALUES:
        raise ValueError("unsupported evidence freshness for decision evaluation")
    if not (0.0 <= float(value.confidence) <= 1.0):
        raise ValueError("finding confidence must be between 0 and 1")
    if value.asset_importance not in ASSET_IMPORTANCE_INPUTS:
        raise ValueError("unsupported asset importance for decision evaluation")
    lifecycle_class(value.status)
    _utc(value.finding_evaluated_at)
    return value


def _require_ruleset(ruleset_version: str) -> str:
    if ruleset_version not in SUPPORTED_DECISION_RULESETS:
        raise ValueError("unsupported decision ruleset version")
    return ruleset_version


def _effective_importance(value: DecisionInput, ruleset_version: str) -> AssetImportance:
    """Importance as the ruleset sees it. Only asset findings carry importance."""

    if value.subject_type != "asset":
        return "not-applicable"
    if ruleset_version == DECISION_RULESET_V1:
        return "unknown"
    return value.asset_importance  # type: ignore[return-value]


def input_digest(value: DecisionInput) -> str:
    """SHA-256 over the exact normalized inputs and the active ruleset version."""

    return input_digest_for_ruleset(value, DECISION_RULESET_VERSION)


def input_digest_for_ruleset(value: DecisionInput, ruleset_version: str) -> str:
    """SHA-256 over the exact normalized inputs and ruleset version.

    The v1 payload is byte-for-byte the original one, so v1 digests stay
    reproducible. Later rulesets add only the inputs they read.
    """

    _require_ruleset(ruleset_version)
    payload: dict[str, Any] = {
        "ruleset_version": ruleset_version,
        "finding_id": value.finding_id,
        "site_id": value.site_id,
        "rule_id": value.rule_id,
        "subject_type": value.subject_type,
        "category": value.category,
        "severity": value.severity,
        "confidence": round(float(value.confidence), 6),
        "evidence_freshness": value.evidence_freshness,
        "lifecycle": lifecycle_class(value.status),
        "evidence": sorted(
            [item.evidence_ref, item.evidence_type, item.freshness] for item in value.evidence
        ),
    }
    if ruleset_version != DECISION_RULESET_V1:
        payload["asset_importance"] = _effective_importance(value, ruleset_version)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _ordered(codes: Iterable[str]) -> tuple[str, ...]:
    unique = set(codes)
    unknown = unique - set(REASON_CODE_ORDER)
    if unknown:
        raise ValueError("reason code is not in the reviewed catalog")
    return tuple(sorted(unique, key=REASON_CODE_ORDER.__getitem__))


def _severity_default_band(severity: str) -> ActionBand:
    if severity in {"critical", "high"}:
        return "prioritize"
    if severity in {"medium", "low"}:
        return "plan"
    return "monitor"


def _select_rule(
    value: DecisionInput,
    known_exploited: bool,
    *,
    critical_asset: bool,
    exposure: ExposureState,
) -> tuple[str, ActionBand, bool]:
    rule_id = value.rule_id
    if rule_id == VULNERABILITY_RULE:
        # Every predicate is canonical: catalog evidence on a confirmed
        # vulnerable component, an operator-assigned `critical` value, and an
        # exposure state that does not rule exposure out. `critical_asset` is
        # false under v1 and whenever importance is anything but `critical`.
        if known_exploited and critical_asset and exposure not in EXPOSURE_RULED_OUT_STATES:
            return "vulnerability-known-exploited-critical-asset", "act-now", False
        if known_exploited:
            return "vulnerability-known-exploited", "prioritize", False
        if value.severity == "critical":
            return "vulnerability-critical", "prioritize", False
        if value.severity == "informational":
            return "vulnerability-informational", "monitor", False
        return "vulnerability-confirmed", "plan", False
    if rule_id in IDENTITY_OR_VERSION_GAP_RULES:
        return "identity-or-version-gap", "plan", True
    if rule_id in CONFLICT_RULES:
        return "evidence-conflict", "prioritize", True
    if rule_id in COLLECTION_GAP_RULES:
        return "collection-gap", "plan", True
    if rule_id in SEVERITY_DEFAULT_RULES:
        return "severity-default", _severity_default_band(value.severity), False
    return "unmapped-finding-rule", "plan", True


def evaluate_decision(value: DecisionInput) -> FindingDecision:
    """Deterministically decide one finding with the active ruleset.

    Identical inputs give identical output.
    """

    return evaluate_decision_with_ruleset(value, DECISION_RULESET_VERSION)


def evaluate_decision_with_ruleset(value: DecisionInput, ruleset_version: str) -> FindingDecision:
    """Decide one finding under an explicit supported ruleset version.

    Used to reproduce historical decisions. A ruleset version is reviewed
    product code; it is never taken from request or external input.
    """

    _require_ruleset(ruleset_version)
    value = _validated(value)
    lifecycle = lifecycle_class(value.status)
    digest = input_digest_for_ruleset(value, ruleset_version)
    confidence = confidence_band(value.rule_id, float(value.confidence))
    kev = [item for item in value.evidence if item.evidence_type in KEV_EVIDENCE_TYPES]
    known_exploited = value.rule_id == VULNERABILITY_RULE and bool(kev)
    is_asset_vulnerability = value.category == "vulnerability" and value.subject_type == "asset"
    exploitation: ExploitationStatus = (
        "known-exploited" if known_exploited else "unknown" if is_asset_vulnerability else "not-applicable"
    )
    exposure: ExposureState = "unknown" if is_asset_vulnerability else "not-applicable"
    importance = _effective_importance(value, ruleset_version)
    references = tuple(sorted({item.evidence_ref for item in value.evidence}))[:MAX_DECISION_EVIDENCE_REFERENCES]

    common = {
        "schema_version": DECISION_SCHEMA_VERSION,
        "ruleset_version": ruleset_version,
        "finding_id": value.finding_id,
        "site_id": value.site_id,
        "finding_rule_id": value.rule_id,
        "severity": value.severity,
        "evidence_confidence": confidence,
        "evidence_confidence_value": round(float(value.confidence), 6),
        "evidence_freshness": value.evidence_freshness,
        "exploitation_status": exploitation,
        "exposure_state": exposure,
        "asset_importance": importance,
        "evidence_references": references,
        "input_digest": digest,
        "finding_evaluated_at": _utc(value.finding_evaluated_at),
    }

    if lifecycle == "resolved":
        return FindingDecision(
            **common,
            decision_state="not-current",
            decision_rule_id="finding-resolved",
            action_band=None,
            urgency=None,
            uncertainty_present=False,
            verification_required=False,
            prioritization_excluded=True,
            reason_codes=("FINDING_RESOLVED",),
        )

    reasons: list[str] = [RULE_FAMILY_REASON.get(value.rule_id, "DECISION_RULE_UNMAPPED")]
    reasons.append(f"SEVERITY_{value.severity.upper()}")
    kev_stale = False
    if known_exploited:
        reasons.append("EXPLOITATION_KNOWN")
        if any(item.evidence_type == KEV_RANSOMWARE_EVIDENCE_TYPE for item in kev):
            reasons.append("EXPLOITATION_RANSOMWARE_KNOWN")
        kev_stale = any(item.freshness in {"stale", "unknown"} for item in kev)
        if kev_stale:
            reasons.append("EXPLOITATION_SOURCE_STALE")
    if is_asset_vulnerability:
        reasons.extend(("EXPOSURE_UNKNOWN", f"ASSET_IMPORTANCE_{importance.upper()}"))
    if value.evidence_freshness == "stale":
        reasons.append("EVIDENCE_STALE")
    elif value.evidence_freshness == "unknown":
        reasons.append("EVIDENCE_FRESHNESS_UNKNOWN")
    if confidence in {"low", "insufficient"} and value.rule_id not in IDENTITY_OR_VERSION_GAP_RULES:
        reasons.append("CONFIDENCE_LOW")
    suppressed = lifecycle == "suppressed"
    if suppressed:
        reasons.append("SUPPRESSION_ACTIVE")

    decision_rule_id, band, rule_requires_verification = _select_rule(
        value,
        known_exploited,
        critical_asset=is_asset_vulnerability and importance == "critical",
        exposure=exposure,
    )
    uncertainty = (
        value.evidence_freshness in {"stale", "unknown"}
        or confidence in {"low", "insufficient", "conflicted"}
        or kev_stale
    )
    if band == "monitor" and uncertainty:
        band = "plan"
        reasons.append("UNCERTAINTY_FLOOR_APPLIED")
    verification_required = rule_requires_verification or uncertainty
    urgency: Urgency = "verification-required" if verification_required else URGENCY_FOR_BAND[band]
    return FindingDecision(
        **common,
        decision_state="current",
        decision_rule_id=decision_rule_id,
        action_band=band,
        urgency=urgency,
        uncertainty_present=uncertainty,
        verification_required=verification_required,
        prioritization_excluded=suppressed,
        reason_codes=_ordered(reasons),
    )


def decision_input_from_records(
    finding: Mapping[str, Any],
    evidence: Sequence[Mapping[str, Any]],
) -> DecisionInput:
    """Build an input from a persisted finding row and its evidence rows only."""

    evaluated_at = finding.get("evaluated_at")
    if not isinstance(evaluated_at, datetime):
        raise ValueError("finding evaluated_at is required for decision evaluation")
    return DecisionInput(
        finding_id=str(finding["finding_id"]),
        site_id=str(finding["site_id"]),
        rule_id=str(finding["rule_id"]),
        subject_type=str(finding["subject_type"]),
        category=str(finding["category"]),
        severity=str(finding["severity"]),
        confidence=float(finding["confidence"]),
        evidence_freshness=str(finding["evidence_freshness"]),
        status=str(finding["status"]),
        finding_evaluated_at=evaluated_at,
        # Absent importance (no assignment, withdrawn, or not an asset) is unknown.
        asset_importance=str(finding.get("asset_importance") or "unknown"),
        evidence=tuple(
            DecisionEvidence(
                evidence_ref=str(item["evidence_ref"]),
                evidence_type=str(item["evidence_type"]),
                freshness=str(item["freshness"]),
            )
            for item in evidence
        ),
    )


def band_rank(band: str | None) -> int:
    """Higher is more urgent; a non-current decision ranks below Monitor."""

    return ACTION_BANDS.index(band) + 1 if band in ACTION_BANDS else 0  # type: ignore[arg-type]


def ruleset_public() -> dict[str, Any]:
    return {
        "schema_version": DECISION_SCHEMA_VERSION,
        "ruleset_version": DECISION_RULESET_VERSION,
        "action_bands": [
            {"band": band, "label": ACTION_BAND_LABELS[band], "urgency": URGENCY_FOR_BAND[band]}
            for band in ACTION_BANDS
        ],
        "rules": [
            {
                "rule_id": rule.rule_id,
                "order": rule.order,
                "condition": rule.condition,
                "action_band": rule.action_band,
                "verification_required": rule.verification_required,
            }
            for rule in DECISION_RULES
        ],
        "reason_codes": [
            {"code": item.code, "source": item.source, "explanation": item.explanation}
            for item in REASON_CODE_CATALOG
        ],
        "confidence_bands": {
            "high_min": CONFIDENCE_HIGH_MIN,
            "medium_min": CONFIDENCE_MEDIUM_MIN,
            "low_min": CONFIDENCE_LOW_MIN,
        },
        "limitations": [
            "Act Now is produced only by known-exploited catalog evidence on a confirmed "
            "vulnerable component of an asset an operator assigned critical importance.",
            "Exposure is always unknown in this version; unknown importance is never read as low.",
            "The Operational Attention Score is shown for context and never selects a band.",
        ],
    }
