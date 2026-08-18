"""Deterministic, evidence-bounded finding rules for the Control Tower.

Rules in this module are an explicit reviewed registry.  Collected values are
data only: they cannot register rules, select code, or change severity.
"""

from __future__ import annotations

import hashlib
import math
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Literal, Mapping, Sequence


Severity = Literal["critical", "high", "medium", "low", "informational"]
Freshness = Literal["fresh", "aging", "stale", "unknown"]
SubjectType = Literal["asset", "sensor", "site"]

RULESET_VERSION = "oaw.findings.v4"
MAX_FINDING_CANDIDATES = 10_000
MAX_EVIDENCE_REFERENCES = 8
SUPPORTED_SEVERITIES = frozenset({"critical", "high", "medium", "low", "informational"})


def _bounded_int(
    environ: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw, 10)
    except ValueError:
        return default
    return max(minimum, min(value, maximum))


@dataclass(frozen=True)
class FindingsConfig:
    sensor_stale_minutes: int = 120
    asset_stale_hours: int = 72
    new_asset_hours: int = 24
    evidence_fresh_hours: int = 24
    evidence_aging_hours: int = 72
    max_candidates: int = MAX_FINDING_CANDIDATES


def load_findings_config(environ: Mapping[str, str] | None = None) -> FindingsConfig:
    values = os.environ if environ is None else environ
    fresh_hours = _bounded_int(
        values,
        "OPENASSETWATCH_FINDINGS_EVIDENCE_FRESH_HOURS",
        24,
        minimum=1,
        maximum=168,
    )
    aging_hours = _bounded_int(
        values,
        "OPENASSETWATCH_FINDINGS_EVIDENCE_AGING_HOURS",
        72,
        minimum=fresh_hours,
        maximum=720,
    )
    return FindingsConfig(
        sensor_stale_minutes=_bounded_int(
            values,
            "OPENASSETWATCH_FINDINGS_SENSOR_STALE_MINUTES",
            120,
            minimum=15,
            maximum=10_080,
        ),
        asset_stale_hours=_bounded_int(
            values,
            "OPENASSETWATCH_FINDINGS_ASSET_STALE_HOURS",
            72,
            minimum=1,
            maximum=720,
        ),
        new_asset_hours=_bounded_int(
            values,
            "OPENASSETWATCH_FINDINGS_NEW_ASSET_HOURS",
            24,
            minimum=1,
            maximum=168,
        ),
        evidence_fresh_hours=fresh_hours,
        evidence_aging_hours=aging_hours,
        max_candidates=_bounded_int(
            values,
            "OPENASSETWATCH_FINDINGS_MAX_CANDIDATES",
            MAX_FINDING_CANDIDATES,
            minimum=100,
            maximum=MAX_FINDING_CANDIDATES,
        ),
    )


@dataclass(frozen=True)
class EvidenceReference:
    evidence_ref: str
    evidence_type: str
    source: str
    observed_at: datetime | None
    freshness: Freshness
    confidence: float
    summary: str


@dataclass(frozen=True)
class FindingCandidate:
    dedupe_key: str
    rule_id: str
    rule_version: int
    category: str
    subject_type: SubjectType
    site_id: str
    asset_id: str | None
    sensor_id: str | None
    title: str
    description: str
    recommendation: str
    severity: Severity
    confidence: float
    evidence_observed_at: datetime | None
    evidence_freshness: Freshness
    evidence: tuple[EvidenceReference, ...]

    @property
    def subject_id(self) -> str:
        if self.subject_type == "asset":
            return self.asset_id or ""
        if self.subject_type == "sensor":
            return self.sensor_id or ""
        return self.site_id


ResolutionKey = tuple[str, SubjectType, str, str]


@dataclass(frozen=True)
class EvaluationSnapshot:
    candidates: tuple[FindingCandidate, ...]
    resolution_eligible: frozenset[ResolutionKey]
    resolution_eligible_dedupe_keys: frozenset[str]
    evaluated_rule_ids: tuple[str, ...]
    data_as_of: datetime | None
    site_count: int
    sensor_count: int
    asset_count: int


@dataclass(frozen=True)
class RuleContext:
    now: datetime
    config: FindingsConfig
    sites: tuple[dict[str, Any], ...]
    sensors: tuple[dict[str, Any], ...]
    assets: tuple[dict[str, Any], ...]


RuleEvaluator = Callable[[RuleContext], Iterable[FindingCandidate]]


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    version: int
    category: str
    title: str
    rationale: str
    severity: Severity
    scope: SubjectType
    required_evidence: tuple[str, ...]
    freshness_requirement: str
    remediation_guidance: str
    resolution_behavior: str
    evaluator: RuleEvaluator


def _utc(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def evidence_freshness(value: Any, *, now: datetime, config: FindingsConfig) -> Freshness:
    observed_at = _utc(value)
    if observed_at is None:
        return "unknown"
    age = max(now - observed_at, timedelta())
    if age <= timedelta(hours=config.evidence_fresh_hours):
        return "fresh"
    if age <= timedelta(hours=config.evidence_aging_hours):
        return "aging"
    return "stale"


def _confidence(value: Any, default: float = 0.8) -> float:
    if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        return default
    return max(0.0, min(float(value), 1.0))


def _metadata(asset: Mapping[str, Any]) -> dict[str, Any]:
    value = asset.get("metadata")
    return dict(value) if isinstance(value, dict) else {}


def _classification(asset: Mapping[str, Any]) -> dict[str, Any]:
    value = asset.get("classification")
    return dict(value) if isinstance(value, dict) else {}


def _vulnerability_matches(asset: Mapping[str, Any]) -> list[dict[str, Any]]:
    value = asset.get("vulnerability_matches")
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value[:2_000] if isinstance(item, dict)]


def _managed_expectation(
    asset: Mapping[str, Any],
    capability: str,
) -> str:
    managed = _classification(asset).get("managed_capability")
    if not isinstance(managed, dict):
        return "unknown"
    value = _text(managed.get(capability), limit=32).lower()
    return value if value in {"expected", "not-expected", "unknown"} else "unknown"


def _classification_confidence(
    asset: Mapping[str, Any],
    *,
    fallback: float,
) -> float:
    classification = _classification(asset)
    if not classification:
        return _confidence(asset.get("confidence"), fallback)
    return _confidence(classification.get("confidence"), fallback)


def _source_agent_types(sensors: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    return {
        _text(sensor.get("agent_id"), limit=160): _text(
            sensor.get("agent_type"),
            limit=64,
        ).lower()
        for sensor in sensors
    }


def _has_endpoint_evidence(
    asset: Mapping[str, Any],
    source_types: Mapping[str, str],
) -> bool:
    source_agent_id = _text(asset.get("source_agent_id"), limit=160)
    observation_source = _text(asset.get("observation_source"), limit=80).lower()
    return (
        source_types.get(source_agent_id) == "endpoint-agent"
        or observation_source
        in {"endpoint-inventory", "local-inventory", "local-inventory-demo"}
    )


def _has_explicit_healthy_coverage(asset: Mapping[str, Any]) -> bool:
    metadata = _metadata(asset)
    healthy_values = {"active", "covered", "healthy", "installed", "ok", "present"}
    if metadata.get("endpoint_security") is True:
        return True
    return any(
        _text(metadata.get(field), limit=64).lower() in healthy_values
        for field in (
            "security_coverage",
            "coverage_status",
            "security_tooling_status",
        )
    )


def _normalized_mac(value: Any) -> str:
    candidate = _text(value, limit=64).lower().replace("-", ":")
    parts = candidate.split(":")
    if len(parts) != 6 or any(
        len(part) != 2 or any(character not in "0123456789abcdef" for character in part)
        for part in parts
    ):
        return ""
    octets = tuple(int(part, 16) for part in parts)
    if all(octet == 0 for octet in octets) or all(octet == 0xFF for octet in octets):
        return ""
    # Group/multicast addresses identify a destination set, not a stable
    # interface. Treating them as identity evidence would amplify common
    # protocol traffic into high-severity conflicts.
    if octets[0] & 0x01:
        return ""
    return ":".join(parts)


def _text(value: Any, *, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()[:limit]


def _subject_key(
    rule_id: str,
    subject_type: SubjectType,
    site_id: str,
    subject_id: str,
) -> ResolutionKey:
    return (rule_id, subject_type, site_id, subject_id)


def _dedupe_key(
    rule_id: str,
    subject_type: SubjectType,
    site_id: str,
    subject_id: str,
) -> str:
    canonical = "\x00".join((rule_id, subject_type, site_id, subject_id))
    return "fdk_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _evidence_ref(
    *,
    source: str,
    evidence_type: str,
    site_id: str,
    subject_id: str,
) -> str:
    canonical = "\x00".join((source, evidence_type, site_id, subject_id))
    return "ev_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _evidence(
    *,
    source: str,
    evidence_type: str,
    site_id: str,
    subject_id: str,
    observed_at: datetime | None,
    freshness: Freshness,
    confidence: float,
    summary: str,
) -> EvidenceReference:
    return EvidenceReference(
        evidence_ref=_evidence_ref(
            source=source,
            evidence_type=evidence_type,
            site_id=site_id,
            subject_id=subject_id,
        ),
        evidence_type=evidence_type[:64],
        source=source[:120],
        observed_at=observed_at,
        freshness=freshness,
        confidence=_confidence(confidence),
        summary=summary[:240],
    )


def _candidate(
    *,
    rule_id: str,
    rule_version: int,
    category: str,
    subject_type: SubjectType,
    site_id: str,
    asset_id: str | None = None,
    sensor_id: str | None = None,
    title: str,
    description: str,
    recommendation: str,
    severity: Severity,
    confidence: float,
    observed_at: datetime | None,
    freshness: Freshness,
    evidence: Sequence[EvidenceReference],
    dedupe_subject_id: str | None = None,
) -> FindingCandidate:
    subject_id = asset_id if subject_type == "asset" else sensor_id if subject_type == "sensor" else site_id
    if not subject_id:
        raise ValueError("finding candidate requires a subject identifier")
    return FindingCandidate(
        dedupe_key=_dedupe_key(
            rule_id,
            subject_type,
            site_id,
            dedupe_subject_id or subject_id,
        ),
        rule_id=rule_id,
        rule_version=rule_version,
        category=category,
        subject_type=subject_type,
        site_id=site_id,
        asset_id=asset_id,
        sensor_id=sensor_id,
        title=title,
        description=description,
        recommendation=recommendation,
        severity=severity,
        confidence=_confidence(confidence),
        evidence_observed_at=observed_at,
        evidence_freshness=freshness,
        evidence=tuple(evidence[:MAX_EVIDENCE_REFERENCES]),
    )


_VULNERABILITY_SEVERITY_ORDER: tuple[Severity, ...] = (
    "informational",
    "low",
    "medium",
    "high",
    "critical",
)


def _vulnerability_severity(match: Mapping[str, Any]) -> Severity:
    raw = _text(match.get("severity"), limit=32).lower()
    severity: Severity = (
        raw if raw in SUPPORTED_SEVERITIES else "informational"
    )  # type: ignore[assignment]
    if match.get("known_exploited"):
        index = min(
            _VULNERABILITY_SEVERITY_ORDER.index(severity) + 1,
            len(_VULNERABILITY_SEVERITY_ORDER) - 1,
        )
        return _VULNERABILITY_SEVERITY_ORDER[index]
    return severity


def _vulnerability_evidence(
    *,
    match: Mapping[str, Any],
    site_id: str,
    asset_id: str,
    observed_at: datetime | None,
    freshness: Freshness,
    confidence: float,
) -> tuple[EvidenceReference, ...]:
    values = [
        (
            _text(match.get("match_id"), limit=80),
            "vulnerability-match",
            "deterministic-vulnerability-matcher",
            "Server-issued deterministic match result.",
            freshness,
        ),
        (
            _text(match.get("component_id"), limit=80),
            "normalized-component",
            "asset_components",
            "Server-issued normalized component inventory record.",
            freshness,
        ),
        (
            _text(match.get("advisory_id"), limit=80),
            "reviewed-advisory",
            "local-advisory-catalog",
            "Server-issued reviewed local advisory record.",
            freshness,
        ),
    ]
    kev = match.get("kev") if isinstance(match.get("kev"), dict) else {}
    records = kev.get("records") if isinstance(kev.get("records"), list) else []
    for record in records[:5]:
        if not isinstance(record, dict):
            continue
        record_id = _text(record.get("kev_record_id"), limit=80)
        cve_id = _text(record.get("cve_id"), limit=32)
        if not record_id or not cve_id:
            continue
        ransomware = record.get("ransomware_campaign_status") == "Known"
        ransomware_text = (
            "CISA confirms ransomware campaign use"
            if ransomware
            else "ransomware campaign use is unconfirmed"
        )
        values.append(
            (
                record_id,
                "kev-prioritization-ransomware" if ransomware else "kev-prioritization",
                "cisa-kev",
                (
                    f"Exact alias {cve_id} is in CISA KEV; {ransomware_text}; "
                    f"CISA KEV due date {record.get('cisa_due_date')}; local exploitation is not established."
                )[:500],
                (
                    _text(record.get("source_freshness"), limit=16)
                    if _text(record.get("source_freshness"), limit=16) in {"fresh", "aging", "stale"}
                    else "unknown"
                ),
            )
        )
    return tuple(
        EvidenceReference(
            evidence_ref=evidence_ref,
            evidence_type=evidence_type,
            source=source,
            observed_at=observed_at,
            freshness=evidence_freshness_value,
            confidence=confidence,
            summary=summary,
        )
        for evidence_ref, evidence_type, source, summary, evidence_freshness_value in values[:MAX_EVIDENCE_REFERENCES]
        if evidence_ref
    )


def _confirmed_vulnerable_components(
    context: RuleContext,
) -> Iterable[FindingCandidate]:
    rule_id = "vulnerable-component"
    for asset in context.assets:
        site_id = _text(asset.get("site_id"), limit=128)
        asset_id = _text(asset.get("asset_id"), limit=160)
        if not site_id or not asset_id:
            continue
        for match in _vulnerability_matches(asset):
            if match.get("match_status") != "affected":
                continue
            match_id = _text(match.get("match_id"), limit=80)
            component_id = _text(match.get("component_id"), limit=80)
            advisory_id = _text(match.get("advisory_id"), limit=80)
            if not match_id or not component_id or not advisory_id:
                continue
            observed_at = _utc(
                match.get("component_last_seen_at")
                or match.get("evaluated_at")
            )
            freshness_value = _text(
                match.get("component_freshness"),
                limit=32,
            )
            freshness: Freshness = (
                freshness_value
                if freshness_value in {"fresh", "aging", "stale", "unknown"}
                else evidence_freshness(
                    observed_at,
                    now=context.now,
                    config=context.config,
                )
            )  # type: ignore[assignment]
            confidence = _confidence(match.get("match_confidence"), 0.0)
            known_exploited = bool(match.get("known_exploited"))
            kev = match.get("kev") if isinstance(match.get("kev"), dict) else {}
            kev_records = kev.get("records") if isinstance(kev.get("records"), list) else []
            kev_prioritized = bool(kev_records)
            component_name = _text(
                match.get("component_name"),
                limit=160,
            ) or component_id
            title = "KEV-prioritized vulnerable component" if kev_prioritized else (
                "Known-exploited vulnerable component" if known_exploited else "Confirmed vulnerable component"
            )
            fixed_version = _text(match.get("fixed_version"), limit=160)
            description = (
                f"Deterministic match {match_id} confirms {component_name} "
                f"version {_text(match.get('installed_version'), limit=160) or 'unknown'} "
                f"is affected by advisory {advisory_id}."
            )
            if kev_prioritized:
                exact_cves = sorted(
                    {
                        _text(record.get("cve_id"), limit=32)
                        for record in kev_records
                        if isinstance(record, dict) and record.get("cve_id")
                    }
                )
                description += (
                    f" Exact CVE alias correlation lists {', '.join(exact_cves[:5])} in CISA KEV; "
                    "this prioritizes review and does not establish exploitation or compromise of this asset."
                )
                primary = kev_records[0] if isinstance(kev_records[0], dict) else {}
                guidance = _text(primary.get("required_action"), limit=1_000)
                due = _text(str(primary.get("cisa_due_date") or ""), limit=32)
                recommendation = (
                    f"CISA guidance (text only; not executed): {guidance} "
                    f"CISA KEV due date: {due}; this is not automatically a local SLA."
                )
            else:
                recommendation = (
                f"Review and test upgrade to {fixed_version}; no automatic patching occurs."
                if fixed_version
                else "Review the cited advisory and establish a tested remediation plan; no automatic patching occurs."
                )
            yield _candidate(
                rule_id=rule_id,
                rule_version=2,
                category="vulnerability",
                subject_type="asset",
                site_id=site_id,
                asset_id=asset_id,
                title=title,
                description=description,
                recommendation=recommendation,
                severity=_vulnerability_severity(match),
                confidence=confidence,
                observed_at=observed_at,
                freshness=freshness,
                evidence=_vulnerability_evidence(
                    match=match,
                    site_id=site_id,
                    asset_id=asset_id,
                    observed_at=observed_at,
                    freshness=freshness,
                    confidence=confidence,
                ),
                dedupe_subject_id=match_id,
            )


def _component_version_unavailable(
    context: RuleContext,
) -> Iterable[FindingCandidate]:
    rule_id = "component-version-unavailable"
    for asset in context.assets:
        site_id = _text(asset.get("site_id"), limit=128)
        asset_id = _text(asset.get("asset_id"), limit=160)
        seen_components: set[str] = set()
        for match in _vulnerability_matches(asset):
            if match.get("match_status") != "version-unknown":
                continue
            component_id = _text(match.get("component_id"), limit=80)
            if (
                not site_id
                or not asset_id
                or not component_id
                or component_id in seen_components
            ):
                continue
            seen_components.add(component_id)
            observed_at = _utc(
                match.get("component_last_seen_at")
                or match.get("evaluated_at")
            )
            freshness = evidence_freshness(
                observed_at,
                now=context.now,
                config=context.config,
            )
            confidence = _confidence(match.get("match_confidence"), 0.5)
            yield _candidate(
                rule_id=rule_id,
                rule_version=1,
                category="inventory",
                subject_type="asset",
                site_id=site_id,
                asset_id=asset_id,
                title="Component version unavailable",
                description=(
                    f"Normalized component {component_id} has no usable version, "
                    "so it has not been classified as vulnerable."
                ),
                recommendation="Collect a current authoritative version for deterministic evaluation.",
                severity="informational",
                confidence=confidence,
                observed_at=observed_at,
                freshness=freshness,
                evidence=_vulnerability_evidence(
                    match=match,
                    site_id=site_id,
                    asset_id=asset_id,
                    observed_at=observed_at,
                    freshness=freshness,
                    confidence=confidence,
                ),
                dedupe_subject_id=component_id,
            )


def _advisory_identity_uncertain(
    context: RuleContext,
) -> Iterable[FindingCandidate]:
    rule_id = "advisory-identity-uncertain"
    for asset in context.assets:
        site_id = _text(asset.get("site_id"), limit=128)
        asset_id = _text(asset.get("asset_id"), limit=160)
        seen_components: set[str] = set()
        for match in _vulnerability_matches(asset):
            if match.get("match_status") != "identity-uncertain":
                continue
            component_id = _text(match.get("component_id"), limit=80)
            if (
                not site_id
                or not asset_id
                or not component_id
                or component_id in seen_components
            ):
                continue
            seen_components.add(component_id)
            observed_at = _utc(
                match.get("component_last_seen_at")
                or match.get("evaluated_at")
            )
            freshness = evidence_freshness(
                observed_at,
                now=context.now,
                config=context.config,
            )
            confidence = _confidence(match.get("match_confidence"), 0.4)
            yield _candidate(
                rule_id=rule_id,
                rule_version=1,
                category="inventory",
                subject_type="asset",
                site_id=site_id,
                asset_id=asset_id,
                title="Advisory identity requires review",
                description=(
                    f"Component {component_id} resembles a reviewed advisory identity "
                    "but lacks a precise canonical identifier; no vulnerability is confirmed."
                ),
                recommendation="Review package identity and provenance before treating the advisory as applicable.",
                severity="informational",
                confidence=confidence,
                observed_at=observed_at,
                freshness=freshness,
                evidence=_vulnerability_evidence(
                    match=match,
                    site_id=site_id,
                    asset_id=asset_id,
                    observed_at=observed_at,
                    freshness=freshness,
                    confidence=confidence,
                ),
                dedupe_subject_id=component_id,
            )


def _sensor_stale(context: RuleContext) -> Iterable[FindingCandidate]:
    rule_id = "sensor-stale"
    for sensor in context.sensors:
        if _text(sensor.get("identity_status"), limit=32).lower() == "revoked":
            continue
        sensor_id = _text(sensor.get("agent_id"), limit=160)
        site_id = _text(sensor.get("site_id"), limit=128)
        if not sensor_id or not site_id:
            continue
        observed_at = _utc(sensor.get("last_seen_at"))
        age = context.now - observed_at if observed_at else None
        if age is not None and age <= timedelta(minutes=context.config.sensor_stale_minutes):
            continue
        freshness = evidence_freshness(observed_at, now=context.now, config=context.config)
        never_seen = observed_at is None
        yield _candidate(
            rule_id=rule_id,
            rule_version=1,
            category="freshness",
            subject_type="sensor",
            site_id=site_id,
            sensor_id=sensor_id,
            title="Sensor evidence is stale" if not never_seen else "Sensor has not reported evidence",
            description=(
                "The enrolled sensor's last authenticated check-in exceeds the reviewed freshness threshold."
                if not never_seen
                else "The enrolled sensor has no authenticated check-in timestamp."
            ),
            recommendation="Verify sensor service health, connectivity, identity status, and outbound spool delivery.",
            severity="medium",
            confidence=1.0 if observed_at else 0.9,
            observed_at=observed_at,
            freshness=freshness,
            evidence=(
                _evidence(
                    source="agent_enrollments.last_seen_at",
                    evidence_type="sensor-check-in",
                    site_id=site_id,
                    subject_id=sensor_id,
                    observed_at=observed_at,
                    freshness=freshness,
                    confidence=1.0 if observed_at else 0.9,
                    summary="Authenticated sensor check-in freshness crossed the configured threshold.",
                ),
            ),
        )


def _asset_stale(context: RuleContext) -> Iterable[FindingCandidate]:
    rule_id = "asset-stale"
    for asset in context.assets:
        asset_id = _text(asset.get("asset_id"), limit=160)
        site_id = _text(asset.get("site_id"), limit=128)
        if not asset_id or not site_id:
            continue
        observed_at = _utc(asset.get("observed_at") or asset.get("last_seen_at"))
        if observed_at is None or context.now - observed_at <= timedelta(hours=context.config.asset_stale_hours):
            continue
        freshness = evidence_freshness(observed_at, now=context.now, config=context.config)
        yield _candidate(
            rule_id=rule_id,
            rule_version=1,
            category="freshness",
            subject_type="asset",
            site_id=site_id,
            asset_id=asset_id,
            title="Asset evidence is stale",
            description="The normalized asset has not been refreshed within the configured evidence window.",
            recommendation="Restore collection coverage before relying on this asset's current posture.",
            severity="low",
            confidence=_confidence(asset.get("confidence"), 0.75),
            observed_at=observed_at,
            freshness=freshness,
            evidence=(
                _evidence(
                    source="control_tower_assets.observed_at",
                    evidence_type="asset-observation",
                    site_id=site_id,
                    subject_id=asset_id,
                    observed_at=observed_at,
                    freshness=freshness,
                    confidence=_confidence(asset.get("confidence"), 0.75),
                    summary="Normalized asset evidence crossed the configured stale threshold.",
                ),
            ),
        )


def _new_or_unknown_asset(context: RuleContext) -> Iterable[FindingCandidate]:
    rule_id = "unknown-asset"
    for asset in context.assets:
        asset_id = _text(asset.get("asset_id"), limit=160)
        site_id = _text(asset.get("site_id"), limit=128)
        if not asset_id or not site_id:
            continue
        metadata = _metadata(asset)
        classification = _classification(asset)
        category = _text(
            classification.get("category") or metadata.get("category"),
            limit=80,
        ).lower()
        status = _text(classification.get("status"), limit=40).lower()
        if classification:
            if category and category != "unknown" and status not in {
                "unknown",
                "insufficient-evidence",
            }:
                continue
        elif category and not category.startswith("unknown"):
            continue
        observed_at = _utc(asset.get("observed_at") or asset.get("last_seen_at"))
        first_seen_at = _utc(asset.get("first_seen_at") or asset.get("created_at"))
        is_new = bool(first_seen_at and context.now - first_seen_at <= timedelta(hours=context.config.new_asset_hours))
        freshness = evidence_freshness(observed_at, now=context.now, config=context.config)
        yield _candidate(
            rule_id=rule_id,
            rule_version=2,
            category="inventory",
            subject_type="asset",
            site_id=site_id,
            asset_id=asset_id,
            title="New unknown asset requires review" if is_new else "Unknown asset requires review",
            description="The normalized asset does not yet have a recognized, evidence-backed category.",
            recommendation="Validate ownership and expected function, then classify the asset using reviewed inventory data.",
            severity="medium" if is_new else "low",
            confidence=max(0.35, _classification_confidence(asset, fallback=0.7)),
            observed_at=observed_at,
            freshness=freshness,
            evidence=(
                _evidence(
                    source=(
                        "asset_classifications.status"
                        if classification
                        else "control_tower_assets.metadata.category"
                    ),
                    evidence_type="asset-classification",
                    site_id=site_id,
                    subject_id=asset_id,
                    observed_at=observed_at,
                    freshness=freshness,
                    confidence=max(
                        0.35,
                        _classification_confidence(asset, fallback=0.7),
                    ),
                    summary=(
                        "Deterministic classification is unknown or has insufficient evidence."
                        if classification
                        else "Normalized asset classification is absent or explicitly unknown."
                    ),
                ),
            ),
        )


def _passive_only_assets(context: RuleContext) -> Iterable[FindingCandidate]:
    rule_id = "passive-only-asset"
    managed_categories = {
        "computer",
        "desktop",
        "endpoint",
        "laptop",
        "server",
        "virtual-machine",
        "workstation",
    }
    sensor_types = {
        _text(sensor.get("agent_id"), limit=160): _text(sensor.get("agent_type"), limit=64).lower()
        for sensor in context.sensors
    }
    for asset in context.assets:
        asset_id = _text(asset.get("asset_id"), limit=160)
        site_id = _text(asset.get("site_id"), limit=128)
        source_sensor_id = _text(asset.get("source_agent_id"), limit=160)
        observation_source = _text(asset.get("observation_source"), limit=80).lower()
        source_type = sensor_types.get(source_sensor_id, "")
        passive_only = observation_source == "passive-network" or source_type == "network-sensor"
        classification = _classification(asset)
        category = _text(
            classification.get("category") or _metadata(asset).get("category"),
            limit=80,
        ).lower()
        expected = _managed_expectation(asset, "endpoint_collector")
        has_endpoint_evidence = bool(
            classification.get("endpoint_evidence_present")
        ) or _has_endpoint_evidence(asset, sensor_types)
        if (
            not asset_id
            or not site_id
            or not passive_only
            or has_endpoint_evidence
            or (
                expected != "expected"
                if classification
                else category not in managed_categories
            )
        ):
            continue
        observed_at = _utc(asset.get("observed_at") or asset.get("last_seen_at"))
        freshness = evidence_freshness(observed_at, now=context.now, config=context.config)
        if freshness != "fresh":
            continue
        yield _candidate(
            rule_id=rule_id,
            rule_version=2,
            category="coverage",
            subject_type="asset",
            site_id=site_id,
            asset_id=asset_id,
            title="Asset is visible only through passive evidence",
            description=(
                "The current normalized record is backed by a passive network sensor and has no endpoint collection evidence."
            ),
            recommendation="Confirm whether endpoint management is expected for this asset class or document a compensating control.",
            severity="low",
            confidence=_classification_confidence(asset, fallback=0.75),
            observed_at=observed_at,
            freshness=freshness,
            evidence=(
                _evidence(
                    source="control_tower_assets.observation_source",
                    evidence_type="collection-coverage",
                    site_id=site_id,
                    subject_id=asset_id,
                    observed_at=observed_at,
                    freshness=freshness,
                    confidence=_classification_confidence(asset, fallback=0.75),
                    summary=(
                        "Fresh evidence is passive-only while deterministic managed capability expects an endpoint collector."
                    ),
                ),
            ),
        )


def _security_coverage_gap(context: RuleContext) -> Iterable[FindingCandidate]:
    rule_id = "security-coverage-gap"
    gap_values = {"absent", "degraded", "gap", "missing", "not-installed", "uncovered"}
    source_types = _source_agent_types(context.sensors)
    for asset in context.assets:
        asset_id = _text(asset.get("asset_id"), limit=160)
        site_id = _text(asset.get("site_id"), limit=128)
        metadata = _metadata(asset)
        explicit_statuses = (
            _text(metadata.get("security_coverage"), limit=64).lower(),
            _text(metadata.get("coverage_status"), limit=64).lower(),
            _text(metadata.get("security_tooling_status"), limit=64).lower(),
        )
        explicit_boolean_gap = metadata.get("endpoint_security") is False
        endpoint_evidence = _has_endpoint_evidence(asset, source_types)
        classification = _classification(asset)
        endpoint_security_expected = _managed_expectation(
            asset,
            "endpoint_security",
        )
        if (
            not asset_id
            or not site_id
            or not endpoint_evidence
            or (
                classification
                and endpoint_security_expected != "expected"
            )
            or (not explicit_boolean_gap and not any(value in gap_values for value in explicit_statuses))
        ):
            continue
        observed_at = _utc(asset.get("observed_at") or asset.get("last_seen_at"))
        freshness = evidence_freshness(observed_at, now=context.now, config=context.config)
        if freshness != "fresh":
            continue
        yield _candidate(
            rule_id=rule_id,
            rule_version=2,
            category="coverage",
            subject_type="asset",
            site_id=site_id,
            asset_id=asset_id,
            title="Explicit security coverage gap",
            description="Reviewed normalized metadata explicitly reports missing or degraded endpoint security coverage.",
            recommendation="Validate the expected control for this asset and restore coverage or record an approved exception.",
            severity="high",
            confidence=_classification_confidence(asset, fallback=0.8),
            observed_at=observed_at,
            freshness=freshness,
            evidence=(
                _evidence(
                    source="control_tower_assets.metadata.security_coverage",
                    evidence_type="security-coverage",
                    site_id=site_id,
                    subject_id=asset_id,
                    observed_at=observed_at,
                    freshness=freshness,
                    confidence=_classification_confidence(asset, fallback=0.8),
                    summary=(
                        "Normalized metadata reports a gap for a class whose deterministic managed capability expects endpoint security."
                    ),
                ),
            ),
        )


def _classification_conflicts(context: RuleContext) -> Iterable[FindingCandidate]:
    rule_id = "classification-conflict"
    for asset in context.assets:
        asset_id = _text(asset.get("asset_id"), limit=160)
        site_id = _text(asset.get("site_id"), limit=128)
        classification = _classification(asset)
        if (
            not asset_id
            or not site_id
            or _text(classification.get("status"), limit=40) != "conflicting"
        ):
            continue
        evaluated_at = _utc(classification.get("evaluated_at"))
        freshness = evidence_freshness(
            evaluated_at,
            now=context.now,
            config=context.config,
        )
        supporting = classification.get("supporting_evidence_ids")
        conflicting = classification.get("conflicting_evidence_ids")
        evidence_ids = [
            value
            for value in (
                *(supporting if isinstance(supporting, list) else []),
                *(conflicting if isinstance(conflicting, list) else []),
            )
            if isinstance(value, str) and value.startswith("cev_")
        ][:MAX_EVIDENCE_REFERENCES]
        evidence = tuple(
            EvidenceReference(
                evidence_ref=evidence_id[:80],
                evidence_type="classification-evidence",
                source="classification_evidence",
                observed_at=evaluated_at,
                freshness=freshness,
                confidence=_classification_confidence(asset, fallback=0.6),
                summary="Server-issued evidence reference participates in an unresolved deterministic classification conflict.",
            )
            for evidence_id in evidence_ids
        )
        if not evidence:
            evidence = (
                _evidence(
                    source="asset_classifications.status",
                    evidence_type="classification-conflict",
                    site_id=site_id,
                    subject_id=asset_id,
                    observed_at=evaluated_at,
                    freshness=freshness,
                    confidence=_classification_confidence(asset, fallback=0.6),
                    summary="The current deterministic classification has an unresolved material conflict.",
                ),
            )
        yield _candidate(
            rule_id=rule_id,
            rule_version=1,
            category="identity",
            subject_type="asset",
            site_id=site_id,
            asset_id=asset_id,
            title="Conflicting asset classification",
            description="Independent evidence sources support incompatible asset classifications.",
            recommendation="Review the cited evidence and source freshness; do not resolve the conflict from AI interpretation alone.",
            severity="high",
            confidence=_classification_confidence(asset, fallback=0.6),
            observed_at=evaluated_at,
            freshness=freshness,
            evidence=evidence,
        )


def _identity_conflicts(context: RuleContext) -> Iterable[FindingCandidate]:
    rule_id = "identity-conflict"
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for asset in context.assets:
        site_id = _text(asset.get("site_id"), limit=128)
        mac = _normalized_mac(asset.get("mac"))
        asset_id = _text(asset.get("asset_id"), limit=160)
        if site_id and mac and asset_id:
            groups.setdefault((site_id, mac), []).append(asset)
    for (site_id, _mac), values in groups.items():
        unique_assets = {
            _text(asset.get("asset_id"), limit=160): asset
            for asset in values
            if _text(asset.get("asset_id"), limit=160)
        }
        if len(unique_assets) < 2:
            continue
        related = sorted(unique_assets)
        if any(
            evidence_freshness(
                item.get("observed_at") or item.get("last_seen_at"),
                now=context.now,
                config=context.config,
            )
            != "fresh"
            for item in unique_assets.values()
        ):
            continue
        for asset_id, asset in sorted(unique_assets.items()):
            observed_at = _utc(asset.get("observed_at") or asset.get("last_seen_at"))
            freshness = evidence_freshness(observed_at, now=context.now, config=context.config)
            evidence = [
                _evidence(
                    source="control_tower_assets.mac",
                    evidence_type="identity-correlation",
                    site_id=site_id,
                    subject_id=related_asset_id,
                    observed_at=_utc(unique_assets[related_asset_id].get("observed_at") or unique_assets[related_asset_id].get("last_seen_at")),
                    freshness=evidence_freshness(
                        unique_assets[related_asset_id].get("observed_at") or unique_assets[related_asset_id].get("last_seen_at"),
                        now=context.now,
                        config=context.config,
                    ),
                    confidence=_confidence(unique_assets[related_asset_id].get("confidence"), 0.8),
                    summary="A normalized asset identity shares a hardware-address correlation with another asset record.",
                )
                for related_asset_id in related[:MAX_EVIDENCE_REFERENCES]
            ]
            yield _candidate(
                rule_id=rule_id,
                rule_version=1,
                category="identity",
                subject_type="asset",
                site_id=site_id,
                asset_id=asset_id,
                title="Conflicting asset identity",
                description="Multiple normalized asset identities at the same site share one hardware-address correlation.",
                recommendation="Review inventory merge history and sensor evidence before consolidating or reassigning either identity.",
                severity="high",
                confidence=min((_confidence(item.get("confidence"), 0.8) for item in unique_assets.values()), default=0.8),
                observed_at=observed_at,
                freshness=freshness,
                evidence=evidence,
            )


RULE_REGISTRY: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        rule_id="sensor-stale",
        version=1,
        category="freshness",
        title="Sensor evidence is stale",
        rationale="Authenticated check-in freshness is authoritative for sensor health.",
        severity="medium",
        scope="sensor",
        required_evidence=("sensor identity", "last authenticated check-in"),
        freshness_requirement="Triggers when check-in exceeds the configured threshold.",
        remediation_guidance="Verify sensor service health, identity, connectivity, and spool delivery.",
        resolution_behavior="Resolve only after a current authenticated check-in.",
        evaluator=_sensor_stale,
    ),
    RuleDefinition(
        rule_id="asset-stale",
        version=1,
        category="freshness",
        title="Asset evidence is stale",
        rationale="Normalized observation time is authoritative for asset freshness.",
        severity="low",
        scope="asset",
        required_evidence=("normalized asset identity", "observation timestamp"),
        freshness_requirement="Triggers when observation age exceeds the configured threshold.",
        remediation_guidance="Restore collection coverage and refresh normalized evidence.",
        resolution_behavior="Resolve only after a fresh normalized observation.",
        evaluator=_asset_stale,
    ),
    RuleDefinition(
        rule_id="unknown-asset",
        version=2,
        category="inventory",
        title="Unknown asset requires review",
        rationale="Only missing or explicitly unknown normalized classification triggers this rule.",
        severity="low",
        scope="asset",
        required_evidence=("normalized asset identity", "normalized classification"),
        freshness_requirement="Confidence and risk contribution reflect observation freshness.",
        remediation_guidance="Review ownership and classify the asset using trusted inventory evidence.",
        resolution_behavior="Resolve only when fresh evidence supplies a recognized classification.",
        evaluator=_new_or_unknown_asset,
    ),
    RuleDefinition(
        rule_id="passive-only-asset",
        version=2,
        category="coverage",
        title="Asset is visible only through passive evidence",
        rationale="The rule reports collection coverage; it does not classify all IoT assets as risky.",
        severity="low",
        scope="asset",
        required_evidence=("fresh passive observation", "managed-capability expectation"),
        freshness_requirement="Requires fresh passive evidence.",
        remediation_guidance="Confirm whether endpoint management is expected or document a compensating control.",
        resolution_behavior="Resolve only after a fresh normalized record is no longer passive-only.",
        evaluator=_passive_only_assets,
    ),
    RuleDefinition(
        rule_id="security-coverage-gap",
        version=2,
        category="coverage",
        title="Explicit security coverage gap",
        rationale="Only explicit normalized coverage signals trigger this rule.",
        severity="high",
        scope="asset",
        required_evidence=("fresh endpoint inventory", "explicit normalized coverage status"),
        freshness_requirement="Requires fresh endpoint-origin evidence.",
        remediation_guidance="Restore the expected security control or record an approved exception.",
        resolution_behavior="Resolve only from fresh endpoint-origin evidence that no longer reports the gap.",
        evaluator=_security_coverage_gap,
    ),
    RuleDefinition(
        rule_id="classification-conflict",
        version=1,
        category="identity",
        title="Conflicting asset classification",
        rationale="Independent deterministic evidence supports incompatible current classifications.",
        severity="high",
        scope="asset",
        required_evidence=("current classification", "server-issued classification evidence references"),
        freshness_requirement="Uses current persisted classification freshness and confidence.",
        remediation_guidance="Review source provenance and freshness; AI may explain but cannot resolve the conflict.",
        resolution_behavior="Resolve only after deterministic reevaluation reports a fresh non-conflicting classification.",
        evaluator=_classification_conflicts,
    ),
    RuleDefinition(
        rule_id="identity-conflict",
        version=1,
        category="identity",
        title="Conflicting asset identity",
        rationale="A bounded same-site hardware-address correlation identifies conflicting normalized records.",
        severity="high",
        scope="asset",
        required_evidence=("fresh site-scoped hardware address", "two distinct normalized asset identities"),
        freshness_requirement="All correlated identity records must be fresh.",
        remediation_guidance="Review inventory merge and sensor provenance before consolidating identities.",
        resolution_behavior="Does not auto-resolve in v1 because a counterpart record disappearing is insufficient evidence.",
        evaluator=_identity_conflicts,
    ),
    RuleDefinition(
        rule_id="vulnerable-component",
        version=2,
        category="vulnerability",
        title="Confirmed vulnerable component",
        rationale="Only an affected result from the deterministic component-to-advisory matcher triggers this rule.",
        severity="high",
        scope="asset",
        required_evidence=("normalized component", "reviewed advisory", "deterministic match"),
        freshness_requirement="Requires current component evidence and a non-withdrawn reviewed advisory.",
        remediation_guidance="Review and test the source-backed fixed version when supplied; no automatic patching occurs.",
        resolution_behavior="Resolve only after current complete inventory confirms a fixed, non-affected, withdrawn, or removed component state.",
        evaluator=_confirmed_vulnerable_components,
    ),
    RuleDefinition(
        rule_id="component-version-unavailable",
        version=1,
        category="inventory",
        title="Component version unavailable",
        rationale="A missing version is an inventory-quality gap, never proof of vulnerability.",
        severity="informational",
        scope="asset",
        required_evidence=("normalized component", "missing usable version"),
        freshness_requirement="Uses current normalized component evidence.",
        remediation_guidance="Collect a current authoritative component version.",
        resolution_behavior="Resolve after a usable version is deterministically evaluated.",
        evaluator=_component_version_unavailable,
    ),
    RuleDefinition(
        rule_id="advisory-identity-uncertain",
        version=1,
        category="inventory",
        title="Advisory identity requires review",
        rationale="Name similarity without a precise reviewed identity cannot confirm vulnerability.",
        severity="informational",
        scope="asset",
        required_evidence=("normalized component", "reviewed advisory candidate"),
        freshness_requirement="Uses current normalized component evidence.",
        remediation_guidance="Review canonical package, vendor, and product identity.",
        resolution_behavior="Resolve after identity is precise or no reviewed advisory candidate remains.",
        evaluator=_advisory_identity_uncertain,
    ),
)

RULES_BY_ID = {rule.rule_id: rule for rule in RULE_REGISTRY}


def rule_registry_public() -> list[dict[str, Any]]:
    return [
        {
            "rule_id": rule.rule_id,
            "version": rule.version,
            "category": rule.category,
            "title": rule.title,
            "rationale": rule.rationale,
            "severity": rule.severity,
            "scope": rule.scope,
            "required_evidence": list(rule.required_evidence),
            "freshness_requirement": rule.freshness_requirement,
            "remediation_guidance": rule.remediation_guidance,
            "resolution_behavior": rule.resolution_behavior,
        }
        for rule in RULE_REGISTRY
    ]


def _resolution_eligible(
    context: RuleContext,
    evaluated_rules: Sequence[RuleDefinition],
) -> frozenset[ResolutionKey]:
    keys: set[ResolutionKey] = set()
    rule_ids = {rule.rule_id for rule in evaluated_rules}
    for sensor in context.sensors:
        if _text(sensor.get("identity_status"), limit=32).lower() == "revoked":
            continue
        sensor_id = _text(sensor.get("agent_id"), limit=160)
        site_id = _text(sensor.get("site_id"), limit=128)
        observed_at = _utc(sensor.get("last_seen_at"))
        if (
            "sensor-stale" in rule_ids
            and sensor_id
            and site_id
            and observed_at
            and context.now - observed_at <= timedelta(minutes=context.config.sensor_stale_minutes)
        ):
            keys.add(_subject_key("sensor-stale", "sensor", site_id, sensor_id))
    source_types = _source_agent_types(context.sensors)
    for asset in context.assets:
        asset_id = _text(asset.get("asset_id"), limit=160)
        site_id = _text(asset.get("site_id"), limit=128)
        freshness = evidence_freshness(
            asset.get("observed_at") or asset.get("last_seen_at"),
            now=context.now,
            config=context.config,
        )
        if asset_id and site_id and freshness == "fresh":
            if "asset-stale" in rule_ids:
                keys.add(_subject_key("asset-stale", "asset", site_id, asset_id))
            classification = _classification(asset)
            category = _text(
                classification.get("category") or _metadata(asset).get("category"),
                limit=80,
            ).lower()
            if (
                "unknown-asset" in rule_ids
                and category
                and not category.startswith("unknown")
            ):
                keys.add(_subject_key("unknown-asset", "asset", site_id, asset_id))
            if "passive-only-asset" in rule_ids:
                keys.add(_subject_key("passive-only-asset", "asset", site_id, asset_id))
            if (
                "classification-conflict" in rule_ids
                and classification
                and _text(classification.get("status"), limit=40) != "conflicting"
            ):
                keys.add(
                    _subject_key(
                        "classification-conflict",
                        "asset",
                        site_id,
                        asset_id,
                    )
                )
            if (
                "security-coverage-gap" in rule_ids
                and _has_endpoint_evidence(asset, source_types)
                and _has_explicit_healthy_coverage(asset)
            ):
                # A missing field is not proof that an endpoint-reported gap
                # ended; resolution requires an explicit healthy signal.
                keys.add(
                    _subject_key(
                        "security-coverage-gap",
                        "asset",
                        site_id,
                        asset_id,
                    )
                )
            # identity-conflict deliberately has no automatic resolution in
            # v1. A counterpart record disappearing is insufficient evidence.
    return frozenset(keys)


def _resolution_eligible_vulnerability_dedupe_keys(
    context: RuleContext,
    evaluated_rules: Sequence[RuleDefinition],
) -> frozenset[str]:
    keys: set[str] = set()
    rule_ids = {rule.rule_id for rule in evaluated_rules}
    for asset in context.assets:
        site_id = _text(asset.get("site_id"), limit=128)
        asset_id = _text(asset.get("asset_id"), limit=160)
        if not site_id or not asset_id:
            continue
        by_component: dict[str, list[dict[str, Any]]] = {}
        for match in _vulnerability_matches(asset):
            component_id = _text(match.get("component_id"), limit=80)
            if component_id:
                by_component.setdefault(component_id, []).append(match)
            match_id = _text(match.get("match_id"), limit=80)
            status = _text(match.get("match_status"), limit=40)
            if (
                "vulnerable-component" in rule_ids
                and match_id
                and status
                in {"fixed", "not-affected", "advisory-withdrawn"}
            ):
                keys.add(
                    _dedupe_key(
                        "vulnerable-component",
                        "asset",
                        site_id,
                        match_id,
                    )
                )
        for component_id, matches in by_component.items():
            statuses = {
                _text(match.get("match_status"), limit=40)
                for match in matches
            }
            if (
                "component-version-unavailable" in rule_ids
                and statuses
                and "version-unknown" not in statuses
            ):
                keys.add(
                    _dedupe_key(
                        "component-version-unavailable",
                        "asset",
                        site_id,
                        component_id,
                    )
                )
            if (
                "advisory-identity-uncertain" in rule_ids
                and statuses
                and "identity-uncertain" not in statuses
            ):
                keys.add(
                    _dedupe_key(
                        "advisory-identity-uncertain",
                        "asset",
                        site_id,
                        component_id,
                    )
                )
    return frozenset(keys)


def evaluate_rules(
    *,
    sites: Sequence[Mapping[str, Any]],
    sensors: Sequence[Mapping[str, Any]],
    assets: Sequence[Mapping[str, Any]],
    now: datetime | None = None,
    config: FindingsConfig | None = None,
    rule_ids: Sequence[str] | None = None,
    site_id: str | None = None,
    asset_id: str | None = None,
    sensor_id: str | None = None,
) -> EvaluationSnapshot:
    evaluated_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    resolved_config = config or load_findings_config()
    if rule_ids is None:
        selected_rules = RULE_REGISTRY
    else:
        requested = tuple(dict.fromkeys(rule_ids))
        unknown = sorted(set(requested) - RULES_BY_ID.keys())
        if unknown:
            raise ValueError(f"unknown deterministic rule id(s): {', '.join(unknown)}")
        selected_rules = tuple(RULES_BY_ID[rule_id] for rule_id in requested)
    if sensor_id and any(rule.scope != "sensor" for rule in selected_rules):
        raise ValueError("sensor-scoped evaluation supports only sensor rules")
    filtered_sites = tuple(dict(item) for item in sites if not site_id or item.get("site_id") == site_id)
    filtered_sensors = tuple(
        dict(item)
        for item in sensors
        if (not site_id or item.get("site_id") == site_id)
        and (not sensor_id or item.get("agent_id") == sensor_id)
    )
    site_assets = tuple(
        dict(item)
        for item in assets
        if (not site_id or item.get("site_id") == site_id)
    )
    target_assets = (
        tuple(item for item in site_assets if item.get("asset_id") == asset_id)
        if asset_id
        else ()
        if sensor_id
        else site_assets
    )
    context = RuleContext(
        now=evaluated_at,
        config=resolved_config,
        sites=filtered_sites,
        sensors=filtered_sensors,
        # Correlation rules need the complete site context even when only one
        # asset is being reconciled.
        assets=site_assets,
    )
    candidates: list[FindingCandidate] = []
    for rule in selected_rules:
        candidates.extend(rule.evaluator(context))
        if len(candidates) > resolved_config.max_candidates:
            raise ValueError("deterministic finding candidate limit exceeded")
    if asset_id:
        candidates = [
            candidate
            for candidate in candidates
            if candidate.subject_type == "asset" and candidate.asset_id == asset_id
        ]
    candidates.sort(key=lambda item: (item.rule_id, item.site_id, item.subject_type, item.subject_id))
    resolution_eligible = _resolution_eligible(context, selected_rules)
    resolution_eligible_dedupe_keys = (
        _resolution_eligible_vulnerability_dedupe_keys(
            context,
            selected_rules,
        )
    )
    if asset_id:
        resolution_eligible = frozenset(
            key
            for key in resolution_eligible
            if key[1] == "asset" and key[3] == asset_id
        )
        scoped_asset = next(
            (
                item
                for item in site_assets
                if item.get("asset_id") == asset_id
            ),
            None,
        )
        if scoped_asset is not None:
            scoped_context = RuleContext(
                now=context.now,
                config=context.config,
                sites=context.sites,
                sensors=context.sensors,
                assets=(scoped_asset,),
            )
            resolution_eligible_dedupe_keys = (
                _resolution_eligible_vulnerability_dedupe_keys(
                    scoped_context,
                    selected_rules,
                )
            )
        else:
            resolution_eligible_dedupe_keys = frozenset()
    timestamps = [
        value
        for value in (
            *(
                _utc(sensor.get("last_seen_at"))
                for sensor in (() if asset_id else filtered_sensors)
            ),
            *(
                _utc(asset.get("observed_at") or asset.get("last_seen_at"))
                for asset in target_assets
            ),
        )
        if value is not None
    ]
    return EvaluationSnapshot(
        candidates=tuple(candidates),
        resolution_eligible=resolution_eligible,
        resolution_eligible_dedupe_keys=resolution_eligible_dedupe_keys,
        evaluated_rule_ids=tuple(rule.rule_id for rule in selected_rules),
        data_as_of=max(timestamps) if timestamps else None,
        site_count=len(filtered_sites),
        sensor_count=0 if asset_id else len(filtered_sensors),
        asset_count=len(target_assets),
    )
