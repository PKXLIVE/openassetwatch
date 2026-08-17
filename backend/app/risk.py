"""Explainable deterministic asset and site risk scoring."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence


FORMULA_VERSION = "oaw.risk.v1"
SEVERITY_WEIGHTS = {
    "critical": 40.0,
    "high": 25.0,
    "medium": 14.0,
    "low": 7.0,
    "informational": 3.0,
}
FRESHNESS_FACTORS = {
    "fresh": 1.0,
    "aging": 0.8,
    "stale": 0.45,
    "unknown": 0.35,
}
CATEGORY_CAPS = {
    "coverage": 30.0,
    "freshness": 20.0,
    "identity": 35.0,
    "inventory": 25.0,
    "movement": 20.0,
    "vulnerability": 50.0,
    "other": 20.0,
}
DIMINISHING_FACTORS = (1.0, 0.6, 0.35, 0.2)


def _bounded_float(
    environ: Mapping[str, str],
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    raw = environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    if not math.isfinite(value):
        return default
    return max(minimum, min(value, maximum))


@dataclass(frozen=True)
class RiskConfig:
    severity_weights: Mapping[str, float]
    category_caps: Mapping[str, float]
    site_max_weight: float = 0.50
    site_upper_quartile_weight: float = 0.30
    site_top_average_weight: float = 0.20
    site_direct_findings_weight: float = 0.35


def load_risk_config(environ: Mapping[str, str] | None = None) -> RiskConfig:
    values = os.environ if environ is None else environ
    severity_weights = {
        severity: _bounded_float(
            values,
            f"OPENASSETWATCH_RISK_WEIGHT_{severity.upper()}",
            default,
            minimum=0.0,
            maximum=60.0,
        )
        for severity, default in SEVERITY_WEIGHTS.items()
    }
    category_caps = {
        category: _bounded_float(
            values,
            f"OPENASSETWATCH_RISK_CAP_{category.upper()}",
            default,
            minimum=0.0,
            maximum=60.0,
        )
        for category, default in CATEGORY_CAPS.items()
    }
    return RiskConfig(severity_weights=severity_weights, category_caps=category_caps)


@dataclass(frozen=True)
class RiskFactor:
    factor_type: str
    finding_id: str | None
    category: str
    label: str
    severity: str | None
    confidence: float
    freshness: str
    base_weight: float
    adjusted_weight: float
    ordinal: int


@dataclass(frozen=True)
class AssetRiskScore:
    site_id: str
    asset_id: str
    score: int
    band: str
    formula_version: str
    finding_count: int
    data_as_of: datetime | None
    factors: tuple[RiskFactor, ...]


@dataclass(frozen=True)
class SiteRiskScore:
    site_id: str
    score: int
    band: str
    formula_version: str
    asset_count: int
    finding_count: int
    data_as_of: datetime | None
    factors: tuple[RiskFactor, ...]


def risk_band(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "moderate"
    if score >= 15:
        return "low"
    return "minimal"


def _confidence(value: Any) -> float:
    if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        return 0.0
    return max(0.0, min(float(value), 1.0))


def _finding_contributions(
    findings: Sequence[Mapping[str, Any]],
    *,
    config: RiskConfig,
) -> tuple[tuple[RiskFactor, ...], float]:
    grouped: dict[str, list[tuple[Mapping[str, Any], float]]] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "").lower()
        category = str(finding.get("category") or "other").lower()
        base = config.severity_weights.get(severity, 0.0)
        confidence = _confidence(finding.get("confidence"))
        freshness = str(finding.get("evidence_freshness") or "unknown").lower()
        freshness_factor = FRESHNESS_FACTORS.get(freshness, FRESHNESS_FACTORS["unknown"])
        raw = base * confidence * freshness_factor
        grouped.setdefault(category, []).append((finding, raw))
    factors: list[RiskFactor] = []
    total = 0.0
    for category in sorted(grouped):
        values = sorted(
            grouped[category],
            key=lambda item: (-item[1], str(item[0].get("finding_id") or "")),
        )
        category_total = 0.0
        cap = config.category_caps.get(category, config.category_caps.get("other", 20.0))
        for index, (finding, raw) in enumerate(values):
            diminishing = DIMINISHING_FACTORS[min(index, len(DIMINISHING_FACTORS) - 1)]
            remaining = max(0.0, cap - category_total)
            adjusted = min(raw * diminishing, remaining)
            category_total += adjusted
            factors.append(
                RiskFactor(
                    factor_type="finding",
                    finding_id=str(finding.get("finding_id") or "") or None,
                    category=category,
                    label=str(finding.get("title") or finding.get("rule_id") or "Deterministic finding")[:160],
                    severity=str(finding.get("severity") or "") or None,
                    confidence=_confidence(finding.get("confidence")),
                    freshness=str(finding.get("evidence_freshness") or "unknown"),
                    base_weight=round(raw, 4),
                    adjusted_weight=round(adjusted, 4),
                    ordinal=index + 1,
                )
            )
        total += category_total
    return tuple(factors), min(total, 100.0)


def calculate_asset_risk(
    *,
    assets: Sequence[Mapping[str, Any]],
    findings: Sequence[Mapping[str, Any]],
    config: RiskConfig | None = None,
) -> tuple[AssetRiskScore, ...]:
    resolved_config = config or load_risk_config()
    active = [
        finding
        for finding in findings
        if finding.get("asset_id")
        and str(finding.get("status")) in {"active", "acknowledged"}
    ]
    by_asset: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for finding in active:
        by_asset.setdefault((str(finding.get("site_id")), str(finding.get("asset_id"))), []).append(finding)
    scores: list[AssetRiskScore] = []
    for asset in assets:
        site_id = str(asset.get("site_id") or "")
        asset_id = str(asset.get("asset_id") or "")
        if not site_id or not asset_id:
            continue
        asset_findings = by_asset.get((site_id, asset_id), [])
        factors, raw_score = _finding_contributions(asset_findings, config=resolved_config)
        score = max(0, min(int(round(raw_score)), 100))
        observed_at = asset.get("observed_at") or asset.get("last_seen_at")
        data_as_of = observed_at if isinstance(observed_at, datetime) else None
        scores.append(
            AssetRiskScore(
                site_id=site_id,
                asset_id=asset_id,
                score=score,
                band=risk_band(score),
                formula_version=FORMULA_VERSION,
                finding_count=len(asset_findings),
                data_as_of=data_as_of,
                factors=factors,
            )
        )
    return tuple(sorted(scores, key=lambda item: (item.site_id, item.asset_id)))


def _percentile_nearest_rank(values: Sequence[int], percentile: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    rank = max(1, int(math.ceil(percentile * len(ordered))))
    return ordered[rank - 1]


def calculate_site_risk(
    *,
    sites: Sequence[Mapping[str, Any]],
    asset_scores: Sequence[AssetRiskScore],
    findings: Sequence[Mapping[str, Any]],
    config: RiskConfig | None = None,
) -> tuple[SiteRiskScore, ...]:
    resolved_config = config or load_risk_config()
    by_site: dict[str, list[AssetRiskScore]] = {}
    for score in asset_scores:
        by_site.setdefault(score.site_id, []).append(score)
    direct_findings = [
        finding
        for finding in findings
        if not finding.get("asset_id")
        and str(finding.get("status")) in {"active", "acknowledged"}
    ]
    direct_by_site: dict[str, list[Mapping[str, Any]]] = {}
    for finding in direct_findings:
        direct_by_site.setdefault(str(finding.get("site_id") or ""), []).append(finding)
    results: list[SiteRiskScore] = []
    for site in sites:
        site_id = str(site.get("site_id") or "")
        if not site_id:
            continue
        scores = by_site.get(site_id, [])
        values = [item.score for item in scores]
        maximum = max(values, default=0)
        upper_quartile = _percentile_nearest_rank(values, 0.75)
        top_values = sorted(values, reverse=True)[:10]
        top_average = sum(top_values) / len(top_values) if top_values else 0.0
        portfolio = (
            maximum * resolved_config.site_max_weight
            + upper_quartile * resolved_config.site_upper_quartile_weight
            + top_average * resolved_config.site_top_average_weight
        )
        direct_factors, direct_score = _finding_contributions(
            direct_by_site.get(site_id, []),
            config=resolved_config,
        )
        direct_component = (
            (100.0 - portfolio)
            * (direct_score / 100.0)
            * resolved_config.site_direct_findings_weight
        )
        combined = portfolio + direct_component
        direct_scale = direct_component / direct_score if direct_score else 0.0
        scaled_direct_factors = tuple(
            replace(
                factor,
                factor_type="site-finding",
                adjusted_weight=round(factor.adjusted_weight * direct_scale, 4),
            )
            for factor in direct_factors
        )
        score = max(0, min(int(round(combined)), 100))
        component_factors = (
            RiskFactor(
                factor_type="portfolio",
                finding_id=None,
                category="asset-portfolio",
                label="Highest asset risk",
                severity=None,
                confidence=1.0,
                freshness="fresh",
                base_weight=float(maximum),
                adjusted_weight=round(maximum * resolved_config.site_max_weight, 4),
                ordinal=1,
            ),
            RiskFactor(
                factor_type="portfolio",
                finding_id=None,
                category="asset-portfolio",
                label="Upper-quartile asset risk",
                severity=None,
                confidence=1.0,
                freshness="fresh",
                base_weight=float(upper_quartile),
                adjusted_weight=round(upper_quartile * resolved_config.site_upper_quartile_weight, 4),
                ordinal=2,
            ),
            RiskFactor(
                factor_type="portfolio",
                finding_id=None,
                category="asset-portfolio",
                label="Top-ten asset risk average",
                severity=None,
                confidence=1.0,
                freshness="fresh",
                base_weight=round(top_average, 4),
                adjusted_weight=round(top_average * resolved_config.site_top_average_weight, 4),
                ordinal=3,
            ),
        )
        data_as_of_values = [item.data_as_of for item in scores if item.data_as_of]
        results.append(
            SiteRiskScore(
                site_id=site_id,
                score=score,
                band=risk_band(score),
                formula_version=FORMULA_VERSION,
                asset_count=len(scores),
                finding_count=sum(item.finding_count for item in scores) + len(direct_by_site.get(site_id, [])),
                data_as_of=max(data_as_of_values) if data_as_of_values else None,
                factors=component_factors + scaled_direct_factors,
            )
        )
    return tuple(sorted(results, key=lambda item: item.site_id))


def calculate_risk(
    *,
    sites: Sequence[Mapping[str, Any]],
    assets: Sequence[Mapping[str, Any]],
    findings: Sequence[Mapping[str, Any]],
    config: RiskConfig | None = None,
) -> tuple[tuple[AssetRiskScore, ...], tuple[SiteRiskScore, ...]]:
    resolved_config = config or load_risk_config()
    asset_scores = calculate_asset_risk(assets=assets, findings=findings, config=resolved_config)
    site_scores = calculate_site_risk(
        sites=sites,
        asset_scores=asset_scores,
        findings=findings,
        config=resolved_config,
    )
    return asset_scores, site_scores


def calculated_at() -> datetime:
    return datetime.now(timezone.utc)
