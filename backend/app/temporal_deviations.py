"""Deterministic, cutoff-safe deviation assessments over temporal artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol, Sequence

from .temporal_contracts import (
    DEVIATION_ASSESSMENT_ID_PATTERN,
    HISTORY_DIGEST_PATTERN,
    MAX_TEMPORAL_DEVIATION_ASSESSMENTS,
    TEMPORAL_DEVIATION_ASSESSMENT_SCHEMA_VERSION,
    TEMPORAL_DEVIATION_POLICY_VERSION,
    TEMPORAL_METRICS,
    DeviationDirection,
    TemporalDeviationAssessment,
    TemporalDeviationPolicy,
    TemporalExpectation,
    TemporalSignal,
    TemporalSignalSeriesResponse,
    temporal_metric,
)
from .temporal_expectations import (
    TemporalExpectationService,
    temporal_expectation_id,
)
from .temporal_projection import (
    TemporalProjectionError,
    TemporalProjectionService,
    temporal_signal_id,
    utc_daily_bucket,
)


TEMPORAL_DEVIATION_POLICIES: dict[str, TemporalDeviationPolicy] = {
    "site.assets.new.count": TemporalDeviationPolicy(
        policy_id="tdp_site_assets_new",
        policy_version=TEMPORAL_DEVIATION_POLICY_VERSION,
        metric_key="site.assets.new.count",
        allowed_directions=("above",),
        minimum_expectation_confidence="medium",
        required_expectation_data_quality="sufficient",
        required_persistence_buckets=1,
        maximum_persistence_lookback=1,
        supported_granularity="daily",
        entity_scope="site",
    ),
    "site.collectors.active.count": TemporalDeviationPolicy(
        policy_id="tdp_site_collectors_active",
        policy_version=TEMPORAL_DEVIATION_POLICY_VERSION,
        metric_key="site.collectors.active.count",
        allowed_directions=("below",),
        minimum_expectation_confidence="medium",
        required_expectation_data_quality="sufficient",
        required_persistence_buckets=1,
        maximum_persistence_lookback=1,
        supported_granularity="daily",
        entity_scope="site",
    ),
    "site.findings.new.count": TemporalDeviationPolicy(
        policy_id="tdp_site_findings_new",
        policy_version=TEMPORAL_DEVIATION_POLICY_VERSION,
        metric_key="site.findings.new.count",
        allowed_directions=("above",),
        minimum_expectation_confidence="medium",
        required_expectation_data_quality="sufficient",
        required_persistence_buckets=1,
        maximum_persistence_lookback=1,
        supported_granularity="daily",
        entity_scope="site",
    ),
    "site.vulnerabilities.new.count": TemporalDeviationPolicy(
        policy_id="tdp_site_vulnerabilities_new",
        policy_version=TEMPORAL_DEVIATION_POLICY_VERSION,
        metric_key="site.vulnerabilities.new.count",
        allowed_directions=("above",),
        minimum_expectation_confidence="medium",
        required_expectation_data_quality="sufficient",
        required_persistence_buckets=1,
        maximum_persistence_lookback=1,
        supported_granularity="daily",
        entity_scope="site",
    ),
    "site.inventory.collections.count": TemporalDeviationPolicy(
        policy_id="tdp_site_inventory_collections",
        policy_version=TEMPORAL_DEVIATION_POLICY_VERSION,
        metric_key="site.inventory.collections.count",
        allowed_directions=("above", "below"),
        minimum_expectation_confidence="medium",
        required_expectation_data_quality="sufficient",
        required_persistence_buckets=2,
        maximum_persistence_lookback=2,
        supported_granularity="daily",
        entity_scope="site",
    ),
    "site.inventory.asset_observations.count": TemporalDeviationPolicy(
        policy_id="tdp_site_inventory_asset_observations",
        policy_version=TEMPORAL_DEVIATION_POLICY_VERSION,
        metric_key="site.inventory.asset_observations.count",
        allowed_directions=("above", "below"),
        minimum_expectation_confidence="medium",
        required_expectation_data_quality="sufficient",
        required_persistence_buckets=2,
        maximum_persistence_lookback=2,
        supported_granularity="daily",
        entity_scope="site",
    ),
}

if set(TEMPORAL_DEVIATION_POLICIES) != {
    metric.metric_key for metric in TEMPORAL_METRICS
}:
    raise RuntimeError("temporal deviation policy map and metric registry differ")
if len({policy.policy_id for policy in TEMPORAL_DEVIATION_POLICIES.values()}) != len(
    TEMPORAL_DEVIATION_POLICIES
):
    raise RuntimeError("temporal deviation policy identifiers must be unique")
if any(
    policy.required_persistence_buckets > MAX_TEMPORAL_DEVIATION_ASSESSMENTS
    or policy.maximum_persistence_lookback > MAX_TEMPORAL_DEVIATION_ASSESSMENTS
    for policy in TEMPORAL_DEVIATION_POLICIES.values()
):
    raise RuntimeError("temporal deviation persistence must remain bounded")


class DeviationProjection(Protocol):
    def series(self, **kwargs) -> TemporalSignalSeriesResponse: ...


class DeviationExpectation(Protocol):
    def expectation(self, **kwargs) -> TemporalExpectation: ...


@dataclass(frozen=True)
class _AssessmentInputs:
    observation: TemporalSignal
    expectation: TemporalExpectation


def temporal_deviation_policy(metric_key: str) -> TemporalDeviationPolicy:
    try:
        return TEMPORAL_DEVIATION_POLICIES[metric_key]
    except KeyError as exc:
        raise TemporalProjectionError(
            "unknown-metric",
            "unknown temporal metric",
        ) from exc


def _canonical_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat()


def _canonical_digest(payload: object) -> str:
    canonical_json = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def temporal_observation_digest(signal: TemporalSignal) -> str:
    """Bind every governed, non-transient field of one target observation."""

    return _canonical_digest(
        {
            "schema_version": signal.schema_version,
            "signal_id": signal.signal_id,
            "metric_key": signal.metric_key,
            "tenant_id": signal.tenant_id,
            "site_id": signal.site_id,
            "asset_id": signal.asset_id,
            "bucket_start": _canonical_timestamp(signal.bucket_start),
            "bucket_end": _canonical_timestamp(signal.bucket_end),
            "bucket_granularity": signal.bucket_granularity,
            "value": signal.value,
            "unit": signal.unit,
            "evidence_count": signal.evidence_count,
            "source": signal.source,
            "source_observed_at": _canonical_timestamp(signal.source_observed_at),
            "source_received_at": _canonical_timestamp(signal.source_received_at),
            "freshness": signal.freshness,
            "complete": signal.complete,
            "data_quality": signal.data_quality,
            "backfill_state": signal.backfill_state,
            "projection_version": signal.projection_version,
        }
    )


def temporal_assessment_input_digest(
    *,
    observation_digest: str,
    expectation: TemporalExpectation,
    policy: TemporalDeviationPolicy,
    supporting_assessment_ids: Sequence[str],
) -> str:
    if re.fullmatch(HISTORY_DIGEST_PATTERN, observation_digest) is None:
        raise ValueError("observation_digest must be a lowercase SHA-256 digest")
    for assessment_id in supporting_assessment_ids:
        if re.fullmatch(DEVIATION_ASSESSMENT_ID_PATTERN, assessment_id) is None:
            raise ValueError("supporting assessment identifier is invalid")
    return _canonical_digest(
        {
            "schema_version": TEMPORAL_DEVIATION_ASSESSMENT_SCHEMA_VERSION,
            "observation_digest": observation_digest,
            "expectation": {
                "expectation_id": expectation.expectation_id,
                "history_digest": expectation.history_digest,
                "expected": expectation.expected,
                "lower": expectation.lower,
                "upper": expectation.upper,
                "method": expectation.method,
                "method_version": expectation.method_version,
                "confidence": expectation.confidence,
                "data_quality": expectation.data_quality,
            },
            "policy": {
                "policy_id": policy.policy_id,
                "policy_version": policy.policy_version,
                "allowed_directions": list(policy.allowed_directions),
                "minimum_expectation_confidence": (
                    policy.minimum_expectation_confidence
                ),
                "required_expectation_data_quality": (
                    policy.required_expectation_data_quality
                ),
                "required_persistence_buckets": (
                    policy.required_persistence_buckets
                ),
                "maximum_persistence_lookback": policy.maximum_persistence_lookback,
                "supported_granularity": policy.supported_granularity,
                "entity_scope": policy.entity_scope,
            },
            "supporting_assessment_ids": list(supporting_assessment_ids),
        }
    )


def temporal_deviation_assessment_id(
    *,
    input_digest: str,
    metric_key: str,
    site_id: str,
    target_bucket_start: datetime,
    target_bucket_end: datetime,
    policy_version: str,
) -> str:
    if re.fullmatch(HISTORY_DIGEST_PATTERN, input_digest) is None:
        raise ValueError("input_digest must be a lowercase SHA-256 digest")
    identity = "\x1f".join(
        (
            TEMPORAL_DEVIATION_ASSESSMENT_SCHEMA_VERSION,
            input_digest,
            metric_key,
            site_id,
            target_bucket_start.isoformat(),
            target_bucket_end.isoformat(),
            policy_version,
        )
    )
    return "tda_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def _confidence_meets_policy(value: str, minimum: str) -> bool:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    return order[value] >= order[minimum]


class TemporalDeviationService:
    """Compose cutoff-safe Phase 1 and Phase 2 artifacts without writes."""

    def __init__(
        self,
        *,
        projection: DeviationProjection,
        expectations: DeviationExpectation,
    ) -> None:
        self.projection = projection
        self.expectations = expectations

    @classmethod
    def from_projection_store(cls, *, store) -> "TemporalDeviationService":
        return cls(
            projection=TemporalProjectionService(store=store),
            expectations=TemporalExpectationService.from_projection_store(store=store),
        )

    def assessment(
        self,
        *,
        metric_key: str,
        site_id: str,
        target_start: datetime,
        granularity: str = "daily",
        asset_id: str | None = None,
        generated_at: datetime | None = None,
    ) -> TemporalDeviationAssessment:
        metric = temporal_metric(metric_key)
        policy = temporal_deviation_policy(metric_key)
        normalized_target, calculation_time = self._validate_request(
            target_start=target_start,
            granularity=granularity,
            asset_id=asset_id,
            supports_asset_scope=metric.supports_asset_scope,
            generated_at=generated_at,
        )

        current_inputs = self._load_inputs(
            metric_key=metric_key,
            site_id=site_id,
            target_start=normalized_target,
            asset_id=asset_id,
            generated_at=calculation_time,
        )
        current = self._build_assessment(
            inputs=current_inputs,
            policy=policy,
            generated_at=calculation_time,
            supporting=(),
        )
        if current.assessment_state != "pending-persistence":
            return current

        required = policy.required_persistence_buckets
        if required > policy.maximum_persistence_lookback:
            raise TemporalProjectionError(
                "invalid-deviation-policy",
                "temporal deviation policy exceeds its bounded lookback",
            )
        supporting_reverse_chronological: list[TemporalDeviationAssessment] = []
        for offset in range(1, required):
            prior_target = normalized_target - timedelta(days=offset)
            prior_inputs = self._load_inputs(
                metric_key=metric_key,
                site_id=site_id,
                target_start=prior_target,
                asset_id=asset_id,
                generated_at=calculation_time,
            )
            prior = self._build_assessment(
                inputs=prior_inputs,
                policy=policy,
                generated_at=calculation_time,
                supporting=(),
            )
            if (
                prior.assessment_state not in {"pending-persistence", "candidate"}
                or prior.direction != current.direction
            ):
                break
            supporting_reverse_chronological.append(prior)

        supporting = tuple(reversed(supporting_reverse_chronological))
        return self._build_assessment(
            inputs=current_inputs,
            policy=policy,
            generated_at=calculation_time,
            supporting=supporting,
        )

    @staticmethod
    def _validate_request(
        *,
        target_start: datetime,
        granularity: str,
        asset_id: str | None,
        supports_asset_scope: bool,
        generated_at: datetime | None,
    ) -> tuple[datetime, datetime]:
        if granularity != "daily":
            raise TemporalProjectionError(
                "unsupported-granularity",
                "only daily UTC temporal deviation assessments are supported",
            )
        if asset_id is not None and not supports_asset_scope:
            raise TemporalProjectionError(
                "unsupported-scope",
                "the selected temporal metric supports site scope only",
            )
        if target_start.tzinfo is None or target_start.utcoffset() is None:
            raise TemporalProjectionError(
                "timezone-required",
                "target_start must include a timezone",
            )
        normalized_target = target_start.astimezone(timezone.utc)
        if any(
            (
                normalized_target.hour,
                normalized_target.minute,
                normalized_target.second,
                normalized_target.microsecond,
            )
        ):
            raise TemporalProjectionError(
                "unaligned-target",
                "target_start must align to a UTC midnight bucket boundary",
            )
        calculation_time = generated_at or datetime.now(timezone.utc)
        if calculation_time.tzinfo is None or calculation_time.utcoffset() is None:
            raise TemporalProjectionError(
                "timezone-required",
                "generated_at must include a timezone",
            )
        calculation_time = calculation_time.astimezone(timezone.utc)
        current_bucket_start, _ = utc_daily_bucket(calculation_time)
        if normalized_target >= current_bucket_start:
            raise TemporalProjectionError(
                "open-or-future-target",
                "temporal deviation target must be a closed UTC bucket",
            )
        return normalized_target, calculation_time

    def _load_inputs(
        self,
        *,
        metric_key: str,
        site_id: str,
        target_start: datetime,
        asset_id: str | None,
        generated_at: datetime,
    ) -> _AssessmentInputs:
        target_end = target_start + timedelta(days=1)
        series = self.projection.series(
            metric_key=metric_key,
            site_id=site_id,
            start=target_start,
            end=target_end,
            granularity="daily",
            asset_id=asset_id,
            generated_at=target_end,
            knowledge_cutoff=target_end,
        )
        if series.bucket_count != 1 or len(series.signals) != 1:
            raise TemporalProjectionError(
                "invalid-observation-projection",
                "target observation projection must return exactly one bucket",
            )
        observation = series.signals[0]
        expectation = self.expectations.expectation(
            metric_key=metric_key,
            site_id=site_id,
            target_start=target_start,
            granularity="daily",
            asset_id=asset_id,
            generated_at=generated_at,
        )
        self._validate_provenance(
            observation=observation,
            expectation=expectation,
            metric_key=metric_key,
            site_id=site_id,
            asset_id=asset_id,
            target_start=target_start,
            target_end=target_end,
        )
        return _AssessmentInputs(observation=observation, expectation=expectation)

    @staticmethod
    def _validate_provenance(
        *,
        observation: TemporalSignal,
        expectation: TemporalExpectation,
        metric_key: str,
        site_id: str,
        asset_id: str | None,
        target_start: datetime,
        target_end: datetime,
    ) -> None:
        if (
            observation.metric_key != metric_key
            or observation.site_id != site_id
            or observation.asset_id != asset_id
            or observation.bucket_start != target_start
            or observation.bucket_end != target_end
            or observation.bucket_granularity != "daily"
        ):
            raise TemporalProjectionError(
                "observation-provenance-mismatch",
                "target observation provenance does not match the requested scope",
            )
        expected_signal_id = temporal_signal_id(
            metric_key=metric_key,
            site_id=site_id,
            asset_id=asset_id,
            bucket_start=target_start,
            bucket_end=target_end,
            projection_version=observation.projection_version,
        )
        if observation.signal_id != expected_signal_id:
            raise TemporalProjectionError(
                "invalid-observation-identity",
                "target observation identity validation failed",
            )
        if (
            expectation.metric_key != metric_key
            or expectation.site_id != site_id
            or expectation.asset_id != asset_id
            or expectation.tenant_id != observation.tenant_id
            or expectation.target_bucket_start != target_start
            or expectation.target_bucket_end != target_end
            or expectation.bucket_granularity != observation.bucket_granularity
            or expectation.unit != observation.unit
            or expectation.projection_version != observation.projection_version
            or expectation.knowledge_cutoff != target_start
            or expectation.authority != "analytical-context-only"
        ):
            raise TemporalProjectionError(
                "expectation-provenance-mismatch",
                "temporal expectation provenance does not match the target observation",
            )
        expected_expectation_id = temporal_expectation_id(
            metric_key=expectation.metric_key,
            site_id=expectation.site_id,
            target_bucket_start=expectation.target_bucket_start,
            target_bucket_end=expectation.target_bucket_end,
            history_start=expectation.history_start,
            history_end=expectation.history_end,
            method=expectation.method,
            projection_version=expectation.projection_version,
            history_digest=expectation.history_digest,
        )
        if expectation.expectation_id != expected_expectation_id:
            raise TemporalProjectionError(
                "invalid-expectation-identity",
                "temporal expectation identity validation failed",
            )

    @staticmethod
    def _build_assessment(
        *,
        inputs: _AssessmentInputs,
        policy: TemporalDeviationPolicy,
        generated_at: datetime,
        supporting: Sequence[TemporalDeviationAssessment],
    ) -> TemporalDeviationAssessment:
        observation = inputs.observation
        expectation = inputs.expectation
        target_start = observation.bucket_start
        target_end = observation.bucket_end

        ordered_supporting = tuple(
            sorted(
                supporting,
                key=lambda item: (
                    item.target_bucket_start,
                    item.target_bucket_end,
                    item.assessment_id,
                ),
            )
        )
        if len(ordered_supporting) > policy.required_persistence_buckets - 1:
            raise TemporalProjectionError(
                "unbounded-persistence-support",
                "temporal deviation persistence support exceeds policy bounds",
            )
        expected_support_start = target_start - timedelta(days=len(ordered_supporting))
        for index, support in enumerate(ordered_supporting):
            expected_start = expected_support_start + timedelta(days=index)
            if (
                support.metric_key != observation.metric_key
                or support.site_id != observation.site_id
                or support.asset_id != observation.asset_id
                or support.policy_id != policy.policy_id
                or support.policy_version != policy.policy_version
                or support.target_bucket_start != expected_start
                or support.target_bucket_end != expected_start + timedelta(days=1)
                or support.assessment_state
                not in {"pending-persistence", "candidate"}
            ):
                raise TemporalProjectionError(
                    "invalid-persistence-support",
                    "temporal deviation persistence support is not consecutive and aligned",
                )

        reasons: list[str] = []
        if observation.value is None:
            reasons.append("target-observation-unavailable")
        if not observation.complete:
            reasons.append("target-observation-incomplete")
        if observation.freshness == "stale":
            reasons.append("target-observation-stale")
        if observation.data_quality != "observed":
            reasons.append("target-observation-untrusted-quality")
        if any(
            value is None
            for value in (expectation.expected, expectation.lower, expectation.upper)
        ):
            reasons.append("expectation-range-unavailable")
        if expectation.data_quality != policy.required_expectation_data_quality:
            reasons.append("expectation-quality-below-policy")
        if not _confidence_meets_policy(
            expectation.confidence,
            policy.minimum_expectation_confidence,
        ):
            reasons.append("expectation-confidence-below-policy")

        if reasons:
            state = "blocked"
            direction: DeviationDirection = "unknown"
            distance = None
            relative_change = None
            persistence = 0
            candidate = False
            ordered_supporting = ()
        else:
            assert observation.value is not None
            assert expectation.expected is not None
            assert expectation.lower is not None
            assert expectation.upper is not None
            observed_value = float(observation.value)
            if observed_value < expectation.lower:
                direction = "below"
                distance = expectation.lower - observed_value
            elif observed_value > expectation.upper:
                direction = "above"
                distance = observed_value - expectation.upper
            else:
                direction = "inside"
                distance = 0.0
            relative_change = (
                abs(observed_value - expectation.expected) / expectation.expected
                if expectation.expected > 0
                else None
            )
            if direction == "inside":
                state = "within-range"
                reasons = ["within-expected-range"]
                persistence = 0
                candidate = False
                ordered_supporting = ()
            elif direction not in policy.allowed_directions:
                state = "outside-policy-direction"
                reasons = ["direction-not-admitted"]
                persistence = 0
                candidate = False
                ordered_supporting = ()
            else:
                if any(support.direction != direction for support in ordered_supporting):
                    raise TemporalProjectionError(
                        "invalid-persistence-direction",
                        "temporal deviation persistence support changed direction",
                    )
                persistence = 1 + len(ordered_supporting)
                candidate = persistence >= policy.required_persistence_buckets
                state = "candidate" if candidate else "pending-persistence"
                reasons = [
                    "deviation-candidate"
                    if candidate
                    else "persistence-requirement-not-met"
                ]

        supporting_ids = tuple(item.assessment_id for item in ordered_supporting)
        observation_digest = temporal_observation_digest(observation)
        input_digest = temporal_assessment_input_digest(
            observation_digest=observation_digest,
            expectation=expectation,
            policy=policy,
            supporting_assessment_ids=supporting_ids,
        )
        return TemporalDeviationAssessment(
            schema_version=TEMPORAL_DEVIATION_ASSESSMENT_SCHEMA_VERSION,
            assessment_id=temporal_deviation_assessment_id(
                input_digest=input_digest,
                metric_key=observation.metric_key,
                site_id=observation.site_id,
                target_bucket_start=target_start,
                target_bucket_end=target_end,
                policy_version=policy.policy_version,
            ),
            input_digest=input_digest,
            metric_key=observation.metric_key,
            tenant_id=observation.tenant_id,
            site_id=observation.site_id,
            asset_id=observation.asset_id,
            target_bucket_start=target_start,
            target_bucket_end=target_end,
            bucket_granularity=observation.bucket_granularity,
            generated_at=generated_at,
            observation_knowledge_cutoff=target_end,
            signal_id=observation.signal_id,
            observation_digest=observation_digest,
            observed_value=(
                float(observation.value) if observation.value is not None else None
            ),
            observation_unit=observation.unit,
            observation_freshness=observation.freshness,
            observation_data_quality=observation.data_quality,
            observation_complete=observation.complete,
            expectation_id=expectation.expectation_id,
            history_digest=expectation.history_digest,
            expected=expectation.expected,
            lower=expectation.lower,
            upper=expectation.upper,
            expectation_method=expectation.method,
            expectation_method_version=expectation.method_version,
            expectation_confidence=expectation.confidence,
            expectation_data_quality=expectation.data_quality,
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            allowed_directions=policy.allowed_directions,
            required_persistence_buckets=policy.required_persistence_buckets,
            direction=direction,
            distance_beyond_bound=distance,
            relative_change=relative_change,
            persistence_observed_buckets=persistence,
            supporting_assessment_ids=supporting_ids,
            assessment_state=state,
            candidate=candidate,
            reason_codes=tuple(reasons),
            authority="analytical-investigation-context-only",
        )
