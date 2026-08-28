"""Deterministic, cutoff-safe expected ranges over governed temporal signals."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Literal, Protocol, Sequence

from .temporal_contracts import (
    HISTORY_DIGEST_PATTERN,
    TEMPORAL_EXPECTATION_HISTORY_BUCKETS,
    TEMPORAL_EXPECTATION_METHOD_VERSION,
    TEMPORAL_EXPECTATION_SCHEMA_VERSION,
    TEMPORAL_METRICS,
    TemporalExpectation,
    TemporalSignal,
    TemporalSignalSeriesResponse,
    temporal_metric,
)
from .temporal_projection import (
    TemporalProjectionError,
    TemporalProjectionService,
    utc_daily_bucket,
)


ROLLING_SAMPLE_BUCKETS = 28
MINIMUM_ROLLING_OBSERVATIONS = 7
SEASONAL_PERIOD_BUCKETS = 7
MINIMUM_SEASONAL_OBSERVATIONS = 4
ROBUST_MAD_SCALE = Decimal("1.4826")
ROBUST_RANGE_MULTIPLIER = Decimal("3")
OUTPUT_QUANTUM = Decimal("0.000001")

PrimaryMethod = Literal["rolling", "seasonal"]


@dataclass(frozen=True)
class TemporalExpectationPolicy:
    primary_method: PrimaryMethod


TEMPORAL_EXPECTATION_POLICIES: dict[str, TemporalExpectationPolicy] = {
    "site.assets.new.count": TemporalExpectationPolicy(primary_method="rolling"),
    "site.collectors.active.count": TemporalExpectationPolicy(
        primary_method="seasonal"
    ),
    "site.findings.new.count": TemporalExpectationPolicy(primary_method="rolling"),
    "site.vulnerabilities.new.count": TemporalExpectationPolicy(
        primary_method="rolling"
    ),
    "site.inventory.collections.count": TemporalExpectationPolicy(
        primary_method="seasonal"
    ),
    "site.inventory.asset_observations.count": TemporalExpectationPolicy(
        primary_method="seasonal"
    ),
}
if set(TEMPORAL_EXPECTATION_POLICIES) != {
    metric.metric_key for metric in TEMPORAL_METRICS
}:
    raise RuntimeError("temporal expectation policy map and metric registry differ")


class ExpectationProjection(Protocol):
    def series(self, **kwargs) -> TemporalSignalSeriesResponse: ...


def _canonical_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat()


def temporal_history_digest(signals: Sequence[TemporalSignal]) -> str:
    """Return the canonical identity of one complete bounded as-of history."""

    if len(signals) != TEMPORAL_EXPECTATION_HISTORY_BUCKETS:
        raise ValueError(
            "temporal history digest requires exactly "
            f"{TEMPORAL_EXPECTATION_HISTORY_BUCKETS} signals"
        )
    ordered = sorted(
        signals,
        key=lambda signal: (
            signal.bucket_start,
            signal.bucket_end,
            signal.signal_id,
        ),
    )
    canonical_signals = [
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
        for signal in ordered
    ]
    canonical_json = json.dumps(
        canonical_signals,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def temporal_expectation_id(
    *,
    metric_key: str,
    site_id: str,
    target_bucket_start: datetime,
    target_bucket_end: datetime,
    history_start: datetime,
    history_end: datetime,
    method: str,
    projection_version: str,
    history_digest: str,
) -> str:
    if re.fullmatch(HISTORY_DIGEST_PATTERN, history_digest) is None:
        raise ValueError("history_digest must be a lowercase SHA-256 digest")
    identity = "\x1f".join(
        (
            TEMPORAL_EXPECTATION_SCHEMA_VERSION,
            metric_key,
            site_id,
            target_bucket_start.isoformat(),
            target_bucket_end.isoformat(),
            history_start.isoformat(),
            history_end.isoformat(),
            method,
            TEMPORAL_EXPECTATION_METHOD_VERSION,
            projection_version,
            history_digest,
        )
    )
    return "exp_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def _median(values: list[Decimal]) -> Decimal:
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / Decimal(2)


def _rounded(value: Decimal) -> float:
    rounded = float(value.quantize(OUTPUT_QUANTUM, rounding=ROUND_HALF_UP))
    if not math.isfinite(rounded):
        raise ValueError("robust expected range must produce finite values")
    return rounded


def robust_expected_range(values: list[int | float]) -> tuple[float, float, float]:
    if not values:
        raise ValueError("robust expected range requires at least one value")
    decimal_values = [Decimal(str(value)) for value in values]
    if any(not value.is_finite() for value in decimal_values):
        raise ValueError("robust expected range requires finite values")
    center = _median(decimal_values)
    median_absolute_deviation = _median(
        [abs(value - center) for value in decimal_values]
    )
    half_width = (
        median_absolute_deviation * ROBUST_MAD_SCALE * ROBUST_RANGE_MULTIPLIER
    )
    lower = max(Decimal(0), center - half_width)
    upper = center + half_width
    return _rounded(center), _rounded(lower), _rounded(upper)


def _quality_and_confidence(
    *,
    usable_bucket_count: int,
    method_sample_count: int,
    method: str,
) -> tuple[str, str]:
    history_coverage = usable_bucket_count / TEMPORAL_EXPECTATION_HISTORY_BUCKETS
    strong_sample = (
        8 if method == "seasonal_robust_baseline" else 14
    )
    medium_sample = (
        6 if method == "seasonal_robust_baseline" else 10
    )
    if history_coverage >= 0.8 and method_sample_count >= strong_sample:
        return "sufficient", "high"
    if history_coverage >= 0.5 and method_sample_count >= medium_sample:
        return "sufficient", "medium"
    return "limited", "low"


class TemporalExpectationService:
    def __init__(self, *, projection: ExpectationProjection) -> None:
        self.projection = projection

    @classmethod
    def from_projection_store(cls, *, store) -> "TemporalExpectationService":
        return cls(projection=TemporalProjectionService(store=store))

    def expectation(
        self,
        *,
        metric_key: str,
        site_id: str,
        target_start: datetime,
        granularity: str = "daily",
        asset_id: str | None = None,
        generated_at: datetime | None = None,
    ) -> TemporalExpectation:
        try:
            metric = temporal_metric(metric_key)
        except ValueError as exc:
            raise TemporalProjectionError("unknown-metric", "unknown temporal metric") from exc
        if granularity != "daily":
            raise TemporalProjectionError(
                "unsupported-granularity",
                "only daily UTC temporal expectations are supported",
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
        if asset_id is not None and not metric.supports_asset_scope:
            raise TemporalProjectionError(
                "unsupported-scope",
                "the selected temporal metric supports site scope only",
            )
        calculation_time = generated_at or datetime.now(timezone.utc)
        if calculation_time.tzinfo is None or calculation_time.utcoffset() is None:
            raise TemporalProjectionError(
                "timezone-required",
                "generated_at must include a timezone",
            )
        calculation_time = calculation_time.astimezone(timezone.utc)
        latest_closed_bucket_end, _ = utc_daily_bucket(calculation_time)
        if normalized_target > latest_closed_bucket_end:
            raise TemporalProjectionError(
                "future-target",
                "temporal expectation target cannot begin after the current UTC bucket",
            )

        history_end = normalized_target
        history_start = history_end - timedelta(
            days=TEMPORAL_EXPECTATION_HISTORY_BUCKETS
        )
        history = self.projection.series(
            metric_key=metric_key,
            site_id=site_id,
            start=history_start,
            end=history_end,
            granularity="daily",
            asset_id=asset_id,
            generated_at=normalized_target,
            knowledge_cutoff=normalized_target,
        )
        if any(
            signal.bucket_end > normalized_target
            or signal.bucket_end > latest_closed_bucket_end
            for signal in history.signals
        ):
            raise TemporalProjectionError(
                "open-history-bucket",
                "expected-range history must contain closed UTC buckets only",
            )
        history_digest = temporal_history_digest(history.signals)

        quality_counts = {
            quality: sum(signal.data_quality == quality for signal in history.signals)
            for quality in ("observed", "missing", "incomplete", "stale")
        }
        usable = [
            signal
            for signal in history.signals
            if signal.data_quality == "observed" and signal.value is not None
        ]
        policy = TEMPORAL_EXPECTATION_POLICIES[metric_key]
        method, sample = self._method_sample(
            policy=policy,
            usable=usable,
            target_start=normalized_target,
        )
        minimum = (
            MINIMUM_SEASONAL_OBSERVATIONS
            if method == "seasonal_robust_baseline"
            else MINIMUM_ROLLING_OBSERVATIONS
        )
        blocked = len(sample) < minimum
        if blocked:
            expected = lower = upper = None
            data_quality = "insufficient"
            confidence = "none"
            blocked_reason = "insufficient-usable-history"
        else:
            expected, lower, upper = robust_expected_range(
                [signal.value for signal in sample if signal.value is not None]
            )
            data_quality, confidence = _quality_and_confidence(
                usable_bucket_count=len(usable),
                method_sample_count=len(sample),
                method=method,
            )
            blocked_reason = None

        target_end = normalized_target + timedelta(days=1)
        return TemporalExpectation(
            schema_version=TEMPORAL_EXPECTATION_SCHEMA_VERSION,
            expectation_id=temporal_expectation_id(
                metric_key=metric_key,
                site_id=site_id,
                target_bucket_start=normalized_target,
                target_bucket_end=target_end,
                history_start=history_start,
                history_end=history_end,
                method=method,
                projection_version=metric.projection_version,
                history_digest=history_digest,
            ),
            history_digest=history_digest,
            metric_key=metric_key,
            tenant_id=None,
            site_id=site_id,
            asset_id=None,
            target_bucket_start=normalized_target,
            target_bucket_end=target_end,
            bucket_granularity="daily",
            knowledge_cutoff=normalized_target,
            generated_at=calculation_time,
            history_start=history_start,
            history_end=history_end,
            history_bucket_count=TEMPORAL_EXPECTATION_HISTORY_BUCKETS,
            usable_bucket_count=quality_counts["observed"],
            missing_bucket_count=quality_counts["missing"],
            incomplete_bucket_count=quality_counts["incomplete"],
            stale_bucket_count=quality_counts["stale"],
            late_arriving_bucket_count=sum(
                signal.backfill_state == "late-arriving" for signal in history.signals
            ),
            method=method,
            method_version=TEMPORAL_EXPECTATION_METHOD_VERSION,
            method_sample_count=len(sample),
            horizon_buckets=1,
            expected=expected,
            lower=lower,
            upper=upper,
            unit=metric.unit,
            confidence=confidence,
            data_quality=data_quality,
            blocked_reason=blocked_reason,
            projection_version=metric.projection_version,
            authority="analytical-context-only",
        )

    @staticmethod
    def _method_sample(
        *,
        policy: TemporalExpectationPolicy,
        usable: list,
        target_start: datetime,
    ) -> tuple[str, list]:
        if policy.primary_method == "seasonal":
            seasonal = [
                signal
                for signal in usable
                if signal.bucket_start.weekday() == target_start.weekday()
            ]
            if len(seasonal) >= MINIMUM_SEASONAL_OBSERVATIONS:
                return "seasonal_robust_baseline", seasonal
        rolling_cutoff = target_start - timedelta(days=ROLLING_SAMPLE_BUCKETS)
        rolling = [signal for signal in usable if signal.bucket_start >= rolling_cutoff]
        return "rolling_robust_baseline", rolling
