"""Versioned contracts and governed registry for deterministic temporal signals."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .hub_contracts import SITE_ID_PATTERN


TEMPORAL_SIGNAL_SCHEMA_VERSION = "oaw.temporal-signal.v1"
TEMPORAL_REGISTRY_SCHEMA_VERSION = "oaw.temporal-metric-registry.v1"
TEMPORAL_SERIES_SCHEMA_VERSION = "oaw.temporal-series.v1"
TEMPORAL_EXPECTATION_SCHEMA_VERSION = "oaw.temporal-expectation.v1"
TEMPORAL_PROJECTION_VERSION = "1"
TEMPORAL_EXPECTATION_METHOD_VERSION = "1"
MAX_TEMPORAL_HISTORY_DAYS = 366
MAX_TEMPORAL_BUCKETS = 366
TEMPORAL_EXPECTATION_HISTORY_BUCKETS = 56
METRIC_KEY_PATTERN = r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$"
SIGNAL_ID_PATTERN = r"^sig_[0-9a-f]{32}$"
EXPECTATION_ID_PATTERN = r"^exp_[0-9a-f]{32}$"
HISTORY_DIGEST_PATTERN = r"^[0-9a-f]{64}$"

BucketGranularity = Literal["daily"]
EntityScope = Literal["site"]
SignalFreshness = Literal["current", "stale", "unknown"]
SignalDataQuality = Literal["observed", "missing", "incomplete", "stale"]
SignalBackfillState = Literal["live", "backfilled", "late-arriving"]
ExpectationMethod = Literal[
    "rolling_robust_baseline",
    "seasonal_robust_baseline",
]
ExpectationConfidence = Literal["none", "low", "medium", "high"]
ExpectationDataQuality = Literal["insufficient", "limited", "sufficient"]
ExpectationBlockedReason = Literal["insufficient-usable-history"]


class StrictTemporalContract(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )


class TemporalMetricDefinition(StrictTemporalContract):
    metric_key: str = Field(..., pattern=METRIC_KEY_PATTERN, max_length=120)
    name: str = Field(..., min_length=1, max_length=120)
    description: str = Field(..., min_length=1, max_length=500)
    entity_scope: EntityScope
    unit: str = Field(..., min_length=1, max_length=40)
    source_authority: str = Field(..., min_length=1, max_length=160)
    supported_bucket_granularities: tuple[BucketGranularity, ...] = Field(
        default=("daily",),
        min_length=1,
        max_length=1,
    )
    projection_version: str = Field(..., min_length=1, max_length=32)
    freshness_expectation_seconds: int = Field(..., ge=60, le=604_800)
    zero_is_meaningful: bool
    missing_bucket_differs_from_zero: bool
    supports_asset_scope: Literal[False] = False


TEMPORAL_METRICS: tuple[TemporalMetricDefinition, ...] = (
    TemporalMetricDefinition(
        metric_key="site.assets.new.count",
        name="New assets",
        description=(
            "Distinct canonical site asset identities whose authoritative first-seen "
            "timestamp falls in the UTC bucket."
        ),
        entity_scope="site",
        unit="count",
        source_authority="canonical control_tower_assets.first_seen_at",
        projection_version=TEMPORAL_PROJECTION_VERSION,
        freshness_expectation_seconds=129_600,
        zero_is_meaningful=True,
        missing_bucket_differs_from_zero=True,
    ),
    TemporalMetricDefinition(
        metric_key="site.collectors.active.count",
        name="Active collectors",
        description=(
            "Distinct enrolled endpoint-agent or passive-sensor identities with an "
            "accepted check-in in the UTC bucket."
        ),
        entity_scope="site",
        unit="count",
        source_authority="accepted agent_checkins",
        projection_version=TEMPORAL_PROJECTION_VERSION,
        freshness_expectation_seconds=90_000,
        zero_is_meaningful=True,
        missing_bucket_differs_from_zero=True,
    ),
    TemporalMetricDefinition(
        metric_key="site.findings.new.count",
        name="New findings",
        description=(
            "Distinct deterministic findings first opened in the UTC bucket; source "
            "coverage is evaluated from bounded finding evaluation runs."
        ),
        entity_scope="site",
        unit="count",
        source_authority="deterministic findings.first_seen_at",
        projection_version=TEMPORAL_PROJECTION_VERSION,
        freshness_expectation_seconds=129_600,
        zero_is_meaningful=True,
        missing_bucket_differs_from_zero=True,
    ),
    TemporalMetricDefinition(
        metric_key="site.vulnerabilities.new.count",
        name="New affected vulnerability matches",
        description=(
            "Distinct deterministic vulnerability matches first entering affected "
            "state in the UTC bucket."
        ),
        entity_scope="site",
        unit="count",
        source_authority="deterministic vulnerability_matches.first_matched_at",
        projection_version=TEMPORAL_PROJECTION_VERSION,
        freshness_expectation_seconds=172_800,
        zero_is_meaningful=True,
        missing_bucket_differs_from_zero=True,
    ),
    TemporalMetricDefinition(
        metric_key="site.inventory.collections.count",
        name="Accepted inventory collections",
        description=(
            "Replay-safe canonical inventory collections accepted in the UTC bucket; "
            "a retry updates its existing collection instead of adding a new fact."
        ),
        entity_scope="site",
        unit="count",
        source_authority="canonical_inventory_collections",
        projection_version=TEMPORAL_PROJECTION_VERSION,
        freshness_expectation_seconds=129_600,
        zero_is_meaningful=False,
        missing_bucket_differs_from_zero=True,
    ),
    TemporalMetricDefinition(
        metric_key="site.inventory.asset_observations.count",
        name="Canonical asset observations",
        description=(
            "Sum of canonical asset observations accepted across replay-safe inventory "
            "collections in the UTC bucket; this is not a distinct asset population."
        ),
        entity_scope="site",
        unit="asset-observations",
        source_authority="canonical_inventory_collections.canonical_asset_count",
        projection_version=TEMPORAL_PROJECTION_VERSION,
        freshness_expectation_seconds=129_600,
        zero_is_meaningful=True,
        missing_bucket_differs_from_zero=True,
    ),
)

_METRICS_BY_KEY = {metric.metric_key: metric for metric in TEMPORAL_METRICS}
if len(_METRICS_BY_KEY) != len(TEMPORAL_METRICS):
    raise RuntimeError("temporal metric registry contains duplicate metric keys")


class TemporalSignal(StrictTemporalContract):
    schema_version: Literal["oaw.temporal-signal.v1"]
    signal_id: str = Field(..., pattern=SIGNAL_ID_PATTERN)
    metric_key: str = Field(..., pattern=METRIC_KEY_PATTERN, max_length=120)
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128)
    site_id: str = Field(..., min_length=1, max_length=128, pattern=SITE_ID_PATTERN)
    asset_id: str | None = Field(default=None, min_length=1, max_length=160)
    bucket_start: datetime
    bucket_end: datetime
    bucket_granularity: BucketGranularity
    value: int | float | None = Field(default=None, ge=0)
    unit: str = Field(..., min_length=1, max_length=40)
    evidence_count: int = Field(..., ge=0)
    source: str = Field(..., min_length=1, max_length=160)
    source_observed_at: datetime | None = None
    source_received_at: datetime | None = None
    freshness: SignalFreshness
    complete: bool
    data_quality: SignalDataQuality
    backfill_state: SignalBackfillState
    projection_version: str = Field(..., min_length=1, max_length=32)
    generated_at: datetime

    @field_validator(
        "bucket_start",
        "bucket_end",
        "source_observed_at",
        "source_received_at",
        "generated_at",
    )
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("temporal timestamps must include a timezone")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_bucket_and_quality(self) -> "TemporalSignal":
        if self.bucket_end <= self.bucket_start:
            raise ValueError("bucket_end must be after bucket_start")
        if (
            self.bucket_granularity == "daily"
            and self.bucket_end - self.bucket_start != timedelta(days=1)
        ):
            raise ValueError("daily buckets must span exactly one UTC day")
        if any(
            (
                self.bucket_start.hour,
                self.bucket_start.minute,
                self.bucket_start.second,
                self.bucket_start.microsecond,
                self.bucket_end.hour,
                self.bucket_end.minute,
                self.bucket_end.second,
                self.bucket_end.microsecond,
            )
        ):
            raise ValueError("daily bucket boundaries must be UTC midnight")
        if self.value is None:
            if self.complete:
                raise ValueError("a missing value cannot be complete")
            if self.data_quality not in {"missing", "incomplete"}:
                raise ValueError("a missing value must report missing or incomplete quality")
        if self.data_quality == "observed" and (
            not self.complete or self.value is None or self.freshness != "current"
        ):
            raise ValueError("observed quality requires a complete current value")
        if self.data_quality == "missing" and (
            self.complete
            or self.value is not None
            or self.evidence_count != 0
            or self.freshness != "unknown"
        ):
            raise ValueError("missing quality requires an uncovered null value")
        if self.data_quality == "incomplete" and self.complete:
            raise ValueError("incomplete signals cannot claim complete coverage")
        if self.data_quality == "stale" and (
            not self.complete or self.value is None or self.freshness != "stale"
        ):
            raise ValueError("stale quality requires a complete stale value")
        if self.complete and self.freshness == "stale" and self.data_quality != "stale":
            raise ValueError("complete stale signals must report stale quality")
        if self.complete and self.source_observed_at is None:
            raise ValueError("complete signals require a source observation watermark")
        if self.backfill_state == "late-arriving" and (
            self.source_received_at is None or self.source_received_at <= self.bucket_end
        ):
            raise ValueError("late-arriving signals require evidence received after bucket end")
        if (
            self.source_received_at is not None
            and self.source_received_at > self.bucket_end
            and self.backfill_state != "late-arriving"
        ):
            raise ValueError("evidence received after bucket end must be late-arriving")
        return self


class TemporalMetricRegistryResponse(StrictTemporalContract):
    schema_version: Literal["oaw.temporal-metric-registry.v1"]
    metrics: list[TemporalMetricDefinition] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_unique_metrics(self) -> "TemporalMetricRegistryResponse":
        keys = [metric.metric_key for metric in self.metrics]
        if len(keys) != len(set(keys)):
            raise ValueError("temporal metric registry keys must be unique")
        return self


class TemporalSignalSeriesResponse(StrictTemporalContract):
    schema_version: Literal["oaw.temporal-series.v1"]
    metric: TemporalMetricDefinition
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128)
    site_id: str = Field(..., min_length=1, max_length=128, pattern=SITE_ID_PATTERN)
    asset_id: str | None = Field(default=None, min_length=1, max_length=160)
    start: datetime
    end: datetime
    granularity: BucketGranularity
    generated_at: datetime
    bucket_count: int = Field(..., ge=1, le=MAX_TEMPORAL_BUCKETS)
    missing_bucket_count: int = Field(..., ge=0, le=MAX_TEMPORAL_BUCKETS)
    incomplete_bucket_count: int = Field(..., ge=0, le=MAX_TEMPORAL_BUCKETS)
    maximum_bucket_count: Literal[366]
    signals: list[TemporalSignal] = Field(max_length=MAX_TEMPORAL_BUCKETS)

    @field_validator("start", "end", "generated_at")
    @classmethod
    def require_series_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("temporal series timestamps must include a timezone")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_series_consistency(self) -> "TemporalSignalSeriesResponse":
        if self.end <= self.start:
            raise ValueError("series end must be after start")
        if len(self.signals) != self.bucket_count:
            raise ValueError("series bucket_count must match the signal count")
        if self.missing_bucket_count != sum(
            signal.data_quality == "missing" for signal in self.signals
        ):
            raise ValueError("series missing bucket count is inconsistent")
        if self.incomplete_bucket_count != sum(
            not signal.complete for signal in self.signals
        ):
            raise ValueError("series incomplete bucket count is inconsistent")
        expected_start = self.start
        for signal in self.signals:
            if signal.metric_key != self.metric.metric_key:
                raise ValueError("series contains a signal for another metric")
            if signal.site_id != self.site_id or signal.tenant_id != self.tenant_id:
                raise ValueError("series contains a signal for another authority scope")
            if signal.asset_id != self.asset_id:
                raise ValueError("series contains a signal for another asset scope")
            if signal.bucket_start != expected_start:
                raise ValueError("series buckets must be contiguous and ordered")
            expected_start = signal.bucket_end
        if expected_start != self.end:
            raise ValueError("series buckets must cover the requested window")
        return self


class TemporalExpectation(StrictTemporalContract):
    """One deterministic expected range for one governed daily target bucket."""

    schema_version: Literal["oaw.temporal-expectation.v1"]
    expectation_id: str = Field(..., pattern=EXPECTATION_ID_PATTERN)
    history_digest: str = Field(..., pattern=HISTORY_DIGEST_PATTERN)
    metric_key: str = Field(..., pattern=METRIC_KEY_PATTERN, max_length=120)
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128)
    site_id: str = Field(..., min_length=1, max_length=128, pattern=SITE_ID_PATTERN)
    asset_id: str | None = Field(default=None, min_length=1, max_length=160)
    target_bucket_start: datetime
    target_bucket_end: datetime
    bucket_granularity: BucketGranularity
    knowledge_cutoff: datetime
    generated_at: datetime
    history_start: datetime
    history_end: datetime
    history_bucket_count: Literal[56]
    usable_bucket_count: int = Field(..., ge=0, le=TEMPORAL_EXPECTATION_HISTORY_BUCKETS)
    missing_bucket_count: int = Field(..., ge=0, le=TEMPORAL_EXPECTATION_HISTORY_BUCKETS)
    incomplete_bucket_count: int = Field(..., ge=0, le=TEMPORAL_EXPECTATION_HISTORY_BUCKETS)
    stale_bucket_count: int = Field(..., ge=0, le=TEMPORAL_EXPECTATION_HISTORY_BUCKETS)
    late_arriving_bucket_count: int = Field(
        ...,
        ge=0,
        le=TEMPORAL_EXPECTATION_HISTORY_BUCKETS,
    )
    method: ExpectationMethod
    method_version: Literal["1"]
    method_sample_count: int = Field(..., ge=0, le=TEMPORAL_EXPECTATION_HISTORY_BUCKETS)
    horizon_buckets: Literal[1]
    expected: float | None = Field(default=None, ge=0)
    lower: float | None = Field(default=None, ge=0)
    upper: float | None = Field(default=None, ge=0)
    unit: str = Field(..., min_length=1, max_length=40)
    confidence: ExpectationConfidence
    data_quality: ExpectationDataQuality
    blocked_reason: ExpectationBlockedReason | None = None
    projection_version: str = Field(..., min_length=1, max_length=32)
    authority: Literal["analytical-context-only"]

    @field_validator(
        "target_bucket_start",
        "target_bucket_end",
        "knowledge_cutoff",
        "generated_at",
        "history_start",
        "history_end",
    )
    @classmethod
    def require_expectation_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("temporal expectation timestamps must include a timezone")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_expectation_consistency(self) -> "TemporalExpectation":
        if self.target_bucket_end - self.target_bucket_start != timedelta(days=1):
            raise ValueError("expectation targets must span exactly one UTC day")
        for value in (
            self.target_bucket_start,
            self.target_bucket_end,
            self.knowledge_cutoff,
            self.history_start,
            self.history_end,
        ):
            if any((value.hour, value.minute, value.second, value.microsecond)):
                raise ValueError("expectation boundaries must align to UTC midnight")
        if self.knowledge_cutoff != self.target_bucket_start:
            raise ValueError("knowledge_cutoff must equal the target bucket start")
        if self.history_end != self.target_bucket_start:
            raise ValueError("expectation history must end at the target bucket start")
        if self.history_end - self.history_start != timedelta(
            days=TEMPORAL_EXPECTATION_HISTORY_BUCKETS
        ):
            raise ValueError("expectation history must cover the fixed bounded window")
        classified_count = sum(
            (
                self.usable_bucket_count,
                self.missing_bucket_count,
                self.incomplete_bucket_count,
                self.stale_bucket_count,
            )
        )
        if classified_count != self.history_bucket_count:
            raise ValueError("expectation history quality counts are inconsistent")
        if self.method_sample_count > self.usable_bucket_count:
            raise ValueError("expectation method sample cannot exceed usable history")
        values = (self.expected, self.lower, self.upper)
        if any(value is None for value in values):
            if any(value is not None for value in values):
                raise ValueError("expected range values must be all present or all absent")
            if self.data_quality != "insufficient":
                raise ValueError("a blocked expected range must report insufficient quality")
            if self.confidence != "none" or self.blocked_reason is None:
                raise ValueError("a blocked expected range requires no confidence and a reason")
        else:
            assert self.expected is not None
            assert self.lower is not None
            assert self.upper is not None
            if not self.lower <= self.expected <= self.upper:
                raise ValueError("expected range bounds must contain the expected value")
            if self.data_quality == "insufficient":
                raise ValueError("a populated expected range cannot be insufficient")
            if self.confidence == "none" or self.blocked_reason is not None:
                raise ValueError("a populated expected range requires confidence and no block")
        return self


def temporal_metric(metric_key: str) -> TemporalMetricDefinition:
    try:
        return _METRICS_BY_KEY[metric_key]
    except KeyError as exc:
        raise ValueError("unknown temporal metric") from exc


def temporal_registry_public() -> dict[str, object]:
    return {
        "schema_version": TEMPORAL_REGISTRY_SCHEMA_VERSION,
        "metrics": [metric.model_dump(mode="json") for metric in TEMPORAL_METRICS],
    }
