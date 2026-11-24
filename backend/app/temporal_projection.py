"""Deterministic UTC projection of authoritative histories into temporal signals."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

from .hub_contracts import SITE_ID_PATTERN
from .temporal_contracts import (
    MAX_TEMPORAL_BUCKETS,
    MAX_TEMPORAL_HISTORY_DAYS,
    TEMPORAL_SERIES_SCHEMA_VERSION,
    TEMPORAL_SIGNAL_SCHEMA_VERSION,
    BucketGranularity,
    TemporalMetricDefinition,
    TemporalSignal,
    TemporalSignalSeriesResponse,
    temporal_metric,
)


class TemporalProjectionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class TemporalSiteNotFound(TemporalProjectionError):
    def __init__(self) -> None:
        super().__init__("site-not-found", "temporal signal site was not found")


@dataclass(frozen=True)
class ProjectionAggregate:
    """One bounded source aggregate before the public signal projection."""

    value: int | float
    evidence_count: int
    source_observed_at: datetime | None
    source_received_at: datetime | None
    complete: bool
    coverage_observed: bool = True

    def __post_init__(self) -> None:
        if self.value < 0 or self.evidence_count < 0:
            raise ValueError("temporal aggregates cannot be negative")
        for value in (self.source_observed_at, self.source_received_at):
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError("temporal aggregate timestamps must include a timezone")


class TemporalProjectionStore(Protocol):
    def metric_buckets(
        self,
        *,
        metric: TemporalMetricDefinition,
        site_id: str,
        start: datetime,
        end: datetime,
        knowledge_cutoff: datetime | None = None,
    ) -> dict[datetime, ProjectionAggregate]: ...


def _as_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise TemporalProjectionError(
            "timezone-required",
            f"{field} must include a timezone",
        )
    return value.astimezone(timezone.utc)


def utc_daily_bucket(timestamp: datetime) -> tuple[datetime, datetime]:
    observed = _as_utc(timestamp, field="timestamp")
    start = observed.replace(hour=0, minute=0, second=0, microsecond=0)
    return start, start + timedelta(days=1)


def validate_temporal_window(
    *,
    start: datetime,
    end: datetime,
    granularity: str,
) -> tuple[datetime, datetime, int]:
    if granularity != "daily":
        raise TemporalProjectionError(
            "unsupported-granularity",
            "only daily UTC temporal buckets are supported",
        )
    normalized_start = _as_utc(start, field="start")
    normalized_end = _as_utc(end, field="end")
    for field, value in (("start", normalized_start), ("end", normalized_end)):
        if any((value.hour, value.minute, value.second, value.microsecond)):
            raise TemporalProjectionError(
                "unaligned-window",
                f"{field} must align to a UTC midnight bucket boundary",
            )
    if normalized_end <= normalized_start:
        raise TemporalProjectionError(
            "invalid-window",
            "end must be after start",
        )
    bucket_count = (normalized_end - normalized_start).days
    if bucket_count > MAX_TEMPORAL_HISTORY_DAYS or bucket_count > MAX_TEMPORAL_BUCKETS:
        raise TemporalProjectionError(
            "window-too-large",
            f"temporal history is limited to {MAX_TEMPORAL_BUCKETS} daily buckets",
        )
    return normalized_start, normalized_end, bucket_count


def iter_daily_buckets(start: datetime, end: datetime) -> tuple[datetime, ...]:
    cursor = start
    buckets: list[datetime] = []
    while cursor < end:
        buckets.append(cursor)
        cursor += timedelta(days=1)
    return tuple(buckets)


def temporal_signal_id(
    *,
    metric_key: str,
    site_id: str,
    asset_id: str | None,
    bucket_start: datetime,
    bucket_end: datetime,
    projection_version: str,
) -> str:
    identity = "\x1f".join(
        (
            TEMPORAL_SIGNAL_SCHEMA_VERSION,
            metric_key,
            site_id,
            asset_id or "",
            bucket_start.isoformat(),
            bucket_end.isoformat(),
            projection_version,
        )
    )
    return "sig_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def _freshness(
    *,
    metric: TemporalMetricDefinition,
    bucket_end: datetime,
    source_observed_at: datetime | None,
) -> str:
    if source_observed_at is None:
        return "unknown"
    observed = source_observed_at.astimezone(timezone.utc)
    expected_after = bucket_end - timedelta(
        seconds=metric.freshness_expectation_seconds
    )
    return "stale" if observed < expected_after else "current"


def _backfill_state(
    *,
    bucket_end: datetime,
    generated_at: datetime,
    source_received_at: datetime | None,
) -> str:
    if source_received_at is not None and source_received_at.astimezone(timezone.utc) > bucket_end:
        return "late-arriving"
    generated_bucket_start, _ = utc_daily_bucket(generated_at)
    if bucket_end <= generated_bucket_start:
        return "backfilled"
    return "live"


class TemporalProjectionService:
    def __init__(self, *, store: TemporalProjectionStore) -> None:
        self.store = store

    def series(
        self,
        *,
        metric_key: str,
        site_id: str,
        start: datetime,
        end: datetime,
        granularity: str = "daily",
        asset_id: str | None = None,
        generated_at: datetime | None = None,
        knowledge_cutoff: datetime | None = None,
    ) -> TemporalSignalSeriesResponse:
        try:
            metric = temporal_metric(metric_key)
        except ValueError as exc:
            raise TemporalProjectionError(
                "unknown-metric",
                "unknown temporal metric",
            ) from exc
        if not isinstance(site_id, str) or not re.fullmatch(SITE_ID_PATTERN, site_id):
            raise TemporalProjectionError("invalid-site", "invalid temporal site scope")
        if asset_id is not None and not metric.supports_asset_scope:
            raise TemporalProjectionError(
                "unsupported-scope",
                "the selected temporal metric supports site scope only",
            )
        normalized_start, normalized_end, bucket_count = validate_temporal_window(
            start=start,
            end=end,
            granularity=granularity,
        )
        projection_time = _as_utc(
            generated_at or datetime.now(timezone.utc),
            field="generated_at",
        )
        normalized_knowledge_cutoff = (
            _as_utc(knowledge_cutoff, field="knowledge_cutoff")
            if knowledge_cutoff is not None
            else None
        )
        if (
            normalized_knowledge_cutoff is not None
            and normalized_end > normalized_knowledge_cutoff
        ):
            raise TemporalProjectionError(
                "history-after-cutoff",
                "temporal history cannot extend beyond its evidence cutoff",
            )
        _, maximum_end = utc_daily_bucket(projection_time)
        if normalized_end > maximum_end:
            raise TemporalProjectionError(
                "future-window",
                "temporal history cannot extend beyond the current UTC bucket",
            )
        source_buckets = self.store.metric_buckets(
            metric=metric,
            site_id=site_id,
            start=normalized_start,
            end=normalized_end,
            knowledge_cutoff=normalized_knowledge_cutoff,
        )
        normalized_sources: dict[datetime, ProjectionAggregate] = {}
        for bucket, aggregate in source_buckets.items():
            normalized_bucket = _as_utc(bucket, field="source bucket")
            if not normalized_start <= normalized_bucket < normalized_end:
                continue
            if normalized_bucket in normalized_sources:
                raise TemporalProjectionError(
                    "duplicate-source-bucket",
                    "temporal source returned duplicate normalized buckets",
                )
            normalized_sources[normalized_bucket] = aggregate

        signals: list[TemporalSignal] = []
        for bucket_start in iter_daily_buckets(normalized_start, normalized_end):
            bucket_end = bucket_start + timedelta(days=1)
            aggregate = normalized_sources.get(bucket_start)
            signals.append(
                self._signal(
                    metric=metric,
                    site_id=site_id,
                    bucket_start=bucket_start,
                    bucket_end=bucket_end,
                    aggregate=aggregate,
                    generated_at=projection_time,
                )
            )

        return TemporalSignalSeriesResponse(
            schema_version=TEMPORAL_SERIES_SCHEMA_VERSION,
            metric=metric,
            tenant_id=None,
            site_id=site_id,
            asset_id=None,
            start=normalized_start,
            end=normalized_end,
            granularity="daily",
            generated_at=projection_time,
            bucket_count=bucket_count,
            missing_bucket_count=sum(signal.data_quality == "missing" for signal in signals),
            incomplete_bucket_count=sum(not signal.complete for signal in signals),
            maximum_bucket_count=MAX_TEMPORAL_BUCKETS,
            signals=signals,
        )

    @staticmethod
    def _signal(
        *,
        metric: TemporalMetricDefinition,
        site_id: str,
        bucket_start: datetime,
        bucket_end: datetime,
        aggregate: ProjectionAggregate | None,
        generated_at: datetime,
    ) -> TemporalSignal:
        if aggregate is None:
            value: int | float | None = None
            evidence_count = 0
            observed_at = None
            received_at = None
            freshness = "unknown"
            complete = False
            data_quality = "missing"
            backfill_state = _backfill_state(
                bucket_end=bucket_end,
                generated_at=generated_at,
                source_received_at=None,
            )
        else:
            value = aggregate.value
            evidence_count = aggregate.evidence_count
            observed_at = (
                aggregate.source_observed_at.astimezone(timezone.utc)
                if aggregate.source_observed_at is not None
                else None
            )
            received_at = (
                aggregate.source_received_at.astimezone(timezone.utc)
                if aggregate.source_received_at is not None
                else None
            )
            if (
                value == 0
                and not aggregate.complete
                and metric.missing_bucket_differs_from_zero
                and evidence_count == 0
            ):
                value = None
            freshness = _freshness(
                metric=metric,
                bucket_end=bucket_end,
                source_observed_at=observed_at,
            )
            complete = bool(aggregate.complete and value is not None)
            if value is None:
                data_quality = "incomplete" if aggregate.coverage_observed else "missing"
            elif not complete:
                data_quality = "incomplete"
            elif freshness == "stale":
                data_quality = "stale"
            else:
                data_quality = "observed"
            backfill_state = _backfill_state(
                bucket_end=bucket_end,
                generated_at=generated_at,
                source_received_at=received_at,
            )

        return TemporalSignal(
            schema_version=TEMPORAL_SIGNAL_SCHEMA_VERSION,
            signal_id=temporal_signal_id(
                metric_key=metric.metric_key,
                site_id=site_id,
                asset_id=None,
                bucket_start=bucket_start,
                bucket_end=bucket_end,
                projection_version=metric.projection_version,
            ),
            metric_key=metric.metric_key,
            tenant_id=None,
            site_id=site_id,
            asset_id=None,
            bucket_start=bucket_start,
            bucket_end=bucket_end,
            bucket_granularity="daily",
            value=value,
            unit=metric.unit,
            evidence_count=evidence_count,
            source=metric.source_authority,
            source_observed_at=observed_at,
            source_received_at=received_at,
            freshness=freshness,
            complete=complete,
            data_quality=data_quality,
            backfill_state=backfill_state,
            projection_version=metric.projection_version,
            generated_at=generated_at,
        )
