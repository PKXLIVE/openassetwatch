"""Strict API contracts for security outcome metrics (CTEM-GAP-09).

These are the provider-neutral shapes the frontend, the read-only AI Advisor,
and future dashboard composition consume. They reject unknown fields.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

METRIC_ID_PATTERN = r"^[a-z]+(\.[a-z][a-z0-9-]*)+$"
MetricStatus = Literal["measured", "partial", "not-measured", "unavailable"]
TimeSemantics = Literal["current", "window"]
ValueKind = Literal["count", "ratio", "duration"]


class StrictMetricContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MetricDefinitionResponse(StrictMetricContract):
    metric_id: str = Field(..., pattern=METRIC_ID_PATTERN, max_length=80)
    version: int = Field(..., ge=1)
    display_name: str
    description: str
    purpose: str
    unit: str
    counting_grain: str
    population: str
    value_kind: ValueKind
    numerator: str | None = None
    denominator: str | None = None
    time_semantics: TimeSemantics
    source_records: list[str]
    required_evidence: list[str]
    history_sources: list[str]
    filters: list[Literal["site_id", "action_band", "verification_state"]]
    dimensions: list[str]
    freshness_requirement: str
    missing_data_behavior: str
    limitations: list[str]


class StatusReasonResponse(StrictMetricContract):
    code: str = Field(..., pattern=r"^[A-Z][A-Z0-9_]+$")
    explanation: str


class MetricLimitsResponse(StrictMetricContract):
    max_window_days: int
    default_window_days: int


class MetricCatalogResponse(StrictMetricContract):
    catalog_version: str
    metrics: list[MetricDefinitionResponse]
    statuses: list[MetricStatus]
    status_reasons: list[StatusReasonResponse]
    units: list[str]
    limits: MetricLimitsResponse


class MetricValueResponse(StrictMetricContract):
    dimensions: dict[str, str]
    # Count metrics: the count. Ratio metrics: numerator / denominator.
    # Duration metrics: the median in hours. Null when not measured.
    value: float | None = None
    numerator: int | None = Field(default=None, ge=0)
    denominator: int | None = Field(default=None, ge=0)
    count: int | None = Field(default=None, ge=0)
    median: float | None = None
    p90: float | None = None
    max: float | None = None


class MetricTimeRangeResponse(StrictMetricContract):
    # Null start for current-state metrics; end is the as-of time.
    start: datetime | None = None
    end: datetime


class MetricFiltersResponse(StrictMetricContract):
    site_id: str | None = None
    action_band: str | None = None
    verification_state: str | None = None


class MetricCoverageResponse(StrictMetricContract):
    recording_since: dict[str, datetime | None]
    degraded_verification_runs: int | None = Field(default=None, ge=0)
    ongoing_episodes: int | None = Field(default=None, ge=0)
    left_censored_episodes: int | None = Field(default=None, ge=0)
    not_recorded: int | None = Field(default=None, ge=0)


class SourceFreshnessResponse(StrictMetricContract):
    source: str
    latest_record_at: datetime | None = None


class MetricResultResponse(StrictMetricContract):
    catalog_version: str
    metric_id: str = Field(..., pattern=METRIC_ID_PATTERN, max_length=80)
    metric_version: int = Field(..., ge=1)
    display_name: str
    unit: str
    value_kind: ValueKind
    counting_grain: str
    population: str
    numerator_definition: str | None = None
    denominator_definition: str | None = None
    time_semantics: TimeSemantics
    time_range: MetricTimeRangeResponse
    filters: MetricFiltersResponse
    status: MetricStatus
    status_reasons: list[str]
    total: MetricValueResponse
    breakdown: list[MetricValueResponse]
    coverage: MetricCoverageResponse
    source_freshness: list[SourceFreshnessResponse]
    limitations: list[str]
    computed_at: datetime
