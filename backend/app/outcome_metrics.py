"""Security outcome metrics (CTEM-GAP-09): definitions and deterministic calculation.

Metrics are a read model over records the platform already keeps: findings
and their current decisions, decision history, work events, verification
history, and verification run records. Nothing here writes, and nothing is
reconstructed. Historical values come only from recorded events, never from
current values: a band in the past is read from decision history, and a
verification outcome is the latest one recorded before the window ends.

Every result states one counting unit and one of four measurement states:

- `measured`: the population was fully covered by recorded history;
- `partial`: a value exists, but part of the population or window is not
  covered by recorded history (the reasons say which part);
- `not-measured`: nothing to measure (no population, or no history at all in
  the window); the value is null, never zero;
- `unavailable`: the inputs could not be read within the bounds; the value is
  null.

This module has no database, network, or clock dependency; the store loads
bounded inputs and passes `now`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Literal, Mapping, Sequence

from .verification import RECORDED_STATES

CATALOG_VERSION = "oaw.metrics.catalog.v1"
MAX_WINDOW = timedelta(days=366)
DEFAULT_WINDOW = timedelta(days=30)
FUTURE_TOLERANCE = timedelta(minutes=5)

ACTION_BANDS: tuple[str, ...] = ("act-now", "prioritize", "plan", "monitor")
BAND_RANK = {"monitor": 0, "plan": 1, "prioritize": 2, "act-now": 3}
NO_DECISION = "no-current-decision"
NOT_RECORDED = "not-recorded"
FRESHNESS = ("fresh", "aging", "stale", "unknown")
OPEN_STATUSES = ("active", "acknowledged")
UNMEASURABLE_STATES = ("insufficient-evidence", "evidence-stale", "conflicting-evidence", "manual-review-required")
VERIFICATION_RUN_STATUSES = ("completed", "incomplete", "failed", NOT_RECORDED)
HISTORY_SOURCES = ("work-events", "decision-history", "verification-history", "verification-runs")

UNITS = frozenset(
    {"findings", "band-episodes", "decision-transitions", "remediation-reports", "work-items", "evaluation-runs",
     "hours", "ratio"}
)
Status = Literal["measured", "partial", "not-measured", "unavailable"]

STATUS_REASONS: dict[str, str] = {
    "NO_POPULATION": "No member of the population was found, so there is nothing to measure.",
    "NO_HISTORY_IN_WINDOW": "The required history did not exist yet during the window.",
    "HISTORY_STARTS_AFTER_WINDOW_START": "The required history began after the window started; earlier events were not recorded.",
    "SOURCE_NOT_AVAILABLE": "A required source is not present in this database.",
    "ROW_LIMIT_EXCEEDED": "The inputs exceeded the read bound, so no value is reported.",
    "OUTCOME_NOT_RECORDED": "Some remediation reports have no recorded verification outcome yet.",
    "VERIFICATION_RUNS_DEGRADED": "Verification failed or was incomplete in some evaluation runs in the window.",
    "EPISODE_START_UNRECORDED": "Some band episodes began before decision history was recorded for their finding; their durations are excluded.",
    "HISTORY_INCOMPLETE_FOR_FINDINGS": "Some findings existed before a history source began recording.",
}

_COMMON_LIMITS = (
    "Deleted findings and their history are not counted.",
    "Site scope only; there is no asset-group or owner dimension yet.",
)


@dataclass(frozen=True)
class MetricDefinition:
    metric_id: str
    version: int
    display_name: str
    description: str
    purpose: str
    unit: str
    counting_grain: str
    population: str
    value_kind: Literal["count", "ratio", "duration"]
    time_semantics: Literal["current", "window"]
    source_records: tuple[str, ...]
    required_evidence: tuple[str, ...]
    filters: tuple[str, ...]
    dimensions: tuple[str, ...]
    freshness_requirement: str
    missing_data_behavior: str
    limitations: tuple[str, ...]
    # History sources (`HISTORY_SOURCES`) whose recording period bounds the result.
    history_sources: tuple[str, ...] = ()
    numerator: str | None = None
    denominator: str | None = None
    reads_verification: bool = False

    def public(self) -> dict[str, Any]:
        return {
            "metric_id": self.metric_id,
            "version": self.version,
            "display_name": self.display_name,
            "description": self.description,
            "purpose": self.purpose,
            "unit": self.unit,
            "counting_grain": self.counting_grain,
            "population": self.population,
            "value_kind": self.value_kind,
            "numerator": self.numerator,
            "denominator": self.denominator,
            "time_semantics": self.time_semantics,
            "source_records": list(self.source_records),
            "required_evidence": list(self.required_evidence),
            "history_sources": list(self.history_sources),
            "filters": list(self.filters),
            "dimensions": list(self.dimensions),
            "freshness_requirement": self.freshness_requirement,
            "missing_data_behavior": self.missing_data_behavior,
            "limitations": list(self.limitations),
        }


_CURRENT = "Current state when the request is made; no time window."
_WINDOW = "Events with a timestamp in [start, end), UTC. Defaults to the last 30 days; at most 366 days."
_DURATION = (
    "Value is the median in hours; count, 90th percentile (linear interpolation between closest ranks), and "
    "maximum are also returned. Null with NO_POPULATION when there is nothing to measure."
)
_COUNT_MISSING = "A count of 0 is a measured zero. Null only when the result is not measured or unavailable."

METRIC_DEFINITIONS: tuple[MetricDefinition, ...] = (
    MetricDefinition(
        "findings.open-by-band", 1, "Open findings by action band",
        "Findings that are active or acknowledged, grouped by their current action band. Findings with no current "
        "decision are counted separately.",
        "Shows where the current backlog sits on the action scale.",
        "findings", "finding", "Findings with status active or acknowledged in scope.",
        "count", "current", ("findings", "finding_decisions"), ("finding status", "current decision"),
        ("site_id", "action_band"), ("action_band",),
        "Reflects the latest finding evaluation; findings are as current as their last evaluation run.",
        _COUNT_MISSING, ("Suppressed findings are not open and are not counted.",) + _COMMON_LIMITS,
    ),
    MetricDefinition(
        "findings.backlog-age-by-band", 1, "Backlog age by action band",
        "Age of each open finding since its first detection, grouped by its current action band.",
        "Shows how long findings in each band have been waiting.",
        "hours", "finding", "Findings with status active or acknowledged in scope.",
        "duration", "current", ("findings", "finding_decisions"), ("first detection time", "current decision"),
        ("site_id", "action_band"), ("action_band",),
        "Age is measured to the request time.", _DURATION,
        ("A reopened finding's age runs from its original first detection, including resolved periods.",)
        + _COMMON_LIMITS,
    ),
    MetricDefinition(
        "findings.band-episode-duration", 1, "Time spent in each action band",
        "Duration of completed band episodes: a maximal period in which a finding's current decision stayed in one "
        "action band, from recorded decision history. An episode ends when the band changes or the finding resolves.",
        "Shows how long findings remain in each band before moving or resolving.",
        "hours", "band episode", "Band episodes that ended inside the window.",
        "duration", "window", ("finding_decision_history", "findings"), ("decision history transitions",),
        ("site_id", "action_band"), ("action_band",),
        "Decision history is written by each finding evaluation run; episodes are as current as the last run.",
        _DURATION + " Episodes still open at the window end are counted in coverage as ongoing, not measured.",
        ("Episodes that began before decision history was recorded for a finding have no known start and are "
         "excluded; they are counted in coverage.",
         "Time while a finding is suppressed stays in its band.") + _COMMON_LIMITS,
        history_sources=("decision-history",),
    ),
    MetricDefinition(
        "findings.band-transitions", 1, "Action-band transitions",
        "Recorded changes of a current decision from one action band to another.",
        "Shows escalation and de-escalation activity.",
        "decision-transitions", "decision history transition", "Band changes recorded inside the window.",
        "count", "window", ("finding_decision_history",), ("decision history transitions",),
        ("site_id",), ("from_band", "to_band", "direction"),
        "As current as the last finding evaluation run.", _COUNT_MISSING,
        ("Resolution and reopening are not band changes and are not counted here.",) + _COMMON_LIMITS,
        history_sources=("decision-history",),
    ),
    MetricDefinition(
        "findings.reopened", 1, "Reopened findings",
        "Distinct findings that reopened at least once inside the window, from recorded decision history. "
        "`after_verification` is yes when any of the finding's reopens followed a recorded verified outcome.",
        "Shows findings whose resolution did not hold, including after verification.",
        "findings", "finding", "Findings with a recorded reopen inside the window.",
        "count", "window", ("finding_decision_history", "finding_verification_history"),
        ("decision history reopen transitions", "verification history"),
        ("site_id",), ("after_verification",),
        "As current as the last finding evaluation run.", _COUNT_MISSING,
        ("A reopen before decision history existed is not visible.",) + _COMMON_LIMITS,
        history_sources=("decision-history",),
    ),
    MetricDefinition(
        "remediation.reports", 1, "Work reported complete",
        "Remediation reports: each change of a work item to done, including repeated reports for the same work item.",
        "Shows how much remediation work was reported complete.",
        "remediation-reports", "remediation report (work item and revision)", "Reports made inside the window.",
        "count", "window", ("finding_work_events",), ("work status changes",),
        ("site_id",), (), "Reports are recorded when work is marked done.", _COUNT_MISSING,
        ("A report is a claim, not proof of remediation.",) + _COMMON_LIMITS,
        history_sources=("work-events",),
    ),
    MetricDefinition(
        "remediation.verified", 1, "Verified remediation outcomes",
        "Remediation reports whose first recorded verified outcome falls inside the window. Only the verified state "
        "counts; advisory or applicability changes and resolutions before the report never do.",
        "Shows how much reported work was confirmed by evidence.",
        "remediation-reports", "remediation report", "Reports first verified inside the window.",
        "count", "window", ("finding_work_events", "finding_verification_history"), ("verification history",),
        ("site_id",), (), "Verification history is written by finding evaluation runs.", _COUNT_MISSING,
        ("A verified outcome does not show that the remediation caused a risk reduction; it shows the evidence "
         "agrees with it.",
         "Excludes advisory changes, resolutions before the report, and every other verification state.",
         "Confirmed component removal cannot currently reach a verified outcome (see remediation verification).")
        + _COMMON_LIMITS,
        history_sources=("work-events", "verification-history"), reads_verification=True,
    ),
    MetricDefinition(
        "remediation.outcomes-by-state", 1, "Verification outcomes by state",
        "Remediation reports made inside the window, grouped by their latest verification state recorded before the "
        "window end. Reports with no recorded outcome are `not-recorded`.",
        "Shows what happened to reported work, without merging different outcomes.",
        "remediation-reports", "remediation report", "Reports made inside the window.",
        "count", "window", ("finding_work_events", "finding_verification_history"), ("verification history",),
        ("site_id", "verification_state"), ("verification_state",),
        "Verification history is written by finding evaluation runs.", _COUNT_MISSING,
        ("States are as recorded; nothing is recomputed from present evidence.",) + _COMMON_LIMITS,
        history_sources=("work-events", "verification-history"), reads_verification=True,
    ),
    MetricDefinition(
        "remediation.verification-rate", 1, "Verification rate",
        "Share of remediation reports made inside the window whose latest recorded outcome at the window end is "
        "verified. Advisory changes and resolutions before the report stay in the denominator as not verified.",
        "Shows whether reported remediation produces verified outcomes.",
        "ratio", "remediation report", "Reports made inside the window with a recorded outcome.",
        "ratio", "window", ("finding_work_events", "finding_verification_history"), ("verification history",),
        ("site_id",), (), "Verification history is written by finding evaluation runs.",
        "Null with NO_POPULATION when the denominator is 0. Reports with no recorded outcome are left out of the "
        "denominator and reported in coverage.",
        ("Withdrawn reports are excluded from the denominator.",
         "Advisory changes are never counted as verified.") + _COMMON_LIMITS,
        history_sources=("work-events", "verification-history"),
        numerator="Reports whose latest recorded outcome at the window end is verified.",
        denominator="Reports with a recorded outcome other than report-withdrawn.",
        reads_verification=True,
    ),
    MetricDefinition(
        "remediation.time-to-verified-from-detection", 1, "Time from detection to verified resolution",
        "For reports first verified inside the window: time from the finding's first detection to the first "
        "recorded verified outcome.",
        "Shows the end-to-end time to evidence-confirmed remediation.",
        "hours", "remediation report", "Reports first verified inside the window.",
        "duration", "window", ("findings", "finding_work_events", "finding_verification_history"),
        ("first detection time", "verification history"), ("site_id",), (),
        "Verification history is written by finding evaluation runs.", _DURATION,
        ("For a reopened finding the time runs from its original first detection.",
         "The verified time is when verification recorded it, at or after the resolving evaluation.",
         "Advisory changes are never counted as verified.")
        + _COMMON_LIMITS,
        history_sources=("work-events", "verification-history"), reads_verification=True,
    ),
    MetricDefinition(
        "remediation.time-to-verified-from-report", 1, "Time from reported remediation to verified resolution",
        "For reports first verified inside the window: time from the report (work marked done) to the first recorded "
        "verified outcome.",
        "Shows how quickly evidence confirms reported work.",
        "hours", "remediation report", "Reports first verified inside the window.",
        "duration", "window", ("finding_work_events", "finding_verification_history"), ("verification history",),
        ("site_id",), (), "Verification history is written by finding evaluation runs.", _DURATION,
        ("Depends on how often findings are evaluated after collection.",) + _COMMON_LIMITS,
        history_sources=("work-events", "verification-history"), reads_verification=True,
    ),
    MetricDefinition(
        "remediation.done-unverified", 1, "Done but unverified work",
        "Work items currently marked done whose latest report has no recorded verified outcome, grouped by the latest "
        "recorded state (`not-recorded` when none).",
        "Shows completed work that evidence has not confirmed.",
        "work-items", "work item", "Work items with work status done.",
        "count", "current", ("finding_work_items", "finding_work_events", "finding_verification_history"),
        ("work status", "verification history"), ("site_id", "verification_state"), ("verification_state",),
        "States are as recorded by the last finding evaluation run.", _COUNT_MISSING,
        ("Uses recorded history; the live verification view may be newer.",) + _COMMON_LIMITS,
        history_sources=("verification-history",), reads_verification=True,
    ),
    MetricDefinition(
        "quality.history-coverage", 1, "Available versus missing history",
        "For each history source, the findings in scope that existed before the source began recording, so their "
        "early history is missing. The total is the findings missing history from at least one source.",
        "Shows how much of the population historical metrics can describe.",
        "findings", "finding", "Findings in scope, any status.",
        "count", "current", ("findings", "schema_migrations"), ("finding creation time", "migration time"),
        ("site_id",), ("source",), "Recording start is when the source's migration was applied.", _COUNT_MISSING,
        ("Recording start is per database, not per site.",) + _COMMON_LIMITS,
    ),
    MetricDefinition(
        "quality.verification-run-coverage", 1, "Verification evaluation coverage",
        "Completed finding evaluation runs inside the window that cover the scope, grouped by the outcome of their "
        "verification step (`not-recorded` when none was recorded).",
        "Shows failed, incomplete, and missing verification work that other metrics depend on.",
        "evaluation-runs", "finding evaluation run", "Completed finding evaluation runs started inside the window.",
        "count", "window", ("finding_evaluation_runs", "finding_verification_runs"), ("evaluation run records",),
        ("site_id",), ("verification_status",), "Runs are recorded as they complete.", _COUNT_MISSING,
        ("Site scope includes runs without a site scope, which cover every site.",) + _COMMON_LIMITS,
        history_sources=("verification-runs",),
    ),
    MetricDefinition(
        "quality.evidence-freshness", 1, "Evidence freshness of open findings",
        "Open findings grouped by the freshness of their evidence.",
        "Shows how current the evidence behind the backlog is.",
        "findings", "finding", "Findings with status active or acknowledged in scope.",
        "count", "current", ("findings",), ("finding evidence freshness",),
        ("site_id",), ("evidence_freshness",), "Freshness is as of the last finding evaluation.", _COUNT_MISSING,
        ("Collection coverage against an expected asset scope is not measured: no authoritative scope "
         "denominator exists yet.",) + _COMMON_LIMITS,
    ),
    MetricDefinition(
        "quality.unmeasurable-outcomes", 1, "Remediation outcomes that cannot be measured reliably",
        "Remediation reports made inside the window whose latest recorded outcome is insufficient evidence, stale "
        "evidence, conflicting evidence, manual review required, or not recorded.",
        "Shows reported work whose outcome evidence cannot confirm or refute.",
        "remediation-reports", "remediation report", "Reports made inside the window.",
        "count", "window", ("finding_work_events", "finding_verification_history"), ("verification history",),
        ("site_id",), ("verification_state",), "Verification history is written by finding evaluation runs.",
        _COUNT_MISSING, ("Awaiting evidence is not counted; it may still resolve.",) + _COMMON_LIMITS,
        history_sources=("work-events", "verification-history"), reads_verification=True,
    ),
)
METRICS_BY_ID: dict[str, MetricDefinition] = {item.metric_id: item for item in METRIC_DEFINITIONS}


def catalog_public() -> dict[str, Any]:
    return {
        "catalog_version": CATALOG_VERSION,
        "metrics": [METRICS_BY_ID[key].public() for key in sorted(METRICS_BY_ID)],
        "statuses": ["measured", "partial", "not-measured", "unavailable"],
        "status_reasons": [{"code": code, "explanation": text} for code, text in STATUS_REASONS.items()],
        "units": sorted(UNITS),
        "limits": {"max_window_days": MAX_WINDOW.days, "default_window_days": DEFAULT_WINDOW.days},
    }


# ------------------------------------------------------------------ windows and filters


@dataclass(frozen=True)
class MetricWindow:
    start: datetime | None
    end: datetime


@dataclass(frozen=True)
class MetricFilters:
    site_id: str | None = None
    action_band: str | None = None
    verification_state: str | None = None


def _aware(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")
    return value.astimezone(timezone.utc)


def resolve_window(
    definition: MetricDefinition, *, start: datetime | None, end: datetime | None, now: datetime
) -> MetricWindow:
    now = _aware(now, "now")
    if definition.time_semantics == "current":
        if start is not None or end is not None:
            raise ValueError("this metric describes current state and takes no time window")
        return MetricWindow(None, now)
    resolved_end = _aware(end, "end") if end is not None else now
    resolved_start = _aware(start, "start") if start is not None else resolved_end - DEFAULT_WINDOW
    if resolved_end > now + FUTURE_TOLERANCE:
        raise ValueError("end must not be in the future")
    if resolved_start >= resolved_end:
        raise ValueError("start must be before end")
    if resolved_end - resolved_start > MAX_WINDOW:
        raise ValueError("time window must not exceed 366 days")
    return MetricWindow(resolved_start, resolved_end)


def validate_filters(definition: MetricDefinition, filters: MetricFilters) -> None:
    for name in ("site_id", "action_band", "verification_state"):
        value = getattr(filters, name)
        if value is None:
            continue
        if name not in definition.filters:
            raise ValueError(f"{definition.metric_id} does not support the {name} filter")
        if not isinstance(value, str) or not value or len(value) > 128:
            raise ValueError(f"invalid {name}")
    if filters.action_band is not None and filters.action_band not in ACTION_BANDS:
        raise ValueError("unknown action_band")
    if filters.verification_state is not None and filters.verification_state not in (*RECORDED_STATES, NOT_RECORDED):
        raise ValueError("unknown verification_state")


# ------------------------------------------------------------------ inputs


@dataclass(frozen=True)
class MetricInputs:
    """Bounded rows loaded by the store for one metric request."""

    open_findings: Sequence[Mapping[str, Any]] = ()
    decision_history: Sequence[Mapping[str, Any]] = ()
    verified_times: Mapping[str, Sequence[datetime]] = field(default_factory=dict)
    reports: Sequence[Mapping[str, Any]] = ()
    verification_history: Sequence[Mapping[str, Any]] = ()
    done_items: Sequence[Mapping[str, Any]] = ()
    evaluation_runs: Sequence[Mapping[str, Any]] = ()
    history_coverage: Sequence[Mapping[str, Any]] = ()
    recording_since: Mapping[str, datetime | None] = field(default_factory=dict)
    truncated: bool = False
    degraded_verification_runs: int = 0


# ------------------------------------------------------------------ arithmetic


def percentile(values: Sequence[float], q: float) -> float:
    """Linear interpolation between closest ranks (the common default)."""

    ordered = sorted(values)
    if not ordered:
        raise ValueError("percentile of an empty sequence")
    position = (len(ordered) - 1) * q
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _hours(later: datetime, earlier: datetime) -> float:
    return (later - earlier).total_seconds() / 3600.0


def _value(dimensions: Mapping[str, str] | None = None, **fields: Any) -> dict[str, Any]:
    item = {"dimensions": dict(dimensions or {}), "value": None, "numerator": None, "denominator": None,
            "count": None, "median": None, "p90": None, "max": None}
    item.update(fields)
    return item


def _duration(values: Sequence[float], dimensions: Mapping[str, str] | None = None) -> dict[str, Any]:
    if not values:
        return _value(dimensions, count=0)
    median = round(percentile(values, 0.5), 6)
    return _value(dimensions, value=median, count=len(values), median=median,
                  p90=round(percentile(values, 0.9), 6), max=round(max(values), 6))


def _counts(keys: Iterable[str], order: Sequence[str], dimension: str) -> list[dict[str, Any]]:
    tally = {key: 0 for key in order}
    for key in keys:
        tally[key] = tally.get(key, 0) + 1
    return [_value({dimension: key}, value=count) for key, count in tally.items()]


def _in(at: datetime | None, window: MetricWindow) -> bool:
    return at is not None and window.start is not None and window.start <= _aware(at, "time") < window.end


# ------------------------------------------------------------------ history derivations


@dataclass(frozen=True)
class BandEpisode:
    finding_id: str
    band: str
    started_at: datetime
    ended_at: datetime | None
    start_unrecorded: bool


def band_episodes(rows: Sequence[Mapping[str, Any]], *, decision_history_since: datetime | None) -> list[BandEpisode]:
    """Maximal periods in one band per finding, ordered by recorded revision.

    A row that keeps the band (a reason change) continues the episode. Rows at
    the same instant are ordered by revision. The first episode of a finding
    created before decision history began has an unrecorded start.
    """

    by_finding: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        by_finding.setdefault(str(row["finding_id"]), []).append(row)
    episodes: list[BandEpisode] = []
    for finding_id, items in sorted(by_finding.items()):
        items = sorted(items, key=lambda row: int(row["revision"]))
        created = items[0].get("finding_created_at")
        unrecorded_start = (
            int(items[0]["revision"]) == 1
            and decision_history_since is not None
            and created is not None
            and _aware(created, "finding_created_at") < decision_history_since
        )
        current: tuple[str, datetime, bool] | None = None
        for index, row in enumerate(items):
            band = row["action_band"] if row["decision_state"] == "current" else None
            at = _aware(row["evaluated_at"], "evaluated_at")
            if current is not None and band != current[0]:
                episodes.append(BandEpisode(finding_id, current[0], current[1], at, current[2]))
                current = None
            if band is not None and current is None:
                current = (band, at, unrecorded_start and index == 0)
        if current is not None:
            episodes.append(BandEpisode(finding_id, current[0], current[1], None, current[2]))
    return episodes


@dataclass(frozen=True)
class ReportOutcome:
    work_item_id: str
    finding_id: str
    revision: int
    reported_at: datetime
    finding_first_seen_at: datetime | None
    state: str  # latest recorded state before the as-of time, or "not-recorded"
    first_verified_at: datetime | None


def report_outcomes(
    reports: Sequence[Mapping[str, Any]], history: Sequence[Mapping[str, Any]], *, as_of: datetime
) -> list[ReportOutcome]:
    """One outcome per remediation report, from history recorded before `as_of`."""

    latest: dict[tuple[str, int], tuple[int, str]] = {}
    verified: dict[tuple[str, int], datetime] = {}
    for row in history:
        at = _aware(row["evaluated_at"], "evaluated_at")
        if at >= as_of:
            continue
        key = (str(row["work_item_id"]), int(row["report_revision"]))
        sequence = int(row["sequence"])
        if key not in latest or sequence > latest[key][0]:
            latest[key] = (sequence, str(row["verification_state"]))
        if row["verification_state"] == "verified" and (key not in verified or at < verified[key]):
            verified[key] = at
    outcomes = []
    seen: set[tuple[str, int]] = set()
    for row in reports:
        key = (str(row["work_item_id"]), int(row["revision"]))
        if key in seen:  # one report, however many rows reached it
            continue
        seen.add(key)
        outcomes.append(
            ReportOutcome(
                work_item_id=key[0], finding_id=str(row["finding_id"]), revision=key[1],
                reported_at=_aware(row["occurred_at"], "occurred_at"),
                finding_first_seen_at=row.get("finding_first_seen_at"),
                state=latest[key][1] if key in latest else NOT_RECORDED,
                first_verified_at=verified.get(key),
            )
        )
    return outcomes


# ------------------------------------------------------------------ calculation


def _coverage_status(definition: MetricDefinition, window: MetricWindow, inputs: MetricInputs) -> tuple[Status | None, list[str]]:
    """Status forced by source availability and history coverage, before values."""

    reasons: list[str] = []
    if inputs.truncated:
        return "unavailable", ["ROW_LIMIT_EXCEEDED"]
    for source in definition.history_sources:
        since = inputs.recording_since.get(source)
        if since is None:
            return "unavailable", ["SOURCE_NOT_AVAILABLE"]
        if definition.time_semantics == "window" and window.start is not None:
            if since >= window.end:
                return "not-measured", ["NO_HISTORY_IN_WINDOW"]
            if since > window.start and "HISTORY_STARTS_AFTER_WINDOW_START" not in reasons:
                reasons.append("HISTORY_STARTS_AFTER_WINDOW_START")
    if definition.reads_verification and inputs.degraded_verification_runs > 0:
        reasons.append("VERIFICATION_RUNS_DEGRADED")
    return None, reasons


def compute_metric(
    definition: MetricDefinition,
    *,
    window: MetricWindow,
    filters: MetricFilters,
    inputs: MetricInputs,
    now: datetime,
) -> dict[str, Any]:
    """Compute one metric. Returns the value part of a metric result."""

    validate_filters(definition, filters)
    now = _aware(now, "now")
    forced, reasons = _coverage_status(definition, window, inputs)
    coverage: dict[str, Any] = {
        "recording_since": {
            source: inputs.recording_since.get(source) for source in definition.history_sources
        },
        "degraded_verification_runs": inputs.degraded_verification_runs if definition.reads_verification else None,
    }
    if forced in {"unavailable", "not-measured"}:
        return {"status": forced, "status_reasons": reasons, "total": _value(), "breakdown": [], "coverage": coverage}

    total, breakdown, extra_reasons, extra_coverage = _CALCULATORS[definition.metric_id](window, filters, inputs, now)
    coverage.update(extra_coverage)
    for code in extra_reasons:
        if code not in reasons:
            reasons.append(code)
    if "NO_POPULATION" in reasons:
        status: Status = "not-measured"
    elif reasons:
        status = "partial"
    else:
        status = "measured"
    return {"status": status, "status_reasons": reasons, "total": total, "breakdown": breakdown, "coverage": coverage}


Calculation = tuple[dict[str, Any], list[dict[str, Any]], list[str], dict[str, Any]]


def _open(inputs: MetricInputs, filters: MetricFilters) -> list[Mapping[str, Any]]:
    rows = list({str(row["finding_id"]): row for row in inputs.open_findings}.values())
    if filters.action_band is not None:
        rows = [row for row in rows if row.get("action_band") == filters.action_band]
    return rows


def _open_by_band(window, filters, inputs, now) -> Calculation:
    rows = _open(inputs, filters)
    bands = [row.get("action_band") or NO_DECISION for row in rows]
    order = (filters.action_band,) if filters.action_band else (*ACTION_BANDS, NO_DECISION)
    return _value(value=len(rows)), _counts(bands, order, "action_band"), [], {}


def _backlog_age(window, filters, inputs, now) -> Calculation:
    rows = _open(inputs, filters)
    ages: dict[str, list[float]] = {}
    for row in rows:
        ages.setdefault(row.get("action_band") or NO_DECISION, []).append(
            _hours(now, _aware(row["first_seen_at"], "first_seen_at"))
        )
    order = (filters.action_band,) if filters.action_band else (*ACTION_BANDS, NO_DECISION)
    breakdown = [_duration(ages.get(band, []), {"action_band": band}) for band in order]
    all_ages = [value for values in ages.values() for value in values]
    return _duration(all_ages), breakdown, [] if all_ages else ["NO_POPULATION"], {}


def _episodes(window, filters, inputs, now) -> Calculation:
    episodes = band_episodes(inputs.decision_history, decision_history_since=inputs.recording_since.get("decision-history"))
    if filters.action_band is not None:
        episodes = [item for item in episodes if item.band == filters.action_band]
    completed = [item for item in episodes if item.ended_at is not None and _in(item.ended_at, window)]
    measured = [item for item in completed if not item.start_unrecorded]
    unrecorded = len(completed) - len(measured)
    ongoing = sum(1 for item in episodes if item.ended_at is None and item.started_at < window.end)
    order = (filters.action_band,) if filters.action_band else ACTION_BANDS
    breakdown = [
        _duration([_hours(item.ended_at, item.started_at) for item in measured if item.band == band], {"action_band": band})
        for band in order
    ]
    reasons = []
    if not measured:
        reasons.append("NO_POPULATION")
    if unrecorded:
        reasons.append("EPISODE_START_UNRECORDED")
    total = _duration([_hours(item.ended_at, item.started_at) for item in measured])
    return total, breakdown, reasons, {"ongoing_episodes": ongoing, "left_censored_episodes": unrecorded}


def _transitions(window, filters, inputs, now) -> Calculation:
    cells: dict[tuple[str, str, str], int] = {}
    for row in inputs.decision_history:
        before, after = row.get("previous_action_band"), row.get("action_band")
        if not _in(row["evaluated_at"], window) or row["decision_state"] != "current":
            continue
        if before is None or after is None or before == after:
            continue
        direction = "escalation" if BAND_RANK[after] > BAND_RANK[before] else "de-escalation"
        key = (before, after, direction)
        cells[key] = cells.get(key, 0) + 1
    breakdown = [
        _value({"from_band": key[0], "to_band": key[1], "direction": key[2]}, value=count)
        for key, count in sorted(cells.items())
    ]
    return _value(value=sum(cells.values())), breakdown, [], {}


def _reopened(window, filters, inputs, now) -> Calculation:
    after_verification: dict[str, bool] = {}
    for row in inputs.decision_history:
        if row.get("transition_cause") != "finding-reopened" or not _in(row["evaluated_at"], window):
            continue
        finding_id = str(row["finding_id"])
        at = _aware(row["evaluated_at"], "evaluated_at")
        prior = any(_aware(value, "verified_at") < at for value in inputs.verified_times.get(finding_id, ()))
        after_verification[finding_id] = after_verification.get(finding_id, False) or prior
    labels = ["yes" if value else "no" for value in after_verification.values()]
    return _value(value=len(after_verification)), _counts(labels, ("yes", "no"), "after_verification"), [], {}


def _outcomes(window: MetricWindow, inputs: MetricInputs) -> list[ReportOutcome]:
    return report_outcomes(inputs.reports, inputs.verification_history, as_of=window.end)


def _reports(window, filters, inputs, now) -> Calculation:
    reported = [item for item in _outcomes(window, inputs) if _in(item.reported_at, window)]
    return _value(value=len(reported)), [], [], {}


def _verified(window, filters, inputs, now) -> Calculation:
    verified = [item for item in _outcomes(window, inputs) if _in(item.first_verified_at, window)]
    return _value(value=len(verified)), [], [], {}


_STATE_ORDER = (*RECORDED_STATES, NOT_RECORDED)


def _by_state(window, filters, inputs, now) -> Calculation:
    reported = [item for item in _outcomes(window, inputs) if _in(item.reported_at, window)]
    if filters.verification_state is not None:
        reported = [item for item in reported if item.state == filters.verification_state]
    order = (filters.verification_state,) if filters.verification_state else _STATE_ORDER
    not_recorded = sum(1 for item in reported if item.state == NOT_RECORDED)
    return (
        _value(value=len(reported)),
        _counts((item.state for item in reported), order, "verification_state"),
        ["OUTCOME_NOT_RECORDED"] if not_recorded else [],
        {"not_recorded": not_recorded},
    )


def _rate(window, filters, inputs, now) -> Calculation:
    reported = [item for item in _outcomes(window, inputs) if _in(item.reported_at, window)]
    not_recorded = sum(1 for item in reported if item.state == NOT_RECORDED)
    eligible = [item for item in reported if item.state not in {NOT_RECORDED, "report-withdrawn"}]
    numerator = sum(1 for item in eligible if item.state == "verified")
    reasons = ["OUTCOME_NOT_RECORDED"] if not_recorded else []
    if not eligible:
        reasons.append("NO_POPULATION")
        total = _value(numerator=0, denominator=0)
    else:
        total = _value(value=numerator / len(eligible), numerator=numerator, denominator=len(eligible))
    return total, [], reasons, {"not_recorded": not_recorded}


def _time_to_verified(origin: str):
    def calculate(window, filters, inputs, now) -> Calculation:
        values = []
        for item in _outcomes(window, inputs):
            if not _in(item.first_verified_at, window):
                continue
            start = item.reported_at if origin == "report" else item.finding_first_seen_at
            if start is not None:
                values.append(_hours(item.first_verified_at, _aware(start, "start")))
        return _duration(values), [], [] if values else ["NO_POPULATION"], {}

    return calculate


def _done_unverified(window, filters, inputs, now) -> Calculation:
    states = [str(row.get("verification_state") or NOT_RECORDED) for row in inputs.done_items]
    states = [state for state in states if state != "verified"]
    if filters.verification_state is not None:
        states = [state for state in states if state == filters.verification_state]
    order = (filters.verification_state,) if filters.verification_state else tuple(
        state for state in _STATE_ORDER if state != "verified"
    )
    not_recorded = states.count(NOT_RECORDED)
    return (
        _value(value=len(states)),
        _counts(states, order, "verification_state"),
        ["OUTCOME_NOT_RECORDED"] if not_recorded else [],
        {"not_recorded": not_recorded},
    )


def _history_coverage(window, filters, inputs, now) -> Calculation:
    breakdown = [
        _value({"source": str(row["source"])}, value=int(row["findings_before"]),
               numerator=int(row["findings_before"]), denominator=int(row["findings_total"]))
        for row in inputs.history_coverage
    ]
    # Sources started at different times; findings created before the latest
    # start include every finding missing history from any source.
    worst = max((item["value"] for item in breakdown), default=0)
    total_population = max((item["denominator"] for item in breakdown), default=0)
    return (
        _value(value=worst, numerator=worst, denominator=total_population),
        breakdown,
        ["HISTORY_INCOMPLETE_FOR_FINDINGS"] if worst else [],
        {},
    )


def _run_coverage(window, filters, inputs, now) -> Calculation:
    statuses = [str(row.get("verification_status") or NOT_RECORDED) for row in inputs.evaluation_runs]
    return _value(value=len(statuses)), _counts(statuses, VERIFICATION_RUN_STATUSES, "verification_status"), [], {}


def _freshness(window, filters, inputs, now) -> Calculation:
    rows = _open(inputs, filters)
    return _value(value=len(rows)), _counts((str(row["evidence_freshness"]) for row in rows), FRESHNESS,
                                            "evidence_freshness"), [], {}


def _unmeasurable(window, filters, inputs, now) -> Calculation:
    reported = [item for item in _outcomes(window, inputs) if _in(item.reported_at, window)]
    states = [item.state for item in reported if item.state in (*UNMEASURABLE_STATES, NOT_RECORDED)]
    return _value(value=len(states)), _counts(states, (*UNMEASURABLE_STATES, NOT_RECORDED), "verification_state"), [], {}


_CALCULATORS = {
    "findings.open-by-band": _open_by_band,
    "findings.backlog-age-by-band": _backlog_age,
    "findings.band-episode-duration": _episodes,
    "findings.band-transitions": _transitions,
    "findings.reopened": _reopened,
    "remediation.reports": _reports,
    "remediation.verified": _verified,
    "remediation.outcomes-by-state": _by_state,
    "remediation.verification-rate": _rate,
    "remediation.time-to-verified-from-detection": _time_to_verified("detection"),
    "remediation.time-to-verified-from-report": _time_to_verified("report"),
    "remediation.done-unverified": _done_unverified,
    "quality.history-coverage": _history_coverage,
    "quality.verification-run-coverage": _run_coverage,
    "quality.evidence-freshness": _freshness,
    "quality.unmeasurable-outcomes": _unmeasurable,
}
if set(_CALCULATORS) != set(METRICS_BY_ID):  # pragma: no cover - import-time guard
    raise RuntimeError("every metric needs exactly one calculator")
