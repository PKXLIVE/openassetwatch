# CTEM Security Outcome Metrics

`CTEM-GAP-09` adds deterministic, read-only security outcome metrics. They
answer whether posture is improving, how long findings stay unresolved and in
each action band, whether reported remediation produces verified outcomes, how
much completed work is unverified, which findings reopen, and how complete the
evidence behind these answers is.

The metrics are the first entries of the platform-owned semantic metric
catalog. The frontend, the read-only AI Advisor, and future dashboard
composition consume them by stable identifier and version. None of them can
add a metric, a join, or a filter.

## Authority

Metrics are a read model over records that already exist. They add no table,
no migration, and no new source of truth:

| Source | Written by | Used for |
| --- | --- | --- |
| `findings` | Finding lifecycle | Open backlog, first detection, evidence freshness |
| `finding_decisions` | Decision layer | Current action band |
| `finding_decision_history` | Decision layer | Band episodes, band transitions, reopens |
| `finding_work_items`, `finding_work_events` | Work tracking | Remediation reports (work marked done) |
| `finding_verification_history` | Remediation verification | Recorded verification outcomes |
| `finding_evaluation_runs`, `finding_verification_runs` | Finding evaluation | Verification coverage |
| `oaw_schema_migrations` | Migration runner | When each history source began recording |

Historical values come only from recorded events. A past action band is read
from decision history, never from the current decision. A verification
outcome is the latest one recorded before the window end, never recomputed
from present evidence. Nothing is written: each request runs in one read-only
transaction.

## Counting units

Each metric counts exactly one unit, and no metric mixes units:

| Unit | One of these is... |
| --- | --- |
| `findings` | a finding (distinct `finding_id`) |
| `band-episodes` | a maximal period in which a finding's current decision stayed in one band |
| `decision-transitions` | one recorded band change in decision history |
| `remediation-reports` | one change of a work item to done (`work_item_id`, revision); a work item reported done twice is two reports |
| `work-items` | a work item (at most one per finding) |
| `evaluation-runs` | one finding evaluation run |
| `hours` | a duration summary (median, 90th percentile, maximum, count) over the stated grain |
| `ratio` | numerator over denominator, both counts of the stated grain |

A verification episode is the recorded verification sequence of one
remediation report, so outcome metrics count remediation reports. A report is
withdrawn as of the recorded work event that took its work item out of done,
even when no evaluation ran in between to record `report-withdrawn`. A
verified report that is later withdrawn still counts once in verified
outcomes and time to verification, at its first verified time, and is
excluded from the verification-rate denominator as withdrawn.

## Measurement states

Every result has a `status`:

| Status | Meaning | Value |
| --- | --- | --- |
| `measured` | Fully covered by recorded history | Present; 0 is a measured zero |
| `partial` | A value exists, but part of the population or window is not covered | Present, with reasons |
| `not-measured` | Nothing to measure, or no history at all in the window | Null, never 0 |
| `unavailable` | A source is missing or the read bound was exceeded | Null |

`status_reasons` explain every state other than `measured`:

| Reason | Meaning |
| --- | --- |
| `NO_POPULATION` | No member of the population was found |
| `NO_HISTORY_IN_WINDOW` | The required history did not exist yet during the window |
| `HISTORY_STARTS_AFTER_WINDOW_START` | History began inside the window; earlier events were not recorded |
| `SOURCE_NOT_AVAILABLE` | A required source is not present in this database |
| `ROW_LIMIT_EXCEEDED` | More than 100,000 rows were needed; no value is reported rather than a value from truncated input |
| `OUTCOME_NOT_RECORDED` | Some reports made in the window have no recorded verification outcome yet; this also marks verified counts and durations partial, so "0 verified" is never shown as measured while outcomes are missing |
| `VERIFICATION_RUNS_DEGRADED` | An evaluation run or its verification step failed, or verification was incomplete, in the window (for current metrics: in the latest run) |
| `EPISODE_START_UNRECORDED` | Some band episodes began before decision history was recorded for their finding |
| `HISTORY_INCOMPLETE_FOR_FINDINGS` | Some findings existed before a history source began recording |

A source began recording when its migration was applied: work events with
version 5, decision history with version 6, verification history and runs with
version 8. A window that starts before that is `partial`. A window that ends
before it is `not-measured`. Collection coverage against an expected asset
scope is not measured, because no authoritative scope denominator exists yet.

## Time semantics

- All times are UTC. Windows are half-open, `[start, end)`.
- When omitted, `end` defaults to the request time and `start` to 30 days
  before `end`. A window is at most 366 days, and `end` may not be in the
  future.
- `current` metrics describe state at the request time and reject `start` and
  `end`.
- Events at the same instant are ordered by their recorded revision or
  sequence, not by time.
- Ongoing findings and episodes are not given a duration. Episodes still open
  at the window end are counted as `ongoing_episodes` in coverage.
- A finding reopened after resolution keeps its original first detection, so
  age and time to verification include its resolved periods.

## Metric catalog (`oaw.metrics.catalog.v1`)

All metrics are version 1, accept `site_id`, and report `source_freshness`
(the last completed finding evaluation in scope, plus the latest work event
for work metrics).

| Metric | Unit | Time | Population and value | Filters / dimensions |
| --- | --- | --- | --- | --- |
| `findings.open-by-band` | findings | current | Active or acknowledged findings by current band; `no-current-decision` separately | `action_band` / `action_band` |
| `findings.backlog-age-by-band` | hours | current | Age since first detection of open findings, by current band | `action_band` / `action_band` |
| `findings.band-episode-duration` | hours | window | Completed band episodes that ended in the window | `action_band` / `action_band` |
| `findings.band-transitions` | decision-transitions | window | Recorded band changes, escalation or de-escalation | — / `from_band`, `to_band`, `direction` |
| `findings.reopened` | findings | window | Distinct findings whose recorded decision went from not current to current (whatever the recorded cause); `after_verification` is yes when a reopen followed a recorded verified outcome | — / `after_verification` |
| `remediation.reports` | remediation-reports | window | Work marked done in the window | — |
| `remediation.verified` | remediation-reports | window | Reports whose first recorded verified outcome is in the window | — |
| `remediation.outcomes-by-state` | remediation-reports | window | Reports made in the window by latest recorded state at the window end, or `not-recorded` | `verification_state` / `verification_state` |
| `remediation.verification-rate` | ratio | window | Numerator: reports made in the window that are verified at the window end. Denominator: those reports with a recorded state other than `report-withdrawn`. Not-recorded reports are left out and reported in coverage. | — |
| `remediation.time-to-verified-from-detection` | hours | window | First detection to first verified outcome, for reports first verified in the window | — |
| `remediation.time-to-verified-from-report` | hours | window | Report to first verified outcome, for reports first verified in the window | — |
| `remediation.done-unverified` | work-items | current | Work items marked done whose latest report is not verified, by recorded state | `verification_state` / `verification_state` |
| `quality.history-coverage` | findings | current | Findings created before each history source began; the total is those missing any source | — / `source` |
| `quality.verification-run-coverage` | evaluation-runs | window | Evaluation runs in scope by verification outcome: `completed`, `incomplete`, `failed`, `not-recorded`, or `evaluation-failed` when the run failed before verification | — / `verification_status` |
| `quality.evidence-freshness` | findings | current | Open findings by evidence freshness | — / `evidence_freshness` |
| `quality.unmeasurable-outcomes` | remediation-reports | window | Reports made in the window whose recorded outcome is insufficient, stale, conflicting, manual review, or not recorded | — / `verification_state` |

Durations report `value` as the median, with `count`, `p90`, and `max`. The
90th percentile interpolates linearly between the closest ranks.

### Verification boundaries

Only the `verified` state enters verified-remediation metrics. These states
stay separate and are never counted as success: `resolved-by-advisory-change`,
`resolved-before-report`, `awaiting-evidence`, `insufficient-evidence`,
`evidence-stale`, `conflicting-evidence`, `manual-review-required`,
`still-present`, and `report-withdrawn`.

Advisory and applicability changes stay in the verification-rate denominator
as not verified. A verified outcome shows that the evidence agrees with the
report. It does not show that the remediation caused a risk reduction. A
confirmed component removal cannot currently reach `verified` (see
[remediation verification](CTEM_REMEDIATION_VERIFICATION.md)), so removals
are counted under their recorded state.

## API

Both routes are read-only and require the configured administrative token.
They fail closed (`503`) when none is configured, because metrics aggregate
work items.

### `GET /api/v1/metrics/catalog`

This returns `catalog_version`, the metric definitions, the statuses, the
status reasons with explanations, the units, and the limits.

Each definition has these fields:

- `metric_id`, `version`, `display_name`, `description`, `purpose`;
- `unit`, `counting_grain`, `population`, `value_kind`;
- `numerator` and `denominator`, both definitions or null;
- `time_semantics`;
- `source_records`, `required_evidence`, `history_sources`;
- `filters`, `dimensions`;
- `freshness_requirement`, `missing_data_behavior`, `limitations`.

### `GET /api/v1/metrics/{metric_id}`

Query parameters, all optional:

- `site_id`;
- `start` and `end`, as ISO 8601 with a timezone;
- `action_band`, one of `act-now`, `prioritize`, `plan`, `monitor`;
- `verification_state`, a recorded verification state or `not-recorded`.

A filter the metric does not support, an unknown query parameter, an invalid
value, or an invalid window returns `400`. An unknown metric returns `404`. A
database error returns `500` with a generic message.

The response is a strict contract (`MetricResultResponse`):

```json
{
  "catalog_version": "oaw.metrics.catalog.v1",
  "metric_id": "remediation.verification-rate",
  "metric_version": 1,
  "display_name": "Verification rate",
  "unit": "ratio",
  "value_kind": "ratio",
  "counting_grain": "remediation report",
  "population": "Reports made inside the window with a recorded outcome.",
  "numerator_definition": "Reports whose latest recorded outcome at the window end is verified.",
  "denominator_definition": "Reports with a recorded outcome other than report-withdrawn.",
  "time_semantics": "window",
  "time_range": {"start": "2026-10-26T00:00:00Z", "end": "2026-11-25T00:00:00Z"},
  "filters": {"site_id": "site-a", "action_band": null, "verification_state": null},
  "status": "partial",
  "status_reasons": ["OUTCOME_NOT_RECORDED"],
  "total": {"dimensions": {}, "value": 0.3333, "numerator": 1, "denominator": 3,
            "count": null, "median": null, "p90": null, "max": null},
  "breakdown": [],
  "coverage": {"recording_since": {"work-events": "...", "verification-history": "..."},
               "degraded_verification_runs": 0, "not_recorded": 1},
  "source_freshness": [{"source": "finding-evaluation", "latest_record_at": "..."},
                       {"source": "work-events", "latest_record_at": "..."}],
  "limitations": ["..."],
  "computed_at": "2026-11-25T00:00:01Z"
}
```

Frontend components should display `value` together with `unit`, `status`
and `status_reasons`, `time_range`, `source_freshness`, `coverage`, and
`metric_version`. A null `value` must be shown as "not measured" or
"unavailable", never as 0. A saved panel should pin `metric_id` and
`metric_version`.

## Performance

Each request reads one metric's rows, filtered by site in SQL, in one
read-only transaction with a 15-second statement timeout. Rows are ordered,
with no per-finding round trips. Reads stop at 100,000 rows.

Band-episode duration returns only the decision rows where a finding's band
changes: every one in the window, plus the latest one before it when a band
was in effect at the window start, so that an episode's true start is known.

Decision and verification history are reached through their finding indexes.
There is no site-and-time index on history tables; a later migration can add
one if site-scoped windows over large histories become slow.

## Limits

- Deleted findings and their history are not counted.
- Scope is the site. There are no asset-group, owner, or business-service
  dimensions yet (`CTEM-GAP-11`).
- Recording start is per database, not per site.
- Suppressed findings are not open, but time while suppressed stays in the
  band in band-episode duration.
- First episodes of findings created before decision history began are
  excluded from durations and counted as `left_censored_episodes`. These are
  usually the oldest findings, so medians can read low while they remain.
- Recording start is conservative. A finding created before a source began has
  its history reported as incomplete, even where no such events could have
  existed then.
- Run coverage selects runs by start time. A site request includes runs scoped
  to an asset or sensor in that site, as well as unscoped runs.
- Done-but-unverified uses recorded history. The live verification view can
  be newer until the next evaluation run.
- There are no target dates or overdue states (`CTEM-GAP-12`), and no period
  comparison.

## Validation

Run tests in the locked backend image with the repository mounted read-only,
as described in [`docs/LOCAL_DEV_SETUP.md`](../LOCAL_DEV_SETUP.md):

- unit and API tests: the `test_outcome_metrics` and
  `test_outcome_metrics_api` modules;
- gated database tests: `test_outcome_metrics_postgres`, enabled by
  `OPENASSETWATCH_OUTCOME_METRICS_POSTGRES_TEST=1`, which reuses the
  disposable-database harness of the remediation verification tests.
