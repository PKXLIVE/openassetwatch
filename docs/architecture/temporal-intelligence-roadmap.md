# Temporal Intelligence Roadmap

- **Status:** Accepted design; Phases 1-3 deterministic foundation implemented
- **Decision:** `docs/architecture/decisions/0003-native-agent-investigation-and-temporal-intelligence.md`

## Purpose

OpenAssetWatch already records time-bearing evidence: first/last seen values,
collector and sensor check-ins, asset changes, finding lifecycle events,
software and firmware observations, vulnerability matches, and security-tool
coverage.

Temporal Intelligence adds a bounded analytical layer that answers questions
such as:

- Is this change unusual for this site or asset?
- Is asset population increasing faster than expected?
- Are sensors becoming stale earlier or more often than normal?
- Is vulnerability backlog growing instead of shrinking?
- Is a software-version migration progressing or stalling?
- Did security-tool coverage drift after a deployment or environment change?
- Is today's behavior outside the expected historical range?

The purpose is to add context and earlier visibility. Temporal output does not
become authoritative identity, vulnerability, finding, or risk by itself.

## Core rule

```text
observed historical evidence
  -> normalized temporal signal
  -> transparent expected range / forecast
  -> deterministic deviation assessment
  -> optional investigation context
```

The forecast component never owns the final finding lifecycle.

## Initial design principles

1. Start with OpenAssetWatch-owned historical signals.
2. Use deterministic, explainable baselines first.
3. Preserve missingness and irregular collection rather than imputing silently.
4. Keep prediction intervals/expected ranges visible.
5. Compare any advanced model against the deterministic baseline.
6. Keep temporal confidence separate from severity and Operational Attention
   Score.
7. Do not claim causal explanation from correlation or timing alone.
8. Do not predict compromise as fact.
9. Keep local/offline operation available.
10. Make temporal processing optional and bounded by site/tenant policy.

## Signal model

A normalized time-series point should have a stable product contract. Suggested
fields:

```json
{
  "schema_version": "oaw.temporal-signal.v1",
  "signal_id": "sig-...",
  "metric_key": "site.assets.new.count",
  "tenant_id": null,
  "site_id": "site-...",
  "asset_id": null,
  "bucket_start": "2026-08-17T00:00:00Z",
  "bucket_end": "2026-08-18T00:00:00Z",
  "value": 4,
  "unit": "count",
  "evidence_count": 4,
  "source": "openassetwatch",
  "freshness": "current",
  "complete": true
}
```

The signal schema should make missing or incomplete buckets explicit.

## Initial signal families

### Asset population

- total active assets by site;
- newly observed assets per period;
- assets not seen within policy threshold;
- assets returning after a stale period;
- unknown/unmanaged asset counts.

### Collector and sensor health

- check-ins per period;
- stale collector/sensor count;
- check-in interval distribution;
- retry/backlog rate;
- source freshness distribution.

### Finding lifecycle

- new findings;
- reopened findings;
- resolved findings;
- active backlog;
- findings aging into policy bands;
- findings by deterministic rule family.

### Vulnerability intelligence

- matched vulnerabilities by state/severity;
- new matches;
- resolved/superseded matches;
- remediation backlog;
- source-catalog freshness where available.

### Software and firmware transition

- version distribution over time;
- migration progress to an expected version;
- assets remaining on old versions;
- version churn or rollback observations.

### Security-tool coverage

- EDR/MDM/logging/vulnerability-agent coverage percentage;
- newly uncovered assets;
- newly covered assets;
- coverage changes by platform/site;
- stale coverage evidence.

### Bounded network observations

Where current privacy and storage design permit aggregate metrics:

- new service observations;
- service disappearance;
- protocol-observation counts;
- network-neighbor count changes;
- bounded asset-to-site placement changes.

Do not introduce raw packet retention merely to support temporal analytics.

## Deterministic baseline methods

The first implementation should avoid an advanced forecasting model. Transparent
methods are easier to validate and explain.

Candidate methods:

### Rolling robust center and range

Use a rolling median or trimmed mean with a robust spread estimate. Useful for
signals with occasional spikes.

### Exponentially weighted moving average

Useful for gradual changes while weighting recent history more heavily.

### Seasonal comparison

Compare the current bucket with historical buckets from the same day-of-week,
hour-of-day, or other explicitly configured period when enough data exists.

### Bounded trend estimate

Use a simple linear or robust trend over a fixed recent window and expose the
slope plus uncertainty rather than projecting far into the future.

### Rate-of-change rules

For some operational signals, a deterministic percentage/absolute change over a
known window may be more useful than a forecast.

Methods should be selected per signal family. There is no requirement that one
method fit every metric.

## Expected-range contract

A temporal computation should return a typed expected-range artifact rather than
a single unexplained prediction.

Suggested fields:

```json
{
  "schema_version": "oaw.temporal-expectation.v1",
  "expectation_id": "exp-...",
  "metric_key": "site.assets.new.count",
  "site_id": "site-...",
  "generated_at": "2026-08-17T10:00:00Z",
  "history_start": "2026-07-01T00:00:00Z",
  "history_end": "2026-08-16T23:59:59Z",
  "method": "seasonal_robust_baseline",
  "horizon_buckets": 1,
  "expected": 2.0,
  "lower": 0.0,
  "upper": 4.0,
  "confidence": "medium",
  "data_quality": "sufficient",
  "missing_bucket_count": 1,
  "method_version": "1"
}
```

The exact numerical method is implementation-specific, but the product contract
must expose range, history window, method/version, confidence, and data quality.

## Deviation candidate

Observed data can be compared with the expected range in deterministic product
code.

Suggested fields:

- deviation ID;
- signal/expectation IDs;
- observed value;
- lower/upper expected bounds;
- direction (`above`, `below`, `inside`);
- magnitude;
- persistence across buckets;
- data-quality state;
- deterministic rule result;
- evidence IDs/source references; and
- review/investigation status.

A deviation is not automatically a security finding.

## Deterministic finding boundary

If OpenAssetWatch later creates temporal findings, the deterministic rule must
own:

- signal family;
- minimum history length;
- data-completeness requirements;
- expected-range method/version;
- threshold/magnitude;
- persistence duration;
- freshness requirements;
- suppression/reopen lifecycle; and
- severity/action-band mapping.

A forecasting provider cannot choose these values dynamically for production.

## Data-quality rules

Temporal analytics are especially sensitive to missing and irregular data.

Required behavior:

- missing buckets remain missing unless a reviewed method explicitly handles
  them;
- stale source data does not get re-timestamped as current;
- collector outage is distinguishable from asset disappearance;
- a change in collection method/version is recorded;
- sparse history reduces confidence or blocks a forecast;
- large backfills are labeled separately from live observations;
- time-zone/bucketing rules are deterministic; and
- duplicate retries do not inflate counts.

## Causality boundary

Temporal sequencing can identify what changed before or after another event, but
it does not prove cause.

The Advisor and investigators should use language such as:

- "occurred before"
- "correlates with"
- "is consistent with"
- "may explain"
- "requires verification"

They should not state that one change caused another unless direct evidence
supports that conclusion.

## Temporal Intelligence and the AI Advisor

The AI Advisor may explain temporal artifacts using the same evidence-first
boundary as other data.

Example output:

> New-asset observations for this site are above the expected historical range.
> Eleven assets were first observed today versus an expected range of zero to
> three. The increase is observed; the cause is not yet verified.

The Advisor should cite:

- signal ID;
- expectation ID;
- time window;
- observed value;
- expected range;
- data-quality/confidence; and
- related asset/evidence IDs when available.

## Investigation integration

A persistent or material deviation may trigger a bounded
`temporal_deviation_review` investigation.

The investigation should separate:

1. **Observed fact:** the metric is outside the expected range.
2. **Possible explanations:** onboarding, outage, deployment, stale collection,
   inventory churn, or an actual security/environment change.
3. **Evidence needed:** asset history, collector health, finding changes,
   version changes, or site context.
4. **Verification result:** supported, unsupported, or inconclusive.

The temporal engine does not supply the causal hypothesis as truth.

## Target UI

Recommended temporal UI components:

### Environment trends

- active asset count trend;
- newly observed assets;
- unknown/unmanaged trend;
- collector/sensor health trend;
- finding backlog trend.

### Expected range overlays

Show observed values against an expected band. Make the data-quality/confidence
state visible.

### Change cards

For a material deviation, show:

- what changed;
- when;
- expected range;
- magnitude;
- persistence;
- supporting evidence;
- whether an investigation is open; and
- whether the cause is verified.

### Forecast detail

Advanced forecasts, if enabled later, should display method/provider version and
backtest quality. Do not hide model uncertainty behind a single trend line.

## Provider-neutral forecasting contract

Advanced forecasting, if eventually useful, belongs behind the same native
capability/provider boundary used by investigation analytics.

The OpenAssetWatch capability might expose an outcome such as:

```text
temporal.expected_range(signal_history, horizon, policy)
```

The provider may be deterministic local code or a future advanced local/hosted
model. The provider output must normalize into the same
`oaw.temporal-expectation.v1` contract.

Provider choice must not change finding authority or privacy policy.

## Local-first behavior

Temporal Intelligence should work without external services.

The initial deterministic baseline should run locally on the hub. Any future
advanced provider must be optional and explicitly configured.

Historical customer signals should not be uploaded for training or tuning by
default.

## Advanced-model admission gate

Before an advanced forecasting provider may be considered for production:

1. At least one relevant signal family has enough real history for backtesting.
2. A deterministic baseline is implemented and frozen for comparison.
3. Time-split evaluation prevents future leakage.
4. Missingness/outage scenarios are included.
5. Prediction intervals or equivalent uncertainty are available.
6. Resource requirements fit supported deployment profiles.
7. Privacy/data-sharing policy is explicit.
8. Failure, timeout, and cancellation behavior are tested.
9. The advanced provider demonstrates useful improvement on a defined metric.
10. Improvement does not weaken explainability or product reliability.

If these gates are not met, the deterministic baseline remains the production
method.

## Evaluation metrics

Different signal families may need different metrics. Potential measures:

- absolute/percentage error;
- interval coverage;
- interval width;
- false deviation rate;
- missed deviation rate;
- detection lead time;
- performance by history length;
- performance under missing data;
- calibration by expected-range confidence; and
- compute latency/resource use.

Do not optimize solely for point-prediction error when the product decision
uses expected ranges and deviation detection.

## Historical backtesting

Backtesting should simulate what OpenAssetWatch would have known at each point
in time.

For each evaluation cutoff:

1. build the signal using evidence available before the cutoff;
2. generate the expectation;
3. compare against future observed buckets;
4. run deterministic deviation rules;
5. record misses/false positives; and
6. repeat across multiple time windows/sites.

Do not calculate features using future evidence and then claim prospective
performance.

## Privacy and retention

Temporal series can reveal operational schedules and environment behavior even
when they contain no raw payloads.

Controls should include:

- tenant/site scoping;
- minimum necessary resolution;
- bounded retention by signal family;
- aggregated metrics where raw detail is unnecessary;
- provider-facing projection limits;
- explicit external-processing policy; and
- deletion/rebuild behavior when source evidence is removed under policy.

## Initial implementation phases

### Phase 1 — Signal projection

**Implemented and operationally qualified.** See
`docs/TEMPORAL_SIGNAL_FOUNDATION.md` for the governed registry, UTC bucketing,
bounded read-only projection/API, missingness and backfill behavior,
conservative metric deferrals, and Environment Trends UI.

- define temporal signal registry;
- create deterministic bucket rules;
- project selected existing histories into signals;
- expose read-only API/UI trend data;
- validate duplicate/backfill/missingness behavior.

### Phase 2 — Deterministic expected ranges

**Implemented and operationally qualified.** See
`docs/TEMPORAL_EXPECTED_RANGES.md` for the typed expectation contract, governed
rolling/seasonal policies, closed-bucket and exclusive knowledge-cutoff rules,
confidence/data-quality gates, read-only API, and Environment Trends
expected-band overlay.

- implement robust rolling/seasonal methods;
- produce typed expectation artifacts;
- display expected bands;
- add data-quality/confidence state.

### Phase 3 — Deviation candidates

**Implemented.** See `docs/TEMPORAL_DEVIATION_ASSESSMENTS.md` for the strict
assessment contract, cutoff-safe observation and expectation composition,
versioned direction/persistence policies, authenticated read-only API, neutral
Environment Trends context, and non-authoritative boundary. Persistent review
and automatic investigation remain deferred.

- deterministic deviation rules;
- persistence and freshness handling;
- neutral candidate context UI;
- optional investigation trigger (deferred).

### Phase 4 — Advanced forecasting research

- provider-neutral adapter;
- time-split benchmark;
- comparison to deterministic baseline;
- resource/privacy evaluation;
- no default enablement until release gates pass.

## Explicit non-goals

Temporal Intelligence does not approve:

- predicting that an organization will be breached;
- treating an anomaly as compromise;
- changing the Operational Attention Score directly from model output;
- automatic remediation based on forecasts;
- uploading customer histories for external training by default;
- new raw packet retention;
- replacing current finding rules with anomaly scores; or
- making an advanced forecasting model a required OpenAssetWatch dependency.

## Implementation status

Phase 1 signal projection, Phase 2 deterministic expected ranges, and Phase 3
deterministic deviation assessments are implemented and remain read-only.
Phase 4 advanced forecasting research, persistent candidate review, automatic
investigation, finding/alert/risk integration, and related AI Advisor temporal
explanations remain unimplemented. Environment Trends displays observed
signals, source data-quality states, the current target's deterministic expected
band, and neutral assessment context for the latest closed UTC bucket.
