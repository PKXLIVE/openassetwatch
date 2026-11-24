# Deterministic Temporal Expected Ranges

## Status and authority

Temporal Intelligence Phase 2 is implemented as a deterministic, local,
read-only analytical layer over the Phase 1 temporal signal registry. It adds:

- the strict `oaw.temporal-expectation.v1` artifact;
- registry-owned rolling and day-of-week seasonal policies;
- cutoff-safe reconstruction of historical signal knowledge;
- explicit range confidence and data-quality state;
- an authenticated read-only expectation API; and
- an expected-band overlay in **Environment Trends**.

An expected range is `analytical-context-only`. It does not create or change an
asset, classification, vulnerability match, finding, alert, severity, risk or
Operational Attention score, compromise status, investigation, or remediation
action. Phase 3 consumes only sufficiently supported, provenance-aligned
expectations through the separate deterministic assessment boundary documented
in `docs/TEMPORAL_DEVIATION_ASSESSMENTS.md`.

## Closed-history and knowledge-cutoff rule

Every expectation targets exactly one daily UTC bucket. `target_start` may be a
historical bucket boundary or the start of the current open UTC bucket. It may
not be later than the current open bucket.

The baseline window is the fixed half-open interval:

```text
[target_start - 56 days, target_start)
```

All 56 baseline buckets are therefore closed before the target begins. The
current open UTC bucket can be a target, but it can never be a baseline input.

The projection also applies an exclusive source-evidence cutoff. Source rows
are eligible only when the server-side receipt or persistence timestamp is
strictly earlier than `target_start`. Evidence received at or after that cutoff
is excluded before aggregation. This allows a historical expectation to be
reconstructed from information OpenAssetWatch could have known at that point,
rather than leaking a later backfill into the baseline.

The normal Phase 1 signal route remains a current-snapshot projection. The
cutoff query variants are used only when a consumer explicitly requests the
internal as-of projection used by Phase 2.

## Governed method policy

API callers cannot choose an algorithm, SQL query, history length, seasonal
period, threshold, or fallback. Product code owns one policy for every admitted
metric:

| Metric | Primary expected-range policy |
| --- | --- |
| `site.assets.new.count` | rolling robust |
| `site.collectors.active.count` | day-of-week seasonal robust |
| `site.findings.new.count` | rolling robust |
| `site.vulnerabilities.new.count` | rolling robust |
| `site.inventory.collections.count` | day-of-week seasonal robust |
| `site.inventory.asset_observations.count` | day-of-week seasonal robust |

The seasonal policy selects usable buckets with the same UTC weekday as the
target. Four observations are required. If fewer than four are available, the
policy falls back to the rolling method.

The rolling method selects usable observations from the final 28 baseline
buckets. Seven observations are required. If the selected method has too few
observations, the service returns a typed blocked artifact with no point or
bounds; it never invents a range.

## Robust range calculation

For the selected observations, method version `1` calculates:

```text
expected = median(values)
MAD      = median(abs(value - expected))
width    = 3 * 1.4826 * MAD
lower    = max(0, expected - width)
upper    = expected + width
```

Outputs are rounded deterministically to six decimal places. A zero-width band
is valid when the robust spread is zero. No minimum noise, random seed, model,
interpolation, forward fill, or zero fill is introduced. Numeric inputs and
outputs must be finite; positive infinity, negative infinity, and NaN are
rejected rather than clamped or replaced.

## Missingness and data quality

Only signals with all of the following are usable method inputs:

- `data_quality: observed`;
- a non-null value;
- complete source coverage; and
- current freshness for the source bucket.

`missing`, `incomplete`, and `stale` buckets remain distinct counts in the
expectation artifact and are excluded from the numeric sample. They are not
converted to normal values or zero. An authoritative observed zero remains a
real usable value. Late-arriving evidence that was available before the target
cutoff may be used, but its count remains visible; late evidence that missed the
cutoff is excluded by the source query.

The artifact reports `insufficient`, `limited`, or `sufficient` data quality and
separate `none`, `low`, `medium`, or `high` confidence:

- insufficient sample: no range, `insufficient`, and `none`;
- populated range below the medium gates: `limited` and `low`;
- at least 50% usable history plus 10 rolling or 6 seasonal samples:
  `sufficient` and `medium`; and
- at least 80% usable history plus 14 rolling or 8 seasonal samples:
  `sufficient` and `high`.

Confidence describes baseline support only. It is not severity, risk,
likelihood of compromise, or a finding confidence score.

## Expectation contract

`backend/app/temporal_contracts.py` owns the strict
`oaw.temporal-expectation.v1` schema. The artifact includes:

- deterministic `expectation_id`;
- canonical `history_digest` provenance identity;
- governed metric, site, unit, and projection version;
- target bucket and one-bucket horizon;
- exclusive knowledge cutoff;
- fixed history boundaries and all bucket-quality counts;
- selected method, method version, and numeric sample count;
- nullable expected/lower/upper values;
- data quality, confidence, and an explicit blocked reason; and
- the literal `authority: analytical-context-only` boundary.

`history_digest` is the lowercase SHA-256 of canonical compact UTF-8 JSON for
the complete ordered 56-bucket as-of signal history. It covers every projected
bucket, including signals later excluded from the rolling or seasonal numeric
sample. Signals are ordered by bucket start, bucket end, and signal ID; object
keys are recursively sorted; timestamps are normalized to UTC; and non-finite
numbers are forbidden. The digest includes signal identity and schema, metric
and authority scope, bucket boundaries, value and unit, evidence count, source,
observed and received watermarks, freshness, completeness, data quality,
backfill state, and projection version. The transient signal `generated_at`
value is deliberately excluded.

Changing a historical value, missingness or quality state, source watermark,
late-arrival state, evidence count, source authority, or projection version
therefore changes the history digest. The digest is provenance identity, not a
digital signature and not proof that the underlying evidence is trustworthy.

The expectation identifier binds schema, metric, site, target, history window,
selected method/version, projection version, and `history_digest`.
Expectation-level `generated_at` is deliberately excluded, so a repeated
calculation over the identical as-of source history has stable identity while
two different histories cannot share the same expectation identity.

Contract validation rejects partial ranges, inconsistent counts, non-UTC or
non-daily boundaries, history that does not end at the target, method samples
larger than usable history, malformed history digests, non-finite numeric
values, populated insufficient ranges, and any other authority value.

## Read-only API

The existing configured admin-token boundary protects:

```text
GET /api/v1/temporal/expectations
```

The route accepts only:

- governed `metric_key`;
- required `site_id`;
- timezone-aware, UTC-midnight `target_start`;
- `granularity=daily`; and
- optional `asset_id`, rejected for the current site-only metrics.

There is no global aggregation, caller-selected method, arbitrary history
window, tenant override, write path, or raw query interface. Unknown sites fail
closed. Database errors return a bounded message without driver details.

## Environment Trends

The dashboard loads the observed signal series and the current-bucket expected
artifact together. When a range is available, the target bucket displays a
shaded expected band and center marker. The numeric range, method/version,
confidence, and data-quality state remain visible in separate summary cards.

If usable history is insufficient, the UI says the range is unavailable and
still displays the observed/missing/incomplete/stale signal states. The
separate Phase 3 assessment area remains blocked unless the expectation has a
populated range, `sufficient` quality, and at least `medium` confidence. Neither
area implies that a value inside or outside the range is good, bad, safe,
compromised, or actionable.

## Storage, performance, and privacy

Phase 2 remains on-demand and read-only. It adds no materialized expectation
table, scheduler, retention policy, external provider, model dependency,
customer-data upload, telemetry callback, credential collection, or raw packet
retention.

Each calculation performs one fixed, site-scoped, parameterized source query
over 56 daily buckets. The as-of variants add the product-owned receipt cutoff
to the same bounded source predicates. No unbounded history scan or N-per-bucket
backtest query occurs in the normal endpoint.

## Known limitations

- Expectations are daily, one-bucket-horizon, and site-scoped only.
- Each request returns one target artifact, not a multi-target backtest series.
- The six Phase 1 metrics are the only admitted inputs.
- The methods do not impute missing values or adjust for holidays, deployments,
  policy changes, or causal explanations.
- Expected ranges alone are not deviation candidates and do not create
  findings. Phase 3 applies a separate product-owned direction and persistence
  policy without changing expectation authority.
- Phase 2 has passed synthetic local PostgreSQL operational qualification;
  those measurements are not production performance claims.
- Historical reconstruction relies on the authoritative receipt/persistence
  timestamps available for each current source table; it is not a materialized
  immutable report snapshot.

## Safe extension rule

Changing a method or threshold requires a new method version, deterministic
fixtures, time-split cutoff tests, missing/stale/incomplete cases, site-isolation
tests, bounds tests, UI confidence/data-quality coverage, and documentation.
Adding a metric still requires the Phase 1 historical-evidence admission rules
before it can receive an expected-range policy.
