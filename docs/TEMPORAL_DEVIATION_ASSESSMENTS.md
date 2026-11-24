# Deterministic Temporal Deviation Assessments

## Status and authority

Temporal Intelligence Phase 3 is implemented as a deterministic, local,
read-only analytical layer over the Phase 1 signal projection and Phase 2
expected-range engine. It returns the strict
`oaw.temporal-deviation-assessment.v1` artifact for one closed daily UTC target.

Every artifact has the literal authority
`analytical-investigation-context-only`. A candidate means only that a
trustworthy target is outside its expected range in a registry-admitted
direction for the required consecutive buckets. It is not an alert, finding,
severity, risk or Operational Attention Score change, proof of compromise,
incident, investigation, remediation request, autonomous action, or AI
conclusion. Phase 3 writes none of those records.

## Assessment states and direction

The engine returns one of five states:

| State | Meaning |
| --- | --- |
| `blocked` | The observation or expectation does not pass the trust gates. Direction is `unknown`, distance and relative change are null, and persistence is zero. |
| `within-range` | The observation is inside the inclusive lower and upper bounds. |
| `outside-policy-direction` | The observation is outside the range, but the product policy does not admit that direction. |
| `pending-persistence` | The direction is admitted, but the required consecutive support is not complete. |
| `candidate` | The admitted direction and every trust and persistence gate pass. This is the only state in which `candidate` is true. |

Direction is exact: below the lower bound is `below`, above the upper bound is
`above`, and either bound itself is `inside`. There is no hidden epsilon.
Distance is `lower - observed` below the range, `observed - upper` above it,
zero inside it, and null when blocked. Relative change is
`abs(observed - expected) / expected` only when the expected center is positive;
it is null when the center is zero. Non-finite values are rejected.

## Governed policy registry

Callers cannot choose direction, persistence, confidence, quality, method,
history length, formula, SQL, or thresholds. Policy version `1` contains
exactly these reviewed site/daily policies:

| Metric | Policy ID | Admitted direction | Consecutive buckets |
| --- | --- | --- | --- |
| `site.assets.new.count` | `tdp_site_assets_new` | above | 1 |
| `site.collectors.active.count` | `tdp_site_collectors_active` | below | 1 |
| `site.findings.new.count` | `tdp_site_findings_new` | above | 1 |
| `site.vulnerabilities.new.count` | `tdp_site_vulnerabilities_new` | above | 1 |
| `site.inventory.collections.count` | `tdp_site_inventory_collections` | above or below | 2 |
| `site.inventory.asset_observations.count` | `tdp_site_inventory_asset_observations` | above or below | 2 |

Every policy requires `sufficient` expectation data quality and at least
`medium` confidence. Lookback is explicitly bounded and may never exceed three
target assessments. Changing a policy value requires a new policy version,
reviewed deterministic fixtures, cutoff and persistence tests, and updated
documentation.

## Cutoff-safe inputs and trust gates

For target bucket `T`, the service composes the existing projection and
expectation services:

- the target observation is reconstructed over `[T, T + 1 day)` with an
  exclusive knowledge cutoff of `T + 1 day`;
- evidence received exactly at or after the target close is excluded;
- the expectation targets `T` and reconstructs its 56-bucket history using the
  exclusive knowledge cutoff `T`; and
- the current open UTC bucket and future buckets are rejected.

An observation is eligible only when its value is present, it is complete and
current, its quality is `observed`, and its metric, site, asset scope, target,
unit, projection version, signal identity, and close cutoff all align. Missing,
incomplete, and stale activity is never converted to zero.

An expectation is eligible only when its center and bounds are populated, its
quality is `sufficient`, its confidence is medium or high, its authority is
`analytical-context-only`, and its scope, target, unit, projection version,
history digest, and deterministic expectation identity align. Provenance or
identity mismatches fail closed rather than becoming candidates.

## Consecutive persistence

A one-bucket policy can produce a candidate immediately. A two-bucket policy
reconstructs only the immediately preceding closed target when the current
target is otherwise eligible and outside in an admitted direction. Each bucket
uses its own close-cutoff observation and start-cutoff expectation. The support
must be consecutive and outside in the same admitted direction. An inside,
blocked, disallowed, or opposite-direction bucket resets the sequence. No open,
future, or caller-supplied support is used.

`supporting_assessment_ids` is chronological and contains only preceding
assessments. Persistence describes consecutive temporal behavior; Phase 3 does
not materialize or persist assessment objects.

## Digests and identity

`observation_digest` is lowercase SHA-256 over compact, sorted-key UTF-8 JSON.
It binds the signal schema and identity, metric and authority scope, exact
bucket, value and unit, evidence count and source, observed and received
watermarks, freshness, completeness, data quality, backfill state, and
projection version. Transient generation time is excluded.

`input_digest` binds that observation digest to the expectation identity,
history digest, range, method/version, confidence and quality; the complete
policy identity and gates; and chronological supporting assessment IDs.

`assessment_id` binds the assessment schema, input digest, metric, site, exact
target bucket, and policy version. Recalculating identical inputs at a different
generation time preserves identity. Any covered observation, expectation,
history, policy, or persistence-support change produces a different identity.
These digests are deterministic provenance identities, not signatures.

## Read-only API

The configured admin token protects:

```text
GET /api/v1/temporal/deviation-assessments
```

The route accepts only governed `metric_key`, required `site_id`, UTC-midnight
`target_start`, `granularity=daily`, and optional `asset_id` (rejected for the
current site-only metrics). Unknown metrics/sites, unsupported scope or
granularity, unaligned targets, and open/future targets fail closed. There is no
global route or caller-selected policy, method, threshold, formula, severity,
risk, query, or aggregation. Database failures return a bounded error without
driver details.

## Environment Trends UI

Environment Trends continues to load the Phase 1 series and Phase 2
current-bucket expected range. Its separate **Deviation Assessment** area asks
for the latest closed UTC bucket and shows observed and expected values,
direction, distance, optional relative change, expectation support,
persistence, state, bounded reason text, policy/version, and observation and
expectation provenance IDs.

The UI uses neutral labels such as **Within expected historical range**,
**Persistence requirement not yet met**, **Review candidate**, and
**Assessment unavailable**. A Phase 3 request failure does not hide Phase 1 or
Phase 2 output. Untrusted values are inserted with `textContent`; nothing is
saved, polled automatically, or used to open an investigation.

## Performance bounds

One target assessment performs one bounded target projection and one bounded
56-bucket expectation projection. Persistence performs the same independent
pair for each required preceding bucket. Each projection store load issues one
site-existence statement and one fixed aggregate statement. The contract
permits at most three target assessments per request; the initial policies
require at most two. The current Phase 3 endpoint therefore performs at most
four store loads (eight parameterized SQL statements). The full Environment
Trends load performs at most six store loads (12 statements): one Phase 1
series, one current Phase 2 expectation, and four Phase 3 inputs. There is no
unbounded backtest, recursion, automatic polling, scheduler, or materialization.

Local measurements are synthetic implementation validation, not production
performance claims. Operational qualification should continue to observe
median and p95 latency, bounded concurrency, pool/session cleanup, and process
memory with representative PostgreSQL data.

## Non-SIEM and model boundary

Deviation assessments consume only governed OpenAssetWatch temporal artifacts.
Phase 3 adds no generic or raw log ingestion, event stream, packet retention,
event search, log lake, external telemetry upload, or SIEM infrastructure. It
does not call the AI Advisor, a local or hosted model, ROCmFPX, embeddings, or a
forecasting provider, and it does not alter model provenance or runtime trust.

## Known limitations

- Assessments are on-demand, daily, one-target, and site-scoped only.
- Only the six governed Phase 1 metrics are admitted.
- Current policies require one or two consecutive buckets and have no
  caller-defined magnitude threshold.
- There is no persistent candidate review lifecycle, scheduler, automatic
  investigation, finding/alert/risk integration, or causal explanation.
- There is no advanced ML, User Behavior analytics, Adaptive Workspace, AI
  dashboard planner, or scheduled reporting.
- Historical reconstruction depends on authoritative source receipt timestamps;
  assessments are not immutable materialized report snapshots.

## Safe extension rule

A new metric or policy version requires reviewed source authority, exact
missing/zero semantics, fixed cutoff-safe queries, versioned policy fixtures,
contract and identity tests, trust and persistence reset cases, tenant/site
isolation, API bounds, neutral UI coverage, live PostgreSQL qualification,
bounded performance evidence, and documentation. Any future materialization,
review workflow, investigation trigger, finding/risk mapping, model, or broader
event source requires a separate design and authority review.
