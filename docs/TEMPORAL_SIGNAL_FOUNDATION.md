# Temporal Signal Foundation

## Status and scope

Temporal Intelligence Phase 1 is implemented as a deterministic, offline,
read-only projection over OpenAssetWatch-owned historical records. It provides:

- a versioned signal contract;
- a governed six-metric registry;
- reproducible daily UTC buckets;
- bounded, site-scoped projection queries;
- explicit missing, incomplete, stale, and late-arriving states; and
- the read-only **Environment Trends** dashboard view.

Phase 2 deterministic expected ranges and Phase 3 deterministic deviation
assessments are implemented over this foundation; see
`docs/TEMPORAL_EXPECTED_RANGES.md` and
`docs/TEMPORAL_DEVIATION_ASSESSMENTS.md`. Advanced machine learning, User
Behavior analytics, Adaptive Workspaces, AI dashboard planning, advanced
forecasting, persistent candidate review, automatic investigation, and
automated remediation are **not implemented**.

Temporal signals are derived analytical evidence. They do not change or replace
asset identity, classification, vulnerability truth, finding lifecycle,
severity, Operational Attention Score, compromise status, or remediation
authority.

## Signal contract

`backend/app/temporal_contracts.py` owns
`oaw.temporal-signal.v1`. Every signal contains:

- `schema_version` and a deterministic `signal_id`;
- governed `metric_key`;
- `tenant_id` (currently `null`), required `site_id`, and optional `asset_id`
  (not supported by the Phase 1 metrics);
- `bucket_start`, exclusive `bucket_end`, and `bucket_granularity`;
- nullable `value` and registry-owned `unit`;
- `evidence_count` and fixed `source` authority;
- original `source_observed_at` and `source_received_at` watermarks;
- `freshness`, `complete`, and `data_quality`;
- `backfill_state`, `projection_version`, and `generated_at`.

`signal_id` is the stable SHA-256-derived identity of schema, metric, site,
asset scope, bucket boundaries, and projection version. It does not depend on
query time. Repeating the same projection therefore returns the same signal
identity and value for the same authoritative source snapshot.

`generated_at` records projection time. It does not replace the source
watermarks or make stale evidence current.

## Governed metric registry

`GET /api/v1/temporal/metrics` returns
`oaw.temporal-metric-registry.v1`. API callers cannot add metric names, choose
source tables, supply SQL, or select arbitrary aggregations.

Each definition records its entity scope, unit, source authority, supported
granularity, projection version, freshness expectation, zero semantics, and
whether a missing bucket differs from zero.

| Metric | Meaning | Authoritative source |
| --- | --- | --- |
| `site.assets.new.count` | Distinct canonical site asset identities first observed in the bucket | `control_tower_assets.first_seen_at`, with canonical collection activity used only to identify incomplete coverage |
| `site.collectors.active.count` | Distinct enrolled agents or passive sensors with an accepted check-in | `agent_checkins`, joined to `agent_enrollments` |
| `site.findings.new.count` | Distinct deterministic findings first opened | `findings.first_seen_at`, with finding-evaluation coverage |
| `site.vulnerabilities.new.count` | Distinct deterministic matches first entering affected state | `vulnerability_matches.first_matched_at`, with vulnerability-evaluation coverage |
| `site.inventory.collections.count` | Accepted replay-safe canonical inventory collections | `canonical_inventory_collections` |
| `site.inventory.asset_observations.count` | Sum of canonical asset observations across accepted collections; not distinct population | `canonical_inventory_collections.canonical_asset_count` |

Canonical inventory retries update an existing unique collection and do not add
another collection row. Collector activity counts distinct enrolled identities,
so repeated check-ins from one identity do not inflate the bucket.

## Deliberately deferred metrics

Phase 1 does not synthesize totals whose historical truth cannot be reconstructed
from current records:

| Candidate | Reason deferred |
| --- | --- |
| `site.assets.active.count` | Current first/last-seen spans do not prove continuous per-bucket presence; treating the span as history could turn a collection outage into apparent population change. |
| `site.assets.unknown.count` | Classification history records material classified-state transitions, but historical site-wide classification coverage before those transitions is not complete. |
| `site.assets.unmanaged.count` | Current classification stores capability expectations, not an authoritative historical managed/unmanaged lifecycle. The dashboard heuristic is not temporal evidence. |
| `site.collectors.stale.count` | Historical policy-threshold versions and complete enrollment lifecycle intervals are not yet persisted together. |
| `site.findings.active.count` and `site.findings.resolved.count` | Reopening a finding clears its current `resolved_at`; there is no append-only finding lifecycle event table from which every prior backlog/resolution state can be reconstructed. |
| `site.vulnerabilities.active.count` and `site.vulnerabilities.known_exploited.count` | Current match and KEV histories do not yet expose one reviewed, complete as-of-site projection across catalog and evaluation changes. |
| `site.security_coverage.endpoint.percentage` | Historical denominator completeness and security-tool coverage intervals are not yet authoritative at site scope. |

Adding one of these metrics requires the missing historical evidence or lifecycle
contract first. It must not be approximated from display labels or current rows.

## UTC bucketing and bounds

Phase 1 supports `daily` only. A valid query window:

- supplies timezone-aware `start` and `end`;
- normalizes them to UTC;
- aligns both values to UTC midnight;
- treats `start` as inclusive and `end` as exclusive;
- has `end > start`;
- does not extend past the end of the current UTC bucket; and
- contains at most 366 daily buckets.

Offset timestamps are accepted only when they normalize to exact UTC bucket
boundaries. No deployment timezone, browser timezone, interpolation, or
caller-selected bucketing is used.

## Projection and storage design

`backend/app/temporal_projection.py` performs pure, deterministic bucket
projection. `backend/app/temporal_store.py` selects one fixed, parameterized,
indexed source query for each registry metric. Every query requires `site_id`
and applies that predicate before aggregation.

Phase 1 calculates signals on demand and does not add a materialized signal
table. This matches the current monolithic service architecture and avoids
introducing scheduler, rebuild, retention, and derived-state migration behavior
before those contracts exist. It is:

- idempotent and safe to rerun;
- bounded to 366 source buckets;
- safe across application restart because authoritative source histories remain
  the system of record;
- read-only with respect to source and derived records; and
- independent of an external time-series database.

The tradeoff is repeated bounded aggregation for repeated reads and no frozen
report snapshot. If measured load later justifies materialization, use the
existing migration framework and the current deterministic `signal_id` (or an
equivalent unique key over metric, scope, bucket, granularity, and projection
version). A future materializer must be incremental, retention-aware,
site/tenant-scoped, and rebuildable from source evidence.

No performance claim is made for Phase 1 because no production-sized benchmark
has been measured.

## Known limitations

- Phase 1 is daily and site-scoped only; it has no hourly, asset-scoped, global,
  or tenant-scoped series.
- On-demand reads reflect the current authoritative source snapshot. Late source
  evidence can therefore revise a historical value; Phase 1 does not provide a
  frozen report snapshot or materialized retention policy.
- OpenAssetWatch does not yet expose an implemented, product-wide sensitivity
  taxonomy for metric metadata. Phase 1 does not invent one from AI design
  documents; all routes retain the existing authenticated-admin boundary.
- Production-sized query latency has not been benchmarked. The enforced limit
  is 366 daily buckets, and all source queries bind a required `site_id` and
  bounded time window over indexed/filterable fields.

## Missingness, completeness, freshness, and backfill

The projector emits every requested bucket, including gaps:

| State | Contract behavior |
| --- | --- |
| Observed zero | `value: 0`; returned only when an authoritative coverage record makes zero meaningful. |
| Missing | `value: null`, `complete: false`, `data_quality: missing`, and `evidence_count: 0`. |
| Incomplete | A positive observed value may be retained with `complete: false`; an uncovered zero becomes `null`, never a synthetic zero. |
| Stale | The original source watermark remains present, `freshness: stale`, and complete values use `data_quality: stale`. |
| Backfilled | A closed historical bucket projected later uses `backfill_state: backfilled`. |
| Late-arriving | Evidence received after its bucket closed uses `backfill_state: late-arriving`; its observed timestamp is unchanged. |

Canonical coverage is deliberately conservative: one source's complete
inventory is not treated as proof that an entire multi-source site had zero new
assets. A positive new-asset event is observed; collection activity without a
new-asset event is incomplete rather than zero. Completed whole-site finding or
vulnerability evaluations can establish an observed zero, while targeted runs
cannot. A collector outage therefore produces missing collector/collection
history rather than implying assets disappeared.

## Read-only API

Both routes require the explicitly configured
`OPENASSETWATCH_ADMIN_TOKEN`, supplied in
`X-OpenAssetWatch-Admin-Token`. If the secret is not configured, the capability
fails closed with `503`.

```text
GET /api/v1/temporal/metrics
GET /api/v1/temporal/signals
```

The series route accepts only:

- governed `metric_key`;
- required `site_id`;
- timezone-aware, UTC-boundary `start` and `end`;
- `granularity=daily`; and
- optional `asset_id`, which Phase 1 rejects because all current metrics are
  site-scoped.

Unknown metrics, unsupported scope or granularity, missing sites, future or
unaligned windows, reversed windows, and windows over 366 buckets are rejected.
There is no raw SQL, caller-selected grouping, unbounded pagination, or global
cross-site aggregation.

Phase 2 adds `GET /api/v1/temporal/expectations` behind the same configured
admin-token boundary. Its internal as-of projection uses only source evidence
received before the target cutoff and only closed UTC baseline buckets. The
normal Phase 1 signal route remains a current authoritative snapshot.

OpenAssetWatch currently persists no tenant identity in this self-hosted schema,
so Phase 1 returns `tenant_id: null`. The site boundary is mandatory. A future
hosted/multi-tenant schema must add tenant authority to source records and every
projection predicate before tenant-scoped temporal access is enabled.

## Environment Trends UI

The static Control Tower dashboard includes a read-only **Environment Trends**
view. Its metric selector is populated from the server registry. It requests one
site and either 30 or 90 daily buckets, draws only non-null observed values,
breaks chart lines across missing buckets, and overlays the Phase 2 expected
band for the current UTC target when sufficient closed history exists.

The bucket table labels `Observed`, `Missing`, `Incomplete`, and `Stale`
separately. Untrusted metric descriptions and values are assigned through DOM
`textContent`; they are not treated as markup or query fragments. The existing
page-only admin token field is reused and remains unstored.
Expected range, method/version, confidence, and range data quality remain
separate from the observed bucket-quality labels.

## Security and privacy boundaries

- All temporal data reads require configured admin authentication.
- Every source query is parameterized and site-scoped.
- Metric-to-query selection is fixed in product code.
- Query windows and returned buckets are bounded.
- No raw packets, credentials, user content, or new customer payloads are
  collected or retained.
- No external telemetry, callbacks, AI providers, models, or hosted services are
  used.
- Display strings never become SQL or executable parameters.
- Source evidence, findings, vulnerability state, classifications, and risk
  scores are not modified.

## Safe extension rule

A new metric requires reviewed registry metadata, a fixed source query,
authoritative historical evidence, explicit zero/missing semantics, freshness
and completeness behavior, site/tenant isolation tests, bounds tests, duplicate
and backfill tests, UI state coverage where displayed, and updated deferral or
operator documentation. A metric name supplied by an API caller is never enough
to authorize a new projection.
