# Canonical ingestion and compatibility consolidation

OpenAssetWatch accepts four inventory submission contracts through one
server-owned canonical ingestion service. Existing routes and response fields
remain available, but legacy tables are compatibility projections and
historical records rather than competing business-state authorities.

This milestone is additive. It does not delete historical rows, rename routes,
backfill ambiguous assets, add a broker, or change collector capabilities.

## Routes and persisted trust

The hub derives every trust field. Payload values cannot select an adapter,
authentication class, source authority, trust rank, credential, bound identity,
or authoritative status.

| Existing route | Canonical adapter | Server-derived authority | Rank | Status |
| --- | --- | --- | ---: | --- |
| `POST /api/v1/agents/inventory` | `endpoint-agent` | `authenticated-endpoint` | 90 | canonical |
| `POST /api/v1/observations/batches`, bound sensor credential | `passive-sensor` | `authenticated-passive-sensor` | 75 | canonical |
| `POST /api/v1/collectors/inventory` | `python-collector` | `legacy-collector` | 25 | compatibility |
| `POST /api/v1/collections/local-inventory` | `transitional-local` | `untrusted-transitional` | 10 | deprecated |
| `POST /api/v1/observations/batches`, configured development-shared token | `passive-sensor` | `untrusted-transitional` | 10 | deprecated |

The endpoint-agent adapter uses only its bound credential context for site,
agent, deployment, and credential identity. The passive-sensor adapter uses
only the bound sensor credential for authoritative identity. The shared sensor
mode is assigned a separate server-generated transitional identity, even when
its payload claims the name of an enrolled sensor. Python collector input stays
lower trust even when protected by the legacy shared collector token. The
transitional local route remains unauthenticated and untrusted.

## Transaction and authority model

Migration `0003_canonical_ingestion_compatibility.sql` adds:

- `canonical_ingestion_sources`: immutable source/trust domains with first and
  last observation times;
- `canonical_inventory_collections`: the canonical acknowledgement,
  idempotency digest, compatibility mapping, authoritative evaluation asset
  IDs, and evaluation state;
- `canonical_asset_authority`: the current persisted trust decision for each
  site/asset key;
- `legacy_submission_mappings`: non-destructive links from Python collector
  history to canonical collections; and
- `ingestion_compatibility_events`: bounded acceptance, replay, and evaluation
  state audit metadata.

One database transaction performs credential revalidation, source admission,
canonical collection creation, current asset-authority selection, and
compatibility projection. Every newly accepted submission requires a
server-configured site and locks that site row before authority is selected.
The sole exception is the fixed server-derived `legacy-collector-default` site
used when an old Python collector supplies no deployment. Payload-selected
sites are never created during ingestion. This serializes cross-adapter
collisions for a site. Site and asset IDs remain composite-scoped, so the same
asset label at another site is a different canonical asset.

Authenticated endpoint and bound-sensor admission is scoped to its persisted
source identity. Lower-trust adapters use adapter-wide and per-site windows
under fixed server-generated advisory locks, so rotating a payload identity,
site, or shared sensor label cannot bypass bounded admission.

Trust rank wins before observation time. A newer lower-trust report is retained
in its canonical collection but cannot update the current asset's identity,
hostname, addressing, freshness, evidence count, source, or authority. Equal
trust uses the newer observed time. Historical collections and compatibility
mappings are retained; there is no destructive rewrite or asset deletion.

The existing `control_tower_assets` table remains the current normalized asset
projection. `canonical_asset_authority` records which canonical collection and
source currently control that projection. Component, vulnerability-match,
finding, and risk stores remain their existing deterministic authorities.

## Idempotency and replay

The server derives a source ID from the site, adapter, authentication class,
and server-owned source identity. It derives the canonical collection ID from
that source, adapter, and route idempotency identifier. The validated bounded
body is hashed separately.

An identical replay returns the original canonical, compatibility, legacy, and
endpoint-batch identifiers. It does not rewrite assets or components and does
not enqueue evaluation. Reusing an idempotency identifier with different
content fails closed with the existing route's conflict response. Replay audit
rows are capped per collection so repeated delivery cannot create unbounded
event growth; a counter and replay event history both saturate at 16.

## Downstream deterministic evaluation

Acceptance commits first. Only assets that win the persisted authority decision
are recorded as evaluation work. Classification evidence and component
projections for those assets then persist through the existing bounded stores.
A lower-trust collision therefore remains in canonical history without
projecting components, vulnerability matches, findings, or risk over a current
authenticated asset. A projection failure records `retryable-failure` and does
not falsely report downstream completion. Only a new collection in `queued`
state is coalesced for background evaluation.

Evaluation is limited to the accepted collection's site and up to 1,000
deduplicated affected asset IDs. The existing deterministic classification,
component, vulnerability, finding, and risk authorities are invoked in order.
State progresses through `queued`, `running`, and `completed`, or to a bounded
`retryable-failure` code. Identical replay, rejection, conflicting replay, and
failed canonical writes never enqueue this work. The current coalescer is
process-local. An administrator can atomically move a failed persisted item
back to `queued`; the worker reconstructs site, assets, source authority, and
payload only from the stored collection rather than request parameters.

AI remains read-only and advisory. The read-only asset-evidence tool can expose
a persisted `col_<digest>` canonical collection as normalized evidence. Invalid
or client-invented collection IDs are excluded. AI cannot choose trust,
authorize acceptance, start evaluation, or mutate assets, findings, or risk.
Implicit question scoping ignores explicitly legacy or transitional asset
identity and accepts an asset label only when it resolves unambiguously within
the requested site.

## Compatibility status and historical preview

Administrators can review route counts, mappings, recent collection state, and
the number of unmapped historical Python collector rows:

```text
GET /api/v1/admin/ingestion/compatibility-status
```

The endpoint preserves the existing admin-token behavior. The dashboard asset
detail shows canonical collection, source authority, adapter, compatibility
status, and trust rank. Settings shows a bounded compatibility summary when an
admin token is available.

Retry one persisted failed evaluation with the configured administrator token:

```text
POST /api/v1/admin/ingestion/{canonical_collection_id}/retry
```

Only `retryable-failure` rows with persisted authoritative asset work are
eligible. Replay, completed, running, queued, and `not-required` rows fail
closed with a conflict response.

The preview utility never writes or migrates. It starts a PostgreSQL read-only
transaction and reports only counts:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace:ro" `
  --workdir /workspace backend `
  python scripts/preview_canonical_ingestion_compatibility.py
```

`mutation_performed` is always `false`. The utility does not automatically map
or adopt any historical record. Missing migration tables produce a bounded
error code rather than raw database or filesystem details.

## Validation

Run focused unit and route preservation tests through the locked backend image:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace:ro" `
  --workdir /workspace/backend -e OPENASSETWATCH_AI_PROVIDER=demo backend `
  python -m unittest -v tests.test_canonical_ingestion `
    tests.test_endpoint_agent_identity tests.test_observation_batches `
    tests.test_inventory tests.test_local_inventory_ingestion `
    tests.test_ai_advisor tests.test_schema_migrations
```

The PostgreSQL lifecycle creates and drops only a random database matching
`openassetwatch_canonical_test_<hex>`:

```powershell
docker compose run --rm --volume "${PWD}:/workspace:ro" `
  --workdir /workspace/backend `
  -e OPENASSETWATCH_AI_PROVIDER=demo `
  -e OPENASSETWATCH_CANONICAL_INGESTION_POSTGRES_TEST=1 backend `
  python -m unittest -v tests.test_canonical_ingestion_postgres
```

The Compose backend service supplies its configured database connection; do
not paste credentials into documentation, Git, or terminal transcripts. The
tests prove all four adapters, exact and bounded replay, conflicting replay,
first-authority adoption, trust precedence, concurrent cross-adapter collision,
cross-site isolation, configured-site enforcement, durable evaluation retry,
compatibility mappings, targeted evaluation, and absence of duplicate or
lower-trust-poisoned assets, components, matches, findings, or risk rows.

Run the fictional consolidation demonstration in a separate disposable
`openassetwatch_canonical_demo_<hex>` database:

```powershell
docker compose run --rm --volume "${PWD}:/workspace:ro" `
  --workdir /workspace `
  -e OPENASSETWATCH_AI_PROVIDER=demo `
  -e OPENASSETWATCH_CANONICAL_INGESTION_DEMO=1 backend `
  python scripts/demo_canonical_ingestion_compatibility.py
```

The output contains only server-issued IDs, bounded counts, trust labels, and
the read-only AI evidence IDs. It never prints tokens, digests, payloads, or the
database URL.

## Current limitations

- Existing historical collector rows are reported but not automatically
  adopted. Ambiguous records require a future explicitly reviewed operator
  workflow.
- Background evaluation and coalescing are in-process FastAPI work, not a
  durable message broker. Retryable rows are durable and can be retried through
  the authenticated administrator endpoint, but automatic scheduled retry and
  cross-process queue ownership remain deferred.
- This milestone does not add tenancy, RBAC, asset merge/split, new native
  collection, active scanning, or AI write authority.
- Native cross-platform package collection remains the immediate functional
  follow-up; this consolidation does not expand what agents collect.
- A shared legacy token authenticates transport only; it does not establish an
  authoritative collector identity.
