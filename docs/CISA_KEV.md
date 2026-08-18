# CISA Known Exploited Vulnerabilities Prioritization

OpenAssetWatch uses CISA Known Exploited Vulnerabilities (KEV) as a signed,
operator-controlled prioritization signal for vulnerability matches that the
deterministic matcher has already confirmed as currently `affected`. KEV does
not identify vulnerable package versions and cannot create or override a
component/advisory match.

The authority boundary is:

```text
normalized installed component
  -> reviewed advisory and deterministic affected-version match
  -> exact normalized CVE alias in the active CISA KEV catalog
  -> KEV priority factor on the existing finding and risk result
  -> bounded read-only AI explanation
```

Presence in KEV means CISA has evidence of exploitation in the wild. It does
not prove that a specific OpenAssetWatch asset was exploited or compromised.
OpenAssetWatch performs no exploitation test, scanning, patching, ticket
change, or required-action execution.

## Official source, schema, and license

The one-shot publisher accepts only CISA-controlled material:

- machine-readable official GitHub mirror:
  `https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json`
- official schema:
  `https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities_schema.json`
- canonical catalog documentation:
  `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`

The GitHub file is an official machine-readable mirror, not the canonical
catalog page. The normalized bundle preserves that distinction, source ID,
catalog version, release and retrieval times, source and payload SHA-256,
adapter version, and safe provenance.

CISA publishes the `cisagov/kev-data` repository under CC0 1.0. Normalized KEV
data remains `CC0-1.0`; it is not relicensed as Apache-2.0. OpenAssetWatch
adapter code and product-authored synthetic fixtures remain under the project
license. The source decision is recorded in
`docs/SOURCE_LICENSING_REGISTRY.md`. No downloaded KEV corpus is committed.

## Strict schema and text handling

Adapter version 1 validates the current catalog fields `catalogVersion`,
`dateReleased`, `count`, and `vulnerabilities`. Each record requires `cveID`,
`vendorProject`, `product`, `vulnerabilityName`, `dateAdded`,
`shortDescription`, `requiredAction`, and `dueDate`; the reviewed optional
fields are `knownRansomwareCampaignUse`, `notes`, and `cwes`.

Validation rejects duplicate JSON keys, duplicate CVEs, unknown fields,
malformed UTF-8/JSON, BOMs, invalid CVE/CWE/date/timestamp values, count
mismatches, excessive bytes/records/nodes/depth/text/arrays, and noncanonical
normalized payloads. All upstream strings are untrusted bounded text. They are
never interpreted as HTML, code, executable instructions, matching rules, or
model instructions.

An upstream schema revision fails closed. Supporting a future revision
requires reviewing the official schema and license again, updating the typed
source and normalized models, incrementing the adapter version when semantics
change, updating the disabled registry template, and adding offline fixtures
for new, removed, and unknown fields before deployment.

## Publisher and transport

`scripts/publish_cisa_kev.py` is a one-shot administrative publisher. It is
not started by the backend and has no scheduler. It reuses the hardened
advisory downloader and the existing Ed25519 signed bundle format.

The live source policy fixes HTTPS, `raw.githubusercontent.com`, and the exact
CISA KEV path. It rejects redirects, URL credentials, caller URLs, proxy
inheritance, unreviewed paths/content types, unsafe or mixed DNS answers,
private/loopback/link-local/multicast/unspecified/metadata destinations,
oversized responses, and deadline overruns. Error output contains stable codes
and bounded summaries, never bodies, headers, keys, credentials, or private
paths.

Offline schema and normalization dry run from the repository root:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend `
  python scripts/publish_cisa_kev.py sync `
    --state /tmp/oaw-cisa-kev-dry-run-state.json `
    --fixture-file /workspace/backend/tests/fixtures/cisa-kev/catalog-v1.json `
    --dry-run --json
```

Explicit bounded live-source validation performs no signing, state write, or
raw-corpus persistence:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend `
  python scripts/publish_cisa_kev.py live-smoke --total-timeout 30 --json
```

That command uses the public network and should be run only when explicitly
intended. Automated tests never run it.

A signed run is intended for a dedicated Linux publisher account with private
owner-only directories and a single-link `0600` Ed25519 key file:

```text
python scripts/publish_cisa_kev.py sync \
  --state /var/lib/openassetwatch-cisa-kev/publisher-state.json \
  --output /var/lib/openassetwatch-cisa-kev/output \
  --signing-key-file /run/secrets/openassetwatch-cisa-kev-ed25519 \
  --key-id <reviewed-publisher-key-id> \
  --json
```

Private keys are never literal command-line values. State replacement uses a
random exclusive temporary file, no-follow opening, regular/single-link
validation, owner-private parent validation, fsync, atomic replacement, and
post-write safe-read validation. A single-link owner-controlled lock file holds
an OS-released inter-process lock across sequence issuance. The signed sequence
is first recorded as `reserved`, the bundle directory is published, and state
then advances to `published`; a crash can skip a sequence but cannot reuse it
for a conflicting signed bundle. The absolute run deadline covers download,
parse, normalization, signing, state, and output work. The publisher rejects catalog date downgrade,
same-version byte equivocation, inconsistent state digests, and emits no new
bundle for an unchanged successfully published source.

## Shared signed mirror and activation lifecycle

The KEV manifest uses the existing `oaw.advisory-bundle.manifest.v1` envelope
with `payload_kind=kev-prioritization`, payload schema
`oaw.kev-catalog.v1`, and CC0 provenance. Signature, payload digest, license,
attribution, source, payload kind, sequence, expiry, replay, downgrade, and
size/count checks run before preview.

The disabled deployment template is
`backend/advisory_feeds/cisa-kev-official-mirror-source.template.json`. It
contains placeholder host/key IDs and must not be enabled until maintainers
have reviewed the actual static mirror host, separate index and bundle public
keys, hosting controls, and production source-registry change. This branch does
not change production mirror configuration or publish a feed.

Once configured, operators reuse `scripts/advisory_feed_sync.py` and the
existing source-ID-only flow: synchronize, inspect the verified preview,
approve, activate, and if needed roll back a retained last-known-good catalog.
Failed verification/import leaves the prior catalog active. Activation and
rollback occur in the shared database transaction and then reevaluate sites
associated with exact changed CVEs. The explicit admin rebuild is bounded and
rate-limited. Failed KEV reevaluation persists its bounded affected-site scope,
so an administrator retry cannot silently complete without revisiting the
remaining sites.

## Exact CVE correlation and persistence

Only exact normalized `CVE-YYYY-NNNN...` advisory aliases correlate. Case is
normalized. GHSA, PYSEC, vendor identifiers, package names, vendor/product
text, CPEs, versions, fuzzy text, and AI do not correlate KEV. Duplicate aliases
and repeated imports cannot multiply one logical match/CVE contribution. A KEV
record without a current affected match remains catalog intelligence.

The additive PostgreSQL tables are:

- `kev_catalog_imports`
- `kev_records`
- `kev_record_history`
- `advisory_kev_correlations`
- `vulnerability_priority_factors`
- `vulnerability_priority_factor_history`

They retain normalized bounded fields, exact correlation, import/source
digests, catalog state, and activation/deactivation history; no raw source blob,
credential, key, or private path is stored. Indexes cover CVE, dates,
ransomware status, imports, advisories, matches, and current factors. Match
updates refresh factors in the same authoritative transaction, so a fixed,
withdrawn, or otherwise non-affected match loses current KEV contribution
while its history remains. Catalog activation and match reconciliation share
the same PostgreSQL advisory lock before deriving current priority factors,
and scoped asset queries bind site and asset on the same authoritative match.

Current status semantics are `known_exploited`,
`known_exploited_ransomware`, `not_in_active_kev`, `KEV data unavailable`,
`KEV catalog stale`, `alias missing`, `correlation unavailable`, and
`not-currently-affected`. `not_in_active_kev` is not proof that exploitation
has never occurred.

## Findings, risk, ransomware, and due dates

KEV enriches the existing vulnerable-component finding; it does not open a
second logical finding. The finding retains the authoritative component,
advisory, version-range, and match evidence, then adds exact CVE/KEV record,
CISA date added, source freshness, text-only required action, and `CISA KEV due
date`. Advisory severity is not inferred or changed from KEV presence.

The deterministic KEV risk category uses:

```text
known exploited base                         12
CISA-confirmed ransomware campaign base      18
freshness multiplier: fresh / aging / stale  1.00 / 0.80 / 0.45
KEV category cap per asset                    20
```

Fresh is at most 8 days after catalog release, aging is at most 14 days, and
older is stale/degraded. One logical CVE/match contributes once. Missing KEV
data never subtracts existing finding risk. Fixed/non-affected matches stop
contributing. Risk breakdowns cite both the match and KEV record. KEV-enriched
findings use vulnerable-component rule version 2 / findings ruleset v4, and
scores with KEV factors use formula version `oaw.risk.kev.v1`; unchanged
non-KEV calculations retain `oaw.risk.v1`.

`knownRansomwareCampaignUse=Known` means CISA confirms ransomware campaign
use. `Unknown` or an absent field is unconfirmed and must never be rendered as
`No`; neither state establishes ransomware on a local asset.

`dueDate` is stored and labeled separately as `CISA KEV due date`. It is the
CISA/BOD date, not an OpenAssetWatch local SLA and not a claim that every
organization is legally bound by it. OpenAssetWatch does not create/escalate a
ticket, close a finding, or patch a system from that date. A future reviewed
policy layer may map it to local deadlines.

## API, UI, and AI

Fail-closed, configured-admin-token-authenticated, bounded read endpoints are:

- `GET /api/v1/kev/status`
- `GET /api/v1/kev`
- `GET /api/v1/kev/{cve_id}`
- `GET /api/v1/kev/assets/{asset_id}?site_id=<site>`
- `GET /api/v1/kev/summary`

The list supports bounded CVE, vendor/project, ransomware, date-added,
due-date, site, asset, currently-affected, priority, limit, and offset filters.
Asset lookup requires site scope. `POST /api/v1/admin/kev/evaluate` requires an
explicit configured administrator token and the existing full-evaluation rate
limit. Feed import/approval/activation/rollback remain on the generic trusted
feed endpoints.

Asset vulnerability details show Known Exploited, a Known Ransomware Campaign
badge only when confirmed, exact CVE, KEV record/catalog/source/license,
date-added, CISA KEV due date, freshness, match status, risk contribution, and
text-only guidance. Advisory Intelligence Settings shows catalog freshness and
current counts. DOM construction uses `textContent`, not trusted HTML.

The Advisor has bounded read-only tools for KEV-prioritized assets, related
records/current matches, ransomware-confirmed matches, required actions, CISA
due dates, catalog status/freshness, and risk contribution. It cites
server-issued asset/component/advisory/match/finding/KEV/catalog IDs. It may
explain and prioritize human review, but cannot create/change a match, severity,
risk, catalog, finding, ticket, or system state; cannot execute guidance; and
cannot claim exploitation, compromise, or active ransomware. Globally scoped
KEV record evidence is emitted once, while match/finding/risk citations remain
relationally bound to one site and asset.

## Offline validation and demonstration

Focused tests:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace/backend backend `
  python -m unittest -v tests.test_kev_catalog `
    tests.test_kev_correlation_risk tests.test_kev_api_ai_ui
```

Synthetic activation, update, rollback, findings, risk, fixed-state, missing
alias, ransomware Known/Unknown, due-date, and AI demonstration:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend python scripts/demo_cisa_kev.py
```

Synthetic scale benchmark (defaults: 2,000 records, 6,000 aliases, 5,000
current affected matches):

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend python scripts/benchmark_cisa_kev.py
```

`backend/tests/test_kev_postgres.py` is opt-in and must run only against an
explicitly isolated disposable PostgreSQL database. It validates idempotent
schema initialization, activation, update, rollback, factor removal on fixed,
history, queries, and restart persistence.

## Limitations

- This branch does not enable a production KEV source, host a mirror, schedule
  retrieval, publish data, or provide production keys.
- CISA source availability and future schema/endpoint changes are external;
  validation fails closed and the last-known-good catalog remains available.
- The official upstream JSON is protected in transport by HTTPS but is not an
  OpenAssetWatch-signed artifact until the isolated publisher normalizes and
  signs it.
- KEV does not supply component/package version applicability, severity, CVSS,
  exploitability of a specific asset, or proof of compromise.
- Targeted activation reevaluates changed-CVE sites; an administrator-requested
  full rebuild remains bounded but may be expensive on very large estates.
- Required actions and notes are untrusted guidance. AI remains advisory.
