# OSV PyPI Advisory Publisher

OpenAssetWatch's first approved real advisory-source adapter is a separate,
one-shot publisher for Python Packaging Advisory Database records transported
by OSV.dev. It retrieves only reviewed `PYSEC-*` records, normalizes them into
the existing strict advisory catalog, signs the existing bundle format, and
writes a complete local output atomically. It does not import, approve,
activate, or distribute a catalog.

The backend, matcher, dashboard, API, and AI request paths never import this
publisher and never make its upstream network requests.

## Reviewed source and license boundary

The approved source is the
[Python Packaging Advisory Database](https://github.com/pypa/advisory-database),
whose repository [license](https://github.com/pypa/advisory-database/blob/main/LICENSE)
is CC BY 4.0. The adapter uses OSV.dev's documented
[per-ecosystem GCS export](https://google.github.io/osv.dev/data/) only as its
transport:

- index: `https://storage.googleapis.com/osv-vulnerabilities/PyPI/modified_id.csv`;
- records: `https://storage.googleapis.com/osv-vulnerabilities/PyPI/PYSEC-<year>-<number>.json`.

The PyPI ecosystem export is not itself a single licensed source. It contains
other identifier families. The adapter selects only `PYSEC-*`, then requires
each record to identify its matching YAML source under
`github.com/pypa/advisory-database`. Other rows are counted by identifier
prefix and sampled in the bounded report, but they are never normalized,
signed, cached, or represented as CC BY material. Missing or ambiguous source
provenance fails the whole run.

Every normalized advisory preserves its source URL, license, attribution,
aliases, upstream and related identifiers, credits, references, affected PyPI
packages, PEP 440 ranges, explicit versions, withdrawal time, upstream
categorical severity, and upstream CVSS vectors. Ranges and explicit versions
retain OSV union semantics: range-covered explicit versions are omitted as
redundant, while out-of-range explicit versions remain affected evidence. OSV
`introduced: "0"` becomes an explicit unbounded-lower marker instead of the
literal PEP 440 version zero.

The adapter computes a CVSS base score and scalar category only for strict
CVSS 3.0/3.1 base vectors. Malformed, duplicate-metric, extended, or unsupported
vectors fail the run. It never invents known-exploitation status. When the
source reports no usable severity, the existing non-escalating
`informational` compatibility value is paired with
`severity_basis=not-reported`; it is not an assertion of low risk.

The exact engineering license decision, obligations, evidence, review date,
and re-review trigger are recorded in `docs/SOURCE_LICENSING_REGISTRY.md`.

## Trust and data flow

```text
fixed OSV GCS host and paths
  -> public-IP DNS validation and pinned-IP TLS
  -> bounded modified_id index
  -> PYSEC source-family and per-record provenance gate
  -> bounded concurrent record retrieval
  -> strict OSV 1.x parsing and PEP 440 normalization
  -> deterministic oaw.advisory-catalog.v1 bytes
  -> existing signed-manifest and Ed25519 verifier
  -> private staged files
  -> atomic complete local bundle directory
  -> private cursor update after output publication
```

There is no configurable upstream URL, redirect following, proxy use,
authentication header, active package lookup, runtime scheduler, unsigned
mode, skip-verification flag, partial output, or quarantine-and-continue mode.
The network client caps DNS results, index/record/total bytes, rows, record
count, concurrency, retries, connection/read/overall time, content type, and
error text. Private, loopback, link-local, reserved, multicast, and mixed
public/private DNS answers are rejected. Responses are accepted only from the
exact TLS host with the exact path and one explicit `Host` header.
On Linux, one absolute alarm bounds retrieval, retries/backoff, normalization,
catalog generation, signing, staging, verification, output, and state commit;
blocking DNS attempts also run behind the remaining source deadline.

The OSV GCS export is authenticated by HTTPS but does not provide an upstream
dataset signature. The publisher's Ed25519 signature attests to the exact
normalized bytes and provenance it emitted; it does not prove that upstream
advisory content is correct. Preview and explicit human approval remain
separate trust decisions.

Raw upstream bodies exist only in bounded memory for the run. Local state
stores normalized records, source cursor, sequence, adapter/catalog versions,
index and payload digests, and the last successful time. It stores no private
key, credential, authorization header, or raw record body.

## Run in the Linux backend environment

All paths passed to the CLI must be absolute inside the container. Dry runs and
synthetic demonstrations may use ignored repository-local paths. Production
cursor state, output, and signing material must use Linux-private storage. The
publisher rejects native Windows signed production because portable Python
cannot establish the required private DACL ownership guarantees. A Docker named
volume is suitable for local operator evaluation from a Windows host; do not
bind-mount a Windows repository directory for production private state.

Perform a bounded live source check. It downloads the index and exactly one
named record, validates and normalizes it, prints bounded metadata, and
persists nothing:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend `
  python scripts/publish_osv_pypi_advisories.py live-smoke `
    --record-id PYSEC-2021-66 --json
```

Perform a full dry run. Dry run accepts no output or signing-key option and
does not create cursor state:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend `
  python scripts/publish_osv_pypi_advisories.py sync --full --dry-run `
    --state /tmp/openassetwatch-publisher-state.json --json
```

For a real signed run, provision an Ed25519 private key through the operator's
secret manager. Prefer a protected environment-variable reference containing
canonical base64 for exactly 32 raw private-key bytes. The variable name, not
the secret value, is passed on the command line. A PEM or canonical raw-base64
key file is also supported, but must be absolute, regular, single-link,
root/operator-owned, and mode `0600` on POSIX. Native Windows signed
publication fails closed. Use the Linux publisher environment, a Linux-private
named volume, and a secret manager for production keys and state.

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace:ro" `
  --volume "openassetwatch_osv_publisher:/var/lib/openassetwatch-publisher" `
  --workdir /workspace --env OPENASSETWATCH_OSV_PYPI_SIGNING_KEY backend `
  python scripts/publish_osv_pypi_advisories.py sync --full `
    --state /var/lib/openassetwatch-publisher/state/publisher-state.json `
    --output /var/lib/openassetwatch-publisher/output `
    --key-id oaw-osv-pypi-ed25519-2026-01 `
    --signing-key-env OPENASSETWATCH_OSV_PYPI_SIGNING_KEY --json
```

Subsequent runs default to incremental mode and re-fetch a bounded overlap to
avoid same-timestamp or late-visible records. `--incremental` makes that intent
explicit. Use `--full` for the initial run and after a reviewed upstream record
removal. The publisher rejects cursor rollback, gaps, incompatible or corrupt
state, future timestamps, missing previously published records during an
incremental run, modification-time regression for any existing record,
withdrawal reversal or regression, and any incomplete normalized catalog.

The successful output directory contains only:

- `catalog.json`;
- `manifest.json`;
- `manifest.ed25519`;
- `publisher-report.json`.

The report includes the key ID, raw public key in base64, and SHA-256 public-key
fingerprint for comparison during independent registry review. It is not a
trust-registration authority and must never bootstrap its own key. The report
never includes the private key or absolute bundle path. Prefix maps and samples,
warning/error text, and the complete serialized report are deterministically
bounded, with explicit truncation metadata. Output uses private staging and an
atomic directory rename. The cursor is
replaced atomically only after staged verification and final output publication.
If cursor persistence fails after output publication, the command fails and
the old cursor remains, so a retry reprocesses overlap rather than skipping
data. A failed fetch, parse, validation, signing, or staging step leaves the
last successful state and complete outputs untouched.

Stateless protected publication runners may pass `--sequence-floor` only from
the latest sequence of a successfully verified signed mirror snapshot. A full
rebuild then signs `floor + 1` and writes that value into new private state.
Arbitrary or unauthenticated sequence floors are prohibited; the mirror builder
also rejects an update that does not advance its verified prior sequence.

Inspect non-secret cursor metadata:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace:ro" `
  --volume "openassetwatch_osv_publisher:/var/lib/openassetwatch-publisher" `
  --workdir /workspace backend `
  python scripts/publish_osv_pypi_advisories.py state `
    --state /var/lib/openassetwatch-publisher/state/publisher-state.json --json
```

## Register and consume a published bundle

Local verification during publishing uses the exact production
`ReviewedFeedRegistry`, `FeedSource`, manifest, signature, catalog, and
`verify_bundle` types. There is no compatibility verifier or second catalog
model. That local proof does not create trust-on-first-use in the hub.

Before official distribution or hub synchronization, an operator must follow
the reviewed static-mirror process in `docs/ADVISORY_MIRROR.md`:

1. verify the complete bundle into an immutable static mirror snapshot and
   sign the canonical mirror index;
2. obtain the bundle and index public keys through an independent administrator-approved channel,
   compare its key ID and fingerprint with the report only as a secondary
   check, and add it to `backend/advisory_feeds/publishers.json` through normal
   review;
3. replace the disabled `.invalid` mirror source template with the reviewed
   host, stable index/signature paths, trusted key IDs, accepted CC-BY-4.0
   license/attribution, and conservative bounds in
   `backend/advisory_feeds/sources.json`;
4. review and test that registry change as a separate trust-policy change;
5. run the existing `scripts/advisory_feed_sync.py` preview, approval, and
   activation workflow.

The publisher cannot alter either registry. A publisher success does not mean
the hub has approved or activated the catalog. The hub retains its last known
good active catalog on any later retrieval, verification, approval, import, or
reevaluation failure. Activation and rollback continue to trigger the existing
targeted deterministic vulnerability, finding, and risk reevaluation. The AI
Advisor receives only bounded server-issued read-only evidence and has no
publisher, registry, approval, activation, or rollback authority.

## Offline demonstration, benchmark, and tests

The demonstration is fully offline and creates all fixtures and signing
material in a temporary directory. Its fictional OSV-format input is authored
by OpenAssetWatch and labeled Apache-2.0; no downloaded third-party advisory is
committed or falsely labeled as the PyPI database.

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend python scripts/demo_osv_pypi_publisher.py

docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend `
  python scripts/benchmark_osv_pypi_publisher.py --count 2000

docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace/backend backend `
  python -m unittest -v tests.test_osv_pypi_publisher tests.test_osv_pypi_demo
```

The demo proves full publish, signature acceptance by the existing verifier,
preview, approval, activation and targeted reevaluation, then an incremental
fixed-version correction that changes a synthetic component from affected to
fixed, removes its deterministic finding and risk, and finally rolls back. It
also proves that the advisory-feed status, preview, and activation-impact tools
carry server-issued run/catalog evidence IDs into the read-only AI context.

The benchmark measures thousands of strict synthetic normalizations,
deterministic catalog construction, signing and verification, payload size,
elapsed time, and peak Python-tracked memory. It does not contact OSV.dev or
claim PostgreSQL import performance.

## Known limitations and operator alerts

- The adapter intentionally supports a reviewed, bounded OSV 1.x field set.
  Unknown fields and unsupported range types fail the full run for review.
- Only PyPI/PEP 440 ecosystem ranges and explicit versions are normalized.
- Only CVSS 3.0/3.1 base vectors are numerically derived. Other vector types or
  metric sets fail closed for review. Missing severity is explicit and
  non-escalating; deterministic risk must not infer certainty from absence.
- Upstream removals require an operator-reviewed full rebuild. There is no
  silent deletion during incremental synchronization.
- OSV/PyPI service availability is external. Failure leaves the last known good
  output and hub catalog in place; monitor failed exit status, stale
  `last_successful_run_at`, cursor age, source row-count shifts, out-of-scope
  prefix shifts, and repeated full-rebuild requirements.
- Publisher key generation, escrow, rotation, revocation, registry review, and
  publication authorization remain operator responsibilities. The separate
  mirror workflow provides a gated, static-host foundation but does not enable
  hosting, enroll keys, or grant this command ambient authority.

## Adding another reviewed publisher adapter

A second source must receive its own licensing decision, immutable source-family
policy, exact endpoints, schema and version semantics, provenance checks,
normalizer, synthetic fixtures, bounds, correction/withdrawal rules, and
security review. It must emit the existing vendor-neutral catalog and signed
bundle types; it must not add a source-specific model to matching, findings,
risk, or AI. Optional distribution uses the same separately managed signed
mirror-index contract; it must not introduce source-specific hub behavior.
