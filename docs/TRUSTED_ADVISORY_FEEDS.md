# Trusted Advisory Feed Synchronization

OpenAssetWatch retrieves advisory updates only through an explicit, one-shot,
administrator-controlled supply-chain workflow. A feed is not trusted merely
because it uses HTTPS. The current implementation authenticates a configured
publisher, validates a bounded catalog, presents a preview, requires human
approval, activates it atomically, and then asks the existing deterministic
matcher to reevaluate only changed advisories.

The normal API, asset, matching, dashboard, and AI request paths never download
advisories. The last successfully activated catalog remains usable when the
network, a publisher, or a later synchronization fails.

## Trust flow

```text
reviewed source_id
  -> one-shot CLI or explicit admin request
  -> exact configured HTTPS host and paths
  -> public-address DNS validation and pinned-IP TLS connection
  -> bounded manifest and detached signature
  -> Ed25519 verification against the local reviewed keyring
  -> bounded payload download and private staging
  -> digest, compression, schema, license, attribution, and provenance checks
  -> bounded catalog diff preview
  -> explicit administrator approval
  -> serialized atomic import and activation
  -> targeted deterministic vulnerability reevaluation
  -> findings, risk, and read-only AI evidence
```

Signatures authenticate the configured publisher and the exact manifest bytes;
they do not prove that an advisory is correct. Operator approval remains
mandatory. Vulnerability matching, findings, and risk remain deterministic.
The AI Advisor can explain server-issued evidence but cannot synchronize,
approve, reject, activate, roll back, or alter trust policy.

## Reviewed source registry

`backend/advisory_feeds/sources.json` is the versioned source registry.
Requests provide only `source_id`; no API or CLI accepts a URL. Each source
fixes its adapter/version, exact HTTPS host and artifact paths, schemas,
payload name, trusted key IDs, accepted license, required attribution, content
types, byte/count/time limits, downgrade policy, approval policy, and source
documentation. Downloaded data cannot change any of these values.

The included `openassetwatch-synthetic-signed` source is test-only. Its
`.invalid` hostname cannot be a production destination; the reviewed local
fixture under `backend/advisory_feeds/fixtures/` drives tests and demos. It
contains one fictional advisory and no third-party corpus.

To add a source:

1. Complete the decision record in `docs/SOURCE_LICENSING_REGISTRY.md` using
   authoritative source terms.
2. Define exact endpoints and conservative bounds in `sources.json`.
3. Add a source adapter implementing the existing `AdvisoryAdapter` boundary;
   do not add a second advisory model.
4. Add the publisher public key to the reviewed keyring independently of feed
   transport.
5. Add malformed, bounds, license, provenance, replay, downgrade, and lifecycle
   tests using synthetic records.
6. Review the full security diff and operate the source initially through
   explicit approval.

## Signed bundle v1

A bundle has three logical objects:

- `manifest.json`: exact UTF-8 bytes, without a BOM;
- `manifest.ed25519`: canonical base64 for exactly one 64-byte detached
  Ed25519 signature, with one optional final newline;
- the named catalog payload: plain JSON or one gzip stream.

The signature covers the exact manifest bytes. The strict
`oaw.advisory-bundle.manifest.v1` object binds the source and publisher key,
catalog version and positive monotonic sequence, creation and expiry,
payload name/media/compression/digest and byte counts, advisory/alias/reference
counts, license and attribution, upstream source/version/dataset/retrieval
metadata, adapter version, and minimum catalog format version. Unknown fields,
duplicate JSON keys, malformed timestamps, source/key substitution, unsigned
metadata, or schema confusion fail closed.

The payload must parse as the existing strict `oaw.advisory-catalog.v1`
format. Its source, source version, license, advisory count, alias count, and
reference count must agree with the signed manifest. Normalized catalog bytes
and all signed artifacts are retained in PostgreSQL for verified rollback and
audit; they are never executed as code.

## Publisher keyring

`backend/advisory_feeds/publishers.json` contains pinned Ed25519 public keys,
explicit key IDs, publisher identity, state (`active`, `retired`, or `revoked`),
and optional validity intervals. There is no dynamic key retrieval,
trust-on-first-use, or unsigned fallback.

For rotation, add the new active public key and approve it for the source before
the publisher changes signatures. Retire an old key after the overlap window;
retired keys cannot authorize new bundles but may authenticate a locally
retained rollback catalog. Mark a compromised key revoked. Revocation blocks
both new activation and rollback. Never commit a production private key or a
test private-key file; tests create ephemeral keys only in memory.

## Downloader and private staging

`backend/app/advisory_transport.py` uses the reviewed hostname and exact paths,
HTTPS only, default port only, no URL credentials, disabled redirects, no
cookies, and no proxy-environment inheritance. It resolves at most 32 DNS
answers, rejects the full result if any address is loopback, private,
link-local, multicast, unspecified, reserved, metadata-addressed, or otherwise
non-global, then connects to one validated IP while retaining hostname TLS
verification. The connected peer must equal the pinned address. This removes
the usual resolver-to-connect DNS rebinding window; routing changes below the
socket layer remain outside application control.

Connection, read, and total timeouts apply. Response status, header count and
bytes, duplicate security-sensitive headers, content type, HTTP content
encoding, declared length, streamed body length, and SHA-256 are bounded.
Errors and logs use fixed codes/summaries and never include response bodies,
authorization headers, cookies, tokens, or staging paths.

Plain JSON and a single gzip stream are supported. ZIP, TAR, concatenated gzip,
and trailing data are rejected. Both compressed and uncompressed limits apply,
as does an expansion-ratio limit, and decompression stops on violation.

Staging is outside the web root. Files use randomized same-directory temporary
names, exclusive no-follow creation where supported, mode `0600`, file and
directory synchronization, atomic replacement, regular-file checks, and
single-link checks. The deployment must pre-create the staging parent with a
trusted owner; the service creates or opens the private leaf without following
links, verifies the opened directory identity, and changes permissions only
through the open descriptor. Directories are private and owner-checked. Cleanup accepts
only a bounded set of expected regular single-link files. Compose mounts a
16 MiB private tmpfs at `/var/lib/openassetwatch`; successful verification
cleans staging before a run becomes visible for approval. Abandoned cleanup is
age- and count-bounded.

## License and provenance policy

The reviewed registry and signed manifest must agree on an accepted license and
the exact required attribution. The normalized catalog must repeat the same
license and source/version provenance. Each imported advisory retains its
source record identity, and retained catalog metadata includes retrieval time,
adapter version, manifest/payload digests, publisher key, license, attribution,
and upstream dataset identity. Missing or conflicting data is rejected.

The only enabled source is OpenAssetWatch-owned fictional Apache-2.0 material.
No real third-party advisory data is bundled or redistributed by this feature.
The new runtime `cryptography` dependency is Apache-2.0 OR BSD-3-Clause, both
permitted by `LICENSE_POLICY.md`, and exists solely for reviewed Ed25519
verification.

## Run lifecycle and coordination

PostgreSQL stores bounded run, retained-catalog, and activation records. Run
states progress through `created`, `downloading`, `downloaded`, `verifying`,
`pending_approval`, `approved`, `importing`, and `activated`; safe terminal or
degraded states include `rejected`, `failed`, `expired`, and
`activated_degraded`. API projections omit retained bytes and local paths.

A partial unique index plus a per-source PostgreSQL advisory transaction lock
enforces one active synchronization for each source across backend processes.
Replay checks reject reused manifest digests, reused versions, duplicate
sequences, and identical payloads under conflicting signed metadata. The
downgrade watermark advances only after a catalog has been activated, so a
rejected preview cannot ratchet a source forward. A global PostgreSQL advisory
transaction lock serializes activation
and rollback. The existing catalog importer also locks its catalog transaction.
These controls do not rely on a process-local mutex.

After verification, preview reports source, publisher/signature, version and
sequence, dates, license/attribution, payload digest, total/added/updated/
withdrawn advisories, alias changes, ecosystems, known-exploited count,
validation warnings, rejected/incompatible counts, and a bounded changed-ID
impact estimate. Exact production risk is not predicted before activation.

Approval and rejection require configured administrator authentication. API
audit records use the server-derived `api-admin-token` capability label rather
than accepting a client-asserted identity; CLI actor labels are operator-supplied
audit descriptions, not authenticated individual identities. Rejection is
terminal. Approval does not itself activate.
Activation rechecks current key policy and manifest expiry, verifies retained
bytes, imports the normalized catalog, switches active state, and records the
activation in one database transaction. Import failure rolls the entire
transaction back, leaving the previous catalog active. Activation also rejects
a stale preview when the active catalog has changed since verification.

Targeted reevaluation runs after commit for changed advisory IDs. Each database
reconciliation is capped at 20,000 IDs; a maximum-size 20,000-to-20,000 catalog
transition is processed as two bounded chunks, and findings/risk are updated
only after the final chunk. Findings-update failures propagate to the activation
record. If reevaluation fails,
the new catalog remains active but is marked degraded with a safe retry action;
the failure is not hidden. An explicit rollback selects only a locally retained
previously activated catalog, verifies its digest and current key revocation
policy, switches atomically without networking, records the operator action,
and triggers the same deterministic reevaluation. Control-action cooldowns
limit repeated rollback requests.

## CLI

Run inside the Linux backend image so the hashed runtime lock applies:

```powershell
docker compose run --rm backend python scripts/advisory_feed_sync.py sources
docker compose run --rm backend python scripts/advisory_feed_sync.py status --source openassetwatch-synthetic-signed
docker compose run --rm backend python scripts/advisory_feed_sync.py verify-bundle --source openassetwatch-synthetic-signed
docker compose run --rm backend python scripts/advisory_feed_sync.py import-local --source openassetwatch-synthetic-signed --requested-by maintainer
docker compose run --rm backend python scripts/advisory_feed_sync.py preview --run afrun_<server-issued-id>
docker compose run --rm backend python scripts/advisory_feed_sync.py approve --run afrun_<server-issued-id> --actor maintainer
docker compose run --rm backend python scripts/advisory_feed_sync.py reject --run afrun_<server-issued-id> --actor maintainer --reason "review result"
docker compose run --rm backend python scripts/advisory_feed_sync.py activate --run afrun_<server-issued-id> --actor maintainer
docker compose run --rm backend python scripts/advisory_feed_sync.py catalogs --source openassetwatch-synthetic-signed
docker compose run --rm backend python scripts/advisory_feed_sync.py rollback --catalog afcat_<server-issued-id> --actor maintainer
docker compose run --rm backend python scripts/advisory_feed_sync.py retry-reevaluation --activation afact_<server-issued-id> --actor maintainer
docker compose run --rm backend python scripts/advisory_feed_sync.py cleanup-staging --older-than-seconds 3600
```

`sync` uses only the configured remote endpoint. `import-local` and
`verify-bundle` use only the repository-reviewed fixture directory. The CLI
accepts no arbitrary URL/path, token, private key, unsigned mode, or skip flag.
`scripts/import_advisory_catalog.py` now fails closed because unsigned imports
are obsolete.

## Administrative API and UI

All feed endpoints require `X-OpenAssetWatch-Admin-Token`; they return 503 when
the admin credential is not configured and 401 when it is invalid.

- `GET /api/v1/admin/advisory-feeds`
- `GET /api/v1/admin/advisory-feeds/{source_id}`
- `POST /api/v1/admin/advisory-feeds/{source_id}/sync`
- `GET /api/v1/admin/advisory-feed-runs`
- `GET /api/v1/admin/advisory-feed-runs/{run_id}`
- `GET /api/v1/admin/advisory-feed-runs/{run_id}/preview`
- `POST /api/v1/admin/advisory-feed-runs/{run_id}/approve`
- `POST /api/v1/admin/advisory-feed-runs/{run_id}/reject`
- `POST /api/v1/admin/advisory-feed-runs/{run_id}/activate`
- `GET /api/v1/admin/advisory-catalogs?source_id=...`
- `POST /api/v1/admin/advisory-catalog/rollback`
- `POST /api/v1/admin/advisory-catalog-activations/{activation_id}/retry-reevaluation`

Run history is paginated and bounded. IDs have strict server-issued formats;
request bodies are strict and size-limited, and lifecycle audit actors are
derived by the server after admin-token validation. Background tasks execute only
after an explicit administrator request and are still coordinated by the
database.

Settings -> Advisory Intelligence reuses the manually entered admin token
without persisting it. It shows source/trust status, active and last-known-good
catalogs, failure/pending state, run history, a bounded preview, and explicit
sync/approve/reject/activate/rollback controls. Feed text is assigned through
DOM `textContent`, never trusted HTML. The dashboard does not synchronize on
load; feed status is loaded only when the operator selects the control.

## AI evidence and offline behavior

Read-only AI tools expose bounded feed status, pending preview, and activation
impact only when an admin credential is explicitly configured and the AI request
presents that valid credential. General local/demo AI behavior may retain the
project's optional-auth mode, but it receives no feed-administration evidence in
that mode. Evidence uses server-issued `afrun_`, `afcat_`, advisory, match,
finding, asset, and evaluation IDs. Feed text is untrusted evidence, not model
instructions. The tool allowlist contains no mutation operation. AI output
cannot become catalog input or alter deterministic results.

Matching reads only the locally active normalized catalog. A failed, expired,
offline, rejected, or unapproved synchronization cannot change it. Rollback
also uses retained local bytes and performs no network request.

## Real-source adapter decision

No real adapter is enabled. OSV offers a stable machine-readable API, but it is
an unsigned aggregation of upstream databases whose per-record licenses and
redistribution obligations can differ. HTTPS transport cannot substitute for a
publisher signature, and the existing source licensing registry therefore
keeps OSV at `review-required`. See the official [OSV API documentation](https://google.github.io/osv.dev/api/)
and [OSV data-source documentation](https://google.github.io/osv.dev/data/).

The immediate follow-up is a separately operated OpenAssetWatch publisher or
mirror pipeline: fetch one legally approved upstream, preserve per-record
license/provenance, normalize it offline, enforce publisher-side bounds and
duplicate controls, emit bundle v1, and sign the manifest with an offline or
managed signing key. The hub would trust only that independently reviewed
publisher public key. Core matching and bundle formats remain vendor-neutral.

## Known limitations

- Live PostgreSQL transaction/race validation and Compose health require a
  running Docker daemon; unit tests cover service behavior and assert the
  production lock/constraint definitions, while CI should run the live stack.
- Synchronization execution currently uses an explicit CLI process or FastAPI
  background task. A future cron/systemd timer can invoke the same one-shot CLI;
  there is no embedded scheduler or durable job broker.
- Publisher correctness, source governance, and key custody remain operational
  responsibilities outside cryptographic verification.
- Retained artifacts currently live in PostgreSQL. Retention count/age policy
  beyond last-known-good selection is an operational follow-up.
- Gzip and catalog limits are source-wide; a future real adapter should lower
  them from global maxima based on measured authoritative-source behavior.
