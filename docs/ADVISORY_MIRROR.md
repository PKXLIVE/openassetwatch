# Official Signed Advisory Mirror Foundation

OpenAssetWatch can publish its already normalized, signed advisory bundle v1
artifacts through a vendor-neutral static HTTPS mirror. The mirror adds a
small signed discovery index; it does not replace the OSV PyPI publisher, the
bundle format, the hub verifier, administrator approval, activation, rollback,
matching, findings, risk, or AI evidence contracts.

The official source is deliberately not live in this change. The reviewed
template at `backend/advisory_feeds/official-mirror-source.template.json` is
disabled, uses an `.invalid` host, and contains placeholder key IDs. Do not add
it to `sources.json` or enable publication until maintainers review the real
domain, TLS/static-host configuration, Ed25519 public keys, key IDs, protected
GitHub environment, license/attribution output, retention, and incident plan.

## Trust and publication flow

```text
reviewed PYSEC-only OSV export
  -> existing bounded OSV PyPI publisher and normalizer
  -> existing canonical advisory catalog and signed bundle v1
  -> local-only mirror builder verifies the complete bundle again
  -> immutable catalogs/<sequence>-<manifest-digest>/ bundle artifacts
  -> canonical index.json plus detached Ed25519 index.ed25519
  -> whole static-host snapshot deployment

reviewed HTTPS mirror host
  -> fixed index and index-signature paths from the source registry
  -> exact-byte index signature and strict schema verification
  -> latest immutable relative paths from the authenticated index
  -> artifact size and SHA-256 checks
  -> existing bundle-v1 signature, digest, schema, license, attribution,
     provenance, replay, and downgrade checks
  -> existing preview -> explicit administrator approval -> activation
  -> existing deterministic vulnerability, finding, risk, and AI evidence
```

The publication side has no hub database, customer inventory, write API, or
dynamic upload endpoint. The consumption side accepts no caller URL, host,
path, token, key, unsigned mode, or verification-skip flag. A signed index may
choose only bounded relative paths. The hub resolves them below the directory
that contains the reviewed `index.json` path; the host and path prefix remain
fixed by the source registry.
Redirects, credentials, alternate ports, queries, fragments, encoded path
segments, private or mixed DNS results, and unexpected media types fail closed.
The index must also be newer than the reviewed maximum age (14 days in the
template), bounding stale-index replay for a newly installed hub; previously
observed bundle sequences provide the stronger downgrade check thereafter.

## Mirror index v1

`index.json` uses the strict schema ID `oaw.advisory-mirror-index.v1` and schema
version `1`. Unknown fields and duplicate JSON keys are rejected. It is encoded
as sorted, compact, ASCII-safe canonical JSON with no trailing newline. The
detached `index.ed25519` is canonical base64 for a 64-byte Ed25519 signature;
verification covers the exact `index.json` bytes before any catalog path is
trusted.

The index contains:

- source ID, index-signing key ID, and publication time;
- the latest catalog version and monotonic bundle sequence;
- the reviewed adapter version, minimum catalog format, and minimum supported
  OpenAssetWatch version;
- exact license, attribution, and latest upstream source provenance;
- a bounded, sequence-ordered retained catalog list;
- each catalog's creation and expiry, bundle publisher key ID, immutable
  manifest/signature/payload relative paths, exact byte lengths, SHA-256
  digests, license, attribution, and source provenance.

The latest pointer must select the highest retained sequence. Catalog versions,
sequences, and all artifact paths must be unique. All three bundle files share
one immutable `catalogs/` directory. The hub verifies the index signature and
policy, selects the latest entry, validates each downloaded object's signed
length and digest, and then invokes the unchanged bundle-v1 verifier. A valid
index signature therefore cannot bypass bundle verification or administrator
approval.

## Local builder and static layout

`scripts/build_advisory_mirror.py` provides three one-shot commands:

- `build` accepts one or more complete local signed bundle directories, an
  optional previously verified mirror snapshot, an output directory that must
  not exist, reviewed registry/source selection, retention bound, and protected
  index signing-key reference;
- `verify` re-verifies the index, every retained object, and every complete
  bundle without importing or activating anything;
- `snapshot` downloads a complete bounded existing mirror through the same
  fixed-host, signature-first transport for use as retention input.

`build` performs no network request. It re-verifies inputs, keeps the latest
catalog plus the configured number of prior catalogs, signs the new canonical
index, writes into a same-filesystem staging directory with exclusive file
creation, re-reads the finished snapshot, and renames it only if the requested
output path is still absent. An existing target is never replaced. A partial
failure cannot change the previous mirror input or an already deployed static
snapshot.
Its bounded JSON report names the exact retained and removed catalog sequences;
removal means omission from the complete next snapshot only, after successful
verification. The previous input tree is never edited or pruned in place.

The snapshot path additionally caps total catalog count, index bytes, complete
snapshot bytes, per-object bytes, DNS answers, headers, and absolute elapsed
time. It writes verified objects directly into private staging rather than
holding an entire retained mirror in unbounded memory.

The static root contains only:

```text
index.json
index.ed25519
catalogs/
  <20-digit-sequence>-<manifest-digest-prefix>/
    manifest.json
    manifest.ed25519
    catalog.json
```

No raw OSV response, publisher cursor, state file, private key, signing-key
path, authentication header, customer data, or hub database content belongs in
the public root.

Example Linux invocation after a real source and public keys have been reviewed
and registered:

```bash
python scripts/build_advisory_mirror.py build \
  --registry-root /workspace/backend/advisory_feeds \
  --source osv-pypi-pysec-signed \
  --bundle /private/publisher/osv-pypi-00000042-example-digest \
  --existing-root /private/verified-prior-mirror \
  --output /private/publication/mirror-next \
  --index-key-id oaw-advisory-index-ed25519-YYYY-NN \
  --signing-key-file /run/secrets/oaw-advisory-index-key \
  --retain-prior 3
python scripts/build_advisory_mirror.py verify \
  --registry-root /workspace/backend/advisory_feeds \
  --source osv-pypi-pysec-signed \
  --root /private/publication/mirror-next
```

Use a protected Linux execution environment for real signing. A key file must
be a process-owned, mode-`0600`, single-link regular file; the production
workflow creates it below runner temporary storage with `mktemp`, disables
shell tracing, unsets the source environment variable, and removes the file
through an exit/signal trap. Shell history, workflow debug tracing,
command-line key values, caches, and artifacts are prohibited.

## Offline demonstration and tests

The demonstration generates only fictional OpenAssetWatch OSV records and uses
in-memory transient bundle and index keys:

```powershell
docker compose run --rm --no-deps -e PYTHONDONTWRITEBYTECODE=1 `
  --entrypoint python demo-seed scripts/demo_advisory_mirror.py
```

It covers full then incremental publisher output, two mirror builds, exact
index signatures, fixed-path loopback HTTP serving, production trusted-feed
synchronization, preview, administrator approval, activation, deterministic
affected-to-fixed match/finding/risk change, server shutdown, failed offline
sync with last-known-good preservation, retained-catalog rollback, and
advisory-only AI evidence with server-issued IDs. It writes only below a
temporary directory, uses no public network, persists no key, and imports no
third-party advisory data.

Focused tests in the locked backend environment:

```powershell
docker compose run --rm --no-deps -e PYTHONDONTWRITEBYTECODE=1 `
  --entrypoint python demo-seed -m unittest `
  backend.tests.test_advisory_mirror `
  backend.tests.test_advisory_mirror_demo `
  backend.tests.test_advisory_mirror_workflow
```

The opt-in PostgreSQL integration test must use a disposable database created
only for the test. It exercises the production SQL stores through remote mirror
preview, approval, activation, restart, and offline last-known-good recovery:

```powershell
docker compose exec -T postgres createdb -U openassetwatch oaw_mirror_validation
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace/backend `
  -e PYTHONDONTWRITEBYTECODE=1 `
  -e OPENASSETWATCH_MIRROR_POSTGRES_TEST=1 `
  -e OPENASSETWATCH_MIRROR_POSTGRES_DATABASE=oaw_mirror_validation `
  backend python -m unittest -v tests.test_advisory_mirror_postgres
docker compose exec -T postgres dropdb -U openassetwatch oaw_mirror_validation
```

Use a unique disposable name, verify it does not already exist, and drop only
that exact database after the test. Never point this test at the application
database.

## GitHub Actions publication gate

`.github/workflows/advisory-mirror-publish.yml` has two isolated paths:

- pull requests install the hashed backend lock and run only synthetic offline
  tests and the demo; they receive no publication secret and cannot upload or
  deploy a Pages artifact;
- scheduled or manual runs must execute from `main`, the repository variable
  `OPENASSETWATCH_ADVISORY_MIRROR_PUBLISH_ENABLED` must equal `true`, and the
  `advisory-mirror-production` environment must authorize the job.

Production setup, deliberately outside this branch, requires:

1. Review the real static HTTPS host and replace the `.invalid` source template.
2. Register the exact bundle and index public keys in `publishers.json`, place
   their IDs in the source, keep the source disabled through review, and then
   enable it in one reviewed change.
3. Create the protected `advisory-mirror-production` environment with required
   reviewers and no unprotected branch access.
4. Store `OPENASSETWATCH_ADVISORY_BUNDLE_SIGNING_KEY_BASE64` and
   `OPENASSETWATCH_ADVISORY_INDEX_SIGNING_KEY_BASE64` as separate environment
   secrets, or replace the first-party signing steps with reviewed managed
   signers. Configure non-secret variables
   `OPENASSETWATCH_ADVISORY_MIRROR_SOURCE_ID`,
   `OPENASSETWATCH_ADVISORY_BUNDLE_KEY_ID`, and
   `OPENASSETWATCH_ADVISORY_INDEX_KEY_ID`.
5. Configure the repository's Pages/static-host source for Actions and review
   the custom-domain/TLS settings. This branch does not enable or reconfigure
   Pages.
6. For the single first publication only, temporarily set
   `OPENASSETWATCH_ADVISORY_MIRROR_BOOTSTRAP_ENABLED=true` and run a manual
   `bootstrap: true` dispatch while no publication checkpoint or prior mirror
   exists. Remove or disable that variable immediately afterward. Every later
   run uses `bootstrap: false`.
7. Set `OPENASSETWATCH_ADVISORY_MIRROR_PUBLISH_ENABLED=true` only after the
   preceding controls pass review.

The protected job obtains public OSV data only on manual/scheduled runs. It
first verifies the existing mirror, seeds the stateless full publisher's next
bundle sequence from the greater of that authenticated sequence and a bounded
UTC nanosecond floor, and checks the live sequence/digest against a small
GitHub-side last-published checkpoint. A replayed or conflicting static-host
snapshot therefore fails before signing. The job then produces a new signed
bundle, rebuilds a snapshot retaining at least three prior catalogs when that
history exists, re-verifies the complete chain, and uploads a whole Pages
artifact. Only after deployment does the protected deploy job save the new
non-secret sequence/digest checkpoint. The checkpoint contains no advisory
corpus, key, token, or path. The deploy job alone receives `pages: write` and
`id-token: write`.
Checkout credentials are not persisted, all actions are pinned to full commit
SHAs, concurrency is serialized, and failures do not cancel the last known good
run.

## Rotation, corrections, compromise, and rollback

- Bundle and index keys are separate trust roles. The reviewed registry rejects
  both shared key IDs and identical Ed25519 public-key material across those
  roles; production secrets must also remain distinct.
- Add a new public key and trusted key ID before switching signatures. Keep the
  old bundle key active until every catalog it signed has aged out of mirror
  retention; the hub can still roll back an already retained database catalog
  after a key is retired. Remove trust only after consumer rollout is verified.
- A correction or withdrawal creates a new bundle version and higher sequence.
  Never alter or overwrite an immutable prior directory.
- On suspected compromise, disable the publication variable, revoke the key in
  the reviewed keyring, stop scheduled publication, preserve audit evidence,
  rotate through a separately reviewed key, and publish a new clean snapshot.
  There is no unsigned emergency mode.
- Missing, truncated, stale, conflicting, noncanonical, wrongly licensed, or
  invalidly signed prior content aborts before upload/deploy. Operators repair
  the source or intentionally perform a reviewed manual bootstrap; scheduled
  jobs never bootstrap themselves.
- If the independent GitHub checkpoint cache is unavailable, normal
  publication fails closed. Validate the currently deployed mirror and restore
  an independently reviewed checkpoint rather than bypassing continuity with a
  new bootstrap.
- Static-host rollback redeploys a previously preserved complete Pages
  artifact only after verifying its index and bundles. Hub rollback remains the
  existing retained-catalog administrator action and is independent of mirror
  rollback.

## Licensing and privacy boundary

Official publication is limited to the exact `PYSEC-*` Python Packaging
Advisory Database scope already approved with CC BY 4.0 obligations in
`docs/SOURCE_LICENSING_REGISTRY.md`. The index and every bundle repeat the
approved license, contributor attribution, OpenAssetWatch normalization notice,
and upstream provenance. Other OSV source families remain review-required and
must not enter the mirror. CISA KEV is not included.

The mirror contains public advisory intelligence only. Raw upstream responses
are not retained, and the publisher's bounded public credit strings are the
only expected personal-name-like content. Customer assets, findings, prompts,
tokens, authorization headers, internal hostnames, local paths, publisher
state, and private keys are excluded by design and checked before publication.

OSV retrieval is protected by HTTPS, but the upstream exported dataset is not
itself signed. OpenAssetWatch signs the normalized bundle, and the mirror index
authenticates selection of that bundle. Those signatures prove exact bytes and
the configured OpenAssetWatch signing identity; they do not prove that an
upstream advisory is correct. Preview and explicit administrator approval
remain mandatory before activation, and AI cannot approve or activate a feed.

## Static-host contract

Serve the generated directory as exact static bytes over HTTPS with no
redirect, authentication, cookies, HTML wrapping, JavaScript,
directory-listing dependency, or content transformation. Serve JSON as
`application/json` (or the committed OpenAssetWatch vendor media type) and
detached signatures as `application/octet-stream` or `text/plain`. Immutable
`catalogs/...` objects should receive a long immutable cache lifetime;
`index.json` and `index.ed25519` need a short cache lifetime or mandatory
revalidation. Publish all catalog objects first and expose the signed index
pair last, or deploy the complete directory atomically as the Pages workflow
does.

GitHub Pages does not offer this workflow precise per-path cache-header
control. That hosting option therefore relies on whole-artifact deployment plus
exact signatures, digests, expiry, the independent checkpoint, and hub
sequence/replay controls. An alternative static host may set the recommended
headers but must preserve the same bytes and ordering contract.

## Known limitations

- No official host or production key is registered yet, so the gated real job
  intentionally fails closed until maintainers complete activation.
- First publication cannot retain three unavailable predecessors. Retention
  reaches latest plus three prior catalogs after four successful publications.
- A newly installed hub cannot cryptographically prove that a valid unexpired
  signed index is globally freshest. Previously observed bundle sequences and
  retained hub history prevent later downgrade; availability/freshness
  monitoring remains an operator responsibility.
- GitHub Actions cache is used only for a tiny non-secret publication
  checkpoint and may be evicted; its absence blocks normal publication until
  operators restore continuity through a reviewed recovery.
- GitHub Pages is the initial static-host example, not a core dependency. Any
  future object store or CDN adapter must preserve exact bytes, HTTPS host
  review, atomic snapshot exposure, immutable paths, and the same index and
  bundle verification contracts.
