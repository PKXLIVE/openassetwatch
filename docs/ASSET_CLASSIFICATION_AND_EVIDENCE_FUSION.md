# Deterministic Asset Classification and Evidence Fusion

OpenAssetWatch classification is authoritative, deterministic Control Tower
data. It does not use an LLM, active fingerprinting, network probes, dynamic
rules, plugins, shell commands, or model-generated classifiers.

```text
endpoint and passive evidence
  -> source-aware evidence fusion
  -> oaw.classifier.v1
  -> current classification, history, and conflicts
  -> targeted deterministic findings and risk reevaluation
  -> read-only AI explanation
  -> human review
```

The AI Advisor may explain and cite a persisted classification. It cannot
create, change, supersede, or resolve one.

## Classification Model

The current model records:

- stable `cls_...` classification ID, site ID, and asset ID;
- classifier version;
- category, optional subtype/device role, manufacturer, product/model hint,
  OS family, and OS-version hint;
- four-dimensional managed-capability expectations;
- deterministic confidence and status;
- supporting and conflicting `cev_...` evidence IDs;
- independent-source and evidence counts;
- first/last classified and evaluated timestamps;
- freshness, bounded reason codes, and structured conflicts; and
- a superseded snapshot whenever a semantic result changes.

Statuses are `classified`, `partially-classified`, `unknown`, `conflicting`,
and `insufficient-evidence`. The implemented categories are:

- `workstation`
- `server`
- `mobile`
- `network-device`
- `printer`
- `camera`
- `media-device`
- `storage`
- `iot`
- `ot-industrial`
- `virtual-machine`
- `unknown`

A recognized OS or manufacturer can be retained without claiming a category.
An IP address contributes no classification signal. A hostname pattern remains
weak supporting evidence and does not establish identity.

## Static Signal Registry

`backend/app/classification.py` is the reviewed, versioned classifier registry.
Collected values are bounded strings used only as data against fixed mappings.
They cannot choose code.

| Signal | Base weight | Meaning and boundary |
| --- | ---: | --- |
| Direct category | 0.98 | Reviewed category from a server-authenticated endpoint source. Payload-declared source type or agent ID is never sufficient. |
| Direct device role | 0.94 | Category alias and optional subtype. |
| Direct endpoint OS | 0.91-0.96 category; 0.98 OS | Windows/macOS endpoint evidence may distinguish workstation/server when the value says server; Android/iOS maps to mobile. Linux OS alone does not guess server versus workstation. |
| Direct manufacturer/product | 0.95/0.92 | Attribute only; it does not prove device type. |
| DHCP vendor class | 0.73 | Reviewed printer, camera, mobile, network-device, and storage substrings. |
| mDNS service | 0.78 | Reviewed printer, media, storage, and camera services. |
| SSDP device type/server | 0.76 | Reviewed network-device, media, printer, camera, and storage strings. No SSDP URL is fetched. |
| NBNS name | 0.43 | Weak reviewed hostname-token mapping. |
| Hostname/DNS pattern | 0.34 | Weak supporting category mapping only. |
| OUI manufacturer | 0.72 | Manufacturer only. OUI never establishes category. |
| Passive OS/manufacturer/product | 0.55/0.62/0.55 | Attribute hints only. |
| IP or MAC address | 0 | Retained as bounded observation/identity context, not category evidence. |

Evidence strength is multiplied by source confidence and a freshness factor:

| Freshness | Age/source state | Factor |
| --- | --- | ---: |
| `fresh` | at most 24 hours | 1.00 |
| `aging` | over 24 and at most 72 hours | 0.80 |
| `stale` | over 72 hours | 0.35 |
| `unknown` | missing/invalid time | 0.45 |
| revoked source | historical evidence from a revoked source | 0.10 |

Evidence more than five minutes in the future is excluded from classification
and records `future-evidence-rejected`. The strict observation-batch contract
rejects that clock skew. Transitional local-inventory ingestion clamps it to
hub receive time so a bad client clock cannot pin current asset state.

Because adjusted weight is ranked before the direct-evidence tie-breaker, stale
direct evidence cannot automatically override sufficiently stronger fresh
evidence. Classification freshness is derived from the evidence that actually
supports or conflicts with the classification; an unrelated fresh IP does not
freshen a stale classification.

## Source-Aware Fusion and Confidence

Evidence identity includes site, asset, source type, source ID, collection
method, kind, and normalized value. Repeated observations update first/last
seen time and a capped observation count; they do not create independent
sources. For a source/method/kind, only its latest value participates in one
evaluation. Evaluation scans at most 4,096 candidate rows, admits at most 48
latest source/kind records from one source, prioritizes authenticated direct
evidence, and caps the final set at 256. PostgreSQL performs the latest
source/kind and per-asset bound before rows enter Python, so a noisy sensor
cannot evict trusted endpoint evidence by simply supplying newer duplicates.

Directness is server-derived. The authenticated observation-batch path may
mark an `endpoint-collector` source direct after its request identity is
validated. The transitional unauthenticated
`POST /api/v1/collections/local-inventory` route remains accepted for local
compatibility, but its payload-declared `agent_id`, `sensor_type`, or
`observation_source` cannot create direct evidence. The hub also replaces all
payload-declared source identities on that route with one server-assigned
`untrusted-transitional` identity, so callers cannot manufacture
independent-source agreement.

For each candidate category:

```text
adjusted signal =
  base weight * bounded source confidence * freshness factor

candidate score =
  strongest adjusted signal
  + min(0.05 * additional independent agreeing sources, 0.10)

classification confidence =
  candidate score
  + min(0.02 * populated supporting attributes, 0.08)
  - 0.22 when a material conflict exists
```

The final value is rounded to four decimal places and bounded to 0.00-0.99.
`classified` requires a score of at least 0.72; `partially-classified` requires
0.45. A lower category score becomes `unknown` with
`insufficient-evidence`. Attribute-only confidence is capped at 0.39.

This confidence measures evidence quality, not impact. Finding severity and
risk remain separate authoritative calculations.

## Conflicts and History

Independent material category, OS-family, OS-version, and device-role
disagreements are retained. A disagreement becomes material when independent
sources clear the fixed conflict thresholds; repeated values from one source
cannot create or amplify it. Strong fresh direct evidence normally wins over
weak inference without manufacturing a conflict. Two strong direct sources, or
strong direct evidence versus substantial passive evidence, preserve both
sides.

An open conflict:

- sets classification status to `conflicting`;
- subtracts 0.22 from confidence;
- records selected/conflicting values and their evidence IDs;
- opens or updates a `classification-conflict` finding; and
- remains explainable but not mutable through AI.

Reevaluation resolves a stored conflict only when current deterministic output
no longer contains it. Semantic classification changes copy the prior result
to `asset_classification_history` before the current row changes.

## Managed Capability

Managed capability describes normal evidence expectations for a class. It does
not label a device compliant, safe, or compromised.

| Category | Endpoint collector | Endpoint security | Software inventory | Patch management |
| --- | --- | --- | --- | --- |
| workstation, server, virtual machine | expected | expected | expected | expected |
| mobile | expected | expected | unknown | expected |
| network device, printer, camera, media device, storage, IoT, OT/industrial | not expected | not expected | not expected | unknown |
| unknown | unknown | unknown | unknown | unknown |

The finding engine uses this model so a printer, camera, or IoT device is not
called unmanaged merely because it cannot run an endpoint collector. A
workstation/server passive-only finding requires fresh passive evidence and no
historical endpoint evidence. A security-coverage gap requires fresh endpoint
evidence and an expected endpoint-security capability.

## Persistence and Evaluation Lifecycle

Startup adds only additive tables:

- `classification_evidence`
- `classification_runs`
- `asset_classifications`
- `asset_classification_history`
- `asset_classification_evidence`
- `classification_conflicts`

Canonical evidence ingestion commits before classification is queued.
Endpoint, Python collector, transitional local inventory, and passive
observation adapters enqueue only the affected site and asset IDs for new
collections. An idempotent replay does not enqueue evaluation.
Classification failure is logged with a bounded exception type and cannot
invalidate accepted evidence.

Evaluation supports one asset, up to 500 explicitly targeted assets, one site,
or an administrative global rebuild. Global and site-wide bulk requests share
a process-local cooldown; targeted requests remain available. A global load is
capped at 50,000 assets. Run records contain bounded scope, counts, timestamps,
classifier version, and secret-free error codes.

PostgreSQL advisory locks serialize classification reconciliation per asset.
Evidence loads are grouped by site and asset IDs, and the AI evidence snapshot
uses one bounded query rather than a per-asset query.

## API

Read endpoints follow the existing optional local admin-token convention.
When `OPENASSETWATCH_ADMIN_TOKEN` is configured,
`X-OpenAssetWatch-Admin-Token` is required.

- `GET /api/v1/classifications`
- `GET /api/v1/classifications/summary`
- `GET /api/v1/classifications/catalog/status`
- `GET /api/v1/classifications/assets/{asset_id}?site_id=...`
- `GET /api/v1/classifications/assets/{asset_id}/evidence?site_id=...`

List filters are bounded and parameterized: site, category, manufacturer, OS
family, endpoint-collector expectation, status, minimum confidence, and open/no
conflict. Pages are limited to 200 items and offsets to 10,000.

The mutation endpoint fails closed unless an admin token is configured:

```text
POST /api/v1/admin/classifications/evaluate
```

Examples:

```sh
curl -sS \
  -H "X-OpenAssetWatch-Admin-Token: ${OPENASSETWATCH_ADMIN_TOKEN}" \
  "http://127.0.0.1:8000/api/v1/classifications?site_id=demo-office&limit=50"

curl -sS -X POST \
  -H "Content-Type: application/json" \
  -H "X-OpenAssetWatch-Admin-Token: ${OPENASSETWATCH_ADMIN_TOKEN}" \
  --data '{"site_id":"demo-office","asset_id":"asset-office-workstation-demo","requested_by":"local-admin"}' \
  http://127.0.0.1:8000/api/v1/admin/classifications/evaluate
```

## Local Vendor/OUI Catalog

The catalog interface never performs Internet lookup or URL fetching. Runtime
uses the bundled fictional catalog unless
`OPENASSETWATCH_VENDOR_CATALOG_PATH` names an absolute local file. A catalog
can establish a manufacturer, never device type.

`oaw.vendor-catalog.v1` requires:

```json
{
  "schema_version": "oaw.vendor-catalog.v1",
  "catalog_version": "reviewed-version",
  "source": {
    "name": "reviewed source name",
    "license": "reviewed license identifier"
  },
  "entries": [
    {"prefix": "02AABB", "manufacturer": "Example Print Systems"}
  ]
}
```

`source.url` and a `sha256:<lowercase-hex>` checksum are optional metadata.
Unknown fields, duplicate prefixes, non-six-hex prefixes, invalid UTF-8/JSON,
more than 4,096 entries, or a file over 1 MiB are rejected.

The importer accepts only an absolute regular one-link source file. It rejects
symlinks/hard links and verifies that the opened inode still matches the named
path. On POSIX systems, the existing target directory must be owned by the
current user and not group/world writable; non-sticky writable ancestors and
symlinked ancestors are rejected. The opened directory descriptor must still
match the validated device/inode and ownership/mode before any write. The
importer writes a randomized exclusive `0600` temporary file through that
descriptor, flushes it, atomically replaces the fixed
`vendor-catalog.json`, and flushes the directory. It never follows a
user-provided target filename.

Catalog replacement fails closed outside POSIX because the current
implementation requires directory-relative open/rename semantics; catalog
loading and schema validation remain cross-platform. Run replacement inside
the Linux backend environment. This
example uses an ephemeral trusted target; mount a reviewed persistent directory
at that path when retaining the result:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend `
  sh -c 'install -d -m 0700 /tmp/oaw-catalog && python scripts/import_vendor_catalog.py --source /workspace/reviewed/vendor-catalog.json --target-directory /tmp/oaw-catalog'
```

Do not commit a real third-party OUI database until maintainers have reviewed
its source, license, redistribution terms, update process, checksum, and size.
The repository contains only fictional locally administered prefixes licensed
as `synthetic-test-data`.

## Findings, Risk, AI, and UI

`oaw.findings.v2` consumes the current classification. It adds an authoritative
classification-conflict finding and applies managed-capability expectations to
unknown, passive-only, and security-coverage rules. Reclassification triggers
targeted finding and risk replacement. Classification confidence flows into
finding confidence and therefore risk contribution without replacing finding
severity.

The AI Advisor exposes bounded read-only tools for classification summary,
asset classification/evidence/conflicts, unknown assets, categories,
managed-capability gaps, and confidence. Provider output must cite server-issued
IDs. The model cannot select tools from packet strings, execute a rule, or
override the deterministic result.

The existing dashboard uses the classification projection for category,
search, managed status, and detail. It shows basis, confidence, source/evidence
counts, freshness, and conflicts. Technical IDs remain collapsed and all
untrusted values use DOM `textContent`; there is no HTML injection path.

## Deterministic Demo

The pure local demo needs no database, Internet, capture interface,
credentials, or model:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend `
  python scripts/demo_asset_classification.py
```

It demonstrates:

- a Home printer inferred from mDNS;
- an Office workstation from direct endpoint category and OS evidence;
- a Lab server/printer conflict with both evidence references;
- a Lab printer-to-server reclassification with one history snapshot; and
- an advisory AI explanation citing both `cls_...` and `cev_...` records.

The Compose demo seed extends Home, Office, and Lab with endpoint, DHCP, mDNS,
SSDP, NBNS, fictional OUI, unknown, conflict, and reclassification examples,
then invokes the production classifier and findings engine.

## Adding a Reviewed Classifier

1. Confirm the normalized evidence field is durable, bounded, non-secret, and
   source/time aware.
2. Add a fixed mapping to `backend/app/classification.py`; never add dynamic
   expressions, a user-selected module, network fetch, shell, or model output.
3. Choose a conservative base weight and state whether the signal sets category
   or only an attribute.
4. Define its freshness, disagreement, identity, and false-positive boundary.
5. Add positive, negative, stale, repeated-source, independent-source,
   conflict, injection, and performance tests.
6. If it changes meaning, increment the classifier version and document
   reclassification behavior.
7. Review findings/risk effects and AI/UI projection without granting mutation
   authority.

## Validation

The backend lock targets Linux/Python 3.12, so run its complete tests through
the Docker backend environment:

```powershell
docker compose config
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace/backend backend `
  python -m unittest discover -s tests -v
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend `
  python -m unittest scripts.test_asset_classification_demo `
    scripts.test_control_tower_demo_seed scripts.test_control_tower_dashboard -v
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace/backend backend `
  python -m compileall -q app tests
docker compose run --rm --no-deps backend python -m pip check
```

The 10,000-asset pure-engine test is a development bound, not a database/load
benchmark. A production PostgreSQL concurrency and pagination test remains
necessary before increasing service limits.

## Security Properties and Limitations

- Packet-derived DHCP, mDNS, SSDP, NBNS, hostname, and vendor strings are
  bounded data and cannot select code.
- Only reviewed classification-safe evidence kinds are projected. Raw
  packet/frame/PCAP/payload/body/header and credential, key, bearer, cookie,
  session, password, secret, and token families are rejected.
- Payload-declared source identity cannot create direct evidence; direct
  endpoint authority requires a server-authenticated ingestion context.
- Evidence beyond the five-minute future-skew allowance is rejected or
  clamped at ingestion and excluded again by the classifier.
- No SSDP location is fetched; no callback URL, active scan, shell, or arbitrary
  HTTP endpoint exists.
- Catalog errors return bounded codes, not local paths or stack traces.
- Site and asset predicates are applied to classification/evidence reads;
  parameterized filters prevent SQL injection and cross-site API leakage.
- Source revocation discounts historical evidence instead of deleting audit
  history.
- Full/site rebuilds are bounded and rate limited; targeted ingestion avoids a
  full-table scan by applying site and requested asset IDs in SQL.
- The current classifier does not claim firmware, vulnerability, patch, owner,
  exposure, or compromise state.
- Tenant identity beyond the current site boundary, durable job scheduling,
  retention policy, migration tooling, production catalog distribution, and
  full database load testing remain future work.

The next asset-intelligence milestone should add normalized software and
firmware evidence with source/version provenance, followed by separately
licensed vulnerability intelligence. Vulnerability or patch findings must wait
until those data contracts and freshness semantics are durable and tested.
