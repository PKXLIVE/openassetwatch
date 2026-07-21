# Hub-and-Spoke AI Showcase Foundation

OpenAssetWatch uses a hub-and-spoke architecture. The Control Tower hub owns
normalized inventory, history, correlation, findings, AI policy, provider
configuration, authentication, and audit records. Spokes collect narrowly
scoped evidence at a site and send authenticated outbound updates to the hub.

This document describes the first implemented AI showcase foundation. It is a
small, read-only demonstration over existing normalized inventory; it is not a
production authorization system or a passive packet-capture sensor.

## Runtime Shape

```text
Windows / Linux / macOS collectors       Future passive network sensor
SNMP / cloud / vulnerability / SIEM      Future evidence connectors
                \                              /
                 outbound authenticated batches
                              |
                              v
                 Control Tower Hub API
          site + sensor identity + freshness
                              |
                              v
            PostgreSQL normalized evidence
        assets + findings + AI run audit metadata
                              |
                              v
        bounded read-only AI tool gateway
                              |
               +--------------+--------------+
               |                             |
      deterministic demo          optional configured
       provider (default)        OpenAI-compatible provider
               |                             |
               +--------------+--------------+
                              |
                              v
               evidence-backed AI response
```

The AI runs at the hub. It does not run on a spoke and cannot connect back to a
spoke. Future spokes should expose no inbound management port by default,
retain observations locally during a hub outage, and retry the same stable
batch identifier after connectivity returns.

## Implemented Domain Model

The existing `sites`, `agent_enrollments`, `agent_checkins`,
`local_inventory_collections`, and `control_tower_assets` records remain the
foundation. The showcase adds these normalized observation properties:

- stable `site_id` and hub-managed site name/description
- stable `sensor_id` represented by an enrolled spoke identity
- sensor name, type, version, last-seen time, and derived health
- enrolled identity status
- observation source and observation time
- stable client `observation_batch_id`
- `live` or `cached-retry` delivery state
- source confidence and derived data freshness

Sensor status is derived at read time: up to 30 minutes is healthy, 31-90
minutes is delayed, and more than 90 minutes is stale. Inventory freshness is
fresh for 60 minutes, aging through 24 hours, then stale. These initial
thresholds are deterministic showcase policy, not final production policy.

Risk and findings are currently deterministic projections over normalized
asset metadata. This avoids a premature findings storage migration while still
giving the Advisor stable finding IDs, scores, sources, observation times, and
confidence. A future rules-engine workstream can promote these records into a
dedicated versioned finding history.

## Outbound Observation Batch Contract

Future spokes submit normalized evidence to:

`POST /api/v1/observations/batches`

The endpoint uses the existing optional collector-token enforcement pattern.
When `OPENASSETWATCH_COLLECTOR_TOKEN` is configured, the caller must provide it
in `X-OpenAssetWatch-Collector-Token`.

Example normalized batch:

```json
{
  "schema_version": "oaw.observation-batch.v1",
  "observation_batch_id": "sensor-home:20260720T120000Z:0001",
  "site_id": "home",
  "sensor_id": "sensor-home",
  "sensor_name": "Home Passive Sensor",
  "sensor_type": "passive-network-sensor",
  "sensor_version": "0.1.0",
  "observed_at": "2026-07-20T12:00:00Z",
  "observation_source": "passive-network",
  "delivery_state": "cached-retry",
  "confidence": 0.9,
  "assets": [
    {
      "asset_id": "home-router",
      "hostname": "home-router",
      "primary_ip": "192.0.2.1",
      "mac": "02:00:5e:10:00:01",
      "category": "router"
    }
  ]
}
```

The schema is strict and capped at 500 assets. Unknown fields, including raw
packet or command channels, are rejected. A `(site_id, sensor_id,
observation_batch_id)` retry returns the original storage identifier and does
not add the same evidence twice. `cached-retry` records an offline queue retry;
it does not reduce the submitted observation time to the hub receive time.

Risk, management posture, and finding IDs are hub-owned decisions and are not
accepted from a spoke. The older local-inventory normalizer also strips those
reserved hub fields before persistence. This contract accepts normalized
observations only. It does not accept packet payloads, PCAP data, credentials,
scripts, arbitrary attributes, or collection instructions. The actual passive
network sensor, its local cache, backoff, and capture-free normalization
pipeline remain a separate branch.

## Read-Only Hub API

The showcase adds:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/hub/sites/summary` | Bounded site, asset, finding, risk, sensor, and freshness summaries. |
| `GET /api/v1/hub/sensors` | Enrolled spoke identity, health, last check-in, source, and freshness. |
| `GET /api/v1/ai/status` | Provider mode and availability without secrets or the configured URL. |
| `POST /api/v1/ai/advisor/query` | A read-only question over allowlisted evidence tools. |

These endpoints use `X-OpenAssetWatch-Admin-Token` when
`OPENASSETWATCH_ADMIN_TOKEN` is configured. An empty value preserves the
repository's local-development convention. Any non-local or shared deployment
must configure a strong secret and terminate TLS before exposing the API.

The first version has a single optional admin-token boundary, not users, roles,
tenant authorization, or token issuance. Those are required before a hosted or
multi-tenant deployment.

## AI Provider Design

The provider interface receives only a bounded, allowlisted projection. It
never receives a database connection, tool callback, shell, filesystem,
packet source, or user-controlled URL.

### Deterministic demo provider

`OPENASSETWATCH_AI_PROVIDER=demo` is the default. It:

- makes no network request
- requires no provider credential
- deterministically answers the supported site, sensor, asset, finding,
  change, freshness, and comparison questions
- returns the same typed response contract as an external provider
- cites OpenAssetWatch evidence IDs and caps confidence when evidence is absent

### Optional OpenAI-compatible provider

The interface is intentionally protocol-compatible rather than tied to a
mandatory vendor. The same variables support either a model running on the
OpenAssetWatch machine or a hosted provider:

| Variable | Meaning |
| --- | --- |
| `OPENASSETWATCH_AI_PROVIDER=openai-compatible` | Select the generic OpenAI-compatible interface. |
| `OPENASSETWATCH_AI_EXTERNAL_ENABLED` | Keep `false` for a local model; hosted providers require `true`. |
| `OPENASSETWATCH_AI_BASE_URL` | Administrator-controlled API base. Local HTTP is allowlisted; hosted providers require HTTPS. |
| `OPENASSETWATCH_AI_MODEL` | Configured model identifier. |
| `OPENASSETWATCH_AI_API_KEY` | Optional for approved local endpoints; required for hosted providers. |
| `OPENASSETWATCH_AI_TIMEOUT_SECONDS` | Request timeout: 2-90 seconds locally and 2-30 seconds for hosted providers. |

Plain HTTP is accepted only for `localhost`, `127.0.0.1`, `::1`, and
`host.docker.internal`. Other private, reserved, link-local, metadata-service,
or arbitrary HTTP targets are rejected. Hosted endpoints require HTTPS,
explicit external enablement, and an API key.

The local status check calls the bounded OpenAI-compatible `/models` endpoint,
verifies that the configured model is installed, and never sends an
Authorization header when the key is blank. Redirects are rejected. Chat uses
only `POST /chat/completions`; no provider tool, function, browsing, file, URL,
code, or shell capability is requested.

Provider responses are capped, parsed as JSON, and validated against a strict
schema. Every returned evidence ID must match the server-issued evidence
catalog; an unknown ID rejects the response. Provider errors return bounded
`502` or `503` messages without response bodies, authorization headers, URLs,
keys, internal prompts, or stack traces.

### Local Ollama example

Ollama remains a separate host service and is not added to the Compose stack.
For the confirmed local model, place this configuration in the ignored `.env`
file:

```dotenv
OPENASSETWATCH_AI_PROVIDER=openai-compatible
OPENASSETWATCH_AI_EXTERNAL_ENABLED=false
OPENASSETWATCH_AI_BASE_URL=http://host.docker.internal:11434/v1
OPENASSETWATCH_AI_MODEL=qwen3.6:27b
OPENASSETWATCH_AI_API_KEY=
OPENASSETWATCH_AI_TIMEOUT_SECONDS=90
```

Recreate only the backend and inspect its privacy/status fields:

```powershell
docker compose up -d --no-deps --force-recreate backend
Invoke-RestMethod http://127.0.0.1:8000/api/v1/ai/status
```

To restore deterministic mode without editing tracked files:

```powershell
$env:OPENASSETWATCH_AI_PROVIDER = "demo"
docker compose up -d --no-deps --force-recreate backend
Invoke-RestMethod http://127.0.0.1:8000/api/v1/ai/status
```

Remove the temporary shell override with
`Remove-Item Env:OPENASSETWATCH_AI_PROVIDER` before activating the ignored
`.env` configuration again.

## Tool And Prompt Trust Boundary

The service selects tools deterministically from the question. There is no
request field for a tool name and no provider function-calling surface. The
allowlist is:

- environment summary
- site summary
- sensor health
- highest-risk assets
- unmanaged or weakly managed assets
- findings grouped by site
- recent inventory changes
- evidence for a specific asset
- data freshness

Each tool projects only named fields and returns no more than 50 records. The
provider context is capped at 60,000 characters and evidence at 30 items.

Hostnames, DNS names, software labels, banners, findings, and other collected
text are untrusted data. They are placed only in the data section of the
external request. They cannot add tools or override the server allowlist. The
UI inserts all answer and evidence values with DOM `textContent`; it does not
render model HTML.

The hub stores AI audit metadata in `ai_advisor_runs`: run ID, SHA-256 of the
question, optional site scope, provider/mode, selected tool names, evidence
count, status, and timestamp. It intentionally does not store the raw question,
prompt, provider credential, or authorization header.

## Typed Response

An Advisor response includes:

- answer
- evidence items with source, site/sensor/asset association, observation time,
  freshness, and confidence
- affected sites, sensors, and assets derived from accepted evidence references
- advisory recommended actions
- overall confidence
- `data_as_of`
- provider and mode
- `live`, `cached`, or `demonstration` data state
- tools used, warnings, and limitations

If no supported evidence remains, confidence is capped at 35 percent and the
UI explicitly marks the answer as unverified.

## Local Demonstration

Start and seed the local stack:

```powershell
docker compose up -d --build --remove-orphans
docker compose --profile demo run --rm demo-seed
docker compose ps
```

Open `http://localhost:8080/#ai-advisor`. The seed creates Home, Office, and
Lab locations; one passive sensor plus an endpoint collector per site; healthy,
delayed, and stale health examples; twelve assets; and findings at all three
sites. Office observations demonstrate a cached retry.

The default demo provider is ready immediately. Example prompts in the UI cover
environment summary, attention priority, highest-risk site, stale sensors, and
cross-site comparison. If an admin token is configured, enter it in the
session-only password field. The UI does not persist it.

## Privacy And Data Handling

- Default demo mode keeps all processing in the hub and sends nothing to an AI
  provider.
- Enabling a hosted provider is an explicit data-sharing decision. Only the
  bounded normalized projection is sent, but it can still contain operational
  asset identifiers and findings.
- Approved local OpenAI-compatible endpoints report `mode: local` and
  `external_data_sharing: false`; processing remains on the local machine.
- Secrets, raw packets, arbitrary metadata, SQL, filesystem data, and hidden
  prompts are outside the provider contract.
- Provider keys and admin/collector tokens must come from runtime secret
  handling and must never be committed, returned, or logged.
- Hosted deployments need tenant-scoped authorization, retention policy,
  provider allowlists, and customer-visible data-sharing controls before use.

## Limitations And Follow-Up

- no real passive network sensor or packet collection
- no spoke-side durable queue, retry backoff, enrollment exchange, or signed
  identity yet
- the shared collector token authenticates ingestion but does not yet bind a
  token to one site/sensor identity; production enrollment must add that binding
- no tenant isolation, user accounts, RBAC, or production audit viewer
- no dedicated versioned findings/history table yet
- no general natural-language planner, vector database, autonomous agent, or
  remediation path
- the external provider interface has schema validation but no evaluation or
  provider-specific compatibility matrix yet
- the static UI is a showcase addition, not the broader dashboard redesign

The next sensor branch should implement stable local identity persistence,
outbound TLS authentication, a size-bounded encrypted local queue, idempotent
retry with jitter/backoff, heartbeat behavior, and normalization into this
contract without retaining or uploading packets.

## Vendor-Neutral Core And Splunk Roadmap

The core event, asset, evidence, finding, and AI schemas remain vendor-neutral.
OpenAI-compatible transport is optional; no provider is mandatory.

OpenAssetWatch still plans a dedicated future Splunk Technology Add-on,
`TA-openassetwatch`. The add-on should map stable core events to Splunk
sourcetypes, knowledge objects, and appropriate CIM fields. Splunk naming and
runtime dependencies must stay in that integration rather than shaping the
hub's canonical schema.
