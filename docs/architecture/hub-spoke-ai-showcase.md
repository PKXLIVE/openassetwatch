# Hub-and-Spoke AI Showcase Foundation

OpenAssetWatch uses a hub-and-spoke architecture. The Control Tower hub owns
normalized inventory, history, classification, findings, attention scoring, AI
policy, provider configuration, authentication boundaries, and audit metadata.
Spokes collect narrowly scoped evidence at a site and send authenticated
outbound updates to the hub.

This document describes the first implemented AI showcase foundation. The AI
showcase does **not** capture packets itself. It consumes normalized evidence
from endpoint collectors and the separately implemented passive network sensor
MVP documented in `docs/PASSIVE_SENSOR_MVP.md`. Sensor enrollment, credential
rotation, and revocation are documented in `docs/SENSOR_ENROLLMENT.md`.

The showcase remains a read-only AI experience, not a production authorization
or autonomous-remediation system.

## Runtime Shape

```text
Windows / Linux / macOS collectors       Linux passive network sensor
SNMP / cloud / vulnerability / SIEM      Future reviewed connectors
                \                              /
                 outbound authenticated batches
                              |
                              v
                 Control Tower Hub API
          site + sensor identity + freshness
                              |
                              v
            PostgreSQL normalized evidence
 assets + classification + components + matches + findings + audit
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
spoke. Spokes expose no inbound management port by default. The passive sensor
uses a bounded private spool for hub outages and retries stable batch
identifiers without uploading packet payloads.

## Implemented Domain Model

The existing `sites`, `agent_enrollments`, `agent_checkins`,
`local_inventory_collections`, and `control_tower_assets` records remain the
foundation. The hub also persists source-aware classification evidence,
components, vulnerability matches, findings, score factors, sensor identity,
and AI run audit metadata.

Normalized observations include:

- stable `site_id` and hub-managed site metadata;
- stable `sensor_id` represented by an enrolled spoke identity;
- sensor name, type, version, last-seen time, and derived health;
- enrolled identity and credential status;
- observation source and observation time;
- stable client `observation_batch_id`;
- `live` or `cached-retry` delivery state;
- source confidence and derived data freshness.

Initial showcase freshness thresholds are deterministic policy, not universal
production policy. The authoritative finding lifecycle and scoring behavior are
documented in `docs/DETERMINISTIC_FINDINGS_AND_RISK.md`. Software, firmware,
and vulnerability intelligence are documented in
`docs/SOFTWARE_AND_VULNERABILITY_INTELLIGENCE.md`.

## Outbound Observation Batch Contract

Spokes submit normalized evidence to:

`POST /api/v1/observations/batches`

The endpoint follows the repository's collector-token boundary. Sensor-specific
enrollment and credential behavior are handled by the sensor identity routes.
Any non-local deployment must use the configured authentication controls and
TLS.

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
      "category": "router",
      "evidence": [
        {
          "protocol": "vlan",
          "kind": "vlan-id",
          "value": "100",
          "confidence": 1.0
        }
      ]
    }
  ]
}
```

The schema is strict and bounded. Unknown fields, including packet, command,
script, credential, and arbitrary-metadata channels, are rejected. A repeated
`(site_id, sensor_id, observation_batch_id)` returns the original storage
identity and does not duplicate evidence. `cached-retry` preserves the original
observation time instead of pretending the data was collected at hub receipt.

Classification, risk, management posture, vulnerability applicability, and
finding IDs are hub-owned decisions and are not accepted from a spoke. The
older local-inventory normalizer also strips reserved hub fields before
persistence.

The passive sensor implements the contract with bounded protocol evidence,
conservative site/MAC/VLAN correlation, a private durable spool, and
authenticated outbound-only delivery. It does not upload packets or follow
SSDP-discovered URLs.

## Read-Only Hub API

The showcase exposes bounded hub and Advisor surfaces, including:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/hub/sites/summary` | Site, asset, finding, score, sensor, and freshness summaries. |
| `GET /api/v1/hub/sensors` | Enrolled spoke identity, health, last check-in, source, and freshness. |
| `GET /api/v1/ai/status` | Provider mode and availability without secrets or the configured URL. |
| `POST /api/v1/ai/advisor/query` | A read-only question over allowlisted evidence tools. |

Additional deterministic APIs provide classifications, components,
vulnerability matches, findings, and score factors. These endpoints follow the
existing optional admin-token convention. State-changing administrative routes
fail closed when required authorization is not configured.

The current implementation has site scoping and distinct collector, sensor, and
admin boundaries. It does not yet provide complete hosted tenant isolation,
user accounts, tenant-aware RBAC, token issuance, or a production audit viewer.
Those are required before shared or hosted multi-tenant operation.

## AI Provider Design

The provider receives only a bounded, allowlisted projection. It never receives
a database connection, tool callback, shell, filesystem, packet source,
write-capable OpenAssetWatch route, or user-controlled URL.

### Deterministic demo provider

`OPENASSETWATCH_AI_PROVIDER=demo` is the default. It:

- makes no network request;
- requires no provider credential;
- deterministically answers supported environment, site, sensor, asset,
  finding, component, vulnerability, change, freshness, and comparison
  questions;
- returns the same typed response contract as an external provider;
- cites server-issued evidence IDs and caps confidence when evidence is absent.

The demo provider demonstrates the contract. It is not evidence of live-model
accuracy.

### Optional OpenAI-compatible provider

The interface is protocol-compatible rather than tied to one mandatory vendor.
The same variables support either an approved model running on the
OpenAssetWatch machine or a hosted provider:

| Variable | Meaning |
| --- | --- |
| `OPENASSETWATCH_AI_PROVIDER=openai-compatible` | Select the generic interface. |
| `OPENASSETWATCH_AI_EXTERNAL_ENABLED` | Keep `false` for a local model; hosted providers require `true`. |
| `OPENASSETWATCH_AI_BASE_URL` | Administrator-controlled API base. Local HTTP is allowlisted; hosted providers require HTTPS. |
| `OPENASSETWATCH_AI_MODEL` | Configured model identifier. |
| `OPENASSETWATCH_AI_API_KEY` | Optional for approved local endpoints; required for hosted providers. |
| `OPENASSETWATCH_AI_TIMEOUT_SECONDS` | Bounded request timeout. |
| `OPENASSETWATCH_AI_QUALIFICATION_RESULT` | Optional operator-owned local qualification record. |
| `OPENASSETWATCH_AI_MODEL_MANIFEST` | Optional operator-owned model artifact provenance manifest; exact qualification binding is required when configured. |
| `OPENASSETWATCH_AI_REQUIRE_MODEL_MANIFEST` | Opt-in policy requiring a valid complete local manifest. |
| `OPENASSETWATCH_AI_ARTIFACT_ADVISORIES` | Optional reviewed local artifact advisory registry. |

Plain HTTP is accepted only for approved local hosts. Other private, reserved,
link-local, metadata-service, or arbitrary HTTP targets are rejected. Hosted
endpoints require HTTPS, explicit external enablement, and an API key.

The status check calls only the bounded `/models` endpoint. Chat uses only
`POST /chat/completions`; no provider function, browsing, file, URL, code,
shell, or tool-execution capability is requested. Redirects are rejected.

Provider responses are capped, parsed as JSON, and validated against a strict
schema. Every returned evidence ID must match the server-issued catalog. An
unknown ID rejects the response. Errors return bounded messages without
provider bodies, secrets, internal prompts, or stack traces.

### Local model example

An approved local OpenAI-compatible service can be configured through ignored
runtime environment values. Local model services remain outside the tracked
Compose stack unless a separately reviewed deployment workstream changes that
boundary.

## Tool and Prompt Trust Boundary

The service selects tools deterministically from the question. There is no
request field for a tool name and no provider function-calling surface. The
read-only tool catalog covers bounded environment, site, sensor, asset,
classification, component, vulnerability, finding, score-factor, change,
evidence, and freshness projections.

Each tool projects named fields with bounded records and text size. The model
cannot select arbitrary SQL, joins, tables, files, commands, URLs, or network
targets.

Hostnames, DNS names, software labels, banners, catalog text, findings, and
other collected values are untrusted data. They are placed only in the data
section of the provider request. They cannot add tools or override the server
allowlist. The UI inserts answer and evidence values with DOM `textContent`; it
does not render model HTML.

The hub stores bounded AI audit metadata in `ai_advisor_runs`, including run
identity, a question hash, optional site scope, provider/mode, selected tools,
evidence count, status, and timestamp. It intentionally does not store the raw
question, prompt, provider credential, or authorization header.

## Typed Response

An Advisor response includes:

- answer;
- evidence items with source, entity association, observation time, freshness,
  and confidence;
- affected sites, sensors, and assets derived from accepted evidence;
- advisory recommended actions;
- overall confidence;
- `data_as_of`;
- provider and mode;
- `live`, `cached`, or `demonstration` state;
- tools used, warnings, and limitations.

If no supported evidence remains, confidence is capped and the UI marks the
answer as unverified.

## Local Demonstration

The local stack and deterministic seed demonstrate Home, Office, and Lab sites;
endpoint and passive evidence; healthy, delayed, and stale sensor states;
assets and findings; software/firmware inventory; synthetic vulnerability
matches; and evidence-backed Advisor responses.

The seed uses fictional or documentation-range data and production
deterministic evaluators. It does not establish production performance or
provider accuracy.

## Privacy and Data Handling

- Default demo mode sends nothing to an AI provider.
- Enabling a hosted provider is an explicit data-sharing decision.
- Approved local endpoints report local mode and keep processing on the local
  machine.
- Only bounded normalized projections are sent, but they may still contain
  operational identifiers and findings.
- Secrets, raw packets, arbitrary metadata, SQL, filesystem data, and hidden
  prompts are outside the provider contract.
- Provider keys and OpenAssetWatch tokens must come from runtime secret handling
  and must never be committed, returned, or logged.
- Hosted operation requires tenant-scoped authorization, retention, provider
  allowlists, privacy controls, and customer-visible data-sharing choices.

## Current Limitations and Follow-Up

These limitations describe the current product and showcase accurately:

- the AI runtime is one bounded Advisor, not a multi-agent coordinator with
  specialist identities and typed handoffs;
- the MCP stdio command remains a foundation stub rather than an integrated
  agent surface;
- no model or agent can write authoritative facts, findings, scores, decisions,
  suppressions, or remediation actions;
- no user account system, complete tenant isolation, tenant-aware RBAC, or
  production audit viewer exists;
- the sensor credential authenticates an enrolled sensor but does not provide
  hardware attestation of the machine running it;
- IPv6 neighbor discovery, LLDP, broader protocol support, and any safe-active
  discovery remain follow-up work;
- no general natural-language planner, vector memory, autonomous agent, or
  remediation executor exists;
- the external provider interface has schema validation but does not yet have a
  provider compatibility matrix, repeated-run reliability program, or adaptive
  prompt-injection campaign;
- the static UI provides fixed drilldowns, not a semantic metrics layer,
  approved panel catalog, or AI-composed investigation dashboards;
- hosted and multi-tenant deployment remain architecture planning rather than
  production capability.

The accepted direction and gates for identity, source licensing, risk decision
bands, VEX, multi-agent work, adaptive dashboards, evaluation, and hosted
operation are recorded in
`docs/architecture/decisions/0001-research-aligned-expansion.md`.

## Vendor-Neutral Core and Splunk Roadmap

The core event, asset, evidence, finding, vulnerability, score, and AI schemas
remain vendor-neutral. OpenAI-compatible transport is optional; no provider is
mandatory.

OpenAssetWatch still plans a dedicated future Splunk Technology Add-on,
`TA-openassetwatch`. The add-on should map stable core events to Splunk
sourcetypes, knowledge objects, and appropriate CIM fields. Splunk naming and
runtime dependencies must stay in that integration rather than shaping the
hub's canonical schema.
