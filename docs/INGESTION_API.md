# Ingestion API

This document records the first OpenAssetWatch backend ingestion endpoint for
Go local inventory collection JSON, plus the identity model needed for future
tenant, deployment, and CMDB reconciliation.

This pass implements backend import only. The Go agent does not call the
server yet, and this endpoint does not implement cloud sync, licensing
enforcement, enrollment, or CMDB connectors.

## Agent Check-In Endpoint

`POST /api/v1/agents/check-in`

The endpoint accepts identity and health metadata for a future enrolled agent:

```json
{
  "tenant_id": "tenant-example",
  "site_id": "site-local",
  "deployment_id": "11111111-1111-4111-8111-111111111111",
  "agent_id": "22222222-2222-4222-8222-222222222222",
  "sensor_id": "33333333-3333-4333-8333-333333333333",
  "agent_version": "0.1.0",
  "hostname": "workstation-01",
  "platform": {
    "os": "windows",
    "architecture": "amd64"
  },
  "check_in_at": "2026-06-17T12:00:00Z",
  "enrollment_token": "<enrollment-token-secret-ref>"
}
```

`site_id` is required. `tenant_id`, `deployment_id`, `agent_id`, `sensor_id`,
`agent_version`, `hostname`, `platform`, `check_in_at`, and
`enrollment_token` are optional for now.

The endpoint returns:

```json
{
  "status": "accepted",
  "site_id": "site-local",
  "agent_id": "22222222-2222-4222-8222-222222222222",
  "received_at": "2026-06-17T12:01:00Z",
  "message": "agent check-in accepted as identity and health metadata"
}
```

`deployment_id`, `agent_id`, and `sensor_id` must not be fabricated. If
`agent_id` is absent, the response omits it.

`enrollment_token` is a secret. It must never be returned in an API response,
logged as a full token, or stored in repository examples as a real value. The
first endpoint strips it from transitional in-memory storage.

Check-in metadata is not privileged truth. Hosted and hybrid deployments must
eventually bind tenant and deployment ownership through server-side enrollment
and authentication context, not arbitrary client-submitted values.

Top-level unsafe execution or credential fields are rejected, including
`command`, `args`, `additional_args`, `password`, `hash`, and
`script_content`.

See `docs/AGENT_CHECKIN.md` for the agent check-in identity model, installer
identity file direction, and token safety rules.

## Local Inventory Collection Endpoint

`POST /api/v1/collections/local-inventory`

The endpoint accepts JSON produced by:

```powershell
go run ./cmd/oaw-agent collect --once --site-id site-local
```

To manually post saved local collection JSON while the backend is running:

```powershell
go run ./cmd/oaw-agent collect --once --site-id site-local --output inventory.json

go run ./cmd/oaw-agent submit --file inventory.json --server-url http://localhost:8000
```

The submit command posts to `/api/v1/collections/local-inventory` using
`Content-Type: application/json`. In this pass, the backend URL must be
explicitly supplied with `--server-url`; OpenAssetWatch must not default to an
external service.

Manual import with `curl.exe` remains equivalent for local testing:

```powershell
curl.exe -X POST http://localhost:8000/api/v1/collections/local-inventory `
  -H "Content-Type: application/json" `
  --data-binary "@inventory.json"
```

The endpoint treats all submitted host, platform, interface, gateway, and
neighbor data as passive observations. Client-submitted values are not treated
as privileged truth and do not by themselves establish tenant ownership,
license entitlement, or final asset identity.

## Expected Request Shape

```json
{
  "schema_version": "oaw.inventory.v1",
  "tenant_id": "tenant-example",
  "site_id": "site-local",
  "deployment_id": "11111111-1111-4111-8111-111111111111",
  "agent_id": "22222222-2222-4222-8222-222222222222",
  "sensor_id": "33333333-3333-4333-8333-333333333333",
  "collected_at": "2026-06-17T12:00:00Z",
  "assets": [
    {
      "asset_id": "local-host",
      "site_id": "site-local",
      "external_ci_id": "ci-123",
      "external_ci_source": "ServiceNow",
      "hostname": "workstation-01",
      "fqdn": "workstation-01.example.test",
      "os": "windows",
      "platform": "windows/amd64",
      "architecture": "amd64",
      "host": {
        "hostname": "workstation-01",
        "source": "os_hostname",
        "collected_at": "2026-06-17T12:00:00Z"
      },
      "platform_info": {
        "os": "windows",
        "platform": "windows/amd64",
        "architecture": "amd64",
        "source": "go_runtime",
        "collected_at": "2026-06-17T12:00:00Z"
      },
      "primary_interfaces": [
        {
          "name": "Ethernet",
          "mac_address": "00:11:22:33:44:55",
          "ip_addresses": [
            {
              "address": "192.0.2.10",
              "family": "ipv4",
              "interface": "Ethernet",
              "source": "go_net_interfaces",
              "collected_at": "2026-06-17T12:00:00Z"
            }
          ],
          "source": "go_net_interfaces",
          "collected_at": "2026-06-17T12:00:00Z"
        }
      ],
      "ip_addresses": [],
      "mac_addresses": [],
      "default_gateway": {
        "address": "192.0.2.1",
        "interface": "Ethernet",
        "source": "windows_get_net_route",
        "collected_at": "2026-06-17T12:00:00Z"
      },
      "network_neighbors": [
        {
          "ip_address": "192.0.2.1",
          "mac_address": "66:77:88:99:aa:bb",
          "interface": "Ethernet",
          "state": "reachable",
          "source": "windows_get_net_neighbor",
          "collected_at": "2026-06-17T12:00:00Z"
        }
      ]
    }
  ]
}
```

`tenant_id`, `deployment_id`, `agent_id`, and `sensor_id` are optional for now.
The backend must not fabricate them when they are missing.

## Validation Rules

- malformed JSON is rejected by the API layer
- empty payloads are rejected
- `site_id` is required
- `deployment_id`, `agent_id`, and `sensor_id` are optional until enrollment
  and installed identity are implemented
- `external_ci_id` and `external_ci_source` are accepted only as optional
  reconciliation hints
- `assets` must be a JSON array when present
- top-level unsafe execution, credential, or raw scope selector fields are
  rejected, including `command`, `args`, `additional_args`, `username`,
  `password`, `hash`, and `script_content`

## Response Shape

```json
{
  "status": "accepted",
  "observation_batch_id": 1,
  "site_id": "site-local",
  "received_at": "2026-06-17T12:01:00Z",
  "observed_asset_count": 1,
  "message": "local inventory collection accepted as passive observations"
}
```

## Durable MVP Storage

The Control Tower foundation stores accepted agent check-ins and local
inventory collections in PostgreSQL. Raw local inventory payloads are retained
as evidence, then minimally normalized into `control_tower_assets` records with
site ID, host, primary IP, MAC address, OS, platform, source agent ID, first and
last seen timestamps, and an evidence count.

This is still MVP normalization. Tenant authorization, enrollment-token
issuance, full asset reconciliation, richer audit records, findings, and CMDB
matching remain future backend workstreams.

## Passive Observation Safety Model

Backend ingestion does not perform active collection. It does not run network
discovery, connect to observed hosts, validate credentials, execute commands,
load tool configs, or load anything from `configs/quarantine/`.

The endpoint accepts passive local observations that were already collected by
the agent from local operating-system state:

- host identity
- platform details
- network interface inventory
- IP and MAC address observations
- default gateway observations
- local neighbor/ARP cache observations

It must not introduce CIDR discovery, port checks, packet injection, credential
handling, command execution, or trust elevation based only on client-submitted
JSON.

Agent check-in follows the same safety boundary. It accepts identity and health
metadata only; it does not execute commands, validate credentials, perform
active network collection, or load quarantined configuration material.

Agent submit is the only agent-side network action added in this workstream. It
performs a single POST to the explicitly configured OpenAssetWatch backend URL,
does not add arbitrary headers, does not include enrollment tokens, and does
not retry aggressively.

## Current State

OpenAssetWatch already has a partial durable identity model in the transitional
Python collector and backend:

- Python collector installers can create and preserve a `collector_guid`.
- Python collector payloads can include `deployment` metadata with a
  `deployment_id`.
- Backend storage already has collector and inventory columns for
  `collector_guid` and `deployment_id`.

The new Go local inventory model did not previously expose a first-class
deployment/agent identity envelope. This pass adds optional Go model fields so
future ingestion can carry durable identity without fabricating values during
local collection.

## Required Identity Fields

- `tenant_id`: customer/account boundary. Optional for self-hosted
  single-tenant mode for now; required for hosted/multi-tenant control planes.
- `site_id`: required environment, site, workspace, or operational boundary.
- `deployment_id`: unique GUID for an installer or deployment package. It is
  safe to log and should identify the deployment wrapper/config, not a secret.
- `agent_id`: unique installed agent instance ID. It should be generated on
  first install or first run and persisted locally.
- `sensor_id`: unique installed sensor instance ID. It should be generated on
  first install or first run and persisted locally.
- `asset_id`: OpenAssetWatch asset identity after normalization and matching.
- `external_ci_id`: optional external CMDB CI identifier for future
  reconciliation.
- `external_ci_source`: optional external CMDB source name, such as
  `ServiceNow`, `Jira Assets`, or `Device42`.

## Installer And Enrollment Design

Signed binaries and native installers should remain generic where possible.
Tenant, site, deployment, and enrollment identity should be supplied through one
of these scoped inputs:

- deployment config
- enrollment config
- installer wrapper
- MDM/RMM deployment profile
- self-hosted administrator-provided config

Do not store raw secrets in the repository or in example configs. Enrollment
tokens, license keys, signing keys, and customer secrets must be represented as
secret references or placeholders only.

`deployment_id` is safe to log. Enrollment tokens are secrets and must not be
logged after initial validation.

Agent check-in accepts an `enrollment_token` field as a future enrollment proof
placeholder, but this first backend implementation does not complete
enrollment. The token must be treated as a secret and excluded from responses,
logs, and repository examples.

## Local Collection Behavior

`oaw-agent collect --once` currently emits local inventory JSON and sets
`site_id` when provided by CLI/config. It does not yet generate or persist
`deployment_id`, `agent_id`, or `sensor_id`.

The Go inventory model now includes optional top-level identity fields:

- `tenant_id`
- `site_id`
- `deployment_id`
- `agent_id`
- `sensor_id`

The current local JSON uses `assets` for collected asset observations. Future
backend ingestion may stage these as `asset_observations` internally, but any
public JSON rename should be versioned rather than silently changing the
current schema.

The model also includes optional asset-level CMDB reconciliation fields:

- `external_ci_id`
- `external_ci_source`

TODO: add enrollment/install identity loading for Go agent and sensor runtimes.
That work should generate durable `agent_id` or `sensor_id` once, persist it
locally, and include deployment identity from scoped config without inventing
IDs silently.

## Future Durable Ingestion Shape

Future durable ingestion should continue accepting an inventory envelope shaped
like:

```json
{
  "schema_version": "oaw.inventory.v1",
  "tenant_id": "tenant-example",
  "site_id": "site-local",
  "deployment_id": "11111111-1111-4111-8111-111111111111",
  "agent_id": "22222222-2222-4222-8222-222222222222",
  "collected_at": "2026-06-17T12:00:00Z",
  "assets": []
}
```

For self-hosted single-tenant mode, `tenant_id` may be omitted initially. For
hosted and hybrid managed deployments, tenant ownership must come from
server-side enrollment context rather than trusting arbitrary client-provided
tenant claims.

## CMDB Reconciliation Direction

OpenAssetWatch should reconcile observed assets to external CMDB CIs using
evidence such as:

- hostname
- FQDN
- serial number
- MAC address
- IP address
- cloud instance ID
- device management ID
- EDR ID
- source confidence and observation freshness

CMDB reconciliation should be evidence-based and auditable. External CI fields
should identify mapping candidates or accepted mappings; they must not replace
OpenAssetWatch's own `asset_id` normalization and matching process.

## Non-Goals For This Pass

- no cloud sync
- no licensing enforcement
- no CMDB connector
- no durable observation storage or asset matching migration
- no secrets in docs or config examples
- no change to quarantine policy
