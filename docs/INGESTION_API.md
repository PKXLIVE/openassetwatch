# Ingestion API Identity Model

This document records the identity model needed before adding the Go agent
ingestion endpoint. It is design documentation only in this pass. It does not
implement backend ingestion, cloud sync, licensing enforcement, enrollment, or
CMDB connectors.

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

## Future Ingestion Shape

Future ingestion should accept an inventory envelope shaped like:

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

- no backend ingestion endpoint implementation
- no cloud sync
- no licensing enforcement
- no CMDB connector
- no secrets in docs or config examples
- no change to quarantine policy
