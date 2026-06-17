# Agent Check-In

OpenAssetWatch has a first backend endpoint for agent identity and health
metadata:

`POST /api/v1/agents/check-in`

This is a foundation endpoint only. The Go agent does not call it
automatically yet, and it does not implement enrollment, licensing
enforcement, cloud sync, CMDB reconciliation, or durable agent state.

## Request Shape

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

Required:

- `site_id`: environment, site, workspace, or operational boundary.

Optional:

- `tenant_id`: customer/account boundary. Optional for self-hosted
  single-tenant mode; expected for hosted and multi-tenant control planes.
- `deployment_id`: installer or deployment package GUID. Safe to log.
- `agent_id`: installed agent instance ID. Future installers should generate
  it once and persist it locally.
- `sensor_id`: installed sensor instance ID. Future sensor installers should
  generate it once and persist it locally.
- `agent_version`: reported agent binary version.
- `hostname`: locally observed hostname.
- `platform`: local platform metadata.
- `check_in_at`: client-side check-in timestamp if available.
- `enrollment_token`: secret enrollment proof or placeholder.

## Response Shape

```json
{
  "status": "accepted",
  "site_id": "site-local",
  "agent_id": "22222222-2222-4222-8222-222222222222",
  "received_at": "2026-06-17T12:01:00Z",
  "message": "agent check-in accepted as identity and health metadata"
}
```

`agent_id` is returned only when supplied. The backend must not fabricate
`deployment_id`, `agent_id`, or `sensor_id`.

## Enrollment Token Safety

Enrollment tokens are secrets:

- never commit real enrollment tokens to the repository
- never include real enrollment tokens in examples
- never return enrollment tokens in API responses
- never log full enrollment tokens
- prefer CI/CD, MDM/RMM, or administrator-provided secret references

The first backend endpoint accepts the `enrollment_token` field but strips it
from transitional in-memory storage. Future durable enrollment should store
only an audit-safe verification result or a secret-manager reference.

## Future Installer Identity File

Future signed installers should remain generic where possible. Tenant and
deployment identity should come from deployment config, enrollment config,
installer wrappers, MDM/RMM profiles, or self-hosted administrator-provided
config.

Installed agents and sensors should eventually persist a local identity file
containing non-secret identifiers such as:

```json
{
  "site_id": "site-local",
  "deployment_id": "11111111-1111-4111-8111-111111111111",
  "agent_id": "22222222-2222-4222-8222-222222222222"
}
```

Do not place enrollment tokens, license keys, signing keys, API keys, or
customer secrets in that file.

## Deployment Models

The check-in identity model should support:

- self-hosted/customer-managed deployments
- hosted/cloud-managed deployments
- hybrid hosted control plane with customer-managed agents, sensors, and
  connectors

Hosted and hybrid deployments must not trust arbitrary client-submitted
`tenant_id` values as authorization. Tenant ownership should come from
server-side enrollment and authentication context in a later workstream.

## Safety Model

Agent check-in is identity and health metadata only:

- no active network collection
- no CIDR discovery
- no port checks
- no packet injection
- no credential validation
- no command execution
- no raw command wrappers
- no arbitrary arguments
- no loading from `configs/quarantine/`
- no trust elevation based only on client-submitted data

## Transitional Storage

The first backend implementation stores accepted check-ins in an in-memory
repository for tests and manual development. This is intentionally
transitional. Durable storage, enrollment verification, tenant authorization,
and audit records should be added in a later backend workstream.
