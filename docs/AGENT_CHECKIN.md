# Agent Check-In

OpenAssetWatch has a first backend endpoint for agent identity and health
metadata:

`POST /api/v1/agents/check-in`

This is a foundation endpoint only. The Go agent can call it explicitly with a
local identity file, but it does not run automatically and it does not
implement enrollment, licensing enforcement, cloud sync, CMDB reconciliation,
or daemon state.

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
  "agent_id": "22222222-2222-4222-8222-222222222222",
  "created_at": "2026-06-17T12:00:00Z",
  "updated_at": "2026-06-17T12:00:00Z"
}
```

The current Go agent includes a small local foundation command for creating
this non-secret identity file explicitly:

```powershell
go run ./cmd/oaw-agent identity init --site-id site-local --output identity.json
```

Optional installer or enrollment input can supply:

```powershell
go run ./cmd/oaw-agent identity init `
  --site-id site-local `
  --deployment-id 11111111-1111-4111-8111-111111111111 `
  --tenant-id tenant-example `
  --output identity.json
```

This command generates `agent_id` only when creating the local identity file.
It does not fabricate `deployment_id`; that value must come from future
deployment config, enrollment config, installer input, or an administrator
provided wrapper.

Future default installed-agent identity locations should be:

- Windows: `%PROGRAMDATA%\OpenAssetWatch\agent\identity.json`
- Linux: `/var/lib/openassetwatch/agent/identity.json`
- macOS: `/Library/Application Support/OpenAssetWatch/agent/identity.json`

Do not place enrollment tokens, license keys, signing keys, API keys, or
customer secrets in that file.

The collection command can consume this file explicitly:

```powershell
go run ./cmd/oaw-agent collect --once --identity-file identity.json --output inventory.json
```

The agent can also send a manual check-in using the same non-secret identity
file:

```powershell
go run ./cmd/oaw-agent check-in --identity-file identity.json --server-url http://localhost:8000
```

OpenAssetWatch also exposes the resolved default local paths:

```powershell
go run ./cmd/oaw-agent paths
```

Default agent identity paths are:

- Windows: `%ProgramData%\OpenAssetWatch\agent\identity.json`
- Linux/macOS: `/etc/openassetwatch/agent/identity.json`

Default agent config paths are:

- Windows: `%ProgramData%\OpenAssetWatch\agent\config.json`
- Linux/macOS: `/etc/openassetwatch/agent/config.json`

When `--identity-file` is omitted, `check-in` reads the default identity path.
If the default file is missing, the command fails clearly and does not create
privileged directories. Explicit `--identity-file` always takes priority.

The local agent config file can provide non-secret defaults:

```json
{
  "server_url": "http://localhost:8000",
  "site_id": "site-local"
}
```

Create it explicitly:

```powershell
go run ./cmd/oaw-agent config init `
  --server-url http://localhost:8000 `
  --site-id site-local `
  --output config.json
```

Config init validates the URL format but does not contact the backend. It
rejects URL credentials, query strings, and fragments. It writes only
`server_url` and `site_id`; do not store enrollment tokens, API keys,
passwords, license keys, or other secrets in this file.

Check-in can use an explicit config file for `server_url`:

```powershell
go run ./cmd/oaw-agent check-in --identity-file identity.json --config config.json
```

The `check-in` command:

- requires a backend URL from explicit `--server-url`, explicit `--config`, or
  the default agent config file
- treats explicit `--server-url` as highest priority
- rejects server URLs with embedded credentials, query strings, or fragments
- uses `--identity-file` when supplied, otherwise the default identity path
- posts to `/api/v1/agents/check-in`
- sends `site_id`, `tenant_id`, `deployment_id`, and `agent_id` when present in
  the identity file
- includes local hostname, platform, and agent version metadata when available
- uses `Content-Type: application/json`
- does not send enrollment tokens
- does not print request or response bodies
- does not default to an external service URL
- does not retry aggressively or run as a daemon

For a local validation helper that runs identity init, check-in, collection,
and submit against a local backend, see `docs/LOCAL_E2E.md`.

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
- no arbitrary request headers
- no raw command wrappers
- no arbitrary arguments
- no loading from `configs/quarantine/`
- no trust elevation based only on client-submitted data

## Transitional Storage

The first backend implementation stores accepted check-ins in an in-memory
repository for tests and manual development. This is intentionally
transitional. Durable storage, enrollment verification, tenant authorization,
and audit records should be added in a later backend workstream.
