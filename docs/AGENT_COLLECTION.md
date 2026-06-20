# Agent Collection

The Go `oaw-agent` command can run a one-time passive local inventory
collection and write JSON output for review, export experiments, or future
agent workflows.

## Run Local Collection

From the repository root:

```powershell
go run ./cmd/oaw-agent collect --once --site-id site-local
```

To include a site identifier:

```powershell
go run ./cmd/oaw-agent collect --once --site-id site-local
```

To write JSON to a local file instead of stdout:

```powershell
go run ./cmd/oaw-agent collect --once --site-id site-local --output inventory.json
```

The current command is local-only. It does not check in with the server, sync to
cloud services, or upload inventory.

## Local Agent Identity File

OpenAssetWatch now has a small durable local identity-file foundation for
installed agents. The identity file stores non-secret identifiers only:

- `agent_id`
- `deployment_id` when supplied by installer, enrollment, or config input
- `site_id`
- `tenant_id` when supplied
- `created_at`
- `updated_at`

Create a local identity file explicitly:

```powershell
go run ./cmd/oaw-agent identity init --site-id site-local --output identity.json
```

Optional deployment and tenant identifiers can be supplied:

```powershell
go run ./cmd/oaw-agent identity init `
  --site-id site-local `
  --deployment-id 11111111-1111-4111-8111-111111111111 `
  --tenant-id tenant-example `
  --output identity.json
```

This command generates `agent_id` only when creating the identity file. It does
not fabricate `deployment_id`, and it does not store enrollment tokens, license
keys, API keys, signing keys, or customer secrets.

Future installed-agent default identity locations should be:

- Windows: `%ProgramData%\OpenAssetWatch\Agent\identity\identity.json`
- Linux: `/var/lib/openassetwatch/agent/identity.json`
- macOS: `/Library/Application Support/OpenAssetWatch/agent/identity.json`

The local collection command can load this identity file explicitly:

```powershell
go run ./cmd/oaw-agent collect --once --identity-file identity.json --output inventory.json
```

To see the resolved default identity and config paths:

```powershell
go run ./cmd/oaw-agent paths
```

Default agent identity paths are:

- Windows: `%ProgramData%\OpenAssetWatch\Agent\identity\identity.json`
- Linux/macOS: `/etc/openassetwatch/agent/identity.json`

If `--identity-file`, `--site-id`, and `--config` are omitted, collection tries
the default identity path. If that file is missing, collection fails clearly
instead of creating privileged directories. Explicit `--identity-file` always
takes priority.

When `--identity-file` is supplied, collection copies `site_id`, `tenant_id`,
`deployment_id`, and `agent_id` from the identity file into the inventory JSON
when those fields are present. It does not fabricate a missing
`deployment_id`, and it does not generate `agent_id`; `agent_id` is generated
only by explicit `identity init`.

If `--site-id` and `--identity-file` are both supplied, the values must match:

```powershell
go run ./cmd/oaw-agent collect `
  --once `
  --site-id site-local `
  --identity-file identity.json `
  --output inventory.json
```

A conflicting `site_id` is rejected instead of silently overriding identity.
Collection ignores unknown identity-file fields and does not store or emit
enrollment tokens.

## Local Agent Config File

OpenAssetWatch also has a small non-secret agent config file for local
defaults. The config file currently supports only:

- `server_url`
- `site_id`

Create one explicitly:

```powershell
go run ./cmd/oaw-agent config init `
  --server-url http://localhost:8000 `
  --site-id site-local `
  --output config.json
```

Config init validates the URL format but does not call the backend. It rejects
URL credentials, query strings, and fragments. It writes only `server_url` and
`site_id`; do not store enrollment tokens, API keys, passwords, license keys,
or other secrets in this file.

Default agent config paths are:

- Windows: `%ProgramData%\OpenAssetWatch\Agent\config\config.json`
- Linux/macOS: `/etc/openassetwatch/agent/config.json`

Default agent log paths are:

- Windows: `%ProgramData%\OpenAssetWatch\Agent\logs\`
- Linux/macOS: `/var/log/openassetwatch/agent/`

The planned last-known local status file is:

- Windows: `%ProgramData%\OpenAssetWatch\Agent\state\status.json`
- Linux/macOS: `/var/log/openassetwatch/agent/status.json`

Explicit CLI flags remain highest priority. For collection:

- `--site-id` overrides config `site_id`.
- `--identity-file` supplies installed-agent identity fields.
- if `--site-id` and identity `site_id` are both supplied, they must match.
- if config `site_id` and identity `site_id` conflict and no explicit
  `--site-id` is supplied, collection fails clearly.

Collection can use an explicit config file for `site_id`:

```powershell
go run ./cmd/oaw-agent collect --once --config config.json --output inventory.json
```

If `--identity-file`, `--site-id`, and `--config` are omitted, collection
tries the default identity path first. If that file is missing and a default
config file exists, collection uses config `site_id`. It does not create
privileged directories or config files during collection.

## Local Setup Doctor

Use `doctor` to validate local config and identity files before collection,
check-in, submit, or future service-style workflows:

```powershell
go run ./cmd/oaw-agent doctor
```

With explicit temporary files:

```powershell
go run ./cmd/oaw-agent doctor --config config.json --identity-file identity.json
```

`doctor` emits JSON only. It checks local file paths, existence, parsing, and
required non-secret fields such as `server_url`, `site_id`, and `agent_id`. It
does not create files, modify files, contact the backend, collect inventory, or
perform active network activity.

Use `status` when you only need a read-only local setup snapshot:

```powershell
go run ./cmd/oaw-agent status --config config.json --identity-file identity.json
```

`status` emits JSON only. It reports resolved config, identity, log, and
status-file paths plus whether the config, identity, log directory, and last
known status file exist. It does not create files or directories, write logs,
contact the backend, collect inventory, or perform active network activity.

## Submit To Backend

Once the backend is running, saved local collection JSON can be submitted to
the first ingestion endpoint with the Go agent:

```powershell
go run ./cmd/oaw-agent collect --once --site-id site-local --output inventory.json

go run ./cmd/oaw-agent submit --file inventory.json --server-url http://localhost:8000
```

With an identity file:

```powershell
go run ./cmd/oaw-agent collect --once --identity-file identity.json --output inventory.json

go run ./cmd/oaw-agent submit --file inventory.json --server-url http://localhost:8000
```

The `submit` command posts the file to
`/api/v1/collections/local-inventory` with `Content-Type: application/json`.
The backend URL can come from explicit `--server-url`, explicit `--config`, or
the default agent config file. Explicit `--server-url` takes priority. The
agent does not default to any external service.

With a config file:

```powershell
go run ./cmd/oaw-agent submit --file inventory.json --config config.json
```

The submit command sends the JSON file unchanged. It does not collect
credentials, add enrollment tokens, retry aggressively, or call any service
other than the configured OpenAssetWatch backend URL. Backend ingestion accepts
the JSON as passive observations; it does not perform active collection, cloud
sync, licensing checks, or CMDB reconciliation in this pass.

Manual import with `curl.exe` remains equivalent for local testing:

```powershell
curl.exe -X POST http://localhost:8000/api/v1/collections/local-inventory `
  -H "Content-Type: application/json" `
  --data-binary "@inventory.json"
```

For a scripted local validation path, including the config-backed
`config init`, collection, and submit flow, see `docs/LOCAL_E2E.md`.

For the full manual agent lifecycle and service-readiness checklist, see
`docs/AGENT_LIFECYCLE.md`.

For future install, uninstall, upgrade, rollback, and package validation
planning, see `docs/AGENT_INSTALLATION.md`.

## Data Collected

The output uses the Go inventory models and includes:

- `schema_version`
- `site_id` when provided by CLI/config
- `tenant_id`, `deployment_id`, and `agent_id` when loaded from an explicit
  local identity file
- `collected_at`
- host identity: hostname and FQDN when already available locally
- platform details: operating system, platform, architecture, and architecture
  family
- network interfaces from local OS APIs
- IP address observations
- MAC address observations
- default gateway observation when safely available
- passive neighbor/local ARP cache observations when safely available
- `source` and `collected_at` fields on observations

The Go inventory model also has optional identity fields for future ingestion:
`tenant_id`, `deployment_id`, `agent_id`, and `sensor_id`. The local collection
command only fills installed-agent identity fields from the explicit local
identity file. It does not generate or fake those values during collection.

## Safety Model

Agent collection is passive and local-only:

- no CIDR discovery
- no port checks
- no packet injection
- no credential use
- no external network calls except explicit submit to the configured OAW backend
- no active probing
- no cloud sync
- no raw command wrappers
- no arbitrary arguments
- no offensive tooling

Where OS-specific data requires a command, the Go collector uses fixed
read-only commands only. Windows may use fixed PowerShell route/neighbor-cache
queries. Linux prefers `/proc/net/route` and `/proc/net/arp`. macOS may use
fixed route and ARP cache reads. These paths read local operating-system state;
they do not discover new hosts.

## Example Output Shape

```json
{
  "schema_version": "oaw.inventory.v1",
  "tenant_id": "tenant-example",
  "site_id": "site-local",
  "deployment_id": "11111111-1111-4111-8111-111111111111",
  "agent_id": "22222222-2222-4222-8222-222222222222",
  "collected_at": "2026-06-17T12:00:00Z",
  "assets": [
    {
      "asset_id": "local-host",
      "site_id": "site-local",
      "hostname": "workstation-01",
      "fqdn": "workstation-01.example.test",
      "os": "windows",
      "platform": "windows/amd64",
      "architecture": "amd64",
      "host": {
        "hostname": "workstation-01",
        "fqdn": "workstation-01.example.test",
        "source": "os_hostname",
        "collected_at": "2026-06-17T12:00:00Z"
      },
      "platform_info": {
        "os": "windows",
        "platform": "windows/amd64",
        "architecture": "amd64",
        "architecture_family": "x86_64",
        "source": "go_runtime",
        "collected_at": "2026-06-17T12:00:00Z"
      },
      "primary_interfaces": [
        {
          "name": "Ethernet",
          "mac_address": "00:11:22:33:44:55",
          "flags": ["up", "broadcast"],
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
      "ip_addresses": [
        {
          "address": "192.0.2.10",
          "family": "ipv4",
          "interface": "Ethernet",
          "source": "go_net_interfaces",
          "collected_at": "2026-06-17T12:00:00Z"
        }
      ],
      "mac_addresses": [
        {
          "address": "00:11:22:33:44:55",
          "interface": "Ethernet",
          "source": "go_net_interfaces",
          "collected_at": "2026-06-17T12:00:00Z"
        }
      ],
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
          "sources": ["windows_get_net_neighbor"],
          "collected_at": "2026-06-17T12:00:00Z"
        }
      ]
    }
  ]
}
```

Some fields may be omitted when the local operating system does not expose them
safely or the relevant local cache is empty.
