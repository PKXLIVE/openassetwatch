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

## Submit To Backend

Once the backend is running, saved local collection JSON can be submitted to
the first ingestion endpoint with the Go agent:

```powershell
go run ./cmd/oaw-agent collect --once --site-id site-local --output inventory.json

go run ./cmd/oaw-agent submit --file inventory.json --server-url http://localhost:8000
```

The `submit` command posts the file to
`/api/v1/collections/local-inventory` with `Content-Type: application/json`.
In this pass, the backend URL must be explicitly provided with `--server-url`;
the agent does not default to any external service.

The submit command does not collect credentials, add enrollment tokens, retry
aggressively, or call any service other than the configured OpenAssetWatch
backend URL. Backend ingestion accepts the JSON as passive observations; it
does not perform active collection, cloud sync, licensing checks, or CMDB
reconciliation in this pass.

Manual import with `curl.exe` remains equivalent for local testing:

```powershell
curl.exe -X POST http://localhost:8000/api/v1/collections/local-inventory `
  -H "Content-Type: application/json" `
  --data-binary "@inventory.json"
```

For a scripted local validation path, see `docs/LOCAL_E2E.md`.

## Data Collected

The output uses the Go inventory models and includes:

- `schema_version`
- `site_id` when provided by CLI/config
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
command does not generate or fake those values yet. Future enrollment/install
work should populate durable installed-instance identity from scoped config or
local identity files.

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
  "site_id": "site-local",
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
