# Agent Collection

The Go `oaw-agent` command can run a one-time passive local inventory
collection and write JSON output for review, export experiments, or future
agent workflows.

## Run Local Collection

From the repository root:

```powershell
go run ./cmd/oaw-agent collect --once
```

To include a site identifier:

```powershell
go run ./cmd/oaw-agent collect --once --site-id site-local
```

To write JSON to a local file instead of stdout:

```powershell
go run ./cmd/oaw-agent collect --once --output inventory.json
```

The current command is local-only. It does not check in with the server, sync to
cloud services, or upload inventory.

## Data Collected

The output uses the Go inventory models and includes:

- `schema_version`
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

## Safety Model

Agent collection is passive and local-only:

- no CIDR scanning
- no port scanning
- no packet injection
- no credential use
- no external network calls
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
