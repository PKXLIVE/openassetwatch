package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/openassetwatch/openassetwatch/pkg/schema"
)

func TestInventoryJSONShapeIsStable(t *testing.T) {
	collectedAt := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	inventory := Inventory{
		SchemaVersion: schema.InventorySchemaVersion,
		CollectedAt:   collectedAt,
		Assets: []Asset{
			{
				AssetID:      "local-host",
				SiteID:       "site-1",
				Hostname:     "host-1",
				FQDN:         "host-1.example.test",
				OS:           "linux",
				Platform:     "linux/amd64",
				Architecture: "amd64",
				Host:         &HostObservation{Hostname: "host-1", FQDN: "host-1.example.test", Source: "fixture", CollectedAt: collectedAt},
				PlatformInfo: &PlatformObservation{OS: "linux", Platform: "linux/amd64", Architecture: "amd64", ArchitectureFamily: "x86_64", Source: "fixture", CollectedAt: collectedAt},
				PrimaryInterfaces: []NetworkInterface{
					{
						Name:        "eth0",
						Index:       2,
						MACAddress:  "00:11:22:33:44:55",
						Flags:       []string{"up", "broadcast"},
						IPAddresses: []IPAddressObservation{{Address: "192.0.2.10", Family: "ipv4", Interface: "eth0", Source: "fixture", CollectedAt: collectedAt}},
						Source:      "fixture",
						CollectedAt: collectedAt,
					},
				},
				IPAddresses:      []IPAddressObservation{{Address: "192.0.2.10", Family: "ipv4", Interface: "eth0", Source: "fixture", CollectedAt: collectedAt}},
				MACAddresses:     []MACAddressObservation{{Address: "00:11:22:33:44:55", Interface: "eth0", Source: "fixture", CollectedAt: collectedAt}},
				DefaultGateway:   &DefaultGatewayObservation{Address: "192.0.2.1", Interface: "eth0", Source: "fixture", CollectedAt: collectedAt},
				NetworkNeighbors: []NetworkNeighbor{{IPAddress: "192.0.2.1", MACAddress: "66:77:88:99:aa:bb", Interface: "eth0", State: "reachable", Source: "fixture", Sources: []string{"fixture"}, CollectedAt: collectedAt}},
			},
		},
		Evidence: []Evidence{{Source: "fixture", Summary: "fixture inventory", Confidence: "high"}},
	}

	data, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	want := `{
  "schema_version": "oaw.inventory.v1",
  "collected_at": "2026-06-17T12:00:00Z",
  "assets": [
    {
      "asset_id": "local-host",
      "site_id": "site-1",
      "hostname": "host-1",
      "fqdn": "host-1.example.test",
      "os": "linux",
      "platform": "linux/amd64",
      "architecture": "amd64",
      "host": {
        "hostname": "host-1",
        "fqdn": "host-1.example.test",
        "source": "fixture",
        "collected_at": "2026-06-17T12:00:00Z"
      },
      "platform_info": {
        "os": "linux",
        "platform": "linux/amd64",
        "architecture": "amd64",
        "architecture_family": "x86_64",
        "source": "fixture",
        "collected_at": "2026-06-17T12:00:00Z"
      },
      "primary_interfaces": [
        {
          "name": "eth0",
          "index": 2,
          "mac_address": "00:11:22:33:44:55",
          "flags": [
            "up",
            "broadcast"
          ],
          "ip_addresses": [
            {
              "address": "192.0.2.10",
              "family": "ipv4",
              "interface": "eth0",
              "source": "fixture",
              "collected_at": "2026-06-17T12:00:00Z"
            }
          ],
          "source": "fixture",
          "collected_at": "2026-06-17T12:00:00Z"
        }
      ],
      "ip_addresses": [
        {
          "address": "192.0.2.10",
          "family": "ipv4",
          "interface": "eth0",
          "source": "fixture",
          "collected_at": "2026-06-17T12:00:00Z"
        }
      ],
      "mac_addresses": [
        {
          "address": "00:11:22:33:44:55",
          "interface": "eth0",
          "source": "fixture",
          "collected_at": "2026-06-17T12:00:00Z"
        }
      ],
      "default_gateway": {
        "address": "192.0.2.1",
        "interface": "eth0",
        "source": "fixture",
        "collected_at": "2026-06-17T12:00:00Z"
      },
      "network_neighbors": [
        {
          "ip_address": "192.0.2.1",
          "mac_address": "66:77:88:99:aa:bb",
          "interface": "eth0",
          "state": "reachable",
          "source": "fixture",
          "sources": [
            "fixture"
          ],
          "collected_at": "2026-06-17T12:00:00Z"
        }
      ]
    }
  ],
  "evidence": [
    {
      "source": "fixture",
      "summary": "fixture inventory",
      "confidence": "high"
    }
  ]
}`
	if string(data) != want {
		t.Fatalf("inventory JSON mismatch\nwant:\n%s\n\ngot:\n%s", want, string(data))
	}
}
