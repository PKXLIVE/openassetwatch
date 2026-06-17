package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openassetwatch/openassetwatch/pkg/models"
	"github.com/openassetwatch/openassetwatch/pkg/schema"
)

func TestRunCollectOnceWritesJSONToStdout(t *testing.T) {
	restore := stubCollector(t)
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect", "--once", "--site-id", "site-test"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run collect code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("run collect stderr = %q, want empty", stderr.String())
	}

	var inventory models.Inventory
	if err := json.Unmarshal(stdout.Bytes(), &inventory); err != nil {
		t.Fatalf("collect output is not JSON: %v\n%s", err, stdout.String())
	}
	if inventory.SchemaVersion != schema.InventorySchemaVersion {
		t.Fatalf("schema_version = %q, want %q", inventory.SchemaVersion, schema.InventorySchemaVersion)
	}
	if len(inventory.Assets) != 1 || inventory.Assets[0].SiteID != "site-test" {
		t.Fatalf("unexpected assets: %+v", inventory.Assets)
	}
}

func TestRunCollectOnceWritesJSONToOutputFile(t *testing.T) {
	restore := stubCollector(t)
	defer restore()

	outputPath := filepath.Join(t.TempDir(), "inventory.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect", "--once", "--site-id", "site-test", "--output", outputPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run collect code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("run collect stdout = %q, want empty when --output is used", stdout.String())
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var inventory models.Inventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatalf("output file is not JSON: %v\n%s", err, string(data))
	}
	if len(inventory.Assets) != 1 || inventory.Assets[0].Hostname != "fixture-host" {
		t.Fatalf("unexpected output inventory: %+v", inventory)
	}
}

func TestRunCollectRequiresOnce(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run collect without --once returned success")
	}
}

func stubCollector(t *testing.T) func() {
	t.Helper()
	previous := collectLocalInventory
	collectedAt := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	collectLocalInventory = func(siteID string) models.Inventory {
		return models.Inventory{
			SchemaVersion: schema.InventorySchemaVersion,
			CollectedAt:   collectedAt,
			Assets: []models.Asset{
				{
					AssetID:      "local-host",
					SiteID:       siteID,
					Hostname:     "fixture-host",
					OS:           "windows",
					Platform:     "windows/amd64",
					Architecture: "amd64",
					Host: &models.HostObservation{
						Hostname:    "fixture-host",
						Source:      "fixture",
						CollectedAt: collectedAt,
					},
					PlatformInfo: &models.PlatformObservation{
						OS:                 "windows",
						Platform:           "windows/amd64",
						Architecture:       "amd64",
						ArchitectureFamily: "x86_64",
						Source:             "fixture",
						CollectedAt:        collectedAt,
					},
					PrimaryInterfaces: []models.NetworkInterface{
						{
							Name:        "Ethernet",
							MACAddress:  "00:11:22:33:44:55",
							Flags:       []string{"up", "broadcast"},
							IPAddresses: []models.IPAddressObservation{{Address: "192.0.2.10", Family: "ipv4", Interface: "Ethernet", Source: "fixture", CollectedAt: collectedAt}},
							Source:      "fixture",
							CollectedAt: collectedAt,
						},
					},
					IPAddresses:      []models.IPAddressObservation{{Address: "192.0.2.10", Family: "ipv4", Interface: "Ethernet", Source: "fixture", CollectedAt: collectedAt}},
					MACAddresses:     []models.MACAddressObservation{{Address: "00:11:22:33:44:55", Interface: "Ethernet", Source: "fixture", CollectedAt: collectedAt}},
					NetworkNeighbors: []models.NetworkNeighbor{{IPAddress: "192.0.2.1", MACAddress: "66:77:88:99:aa:bb", Interface: "Ethernet", Source: "fixture", Sources: []string{"fixture"}, CollectedAt: collectedAt}},
				},
			},
		}
	}
	return func() {
		collectLocalInventory = previous
	}
}
