package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testBatch() Batch {
	return Batch{
		SchemaVersion:      SchemaVersion,
		ObservationBatchID: "sensor-home:20260720T120000Z:0001",
		SiteID:             "home-site",
		SensorID:           "sensor-home",
		SensorName:         "Home Passive Sensor",
		SensorType:         "passive-network-sensor",
		SensorVersion:      "0.1.0",
		ObservedAt:         time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC),
		ObservationSource:  "passive-network",
		DeliveryState:      "live",
		Confidence:         0.9,
		Assets: []Asset{{
			AssetID: "mac-02005e100001", Hostname: "router", PrimaryIP: "192.0.2.1",
			MAC: "02:00:5e:10:00:01", Category: "network-device",
			VLANID: intPtr(20), SourceProtocols: []string{"arp", "dns"},
			Evidence: []Evidence{
				{Protocol: "dns", Kind: "query-name", Value: "router.example.test", Confidence: 0.8},
				{Protocol: "vlan", Kind: "vlan-id", Value: "20", Confidence: 1},
			},
		}},
	}
}

func intPtr(value int) *int { return &value }

func TestMarshalMatchesStrictHubAssetContract(t *testing.T) {
	data, err := Marshal(testBatch())
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	assets := payload["assets"].([]any)
	asset := assets[0].(map[string]any)
	for _, field := range []string{"asset_id", "hostname", "primary_ip", "mac", "category", "evidence"} {
		if _, ok := asset[field]; !ok {
			t.Errorf("hub asset field %q missing", field)
		}
	}
	for _, forbidden := range []string{"vlan_id", "source_protocols", "raw_packet"} {
		if _, ok := asset[forbidden]; ok {
			t.Errorf("forbidden hub asset field %q present", forbidden)
		}
	}
	if got := len(asset["evidence"].([]any)); got != 2 {
		t.Fatalf("evidence count = %d, want 2", got)
	}

	fixturePath := filepath.Join("..", "..", "..", "backend", "tests", "fixtures", "passive_sensor_batch.json")
	fixture, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read shared backend contract fixture: %v", err)
	}
	if strings.TrimSpace(string(data)) != strings.TrimSpace(string(fixture)) {
		t.Fatalf("Go sensor payload does not match the shared backend fixture\nactual: %s\nfixture: %s", data, fixture)
	}
}

func TestIdentifierValidationMatchesBackendPatterns(t *testing.T) {
	for _, value := range []string{"home", "home.site-1", "A_1"} {
		if err := ValidateSiteID(value); err != nil {
			t.Errorf("ValidateSiteID(%q) unexpected error: %v", value, err)
		}
	}
	for _, value := range []string{"home:site", "home site", "home/site", ""} {
		if err := ValidateSiteID(value); err == nil {
			t.Errorf("ValidateSiteID(%q) unexpectedly succeeded", value)
		}
	}
	for _, value := range []string{"sensor-home", "sensor:home", "sensor.home_1"} {
		if err := ValidateSensorID(value); err != nil {
			t.Errorf("ValidateSensorID(%q) unexpected error: %v", value, err)
		}
	}
	for _, value := range []string{"sensor/home", "sensor home", ""} {
		if err := ValidateSensorID(value); err == nil {
			t.Errorf("ValidateSensorID(%q) unexpectedly succeeded", value)
		}
	}
	for _, value := range []string{"sensor-home:20260720T120000Z:0001", "oaw:0123456789abcdef0123456789abcdef"} {
		if err := ValidateBatchID(value); err != nil {
			t.Errorf("ValidateBatchID(%q) unexpected error: %v", value, err)
		}
	}
	for _, value := range []string{"short", "batch id", "batch/id"} {
		if err := ValidateBatchID(value); err == nil {
			t.Errorf("ValidateBatchID(%q) unexpectedly succeeded", value)
		}
	}
}

func TestBatchIDIsStableAndRejectsInvalidInput(t *testing.T) {
	first := testBatch()
	second := testBatch()
	second.Assets = append([]Asset(nil), first.Assets...)
	second.Assets[0].SourceProtocols = []string{"dns", "arp"}
	first.Assets[0].Evidence = append(first.Assets[0].Evidence,
		Evidence{Protocol: "arp", Kind: "reply", Value: "192.0.2.1", Confidence: 0.9},
	)
	second.Assets[0].Evidence = []Evidence{
		first.Assets[0].Evidence[2],
		first.Assets[0].Evidence[1],
		first.Assets[0].Evidence[0],
	}
	second.Assets[0].VLANID = intPtr(20)
	id1, err := BatchID(first.SensorID, first.ObservedAt, first.Assets)
	if err != nil {
		t.Fatalf("BatchID() error = %v", err)
	}
	id2, err := BatchID(second.SensorID, second.ObservedAt, second.Assets)
	if err != nil {
		t.Fatalf("BatchID() error = %v", err)
	}
	if id1 != id2 {
		t.Fatalf("BatchID() differs for equivalent protocol ordering: %q != %q", id1, id2)
	}
	if _, err := BatchID("bad/site", first.ObservedAt, first.Assets); err == nil {
		t.Fatal("BatchID() accepted invalid sensor ID")
	}
	if _, err := BatchID(first.SensorID, time.Time{}, first.Assets); err == nil {
		t.Fatal("BatchID() accepted zero timestamp")
	}
}

func TestValidateRejectsUnboundedOrUnsafeEvidence(t *testing.T) {
	batch := testBatch()
	batch.Assets[0].Evidence = make([]Evidence, MaxEvidence+1)
	if err := batch.Validate(); err == nil {
		t.Fatal("Validate() accepted too many evidence records")
	}
	batch = testBatch()
	batch.Assets[0].Evidence[0].Value = strings.Repeat("x", 513)
	if err := batch.Validate(); err == nil {
		t.Fatal("Validate() accepted oversized evidence")
	}
	batch = testBatch()
	batch.Assets[0].Evidence[0].Value = "line\nfeed"
	if err := batch.Validate(); err == nil {
		t.Fatal("Validate() accepted control characters")
	}
	batch = testBatch()
	batch.Assets = append(batch.Assets, batch.Assets[0])
	if err := batch.Validate(); err == nil {
		t.Fatal("Validate() accepted duplicate asset identifiers")
	}
}
