package runtime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/openassetwatch/openassetwatch/internal/sensor/aggregate"
	"github.com/openassetwatch/openassetwatch/internal/sensor/capture"
	"github.com/openassetwatch/openassetwatch/internal/sensor/contract"
	"github.com/openassetwatch/openassetwatch/internal/sensor/decode"
	"github.com/openassetwatch/openassetwatch/internal/sensor/health"
	"github.com/openassetwatch/openassetwatch/internal/sensor/hubclient"
	"github.com/openassetwatch/openassetwatch/internal/sensor/spool"
)

func privateTempDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("secure test temporary directory: %v", err)
	}
	return path
}

func TestRunnerReportsQueueOverflowAndRetainsUnacknowledgedBatch(t *testing.T) {
	base := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	queue, err := spool.Open(spool.Config{Path: privateTempDir(t), MaxItems: 1, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	pending := contract.Batch{
		SchemaVersion:      contract.SchemaVersion,
		ObservationBatchID: "oaw:pending-batch",
		SiteID:             "site-demo",
		SensorID:           "sensor-demo",
		SensorName:         "Demo Passive Sensor",
		SensorType:         "passive-network-sensor",
		SensorVersion:      "0.1.0",
		ObservedAt:         base,
		ObservationSource:  "passive-network",
		DeliveryState:      "live",
		Confidence:         0.8,
		Assets:             []contract.Asset{},
	}
	if _, err := queue.Enqueue(pending, base); err != nil {
		t.Fatal(err)
	}
	agg, err := aggregate.New(aggregate.Config{SiteID: "site-demo"})
	if err != nil {
		t.Fatal(err)
	}
	if err := agg.Add(decode.Evidence{
		MAC: "02:00:5e:10:00:01", IP: "192.0.2.10", Protocol: "arp",
		Kind: "reply", Value: "192.0.2.10", Confidence: 0.9, ObservedAt: base,
	}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "permanent validation rejection", http.StatusUnprocessableEntity)
	}))
	defer server.Close()
	hub, err := hubclient.New(server.URL, "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tracker := health.NewWithDetails("0.1.0", "site-demo", "sensor-demo", "synthetic", "", "synthetic-replay")
	runner := Runner{
		Config: Config{
			SiteID: "site-demo", SensorID: "sensor-demo", SensorName: "Demo Passive Sensor",
			SensorVersion: "0.1.0", BatchSize: 10, BatchInterval: time.Minute,
			RetryInitial: time.Second, RetryMaximum: time.Minute,
		},
		Source: capture.NewSynthetic(nil), Aggregator: agg, Spool: queue, Hub: hub, Health: tracker,
		Now: func() time.Time { return base },
	}
	err = runner.Run(context.Background())
	if !errors.Is(err, spool.ErrFull) {
		t.Fatalf("Run() = %v, want ErrFull", err)
	}
	state := tracker.Snapshot()
	if !state.QueueOverflow || state.BatchesQueued != 1 {
		t.Fatalf("queue overflow health = %+v", state)
	}
	stats, err := queue.Stats()
	if err != nil || stats.Items != 1 {
		t.Fatalf("unacknowledged queue stats = %+v, %v", stats, err)
	}
}

func TestRunnerReportsRevokedCredentialWithoutDroppingQueuedBatch(t *testing.T) {
	base := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	queue, err := spool.Open(spool.Config{Path: privateTempDir(t), MaxItems: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	pending := contract.Batch{
		SchemaVersion:      contract.SchemaVersion,
		ObservationBatchID: "oaw:revoked-credential",
		SiteID:             "site-demo",
		SensorID:           "sensor-demo",
		SensorName:         "Demo Passive Sensor",
		SensorType:         "passive-network-sensor",
		SensorVersion:      "0.1.0",
		ObservedAt:         base,
		ObservationSource:  "passive-network",
		DeliveryState:      "live",
		Confidence:         0.8,
		Assets:             []contract.Asset{},
	}
	if _, err := queue.Enqueue(pending, base); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "credential revoked", http.StatusUnauthorized)
	}))
	defer server.Close()
	hub, err := hubclient.New(server.URL, "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	aggregator, err := aggregate.New(aggregate.Config{SiteID: "site-demo"})
	if err != nil {
		t.Fatal(err)
	}
	tracker := health.NewWithDetails("0.1.0", "site-demo", "sensor-demo", "synthetic", "", "synthetic-replay")
	runner := Runner{
		Config: Config{
			SiteID: "site-demo", SensorID: "sensor-demo", SensorName: "Demo Passive Sensor",
			SensorVersion: "0.1.0", BatchSize: 10, BatchInterval: time.Minute,
			RetryInitial: time.Second, RetryMaximum: time.Minute,
		},
		Source: capture.NewSynthetic(nil), Aggregator: aggregator, Spool: queue, Hub: hub, Health: tracker,
		Now: func() time.Time { return base },
	}
	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() unexpectedly accepted a revoked credential response")
	}
	state := tracker.Snapshot()
	if state.LastHubError == "" || len(state.LastHubError) > 512 || state.Running {
		t.Fatalf("revoked credential health = %+v", state)
	}
	stats, err := queue.Stats()
	if err != nil || stats.Items != 1 {
		t.Fatalf("revoked credential queue stats = %+v, %v", stats, err)
	}
}
