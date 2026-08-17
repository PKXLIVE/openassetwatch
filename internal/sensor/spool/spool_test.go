package spool

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openassetwatch/openassetwatch/internal/sensor/contract"
)

func queueBatch(id string) contract.Batch {
	return contract.Batch{
		SchemaVersion:      contract.SchemaVersion,
		ObservationBatchID: id,
		SiteID:             "site-demo",
		SensorID:           "sensor-demo",
		SensorName:         "Demo Passive Sensor",
		SensorType:         "passive-network-sensor",
		SensorVersion:      "0.1.0",
		ObservedAt:         time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC),
		ObservationSource:  "passive-network",
		DeliveryState:      "live",
		Confidence:         0.8,
		Assets: []contract.Asset{{
			AssetID: "mac-02005e100001",
			MAC:     "02:00:5e:10:00:01",
			Evidence: []contract.Evidence{{
				Protocol: "arp", Kind: "reply", Value: "192.0.2.10", Confidence: 0.9,
			}},
		}},
	}
}

func openTestQueue(t *testing.T, path string, maxItems int) *Queue {
	t.Helper()
	queue, err := Open(Config{Path: path, MaxItems: maxItems, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = queue.Close() })
	return queue
}

func TestQueuePersistsOldestFirstAcrossRestartAndRemovesOnlyOnAck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool")
	queue := openTestQueue(t, path, 10)
	base := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	firstName, err := queue.Enqueue(queueBatch("oaw:first-batch"), base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Enqueue(queueBatch("oaw:second-batch"), base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	first, err := queue.Next(base.Add(time.Minute))
	if err != nil || first.Name != firstName || first.Batch.ObservationBatchID != "oaw:first-batch" {
		t.Fatalf("Next() = %+v, %v", first, err)
	}
	if err := queue.RecordRetry(first, base.Add(2*time.Minute), "server"); err != nil {
		t.Fatal(err)
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(Config{Path: path, MaxItems: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	next, err := reopened.Next(base.Add(time.Minute))
	if err != nil || next.Batch.ObservationBatchID != "oaw:second-batch" {
		t.Fatalf("retry delay did not preserve oldest eligible ordering: %+v, %v", next, err)
	}
	if err := reopened.Remove(next); err != nil {
		t.Fatal(err)
	}
	retry, err := reopened.Next(base.Add(3 * time.Minute))
	if err != nil || retry.Batch.ObservationBatchID != "oaw:first-batch" || retry.Attempts != 1 || retry.LastErrorClass != "server" {
		t.Fatalf("persisted retry = %+v, %v", retry, err)
	}
}

func TestQueueCapacityCorruptionAndNoRawPackets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool")
	queue := openTestQueue(t, path, 1)
	name, err := queue.Enqueue(queueBatch("oaw:first-batch"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(path, name))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"raw_packet", "packet_bytes", "authorization", "collector_token"} {
		if strings.Contains(strings.ToLower(string(data)), forbidden) {
			t.Fatalf("spool persisted forbidden raw or secret field %q", forbidden)
		}
	}
	if _, err := queue.Enqueue(queueBatch("oaw:second-batch"), time.Now().Add(time.Second)); !errors.Is(err, ErrFull) {
		t.Fatalf("second Enqueue() = %v, want ErrFull", err)
	}

	if err := queue.Remove(Entry{Name: name}); err != nil {
		t.Fatal(err)
	}
	corrupt := filepath.Join(path, "20260721T120000.000000000Z-corrupt.json")
	if err := os.WriteFile(corrupt, []byte(`{"schema_version":"oaw.sensor-spool.v1"}{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Next(time.Now()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Next() corrupt entry = %v, want ErrCorrupt", err)
	}
	matches, err := filepath.Glob(filepath.Join(path, "corrupt-*.bad"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("quarantine matches = %v, %v", matches, err)
	}
}

func TestQueueRejectsNonRegularMultiplyLinkedAndSymlinkEntries(t *testing.T) {
	t.Run("non-regular", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "spool")
		queue := openTestQueue(t, path, 10)
		if err := os.Mkdir(filepath.Join(path, "evil.json"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := queue.Stats(); err == nil {
			t.Fatal("Stats() accepted a directory entry")
		}
	})

	t.Run("hard link", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows hard-link ownership checks remain a documented MVP limitation")
		}
		path := filepath.Join(t.TempDir(), "spool")
		queue := openTestQueue(t, path, 10)
		first := filepath.Join(path, "first.bad")
		if err := os.WriteFile(first, []byte("bounded"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(first, filepath.Join(path, "second.bad")); err != nil {
			t.Skipf("hard links are unavailable: %v", err)
		}
		if _, err := queue.Stats(); err == nil {
			t.Fatal("Stats() accepted multiply-linked files")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "spool")
		queue := openTestQueue(t, path, 10)
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("bounded"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(path, "evil.bad")); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		if _, err := queue.Stats(); err == nil {
			t.Fatal("Stats() accepted a symlink")
		}
	})
}

func TestQueueDirectoryScanIsIncrementallyBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool")
	queue := openTestQueue(t, path, 10)
	queue.scanLimit = 2
	for index, name := range []string{"one.bad", "two.bad", "three.bad"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte{byte(index)}, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := queue.Stats(); err == nil || !strings.Contains(err.Error(), "entry count exceeds safety limit") {
		t.Fatalf("Stats() = %v, want bounded-scan error", err)
	}
}

func TestOpenRejectsUnsafeRootAndLimits(t *testing.T) {
	if _, err := Open(Config{Path: t.TempDir(), MaxItems: MaxItemsAbsolute + 1, MaxBytes: 1 << 20}); err == nil {
		t.Fatal("Open() accepted item limit above absolute maximum")
	}
	if _, err := Open(Config{Path: t.TempDir(), MaxItems: 1, MaxBytes: MaxBytesAbsolute + 1}); err == nil {
		t.Fatal("Open() accepted byte limit above absolute maximum")
	}
	queue := openTestQueue(t, filepath.Join(t.TempDir(), "bounded"), 1)
	if _, err := queue.Enqueue(queueBatch("oaw:zero-time"), time.Time{}); err == nil {
		t.Fatal("Enqueue() accepted a zero creation timestamp")
	}
	name, err := queue.Enqueue(queueBatch("oaw:retry-time"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	entry, err := queue.Next(time.Now())
	if err != nil || entry.Name != name {
		t.Fatalf("Next() = %+v, %v", entry, err)
	}
	if err := queue.RecordRetry(entry, time.Now().Add(MaxRetryDelay+time.Hour), "server"); err == nil {
		t.Fatal("RecordRetry() accepted an unbounded retry timestamp")
	}
	if runtime.GOOS == "windows" {
		t.Log("Windows ACL ownership enforcement remains a documented MVP limitation")
	}
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	link := filepath.Join(parent, "spool")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if _, err := Open(Config{Path: link, MaxItems: 1, MaxBytes: 1 << 20}); err == nil {
		t.Fatal("Open() accepted a symlink root")
	}
}
