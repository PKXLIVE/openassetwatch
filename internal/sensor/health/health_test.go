package health

import (
	"testing"
	"time"
)

func TestTrackerCapturesOperationalStateWithoutSecrets(t *testing.T) {
	tracker := NewWithDetails("1.2.3", "site-demo", "sensor-demo", "synthetic", "", "synthetic-replay")
	tracker.PacketResult(true, false)
	tracker.PacketResult(false, true)
	tracker.Observations(2)
	tracker.Sent(time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC))
	tracker.QueueState(3, 0.5, "hub delivery retry scheduled", false)
	tracker.HubError("hub authentication rejected (HTTP 403)")
	tracker.QueueState(4, 1, "spool is full", true)

	snapshot := tracker.Snapshot()
	if !snapshot.Running || snapshot.CaptureMode != "synthetic" || snapshot.CaptureSource != "synthetic-replay" {
		t.Fatalf("unexpected capture state: %+v", snapshot)
	}
	if snapshot.PacketsObserved != 2 || snapshot.PacketsDecoded != 1 || snapshot.MalformedFrames != 1 {
		t.Fatalf("unexpected packet counters: %+v", snapshot)
	}
	if snapshot.ObservationsGenerated != 2 || snapshot.BatchesSent != 1 || snapshot.BatchesQueued != 4 {
		t.Fatalf("unexpected delivery counters: %+v", snapshot)
	}
	if !snapshot.QueueOverflow || snapshot.QueueWarning != "spool is full" {
		t.Fatalf("unexpected queue state: %+v", snapshot)
	}
	if snapshot.LastHubError == "" || snapshot.LastSuccessfulUpload.IsZero() {
		t.Fatalf("expected bounded hub state: %+v", snapshot)
	}
}

func TestTrackerSanitizesErrorText(t *testing.T) {
	tracker := New("1", "site", "sensor", "source")
	tracker.CaptureError("  bad\nvalue\r\n" + string(make([]byte, 600)))
	if value := tracker.Snapshot().LastCaptureError; value == "" || len(value) > 512 {
		t.Fatalf("capture error was not bounded: %d", len(value))
	}
}
