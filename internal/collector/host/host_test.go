package host

import (
	"testing"
	"time"
)

func TestFQDNFromHostname(t *testing.T) {
	if got := fqdnFromHostname("workstation"); got != "" {
		t.Fatalf("fqdnFromHostname returned %q for short hostname", got)
	}
	if got := fqdnFromHostname("workstation.example.com."); got != "workstation.example.com" {
		t.Fatalf("fqdnFromHostname returned %q", got)
	}
}

func TestDetectAtSetsCollectedAt(t *testing.T) {
	collectedAt := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	observation := DetectAt(collectedAt)
	if !observation.CollectedAt.Equal(collectedAt) {
		t.Fatalf("DetectAt CollectedAt = %s, want %s", observation.CollectedAt, collectedAt)
	}
	if observation.Source != sourceHostname {
		t.Fatalf("DetectAt Source = %q, want %q", observation.Source, sourceHostname)
	}
}
