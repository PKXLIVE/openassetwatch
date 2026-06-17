package platform

import (
	"testing"
	"time"
)

func TestArchitectureFamily(t *testing.T) {
	tests := map[string]string{
		"amd64":   "x86_64",
		"x86_64":  "x86_64",
		"386":     "x86",
		"arm64":   "arm64",
		"aarch64": "arm64",
		"armv7l":  "arm",
		"":        "unknown",
	}

	for input, want := range tests {
		if got := ArchitectureFamily(input); got != want {
			t.Fatalf("ArchitectureFamily(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestDetectAtSetsCollectedAtAndSource(t *testing.T) {
	collectedAt := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	observation := DetectAt(collectedAt)
	if !observation.CollectedAt.Equal(collectedAt) {
		t.Fatalf("DetectAt CollectedAt = %s, want %s", observation.CollectedAt, collectedAt)
	}
	if observation.Source != sourceRuntime {
		t.Fatalf("DetectAt Source = %q, want %q", observation.Source, sourceRuntime)
	}
	if observation.OS == "" || observation.Platform == "" || observation.Architecture == "" {
		t.Fatalf("DetectAt returned incomplete platform observation: %+v", observation)
	}
}
