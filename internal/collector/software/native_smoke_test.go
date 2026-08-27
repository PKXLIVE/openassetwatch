package software

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestNativeSoftwareCountOnlySmoke(t *testing.T) {
	if os.Getenv("OPENASSETWATCH_NATIVE_SOFTWARE_SMOKE") != "1" {
		t.Skip("explicit native software smoke gate is disabled")
	}
	components, sources := CollectAt(context.Background(), time.Now().UTC())
	if len(sources) == 0 {
		t.Fatal("native collector returned no source status")
	}
	reported := 0
	statuses := map[string]int{}
	for _, source := range sources {
		reported += source.RecordCount
		statuses[source.Status]++
	}
	if reported != len(components) {
		t.Fatalf("source record count=%d component count=%d", reported, len(components))
	}
	// Intentionally log counts and bounded statuses only. Never print package
	// names, registry records, command output, local paths, or metadata.
	t.Logf("native software count=%d sources=%d statuses=%v", len(components), len(sources), statuses)
}
