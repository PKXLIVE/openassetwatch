//go:build windows

package software

import (
	"testing"
	"time"

	"github.com/openassetwatch/openassetwatch/pkg/models"
)

func TestWindowsRecordComponentUsesOnlyReviewedRegistryMetadata(t *testing.T) {
	observedAt := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	component, ok := windowsRecordComponent(windowsRegistryRecord{
		name: "Fictional Workstation Suite", version: "4.2.0",
		publisher: "Fictional Systems", recordID: "{00000000-0000-0000-0000-000000000001}",
		sourceID: "windows-uninstall-64",
	}, observedAt)
	if !ok {
		t.Fatal("reviewed registry record was rejected")
	}
	if component.Name != "Fictional Workstation Suite" || component.Version != "4.2.0" {
		t.Fatalf("component = %+v", component)
	}
	if component.PackageManager != "windows-registry" || component.EvidenceMethod != "windows-uninstall-registry" {
		t.Fatalf("source metadata = %+v", component)
	}
	if component.PackageURL != "" || component.Metadata != nil {
		t.Fatalf("unexpected unrestricted metadata retained: %+v", component)
	}
	if component.Architecture != "" {
		t.Fatalf("registry view was incorrectly asserted as package architecture: %+v", component)
	}
}

func TestWindowsRecordComponentRejectsControlCharacters(t *testing.T) {
	_, ok := windowsRecordComponent(windowsRegistryRecord{
		name: "unsafe\nname", recordID: "record", sourceID: "windows-uninstall-32",
	}, time.Now().UTC())
	if ok {
		t.Fatal("control-character record was accepted")
	}
}

func TestWindowsRegistryDuplicateSuppressionIsDeterministicPerView(t *testing.T) {
	observedAt := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	record := func(recordID string) models.SoftwareComponent {
		component, ok := windowsRecordComponent(windowsRegistryRecord{
			name: "Fictional Duplicate Suite", version: "1.0.0",
			recordID: recordID, sourceID: "windows-uninstall-64",
		}, observedAt)
		if !ok {
			t.Fatalf("record %q was rejected", recordID)
		}
		return component
	}
	components, sources := finalize(platformResult{
		components: []models.SoftwareComponent{record("record-b"), record("record-a")},
		sources: []models.SoftwareSourceResult{{
			SourceID: "windows-uninstall-64", Platform: "windows", Status: "complete", ObservedAt: observedAt,
		}},
	}, observedAt)
	if len(components) != 1 || components[0].SourceRecordID != "record-a" {
		t.Fatalf("components = %+v, want deterministic first registry record", components)
	}
	if len(sources) != 1 || sources[0].RecordCount != 1 {
		t.Fatalf("sources = %+v, want one deduplicated record", sources)
	}
}
