package software

import (
	"testing"
	"time"

	"github.com/openassetwatch/openassetwatch/pkg/models"
)

func TestFinalizePreservesDistinctReviewedSourcePresence(t *testing.T) {
	observedAt := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	component := func(source string) models.SoftwareComponent {
		return models.SoftwareComponent{
			ComponentType: "application", Ecosystem: "generic", Name: "Fictional Suite",
			Version: "1.2.3", Architecture: "amd64", InstallScope: "system",
			CollectionSource: source, SourceRecordID: "fictional-suite",
			EvidenceMethod: "native-query", ObservedAt: observedAt, Confidence: 0.9,
		}
	}
	components, sources := finalize(platformResult{
		components: []models.SoftwareComponent{component("source-a"), component("source-b")},
		sources: []models.SoftwareSourceResult{
			{SourceID: "source-a", Platform: "linux", Status: "complete", ObservedAt: observedAt},
			{SourceID: "source-b", Platform: "linux", Status: "complete", ObservedAt: observedAt},
		},
	}, observedAt)

	if len(components) != 2 {
		t.Fatalf("components = %d, want one observation per source", len(components))
	}
	for _, source := range sources {
		if source.RecordCount != 1 || source.Status != "complete" {
			t.Fatalf("source = %+v, want one complete record", source)
		}
	}
}

func TestFinalizeFailsClosedForInvalidOrUnsuccessfulSources(t *testing.T) {
	observedAt := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	components, sources := finalize(platformResult{
		components: []models.SoftwareComponent{
			{Name: "Unbound", CollectionSource: "missing", SourceRecordID: "one"},
			{Name: "Failed", CollectionSource: "failed-source", SourceRecordID: "two"},
		},
		sources: []models.SoftwareSourceResult{{
			SourceID: "failed-source", Platform: "linux", Status: "failed", ObservedAt: observedAt,
		}},
	}, observedAt)

	if len(components) != 0 {
		t.Fatalf("components = %+v, want no records from unbound or failed sources", components)
	}
	if len(sources) != 1 || sources[0].RecordCount != 0 {
		t.Fatalf("sources = %+v, want zero failed-source records", sources)
	}
}

func TestFinalizePreservesDistinctVersions(t *testing.T) {
	observedAt := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	component := func(version, recordID string) models.SoftwareComponent {
		return models.SoftwareComponent{
			ComponentType: "application", Ecosystem: "generic", Name: "Fictional Suite",
			Version: version, InstallScope: "system", CollectionSource: "source-a",
			SourceRecordID: recordID, EvidenceMethod: "native-query", ObservedAt: observedAt,
		}
	}
	components, sources := finalize(platformResult{
		components: []models.SoftwareComponent{
			component("1.0.0", "record-a"), component("2.0.0", "record-b"),
			component("2.0.0", "record-c"),
		},
		sources: []models.SoftwareSourceResult{{
			SourceID: "source-a", Platform: "linux", Status: "complete", ObservedAt: observedAt,
		}},
	}, observedAt)

	if len(components) != 2 {
		t.Fatalf("components = %+v, want side-by-side versions retained and same-version records deduplicated", components)
	}
	if len(sources) != 1 || sources[0].RecordCount != 2 {
		t.Fatalf("sources = %+v, want two retained versions", sources)
	}
}

func TestFinalizeBoundsUntrustedFieldsAndMarksPartial(t *testing.T) {
	observedAt := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	components, sources := finalize(platformResult{
		components: []models.SoftwareComponent{{
			Name: "bad\x00name", CollectionSource: "source-a", SourceRecordID: "record-a",
		}},
		sources: []models.SoftwareSourceResult{{
			SourceID: "source-a", Platform: "linux", Status: "complete", ObservedAt: observedAt,
		}},
	}, observedAt)

	if len(components) != 0 {
		t.Fatalf("components = %+v, want malformed record dropped", components)
	}
	if sources[0].Status != "partial" || len(sources[0].Limitations) != 1 {
		t.Fatalf("source = %+v, want bounded partial result", sources[0])
	}
}
