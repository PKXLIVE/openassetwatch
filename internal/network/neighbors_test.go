package network

import "testing"

func TestDeduplicateKeepsFirstObservation(t *testing.T) {
	observations := []NeighborObservation{
		{AssetID: "asset-1", Source: "neighbor_cache", Confidence: "high"},
		{AssetID: "asset-1", Source: "neighbor_cache", Confidence: "low"},
		{AssetID: "asset-1", Source: "approved_passive_source", Confidence: "medium"},
	}

	result := Deduplicate(observations)
	if len(result) != 2 {
		t.Fatalf("Deduplicate length = %d, want 2", len(result))
	}
	if result[0].Confidence != "high" {
		t.Fatalf("Deduplicate did not keep first observation: %q", result[0].Confidence)
	}
}
