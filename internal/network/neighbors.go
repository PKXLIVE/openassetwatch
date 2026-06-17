package network

type NeighborObservation struct {
	AssetID    string `json:"asset_id,omitempty"`
	SiteID     string `json:"site_id,omitempty"`
	ObservedBy string `json:"sensor_id,omitempty"`
	Source     string `json:"source"`
	Confidence string `json:"confidence,omitempty"`
}

func Deduplicate(observations []NeighborObservation) []NeighborObservation {
	seen := map[string]struct{}{}
	result := make([]NeighborObservation, 0, len(observations))
	for _, observation := range observations {
		key := observation.AssetID + "|" + observation.Source
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, observation)
	}
	return result
}
