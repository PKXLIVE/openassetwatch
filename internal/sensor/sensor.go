package sensor

const (
	CaptureModeSynthetic = "synthetic"
	CaptureModeLive      = "live"
	SensorType           = "passive-network-sensor"
)

type Profile struct {
	SiteID        string   `json:"site_id,omitempty"`
	SensorID      string   `json:"sensor_id,omitempty"`
	AllowedInputs []string `json:"allowed_inputs"`
	Mode          string   `json:"mode"`
}

func DefaultProfile(siteID string) Profile {
	return Profile{
		SiteID:        siteID,
		AllowedInputs: []string{"synthetic_frames", "approved_passive_interface"},
		Mode:          "passive",
	}
}
