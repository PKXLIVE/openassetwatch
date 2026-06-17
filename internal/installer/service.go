package installer

import "github.com/openassetwatch/openassetwatch/internal/config"

type ServiceSpec struct {
	Name       string      `json:"name"`
	Mode       config.Mode `json:"mode"`
	ConfigPath string      `json:"config_path,omitempty"`
}

func DefaultServiceName(mode config.Mode) string {
	if mode == config.ModeSensor {
		return "oaw-sensor"
	}
	return "oaw-agent"
}
