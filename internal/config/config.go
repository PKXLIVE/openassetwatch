package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Mode string

const (
	ModeAgent  Mode = "agent"
	ModeSensor Mode = "sensor"
)

type Config struct {
	Mode            Mode   `json:"mode"`
	SiteID          string `json:"site_id,omitempty"`
	AgentID         string `json:"agent_id,omitempty"`
	SensorID        string `json:"sensor_id,omitempty"`
	ConnectorID     string `json:"connector_id,omitempty"`
	ApprovedScopeID string `json:"approved_scope_id,omitempty"`
	ReviewProfile   string `json:"review_profile,omitempty"`
	ServiceName     string `json:"service_name,omitempty"`
}

func Default(mode Mode) Config {
	return Config{
		Mode:          mode,
		ReviewProfile: "passive_inventory",
	}
}

func LoadJSON(path string) (Config, error) {
	if IsQuarantinedPath(path) {
		return Config{}, fmt.Errorf("refusing to load quarantined config path: %s", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

func IsQuarantinedPath(path string) bool {
	slashPath := strings.ReplaceAll(path, "\\", "/")
	normalized := strings.ToLower(filepath.ToSlash(filepath.Clean(slashPath)))
	return normalized == "configs/quarantine" ||
		strings.HasPrefix(normalized, "configs/quarantine/") ||
		strings.Contains(normalized, "/configs/quarantine/") ||
		strings.HasSuffix(normalized, "/configs/quarantine")
}

func (cfg Config) Validate() error {
	switch cfg.Mode {
	case ModeAgent, ModeSensor:
	default:
		return fmt.Errorf("mode must be %q or %q", ModeAgent, ModeSensor)
	}
	if cfg.SiteID == "" && cfg.ApprovedScopeID == "" {
		return errors.New("site_id or approved_scope_id is required")
	}
	return nil
}
