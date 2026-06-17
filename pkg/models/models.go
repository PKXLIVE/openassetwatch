package models

import "time"

type Evidence struct {
	ID         string `json:"id,omitempty"`
	Source     string `json:"source"`
	Summary    string `json:"summary"`
	ArtifactID string `json:"evidence_artifact_id,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

type Asset struct {
	AssetID  string     `json:"asset_id,omitempty"`
	SiteID   string     `json:"site_id,omitempty"`
	Hostname string     `json:"hostname,omitempty"`
	Platform string     `json:"platform,omitempty"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

type Finding struct {
	FindingID   string     `json:"finding_id,omitempty"`
	AssetID     string     `json:"asset_id,omitempty"`
	Title       string     `json:"title"`
	Severity    string     `json:"severity,omitempty"`
	Status      string     `json:"status,omitempty"`
	Remediation string     `json:"remediation,omitempty"`
	Evidence    []Evidence `json:"evidence,omitempty"`
}

type CollectorHeartbeat struct {
	SiteID      string    `json:"site_id,omitempty"`
	AgentID     string    `json:"agent_id,omitempty"`
	SensorID    string    `json:"sensor_id,omitempty"`
	Mode        string    `json:"mode"`
	Version     string    `json:"version"`
	CheckedInAt time.Time `json:"checked_in_at"`
}

type Inventory struct {
	SchemaVersion string     `json:"schema_version"`
	CollectedAt   time.Time  `json:"collected_at"`
	Assets        []Asset    `json:"assets"`
	Findings      []Finding  `json:"findings,omitempty"`
	Evidence      []Evidence `json:"evidence,omitempty"`
}
