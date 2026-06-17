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
	AssetID           string                     `json:"asset_id,omitempty"`
	SiteID            string                     `json:"site_id,omitempty"`
	ExternalCIID      string                     `json:"external_ci_id,omitempty"`
	ExternalCISource  string                     `json:"external_ci_source,omitempty"`
	Hostname          string                     `json:"hostname,omitempty"`
	FQDN              string                     `json:"fqdn,omitempty"`
	OS                string                     `json:"os,omitempty"`
	Platform          string                     `json:"platform,omitempty"`
	Architecture      string                     `json:"architecture,omitempty"`
	Host              *HostObservation           `json:"host,omitempty"`
	PlatformInfo      *PlatformObservation       `json:"platform_info,omitempty"`
	PrimaryInterfaces []NetworkInterface         `json:"primary_interfaces,omitempty"`
	IPAddresses       []IPAddressObservation     `json:"ip_addresses,omitempty"`
	MACAddresses      []MACAddressObservation    `json:"mac_addresses,omitempty"`
	DefaultGateway    *DefaultGatewayObservation `json:"default_gateway,omitempty"`
	NetworkNeighbors  []NetworkNeighbor          `json:"network_neighbors,omitempty"`
	Evidence          []Evidence                 `json:"evidence,omitempty"`
}

type HostObservation struct {
	Hostname    string    `json:"hostname,omitempty"`
	FQDN        string    `json:"fqdn,omitempty"`
	Source      string    `json:"source"`
	CollectedAt time.Time `json:"collected_at"`
}

type PlatformObservation struct {
	OS                 string    `json:"os,omitempty"`
	Platform           string    `json:"platform,omitempty"`
	Architecture       string    `json:"architecture,omitempty"`
	ArchitectureFamily string    `json:"architecture_family,omitempty"`
	Source             string    `json:"source"`
	CollectedAt        time.Time `json:"collected_at"`
}

type NetworkInterface struct {
	Name        string                 `json:"name"`
	Index       int                    `json:"index,omitempty"`
	MACAddress  string                 `json:"mac_address,omitempty"`
	Flags       []string               `json:"flags,omitempty"`
	IPAddresses []IPAddressObservation `json:"ip_addresses,omitempty"`
	Source      string                 `json:"source"`
	CollectedAt time.Time              `json:"collected_at"`
}

type IPAddressObservation struct {
	Address     string    `json:"address"`
	Family      string    `json:"family,omitempty"`
	Interface   string    `json:"interface,omitempty"`
	Source      string    `json:"source"`
	CollectedAt time.Time `json:"collected_at"`
}

type MACAddressObservation struct {
	Address     string    `json:"address"`
	Interface   string    `json:"interface,omitempty"`
	Source      string    `json:"source"`
	CollectedAt time.Time `json:"collected_at"`
}

type DefaultGatewayObservation struct {
	Address        string    `json:"address,omitempty"`
	Interface      string    `json:"interface,omitempty"`
	InterfaceIndex int       `json:"interface_index,omitempty"`
	Source         string    `json:"source"`
	CollectedAt    time.Time `json:"collected_at"`
}

type NetworkNeighbor struct {
	IPAddress   string    `json:"ip_address,omitempty"`
	MACAddress  string    `json:"mac_address,omitempty"`
	Interface   string    `json:"interface,omitempty"`
	State       string    `json:"state,omitempty"`
	Source      string    `json:"source"`
	Sources     []string  `json:"sources,omitempty"`
	CollectedAt time.Time `json:"collected_at"`
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
	TenantID     string    `json:"tenant_id,omitempty"`
	SiteID       string    `json:"site_id,omitempty"`
	DeploymentID string    `json:"deployment_id,omitempty"`
	AgentID      string    `json:"agent_id,omitempty"`
	SensorID     string    `json:"sensor_id,omitempty"`
	Mode         string    `json:"mode"`
	Version      string    `json:"version"`
	CheckedInAt  time.Time `json:"checked_in_at"`
}

type Inventory struct {
	SchemaVersion string     `json:"schema_version"`
	TenantID      string     `json:"tenant_id,omitempty"`
	SiteID        string     `json:"site_id,omitempty"`
	DeploymentID  string     `json:"deployment_id,omitempty"`
	AgentID       string     `json:"agent_id,omitempty"`
	SensorID      string     `json:"sensor_id,omitempty"`
	CollectedAt   time.Time  `json:"collected_at"`
	Assets        []Asset    `json:"assets"`
	Findings      []Finding  `json:"findings,omitempty"`
	Evidence      []Evidence `json:"evidence,omitempty"`
}
