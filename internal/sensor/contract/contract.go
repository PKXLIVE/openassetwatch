package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	SchemaVersion = "oaw.observation-batch.v1"
	MaxAssets     = 500
	MaxEvidence   = 32
	MaxBodyBytes  = 2 << 20
)

var (
	identifierPattern     = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
	siteIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

type Evidence struct {
	Protocol   string  `json:"protocol"`
	Kind       string  `json:"kind"`
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
}

type Asset struct {
	AssetID   string     `json:"asset_id"`
	Hostname  string     `json:"hostname,omitempty"`
	PrimaryIP string     `json:"primary_ip,omitempty"`
	MAC       string     `json:"mac,omitempty"`
	OS        string     `json:"os,omitempty"`
	Platform  string     `json:"platform,omitempty"`
	Category  string     `json:"category,omitempty"`
	Evidence  []Evidence `json:"evidence,omitempty"`
	// VLANID and SourceProtocols are retained for local correlation and health
	// reporting. They are not part of the hub wire contract; VLAN details are
	// represented by bounded Evidence records when they need to be delivered.
	VLANID          *int     `json:"-"`
	SourceProtocols []string `json:"-"`
}

type Batch struct {
	SchemaVersion      string    `json:"schema_version"`
	ObservationBatchID string    `json:"observation_batch_id"`
	SiteID             string    `json:"site_id"`
	SensorID           string    `json:"sensor_id"`
	SensorName         string    `json:"sensor_name"`
	SensorType         string    `json:"sensor_type"`
	SensorVersion      string    `json:"sensor_version,omitempty"`
	ObservedAt         time.Time `json:"observed_at"`
	ObservationSource  string    `json:"observation_source"`
	DeliveryState      string    `json:"delivery_state"`
	Confidence         float64   `json:"confidence"`
	Assets             []Asset   `json:"assets"`
}

func (b Batch) Validate() error {
	if b.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %q", SchemaVersion)
	}
	if err := ValidateBatchID(b.ObservationBatchID); err != nil {
		return err
	}
	if err := ValidateSiteID(b.SiteID); err != nil {
		return err
	}
	if err := ValidateSensorID(b.SensorID); err != nil {
		return err
	}
	if !validText(b.SensorName, 1, 160) {
		return errors.New("sensor_name must contain 1 to 160 characters")
	}
	if b.SensorType != "passive-network-sensor" {
		return errors.New("sensor_type must be passive-network-sensor")
	}
	if b.SensorVersion != "" && !validText(b.SensorVersion, 1, 80) {
		return errors.New("sensor_version exceeds 80 characters")
	}
	if b.ObservedAt.IsZero() {
		return errors.New("observed_at is required")
	}
	if b.ObservationSource != "passive-network" {
		return errors.New("observation_source must be passive-network")
	}
	if b.DeliveryState != "live" && b.DeliveryState != "cached-retry" {
		return errors.New("delivery_state must be live or cached-retry")
	}
	if math.IsNaN(b.Confidence) || math.IsInf(b.Confidence, 0) || b.Confidence < 0 || b.Confidence > 1 {
		return errors.New("confidence must be between 0 and 1")
	}
	if b.Assets == nil {
		return errors.New("assets must be a JSON array")
	}
	if len(b.Assets) > MaxAssets {
		return fmt.Errorf("assets exceeds maximum of %d", MaxAssets)
	}
	assetIDs := make(map[string]struct{}, len(b.Assets))
	for index := range b.Assets {
		if err := b.Assets[index].Validate(); err != nil {
			return fmt.Errorf("asset %d: %w", index, err)
		}
		if _, duplicate := assetIDs[b.Assets[index].AssetID]; duplicate {
			return fmt.Errorf("asset %d duplicates asset_id %q", index, b.Assets[index].AssetID)
		}
		assetIDs[b.Assets[index].AssetID] = struct{}{}
	}
	return nil
}

func (a Asset) Validate() error {
	if !validText(a.AssetID, 1, 160) {
		return errors.New("asset_id must contain 1 to 160 characters")
	}
	if a.Hostname != "" && !validText(a.Hostname, 1, 255) {
		return errors.New("hostname exceeds 255 characters")
	}
	if a.OS != "" && !validText(a.OS, 1, 160) {
		return errors.New("os exceeds 160 characters")
	}
	if a.Platform != "" && !validText(a.Platform, 1, 160) {
		return errors.New("platform exceeds 160 characters")
	}
	if a.Category != "" && !validText(a.Category, 1, 80) {
		return errors.New("category exceeds 80 characters")
	}
	if a.PrimaryIP != "" && net.ParseIP(a.PrimaryIP) == nil {
		return errors.New("primary_ip is invalid")
	}
	if a.MAC != "" {
		mac, err := net.ParseMAC(a.MAC)
		if err != nil || len(mac) != 6 {
			return errors.New("mac is invalid")
		}
	}
	if a.VLANID != nil && (*a.VLANID < 0 || *a.VLANID > 4094) {
		return errors.New("vlan_id must be between 0 and 4094")
	}
	if len(a.SourceProtocols) > 8 {
		return errors.New("source_protocols exceeds 8 entries")
	}
	if len(a.Evidence) > MaxEvidence {
		return fmt.Errorf("evidence exceeds maximum of %d", MaxEvidence)
	}
	for _, evidence := range a.Evidence {
		if !validProtocol(evidence.Protocol) {
			return fmt.Errorf("unsupported evidence protocol %q", evidence.Protocol)
		}
		if !validText(evidence.Kind, 1, 64) {
			return errors.New("evidence kind must contain 1 to 64 characters")
		}
		if !validText(evidence.Value, 1, 512) {
			return errors.New("evidence value must contain 1 to 512 characters")
		}
		if math.IsNaN(evidence.Confidence) || math.IsInf(evidence.Confidence, 0) || evidence.Confidence < 0 || evidence.Confidence > 1 {
			return errors.New("evidence confidence must be between 0 and 1")
		}
	}
	for _, protocol := range a.SourceProtocols {
		if !validProtocol(protocol) {
			return fmt.Errorf("unsupported source protocol %q", protocol)
		}
	}
	return nil
}

func BatchID(sensorID string, observedAt time.Time, assets []Asset) (string, error) {
	if err := ValidateSensorID(sensorID); err != nil {
		return "", err
	}
	if observedAt.IsZero() {
		return "", errors.New("observed_at is required")
	}
	if assets == nil || len(assets) > MaxAssets {
		return "", fmt.Errorf("assets must contain 0 to %d entries", MaxAssets)
	}
	assetIDs := make(map[string]struct{}, len(assets))
	for index := range assets {
		if err := assets[index].Validate(); err != nil {
			return "", fmt.Errorf("asset %d: %w", index, err)
		}
		if _, duplicate := assetIDs[assets[index].AssetID]; duplicate {
			return "", fmt.Errorf("asset %d duplicates asset_id %q", index, assets[index].AssetID)
		}
		assetIDs[assets[index].AssetID] = struct{}{}
	}
	canonical := make([]Asset, len(assets))
	for index := range assets {
		canonical[index] = assets[index]
		canonical[index].Evidence = append([]Evidence(nil), assets[index].Evidence...)
		sort.Slice(canonical[index].Evidence, func(left, right int) bool {
			a := canonical[index].Evidence[left]
			b := canonical[index].Evidence[right]
			if a.Protocol != b.Protocol {
				return a.Protocol < b.Protocol
			}
			if a.Kind != b.Kind {
				return a.Kind < b.Kind
			}
			if a.Value != b.Value {
				return a.Value < b.Value
			}
			return a.Confidence < b.Confidence
		})
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].AssetID < canonical[j].AssetID })
	payload, err := json.Marshal(struct {
		SensorID   string    `json:"sensor_id"`
		ObservedAt time.Time `json:"observed_at"`
		Assets     []Asset   `json:"assets"`
	}{sensorID, observedAt.UTC(), canonical})
	if err != nil {
		return "", fmt.Errorf("marshal batch identity: %w", err)
	}
	digest := sha256.Sum256(payload)
	return "oaw:" + hex.EncodeToString(digest[:16]), nil
}

func Marshal(b Batch) ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("marshal observation batch: %w", err)
	}
	if len(data) > MaxBodyBytes {
		return nil, fmt.Errorf("observation batch exceeds %d bytes", MaxBodyBytes)
	}
	return data, nil
}

func validateID(name, value string, min, max int) error {
	if len(value) < min || len(value) > max || !identifierPattern.MatchString(value) {
		return fmt.Errorf("%s must be %d to %d characters using letters, digits, dot, underscore, colon, or hyphen", name, min, max)
	}
	return nil
}

// ValidateSiteID, ValidateSensorID, and ValidateBatchID mirror the backend
// Pydantic contract. Site identifiers intentionally do not allow ':' while
// sensor and batch identifiers do.
func ValidateSiteID(value string) error {
	if len(value) < 1 || len(value) > 128 || !siteIdentifierPattern.MatchString(value) {
		return errors.New("site_id must be 1 to 128 characters using letters, digits, dot, underscore, or hyphen")
	}
	return nil
}

func ValidateSensorID(value string) error {
	return validateID("sensor_id", value, 1, 160)
}

func ValidateBatchID(value string) error {
	return validateID("observation_batch_id", value, 8, 160)
}

func validText(value string, min, max int) bool {
	trimmed := strings.TrimSpace(value)
	if utf8.RuneCountInString(trimmed) < min || utf8.RuneCountInString(trimmed) > max || trimmed == "" {
		return false
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validProtocol(value string) bool {
	switch value {
	case "arp", "dhcpv4", "dns", "mdns", "ssdp", "nbns", "vlan":
		return true
	default:
		return false
	}
}
