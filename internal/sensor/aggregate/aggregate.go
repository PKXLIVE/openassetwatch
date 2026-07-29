package aggregate

import (
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openassetwatch/openassetwatch/internal/sensor/contract"
	"github.com/openassetwatch/openassetwatch/internal/sensor/decode"
)

const (
	DefaultMaxDevices           = 2048
	DefaultMaxEvidencePerDevice = 32
	DefaultMaxIPsPerDevice      = 8
	DefaultTTL                  = 30 * time.Minute
	MaxDevicesAbsolute          = 100000
	MaxIPsPerDeviceAbsolute     = 64
	MaxTTLAbsolute              = 24 * time.Hour
	MaxHostnameLength           = 255
	MaxServiceNameLength        = 128
	MaxSSDPMetadataLength       = 256
	MaxVLANID                   = 4094
	MaxProtocolLength           = 32
	MaxEvidenceKindLength       = 64
	MaxEvidenceValueLength      = 512
)

var ErrCapacity = errors.New("sensor aggregation capacity reached")

type Config struct {
	SiteID               string
	MaxDevices           int
	MaxEvidencePerDevice int
	MaxIPsPerDevice      int
	TTL                  time.Duration
}

type Aggregator struct {
	mu      sync.Mutex
	config  Config
	devices map[string]*device
	dropped uint64
}

type device struct {
	mac       string
	vlanID    *int
	hostname  string
	hostScore float64
	firstSeen time.Time
	lastSeen  time.Time
	ips       map[string]time.Time
	evidence  map[string]contract.Evidence
}

func New(config Config) (*Aggregator, error) {
	config.SiteID = strings.TrimSpace(config.SiteID)
	if config.SiteID == "" {
		return nil, errors.New("site ID is required for aggregation")
	}
	if config.MaxDevices <= 0 {
		config.MaxDevices = DefaultMaxDevices
	}
	if config.MaxDevices > MaxDevicesAbsolute {
		return nil, fmt.Errorf("maximum devices cannot exceed %d", MaxDevicesAbsolute)
	}
	if config.MaxEvidencePerDevice <= 0 {
		config.MaxEvidencePerDevice = DefaultMaxEvidencePerDevice
	}
	if config.MaxEvidencePerDevice > contract.MaxEvidence {
		return nil, fmt.Errorf("maximum evidence per device cannot exceed %d", contract.MaxEvidence)
	}
	if config.MaxIPsPerDevice <= 0 {
		config.MaxIPsPerDevice = DefaultMaxIPsPerDevice
	}
	if config.MaxIPsPerDevice > MaxIPsPerDeviceAbsolute {
		return nil, fmt.Errorf("maximum IPs per device cannot exceed %d", MaxIPsPerDeviceAbsolute)
	}
	if config.TTL <= 0 {
		config.TTL = DefaultTTL
	}
	if config.TTL > MaxTTLAbsolute {
		return nil, fmt.Errorf("aggregation TTL cannot exceed %s", MaxTTLAbsolute)
	}
	if err := contract.ValidateSiteID(config.SiteID); err != nil {
		return nil, err
	}
	return &Aggregator{config: config, devices: make(map[string]*device)}, nil
}

func (a *Aggregator) Add(item decode.Evidence) error {
	if err := validateEvidence(item); err != nil {
		return err
	}
	mac, err := NormalizeMAC(item.MAC)
	if err != nil {
		return err
	}
	observedAt := item.ObservedAt.UTC()
	if observedAt.IsZero() {
		return errors.New("observation timestamp is required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expireLocked(observedAt)
	key := deviceKey(a.config.SiteID, mac, item.VLANID)
	current, exists := a.devices[key]
	if !exists {
		if len(a.devices) >= a.config.MaxDevices {
			a.dropped++
			return ErrCapacity
		}
		current = &device{
			mac: mac, vlanID: cloneInt(item.VLANID), firstSeen: observedAt, lastSeen: observedAt,
			ips: make(map[string]time.Time), evidence: make(map[string]contract.Evidence),
		}
		a.devices[key] = current
	}
	if observedAt.After(current.lastSeen) {
		current.lastSeen = observedAt
	}
	if parsed := net.ParseIP(strings.TrimSpace(item.IP)); parsed != nil {
		ip := parsed.String()
		if _, exists := current.ips[ip]; exists || len(current.ips) < a.config.MaxIPsPerDevice {
			current.ips[ip] = observedAt
		} else {
			a.dropped++
		}
	}
	if hostname := cleanHostname(item.Hostname); hostname != "" && (current.hostname == "" || item.Confidence > current.hostScore) {
		current.hostname = hostname
		current.hostScore = item.Confidence
	}
	// Ordinary DNS queries are deliberately not persisted as device history.
	if item.Protocol == "dns" && item.Kind == "query-name" {
		return nil
	}
	value := cleanEvidenceValue(item.Protocol, item.Value)
	if value == "" {
		return nil
	}
	evidenceKey := item.Protocol + "\x00" + item.Kind + "\x00" + value
	if _, exists := current.evidence[evidenceKey]; !exists && len(current.evidence) >= a.config.MaxEvidencePerDevice {
		a.dropped++
		return ErrCapacity
	}
	current.evidence[evidenceKey] = contract.Evidence{
		Protocol: item.Protocol, Kind: item.Kind, Value: value, Confidence: clamp(item.Confidence),
	}
	return nil
}

func (a *Aggregator) Snapshot(now time.Time, limit int) []contract.Asset {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expireLocked(now.UTC())
	keys := make([]string, 0, len(a.devices))
	for key := range a.devices {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if limit <= 0 || limit > contract.MaxAssets {
		limit = contract.MaxAssets
	}
	if len(keys) > limit {
		keys = keys[:limit]
	}
	assets := make([]contract.Asset, 0, len(keys))
	for _, key := range keys {
		current := a.devices[key]
		protocolSet := make(map[string]struct{})
		evidence := make([]contract.Evidence, 0, len(current.evidence))
		category := ""
		for _, item := range current.evidence {
			protocolSet[item.Protocol] = struct{}{}
			if item.Protocol == "ssdp" {
				category = "network-device"
			}
			evidence = append(evidence, item)
		}
		sort.Slice(evidence, func(i, j int) bool {
			left := evidence[i].Protocol + "\x00" + evidence[i].Kind + "\x00" + evidence[i].Value
			right := evidence[j].Protocol + "\x00" + evidence[j].Kind + "\x00" + evidence[j].Value
			return left < right
		})
		if current.vlanID != nil {
			protocolSet["vlan"] = struct{}{}
			if len(evidence) >= contract.MaxEvidence {
				// Reserve one bounded evidence slot for the VLAN scope. VLAN is
				// part of the local correlation key and must not disappear when
				// a device has a full protocol evidence budget.
				evidence = evidence[:contract.MaxEvidence-1]
			}
			evidence = append(evidence, contract.Evidence{
				Protocol: "vlan", Kind: "vlan-id", Value: fmt.Sprintf("%d", *current.vlanID), Confidence: 1,
			})
		}
		protocols := make([]string, 0, len(protocolSet))
		for protocol := range protocolSet {
			protocols = append(protocols, protocol)
		}
		sort.Strings(protocols)
		assets = append(assets, contract.Asset{
			AssetID: stableAssetID(current.mac, current.vlanID), Hostname: current.hostname,
			PrimaryIP: latestIP(current.ips), MAC: current.mac, Category: category,
			VLANID: cloneInt(current.vlanID), SourceProtocols: protocols, Evidence: evidence,
		})
	}
	return assets
}

func (a *Aggregator) Counts() (devices int, dropped uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.devices), a.dropped
}

func (a *Aggregator) Expire(now time.Time) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.expireLocked(now.UTC())
}

func (a *Aggregator) expireLocked(now time.Time) int {
	cutoff := now.Add(-a.config.TTL)
	removed := 0
	for key, current := range a.devices {
		if current.lastSeen.Before(cutoff) {
			delete(a.devices, key)
			removed++
		}
	}
	return removed
}

func NormalizeMAC(value string) (string, error) {
	parsed, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(parsed) != 6 {
		return "", errors.New("observation requires a valid six-byte MAC address")
	}
	if parsed[0]&1 != 0 {
		return "", errors.New("multicast MAC cannot identify a device")
	}
	allZero := true
	for _, octet := range parsed {
		allZero = allZero && octet == 0
	}
	if allZero {
		return "", errors.New("zero MAC cannot identify a device")
	}
	return strings.ToLower(parsed.String()), nil
}

func deviceKey(siteID, mac string, vlanID *int) string {
	vlan := "untagged"
	if vlanID != nil {
		vlan = fmt.Sprintf("%d", *vlanID)
	}
	return siteID + "\x00" + vlan + "\x00" + mac
}

func stableAssetID(mac string, vlanID *int) string {
	identifier := "mac-" + strings.ReplaceAll(mac, ":", "")
	if vlanID != nil {
		identifier += fmt.Sprintf("-vlan-%d", *vlanID)
	}
	return identifier
}

func latestIP(values map[string]time.Time) string {
	latest := ""
	latestAt := time.Time{}
	for value, seenAt := range values {
		if seenAt.After(latestAt) || (seenAt.Equal(latestAt) && value < latest) {
			latest = value
			latestAt = seenAt
		}
	}
	return latest
}

func cleanHostname(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > MaxHostnameLength {
		return ""
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return value
}

func validateEvidence(item decode.Evidence) error {
	if item.VLANID != nil && (*item.VLANID < 0 || *item.VLANID > MaxVLANID) {
		return errors.New("observation VLAN ID is outside 0..4094")
	}
	if item.Protocol == "" || len(item.Protocol) > MaxProtocolLength {
		return errors.New("observation protocol is missing or too long")
	}
	switch item.Protocol {
	case "arp", "dhcpv4", "dns", "mdns", "ssdp", "nbns":
	default:
		return fmt.Errorf("unsupported observation protocol %q", item.Protocol)
	}
	if len(item.Kind) == 0 || len(item.Kind) > MaxEvidenceKindLength {
		return errors.New("observation kind is missing or too long")
	}
	if len(item.Value) > MaxEvidenceValueLength {
		return errors.New("observation value exceeds bounded evidence size")
	}
	if item.Hostname != "" && len(item.Hostname) > MaxHostnameLength {
		return errors.New("observation hostname exceeds bounded size")
	}
	if item.Protocol == "ssdp" && len(item.Value) > MaxSSDPMetadataLength {
		return errors.New("SSDP metadata exceeds bounded evidence size")
	}
	if (item.Kind == "service-name" || item.Kind == "service-target") && len(item.Value) > MaxServiceNameLength {
		return errors.New("service name exceeds bounded evidence size")
	}
	if math.IsNaN(item.Confidence) || math.IsInf(item.Confidence, 0) {
		return errors.New("observation confidence must be finite")
	}
	if item.ObservedAt.IsZero() {
		return errors.New("observation timestamp is required")
	}
	return nil
}

func cleanEvidenceValue(protocol, value string) string {
	value = strings.TrimSpace(value)
	limit := MaxEvidenceValueLength
	if protocol == "ssdp" {
		limit = MaxSSDPMetadataLength
	}
	if len(value) > limit {
		return ""
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return value
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func clamp(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}
