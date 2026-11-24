package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/openassetwatch/openassetwatch/internal/sensor/safefile"
)

const (
	CollectorTokenEnv   = "OPENASSETWATCH_COLLECTOR_TOKEN"
	SensorCredentialEnv = "OPENASSETWATCH_SENSOR_CREDENTIAL"
)

var (
	siteIdentifierPattern      = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	sensorIdentifierPattern    = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
	ErrCollectorTokenTransport = errors.New(
		"collector credentials cannot be sent over non-loopback plaintext HTTP; use HTTPS or a verified loopback destination",
	)
)

type Config struct {
	HubURL                string `json:"hub_url"`
	SiteID                string `json:"site_id"`
	SensorID              string `json:"sensor_id,omitempty"`
	SensorName            string `json:"sensor_name"`
	CaptureMode           string `json:"capture_mode"`
	CaptureInterface      string `json:"capture_interface,omitempty"`
	IdentityPath          string `json:"identity_path"`
	CredentialPath        string `json:"credential_path"`
	SpoolPath             string `json:"spool_path"`
	StatusPath            string `json:"status_path"`
	CredentialEnv         string `json:"credential_env"`
	TokenEnv              string `json:"token_env"`
	BatchSize             int    `json:"batch_size"`
	BatchIntervalSeconds  int    `json:"batch_interval_seconds"`
	RequestTimeoutSeconds int    `json:"request_timeout_seconds"`
	RetryInitialSeconds   int    `json:"retry_initial_seconds"`
	RetryMaxSeconds       int    `json:"retry_max_seconds"`
	SpoolMaxItems         int    `json:"spool_max_items"`
	SpoolMaxBytes         int64  `json:"spool_max_bytes"`
	AggregationMaxDevices int    `json:"aggregation_max_devices"`
	AggregationTTLSeconds int    `json:"aggregation_ttl_seconds"`
}

func Default() Config {
	stateDir := defaultStateDir()
	return Config{
		HubURL: "http://127.0.0.1:8000", SensorName: "OpenAssetWatch Passive Sensor",
		CaptureMode: "synthetic", IdentityPath: filepath.Join(stateDir, "identity.json"),
		CredentialPath: filepath.Join(stateDir, "credential.json"), SpoolPath: filepath.Join(stateDir, "spool"),
		StatusPath:    filepath.Join(stateDir, "status.json"),
		CredentialEnv: SensorCredentialEnv, TokenEnv: CollectorTokenEnv,
		BatchSize: 250, BatchIntervalSeconds: 60, RequestTimeoutSeconds: 10,
		RetryInitialSeconds: 2, RetryMaxSeconds: 300, SpoolMaxItems: 1000,
		SpoolMaxBytes: 256 << 20, AggregationMaxDevices: 2048, AggregationTTLSeconds: 1800,
	}
}

func Load(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, errors.New("sensor config path is required")
	}
	file, err := safefile.OpenRootControlledConfig(path, 64<<10)
	if err != nil {
		return Config{}, fmt.Errorf("inspect sensor config: %w", err)
	}
	defer file.Close()
	cfg := Default()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode sensor config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("decode sensor config: trailing JSON data is not allowed")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (cfg Config) Validate() error {
	if err := ValidateHubURL(cfg.HubURL); err != nil {
		return err
	}
	if err := validateIdentifier("site_id", cfg.SiteID, 1, 128, siteIdentifierPattern); err != nil {
		return err
	}
	if cfg.SensorID != "" {
		if err := validateIdentifier("sensor_id", cfg.SensorID, 1, 160, sensorIdentifierPattern); err != nil {
			return err
		}
	}
	if strings.TrimSpace(cfg.SensorName) == "" || len(cfg.SensorName) > 160 {
		return errors.New("sensor_name must contain 1 to 160 characters")
	}
	if !safeText(cfg.SensorName) {
		return errors.New("sensor_name contains unsafe control characters")
	}
	if cfg.CaptureMode != "synthetic" && cfg.CaptureMode != "live" {
		return errors.New("capture_mode must be synthetic or live")
	}
	interfaceName := strings.TrimSpace(cfg.CaptureInterface)
	if cfg.CaptureInterface != "" && (interfaceName != cfg.CaptureInterface || len(interfaceName) > 64 || !safeText(interfaceName) || strings.ContainsAny(interfaceName, `/\`)) {
		return errors.New("capture_interface must be a safe name of at most 64 characters")
	}
	if cfg.CaptureMode == "live" && interfaceName == "" {
		return errors.New("capture_interface is required for live mode")
	}
	if !safePath(cfg.IdentityPath) || !safePath(cfg.CredentialPath) || !safePath(cfg.SpoolPath) || !safePath(cfg.StatusPath) {
		return errors.New("identity_path, credential_path, spool_path, and status_path must be safe paths of at most 4096 characters")
	}
	if cfg.CredentialEnv != SensorCredentialEnv {
		return fmt.Errorf("credential_env must be %s", SensorCredentialEnv)
	}
	if cfg.TokenEnv != CollectorTokenEnv {
		return fmt.Errorf("token_env must be %s", CollectorTokenEnv)
	}
	if cfg.BatchSize < 1 || cfg.BatchSize > 500 {
		return errors.New("batch_size must be between 1 and 500")
	}
	if cfg.BatchIntervalSeconds < 1 || cfg.BatchIntervalSeconds > 3600 {
		return errors.New("batch_interval_seconds must be between 1 and 3600")
	}
	if cfg.RequestTimeoutSeconds < 1 || cfg.RequestTimeoutSeconds > 120 {
		return errors.New("request_timeout_seconds must be between 1 and 120")
	}
	if cfg.RetryInitialSeconds < 1 || cfg.RetryMaxSeconds < cfg.RetryInitialSeconds || cfg.RetryMaxSeconds > 3600 {
		return errors.New("retry settings must be positive, ordered, and capped at 3600 seconds")
	}
	if cfg.SpoolMaxItems < 1 || cfg.SpoolMaxItems > 10000 || cfg.SpoolMaxBytes < 1<<20 || cfg.SpoolMaxBytes > 10<<30 {
		return errors.New("spool limits must be 1..10000 items and 1 MiB..10 GiB")
	}
	if cfg.AggregationMaxDevices < 1 || cfg.AggregationMaxDevices > 100000 || cfg.AggregationTTLSeconds < 60 || cfg.AggregationTTLSeconds > 86400 {
		return errors.New("aggregation limits are outside supported bounds")
	}
	return nil
}

func ValidateHubURL(value string) error {
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value) > 2048 || !safeText(value) {
		return errors.New("hub_url must be a safe URL of at most 2048 characters")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("hub_url must include an http or https scheme and host")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("hub_url must use http or https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("hub_url must not contain credentials, query, or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return errors.New("hub_url must not contain a path")
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" {
		return errors.New("hub_url host is required")
	}
	if forbiddenHubHost(host) {
		return errors.New("hub_url must not target link-local or cloud metadata addresses")
	}
	if parsed.Scheme == "http" && !isLocalDevelopmentHost(host) {
		return errors.New("hub_url must use HTTPS unless the host is loopback")
	}
	return nil
}

// ValidateCollectorTokenTransport enforces the outbound transport boundary
// before a collector or sensor credential is attached to a request.
func ValidateCollectorTokenTransport(value string) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 2048 || !safeText(value) {
		return ErrCollectorTokenTransport
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return ErrCollectorTokenTransport
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "https" {
		return nil
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if scheme == "http" && host != "" && isLoopbackHost(host) {
		return nil
	}
	return ErrCollectorTokenTransport
}

func (cfg Config) BatchInterval() time.Duration {
	return time.Duration(cfg.BatchIntervalSeconds) * time.Second
}
func (cfg Config) RequestTimeout() time.Duration {
	return time.Duration(cfg.RequestTimeoutSeconds) * time.Second
}
func (cfg Config) RetryInitial() time.Duration {
	return time.Duration(cfg.RetryInitialSeconds) * time.Second
}
func (cfg Config) RetryMax() time.Duration { return time.Duration(cfg.RetryMaxSeconds) * time.Second }
func (cfg Config) AggregationTTL() time.Duration {
	return time.Duration(cfg.AggregationTTLSeconds) * time.Second
}

func validateIdentifier(name, value string, min, max int, pattern *regexp.Regexp) error {
	if len(value) < min || len(value) > max || !pattern.MatchString(value) {
		allowed := "letters, digits, dot, underscore, or hyphen"
		if name == "sensor_id" {
			allowed = "letters, digits, dot, underscore, colon, or hyphen"
		}
		return fmt.Errorf("%s must be %d to %d characters using %s", name, min, max, allowed)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isLocalDevelopmentHost(host string) bool {
	return isLoopbackHost(host) || strings.EqualFold(host, "host.docker.internal")
}

func forbiddenHubHost(host string) bool {
	if strings.Contains(host, "%") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ForbiddenHubIP(ip)
	}
	switch strings.ToLower(strings.TrimSuffix(host, ".")) {
	case "metadata.google.internal", "metadata", "instance-data.ec2.internal":
		return true
	default:
		return false
	}
}

// ForbiddenHubIP is shared with the HTTP dialer so a DNS alias cannot bypass
// the URL-level metadata and link-local checks.
func ForbiddenHubIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	for _, blocked := range []string{
		"169.254.169.254",
		"169.254.170.2",
		"100.100.100.200",
		"fd00:ec2::254",
	} {
		if ip.Equal(net.ParseIP(blocked)) {
			return true
		}
	}
	return false
}

func safePath(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" && trimmed == value && len(value) <= 4096 && safeText(value)
}

func safeText(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func defaultStateDir() string {
	if runtime.GOOS == "linux" {
		return "/var/lib/openassetwatch/sensor"
	}
	if directory, err := os.UserConfigDir(); err == nil {
		return filepath.Join(directory, "OpenAssetWatch", "sensor")
	}
	return filepath.Join(".", ".openassetwatch-sensor")
}
