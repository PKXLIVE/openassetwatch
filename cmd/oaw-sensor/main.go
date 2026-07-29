// Command oaw-sensor runs the passive network sensor and its deterministic
// replay demonstration. Live capture is Linux-only; replay never opens a
// network interface.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/openassetwatch/openassetwatch/internal/sensor"
	"github.com/openassetwatch/openassetwatch/internal/sensor/aggregate"
	"github.com/openassetwatch/openassetwatch/internal/sensor/capture"
	sensorconfig "github.com/openassetwatch/openassetwatch/internal/sensor/config"
	"github.com/openassetwatch/openassetwatch/internal/sensor/contract"
	"github.com/openassetwatch/openassetwatch/internal/sensor/health"
	"github.com/openassetwatch/openassetwatch/internal/sensor/hubclient"
	"github.com/openassetwatch/openassetwatch/internal/sensor/identity"
	sensorreplay "github.com/openassetwatch/openassetwatch/internal/sensor/replay"
	sensorruntime "github.com/openassetwatch/openassetwatch/internal/sensor/runtime"
	"github.com/openassetwatch/openassetwatch/internal/sensor/spool"
	"github.com/openassetwatch/openassetwatch/pkg/version"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

var environmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		return runProfile(nil, out, errOut)
	}
	switch args[0] {
	case "version", "--version", "-version":
		_, _ = fmt.Fprintln(out, version.String())
		return 0
	case "profile":
		return runProfile(args[1:], out, errOut)
	case "validate-config", "validate":
		return runValidateConfig(args[1:], out, errOut)
	case "status", "health":
		return runStatus(args[1:], out, errOut)
	case "demo", "replay":
		return runReplay(args[1:], out, errOut)
	case "live":
		return runLive(args[1:], out, errOut)
	default:
		_, _ = fmt.Fprintf(errOut, "unknown oaw-sensor command %q (use profile, demo, live, validate-config, or status)\n", args[0])
		return 2
	}
}

func runProfile(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("profile", flag.ContinueOnError)
	flags.SetOutput(errOut)
	configPath := flags.String("config", "", "path to an OAW sensor JSON config")
	siteID := flags.String("site-id", "", "safe site identifier")
	sensorID := flags.String("sensor-id", "", "sensor identifier (optional in profile output)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	if *siteID != "" {
		cfg.SiteID = *siteID
	}
	if cfg.SiteID == "" {
		cfg.SiteID = "demo-passive-site"
	}
	if err := contract.ValidateSiteID(cfg.SiteID); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	if *sensorID != "" {
		if err := contract.ValidateSensorID(*sensorID); err != nil {
			_, _ = fmt.Fprintln(errOut, err)
			return 2
		}
	}
	profile := sensor.DefaultProfile(cfg.SiteID)
	profile.SensorID = *sensorID
	if err := writeJSON(out, profile); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

func runValidateConfig(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	flags.SetOutput(errOut)
	configPath := flags.String("config", "", "path to an OAW sensor JSON config")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*configPath) == "" {
		_, _ = fmt.Fprintln(errOut, "--config is required")
		return 2
	}
	cfg, err := sensorconfig.Load(*configPath)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	// Config output intentionally excludes token values; token_env is safe to
	// show because it is only the name of an environment variable.
	result := struct {
		Valid       bool   `json:"valid"`
		HubURL      string `json:"hub_url"`
		SiteID      string `json:"site_id"`
		SensorID    string `json:"sensor_id,omitempty"`
		CaptureMode string `json:"capture_mode"`
	}{true, cfg.HubURL, cfg.SiteID, cfg.SensorID, cfg.CaptureMode}
	if err := writeJSON(out, result); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

func runStatus(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(errOut)
	configPath := flags.String("config", "", "path to an OAW sensor JSON config")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	configured := strings.TrimSpace(*configPath) != ""
	cfg := sensorconfig.Default()
	if configured {
		var err error
		cfg, err = sensorconfig.Load(*configPath)
		if err != nil {
			_, _ = fmt.Fprintln(errOut, err)
			return 1
		}
	} else {
		cfg.SiteID = "(unconfigured)"
	}
	status := struct {
		Running          bool   `json:"running"`
		Configured       bool   `json:"configured"`
		Status           string `json:"status"`
		Version          string `json:"version"`
		SiteID           string `json:"site_id"`
		SensorID         string `json:"sensor_id,omitempty"`
		CaptureMode      string `json:"capture_mode"`
		CaptureInterface string `json:"capture_interface,omitempty"`
		HubURL           string `json:"hub_url"`
		TokenAvailable   bool   `json:"collector_token_available"`
	}{
		Running: false, Configured: configured, Status: "not-running",
		Version: version.String(), SiteID: cfg.SiteID, SensorID: cfg.SensorID,
		CaptureMode: cfg.CaptureMode, CaptureInterface: cfg.CaptureInterface,
		HubURL: cfg.HubURL, TokenAvailable: os.Getenv(cfg.TokenEnv) != "",
	}
	if err := writeJSON(out, status); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

func runReplay(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("demo", flag.ContinueOnError)
	flags.SetOutput(errOut)
	configPath := flags.String("config", "", "optional sensor JSON config")
	hubURL := flags.String("hub-url", "", "hub URL (HTTPS required for non-loopback hosts)")
	siteID := flags.String("site-id", "", "site identifier")
	sensorID := flags.String("sensor-id", "", "stable sensor identifier")
	sensorName := flags.String("sensor-name", "", "sensor display name")
	tokenEnv := flags.String("token-env", "", "environment variable containing the collector token")
	spoolPath := flags.String("spool-path", "", "durable spool directory (temporary when omitted)")
	spoolDir := flags.String("spool-dir", "", "alias for --spool-path")
	identityPath := flags.String("identity-path", "", "identity file (used when --sensor-id is empty)")
	identityFile := flags.String("identity-file", "", "alias for --identity-path")
	timeout := flags.Duration("timeout", 20*time.Second, "overall replay timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*configPath)
	if err != nil && *configPath != "" {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	if *hubURL != "" {
		cfg.HubURL = *hubURL
	}
	if *siteID != "" {
		cfg.SiteID = *siteID
	}
	if cfg.SiteID == "" {
		cfg.SiteID = "demo-passive-site"
	}
	cfg.CaptureMode = sensor.CaptureModeSynthetic
	if *spoolPath != "" {
		cfg.SpoolPath = *spoolPath
	} else if *spoolDir != "" {
		cfg.SpoolPath = *spoolDir
	} else {
		// The replay demo must be usable by an unprivileged developer. Keep its
		// durable queue in a disposable OS temp directory instead of the Linux
		// service state directory.
		cfg.SpoolPath, err = os.MkdirTemp("", "oaw-sensor-demo-spool-")
		if err != nil {
			_, _ = fmt.Fprintln(errOut, err)
			return 1
		}
		defer os.RemoveAll(cfg.SpoolPath)
	}
	if *sensorName != "" {
		cfg.SensorName = *sensorName
	}
	selectedTokenEnv := cfg.TokenEnv
	if *tokenEnv != "" {
		selectedTokenEnv = strings.TrimSpace(*tokenEnv)
		if len(selectedTokenEnv) > 128 || !environmentNamePattern.MatchString(selectedTokenEnv) {
			_, _ = fmt.Fprintln(errOut, "token-env must name a valid environment variable")
			return 2
		}
	}
	if *identityPath == "" {
		*identityPath = *identityFile
	}
	if err := cfg.Validate(); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	requestedSensorID := *sensorID
	if requestedSensorID == "" && cfg.SensorID == "" && strings.TrimSpace(*identityPath) == "" {
		requestedSensorID = "sensor-passive-demo-01"
	}
	resolvedSensorID, err := resolveSensorID(cfg, requestedSensorID, *identityPath)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	ctx, cancel := contextWithTimeout(*timeout)
	defer cancel()
	return runSensor(ctx, cfg, resolvedSensorID, sensorreplay.NewSource(sensorreplay.DemoObservedAt), os.Getenv(selectedTokenEnv), out, errOut)
}

func runLive(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("live", flag.ContinueOnError)
	flags.SetOutput(errOut)
	configPath := flags.String("config", "", "path to an OAW sensor JSON config")
	interfaceName := flags.String("interface", "", "Linux interface connected to a passive SPAN/mirror port")
	siteID := flags.String("site-id", "", "site identifier override")
	sensorID := flags.String("sensor-id", "", "sensor identifier override")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*configPath)
	if err != nil && *configPath != "" {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	if *siteID != "" {
		cfg.SiteID = *siteID
	}
	if *interfaceName != "" {
		cfg.CaptureInterface = *interfaceName
	}
	cfg.CaptureMode = sensor.CaptureModeLive
	if err := cfg.Validate(); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	resolvedSensorID, err := resolveSensorID(cfg, *sensorID, "")
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	source, err := capture.NewLive(cfg.CaptureInterface)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	ctx, stop := contextWithSignals()
	defer stop()
	return runSensor(ctx, cfg, resolvedSensorID, source, os.Getenv(cfg.TokenEnv), out, errOut)
}

func runSensor(ctx context.Context, cfg sensorconfig.Config, sensorID string, source capture.Source, token string, out, errOut io.Writer) int {
	defer source.Close()
	agg, err := aggregate.New(aggregate.Config{SiteID: cfg.SiteID, MaxDevices: cfg.AggregationMaxDevices, TTL: cfg.AggregationTTL()})
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	queue, err := spool.Open(spool.Config{Path: cfg.SpoolPath, MaxItems: cfg.SpoolMaxItems, MaxBytes: cfg.SpoolMaxBytes})
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	defer queue.Close()
	hub, err := hubclient.New(cfg.HubURL, token, cfg.RequestTimeout())
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	tracker := health.NewWithDetails(version.Number, cfg.SiteID, sensorID, cfg.CaptureMode, cfg.CaptureInterface, source.Name())
	runner := &sensorruntime.Runner{
		Config: sensorruntime.Config{SiteID: cfg.SiteID, SensorID: sensorID, SensorName: cfg.SensorName, SensorVersion: version.Number, BatchSize: cfg.BatchSize, BatchInterval: cfg.BatchInterval(), RetryInitial: cfg.RetryInitial(), RetryMaximum: cfg.RetryMax()},
		Source: source, Aggregator: agg, Spool: queue, Hub: hub, Health: tracker,
	}
	// A replay's timestamp is fixed so the same fixture produces the same
	// observation_batch_id on every invocation. Operational health and retry
	// timing continue to use wall clock.
	if source.Name() == "synthetic-replay" {
		runner.ObservedAt = func() time.Time { return sensorreplay.DemoObservedAt }
	}
	err = runner.Run(ctx)
	state := tracker.Snapshot()
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "sensor run failed: %s\n", scrubError(err.Error()))
	}
	if writeErr := writeJSON(out, state); writeErr != nil {
		_, _ = fmt.Fprintln(errOut, writeErr)
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

func loadConfig(path string) (sensorconfig.Config, error) {
	if strings.TrimSpace(path) == "" {
		cfg := sensorconfig.Default()
		cfg.SiteID = "demo-passive-site"
		return cfg, nil
	}
	return sensorconfig.Load(path)
}

func resolveSensorID(cfg sensorconfig.Config, requested, path string) (string, error) {
	if strings.TrimSpace(requested) != "" {
		requested = strings.TrimSpace(requested)
		if err := contract.ValidateSensorID(requested); err != nil {
			return "", err
		}
		return requested, nil
	}
	if cfg.SensorID != "" {
		if err := contract.ValidateSensorID(cfg.SensorID); err != nil {
			return "", err
		}
		return cfg.SensorID, nil
	}
	if path == "" {
		path = cfg.IdentityPath
		if strings.HasPrefix(path, "/var/lib/") && runtimeIsWindows() {
			path = filepath.Join(os.TempDir(), "openassetwatch-sensor", "identity.json")
		}
	}
	identityValue, _, err := identity.LoadOrCreate(path, cfg.SiteID)
	if err != nil {
		return "", err
	}
	return identityValue.SensorID, nil
}

func contextWithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 20 * time.Second
	}
	return context.WithTimeout(context.Background(), timeout)
}

func contextWithSignals() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func runtimeIsWindows() bool { return os.PathSeparator == '\\' }

func writeJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func scrubError(value string) string {
	if strings.Contains(strings.ToLower(value), "token") || strings.Contains(strings.ToLower(value), "authorization") {
		return "sensor operation failed (sensitive details redacted)"
	}
	if len(value) > 512 {
		return value[:512]
	}
	return value
}
