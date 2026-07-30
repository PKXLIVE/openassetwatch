// Command oaw-sensor runs the passive network sensor and its deterministic
// replay demonstration. Live capture is Linux-only; replay never opens a
// network interface.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/openassetwatch/openassetwatch/internal/sensor"
	"github.com/openassetwatch/openassetwatch/internal/sensor/aggregate"
	"github.com/openassetwatch/openassetwatch/internal/sensor/capture"
	sensorconfig "github.com/openassetwatch/openassetwatch/internal/sensor/config"
	"github.com/openassetwatch/openassetwatch/internal/sensor/contract"
	"github.com/openassetwatch/openassetwatch/internal/sensor/credential"
	"github.com/openassetwatch/openassetwatch/internal/sensor/diagnostic"
	"github.com/openassetwatch/openassetwatch/internal/sensor/health"
	"github.com/openassetwatch/openassetwatch/internal/sensor/hubclient"
	"github.com/openassetwatch/openassetwatch/internal/sensor/identity"
	"github.com/openassetwatch/openassetwatch/internal/sensor/interfaceinfo"
	sensorreplay "github.com/openassetwatch/openassetwatch/internal/sensor/replay"
	sensorruntime "github.com/openassetwatch/openassetwatch/internal/sensor/runtime"
	"github.com/openassetwatch/openassetwatch/internal/sensor/spool"
	sensorstatus "github.com/openassetwatch/openassetwatch/internal/sensor/status"
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
	case "config":
		return runConfigCommand(args[1:], out, errOut)
	case "validate-config", "validate":
		return runValidateConfig(args[1:], out, errOut)
	case "status":
		return runStatus(args[1:], out, errOut)
	case "health":
		return runHealth(args[1:], out, errOut)
	case "interface":
		return runInterfaceCommand(args[1:], out, errOut)
	case "spool":
		return runSpoolCommand(args[1:], out, errOut)
	case "service":
		return runServiceCommand(args[1:], out, errOut)
	case "capture-check":
		return runCaptureCheck(args[1:], out, errOut)
	case "enroll":
		return runEnroll(args[1:], out, errOut)
	case "credential-status":
		return runCredentialStatus(args[1:], out, errOut)
	case "replace-credential":
		return runReplaceCredential(args[1:], out, errOut)
	case "clear-credential":
		return runClearCredential(args[1:], out, errOut)
	case "demo", "replay":
		return runReplay(args[1:], out, errOut)
	case "live":
		return runLive(args[1:], out, errOut)
	default:
		_, _ = fmt.Fprintf(errOut, "unknown oaw-sensor command %q (use profile, config validate, interface list, interface validate, service run, capture-check, enroll, credential-status, replace-credential, clear-credential, replay, live, status, health, or spool status)\n", args[0])
		return 2
	}
}

func runConfigCommand(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] != "validate" {
		_, _ = fmt.Fprintln(errOut, "use: oaw-sensor config validate --config <path>")
		return 2
	}
	return runValidateConfig(args[1:], out, errOut)
}

func runServiceCommand(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] != "run" {
		_, _ = fmt.Fprintln(errOut, "use: oaw-sensor service run --config <path>")
		return 2
	}
	return runLive(args[1:], out, errOut)
}

func runInterfaceCommand(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(errOut, "use: oaw-sensor interface list|validate")
		return 2
	}
	switch args[0] {
	case "list":
		flags := flag.NewFlagSet("interface list", flag.ContinueOnError)
		flags.SetOutput(errOut)
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 0 {
			_, _ = fmt.Fprintln(errOut, "interface list does not accept positional arguments")
			return 2
		}
		interfaces, err := interfaceinfo.List()
		if err != nil {
			_, _ = fmt.Fprintln(errOut, err)
			return 1
		}
		result := struct {
			Interfaces   []interfaceinfo.Info          `json:"interfaces"`
			Capabilities interfaceinfo.CapabilityState `json:"capabilities"`
		}{interfaces, interfaceinfo.EffectiveCapabilities()}
		if err := writeJSON(out, result); err != nil {
			_, _ = fmt.Fprintln(errOut, err)
			return 1
		}
		return 0
	case "validate":
		flags := flag.NewFlagSet("interface validate", flag.ContinueOnError)
		flags.SetOutput(errOut)
		name := flags.String("interface", "", "explicit Linux capture interface")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		result, err := interfaceinfo.Validate(*name)
		if err != nil {
			_, _ = fmt.Fprintln(errOut, err)
			return 2
		}
		if err := writeJSON(out, result); err != nil {
			_, _ = fmt.Fprintln(errOut, err)
			return 1
		}
		if !result.Valid {
			return 1
		}
		return 0
	default:
		_, _ = fmt.Fprintln(errOut, "use: oaw-sensor interface list|validate")
		return 2
	}
}

func runSpoolCommand(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] != "status" {
		_, _ = fmt.Fprintln(errOut, "use: oaw-sensor spool status --config <path>")
		return 2
	}
	flags := flag.NewFlagSet("spool status", flag.ContinueOnError)
	flags.SetOutput(errOut)
	configPath := flags.String("config", "", "path to an OAW sensor JSON config")
	if err := flags.Parse(args[1:]); err != nil {
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
	queue, err := spool.Open(spool.Config{Path: cfg.SpoolPath, MaxItems: cfg.SpoolMaxItems, MaxBytes: cfg.SpoolMaxBytes})
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	defer queue.Close()
	stats, err := queue.Stats()
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	result := struct {
		Items       int     `json:"items"`
		Bytes       int64   `json:"bytes"`
		Utilization float64 `json:"utilization"`
		MaxItems    int     `json:"max_items"`
		MaxBytes    int64   `json:"max_bytes"`
	}{stats.Items, stats.Bytes, stats.Capacity, cfg.SpoolMaxItems, cfg.SpoolMaxBytes}
	if err := writeJSON(out, result); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

func runCaptureCheck(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("capture-check", flag.ContinueOnError)
	flags.SetOutput(errOut)
	interfaceName := flags.String("interface", "", "explicit Linux interface connected to a passive SPAN/mirror port")
	duration := flags.Duration("duration", 0, "bounded capture duration between 1s and 5m")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*interfaceName) == "" || *duration == 0 {
		_, _ = fmt.Fprintln(errOut, "--interface and --duration are required")
		return 2
	}
	validation, err := interfaceinfo.Validate(*interfaceName)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	if !validation.Valid {
		_ = writeJSON(out, validation)
		_, _ = fmt.Fprintln(errOut, "capture interface validation failed")
		return 1
	}
	source, err := capture.NewLive(*interfaceName)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, scrubError(err.Error()))
		return 1
	}
	defer source.Close()
	ctx, stop := contextWithSignals()
	defer stop()
	summary, err := diagnostic.Run(ctx, source, *interfaceName, *duration, validation.Capabilities)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, scrubError(err.Error()))
		return 1
	}
	if err := writeJSON(out, summary); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
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
		Valid            bool   `json:"valid"`
		HubURL           string `json:"hub_url"`
		SiteID           string `json:"site_id"`
		SensorID         string `json:"sensor_id,omitempty"`
		CaptureMode      string `json:"capture_mode"`
		CaptureInterface string `json:"capture_interface,omitempty"`
	}{true, cfg.HubURL, cfg.SiteID, cfg.SensorID, cfg.CaptureMode, cfg.CaptureInterface}
	if err := writeJSON(out, result); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

func runHealth(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("health", flag.ContinueOnError)
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
	snapshot, err := sensorstatus.Load(cfg.StatusPath)
	if errors.Is(err, os.ErrNotExist) {
		snapshot = health.Snapshot{
			Running: false, Version: version.Number, SiteID: cfg.SiteID, SensorID: cfg.SensorID,
			CaptureMode: cfg.CaptureMode, CaptureInterface: cfg.CaptureInterface,
		}
	} else if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	if err := writeJSON(out, snapshot); err != nil {
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
	token, authMode, authErr := resolveAuthentication(cfg, cfg.SensorID)
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
		AuthMode         string `json:"authentication_mode"`
		CredentialReady  bool   `json:"credential_available"`
		AuthError        bool   `json:"credential_error"`
	}{
		Running: false, Configured: configured, Status: "not-running",
		Version: version.String(), SiteID: cfg.SiteID, SensorID: cfg.SensorID,
		CaptureMode: cfg.CaptureMode, CaptureInterface: cfg.CaptureInterface,
		HubURL: cfg.HubURL, AuthMode: authMode, CredentialReady: token != "",
		AuthError: authErr != nil,
	}
	if err := writeJSON(out, status); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

func runEnroll(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	flags.SetOutput(errOut)
	configPath := flags.String("config", "", "path to an OAW sensor JSON config")
	identityPath := flags.String("identity-path", "", "identity file override")
	credentialPath := flags.String("credential-path", "", "credential file override")
	tokenFile := flags.String("enrollment-token-file", "", "protected file containing the one-time enrollment token")
	tokenEnv := flags.String("enrollment-token-env", credential.EnrollmentTokenEnv, "environment variable containing the one-time enrollment token")
	tokenStdin := flags.Bool("enrollment-token-stdin", false, "read the one-time enrollment token from standard input")
	timeout := flags.Duration("timeout", 20*time.Second, "enrollment request timeout")
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
	if *identityPath != "" {
		cfg.IdentityPath = *identityPath
	}
	if *credentialPath != "" {
		cfg.CredentialPath = *credentialPath
	}
	if err := cfg.Validate(); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	sensorID, err := resolveSensorID(cfg, "", cfg.IdentityPath)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	if err := credential.EnsureAbsent(cfg.CredentialPath); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	enrollmentToken, err := readSecretInput(*tokenEnv, *tokenFile, *tokenStdin, true)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	hub, err := hubclient.New(cfg.HubURL, "", min(*timeout, cfg.RequestTimeout()))
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	ctx, cancel := contextWithTimeout(*timeout)
	defer cancel()
	response, err := hub.Enroll(ctx, hubclient.EnrollmentRequest{
		EnrollmentToken: enrollmentToken,
		SensorID:        sensorID,
		SensorName:      cfg.SensorName,
		SensorType:      "passive-network-sensor",
		SensorVersion:   version.Number,
		Platform:        runtime.GOOS,
	})
	enrollmentToken = ""
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "sensor enrollment failed: %s\n", scrubError(err.Error()))
		return 1
	}
	if response.SiteID != cfg.SiteID || response.SensorID != sensorID {
		_, _ = fmt.Fprintln(errOut, "sensor enrollment response identity does not match local configuration")
		return 1
	}
	record := credential.Record{
		SchemaVersion: credential.SchemaVersion,
		SiteID:        response.SiteID,
		SensorID:      response.SensorID,
		SensorType:    response.SensorType,
		Credential:    response.SensorCredential,
		IssuedAt:      response.IssuedAt,
	}
	response.SensorCredential = ""
	if err := credential.Write(cfg.CredentialPath, record, false); err != nil {
		_, _ = fmt.Fprintln(errOut, "credential was issued but could not be stored; revoke the sensor and re-enroll")
		return 1
	}
	record.Credential = ""
	return writeSafeCredentialResult(out, "enrolled", response.SiteID, response.SensorID, "bound-sensor", errOut)
}

func runCredentialStatus(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("credential-status", flag.ContinueOnError)
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
	sensorID, err := resolveSensorID(cfg, "", cfg.IdentityPath)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	token, mode, authErr := resolveAuthentication(cfg, sensorID)
	result := struct {
		SiteID              string `json:"site_id"`
		SensorID            string `json:"sensor_id"`
		AuthenticationMode  string `json:"authentication_mode"`
		CredentialAvailable bool   `json:"credential_available"`
		CredentialValid     bool   `json:"credential_valid"`
	}{
		SiteID: cfg.SiteID, SensorID: sensorID, AuthenticationMode: mode,
		CredentialAvailable: token != "", CredentialValid: authErr == nil && token != "",
	}
	token = ""
	if err := writeJSON(out, result); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	if authErr != nil {
		_, _ = fmt.Fprintln(errOut, "sensor credential is unavailable or invalid")
		return 1
	}
	return 0
}

func runReplaceCredential(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("replace-credential", flag.ContinueOnError)
	flags.SetOutput(errOut)
	configPath := flags.String("config", "", "path to an OAW sensor JSON config")
	credentialPath := flags.String("credential-path", "", "credential file override")
	tokenFile := flags.String("credential-file", "", "protected file containing the replacement credential")
	tokenEnv := flags.String("credential-env", credential.EnvironmentName, "environment variable containing the replacement credential")
	tokenStdin := flags.Bool("credential-stdin", false, "read the replacement credential from standard input")
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
	if *credentialPath != "" {
		cfg.CredentialPath = *credentialPath
	}
	if err := cfg.Validate(); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	sensorID, err := resolveSensorID(cfg, "", cfg.IdentityPath)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	value, err := readSecretInput(*tokenEnv, *tokenFile, *tokenStdin, false)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	record := credential.Record{
		SchemaVersion: credential.SchemaVersion,
		SiteID:        cfg.SiteID,
		SensorID:      sensorID,
		SensorType:    "passive-network-sensor",
		Credential:    value,
		IssuedAt:      time.Now().UTC(),
	}
	value = ""
	if err := credential.Write(cfg.CredentialPath, record, true); err != nil {
		_, _ = fmt.Fprintln(errOut, "failed to replace protected sensor credential")
		return 1
	}
	record.Credential = ""
	return writeSafeCredentialResult(out, "credential-replaced", cfg.SiteID, sensorID, "bound-sensor", errOut)
}

func runClearCredential(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("clear-credential", flag.ContinueOnError)
	flags.SetOutput(errOut)
	configPath := flags.String("config", "", "path to an OAW sensor JSON config")
	confirm := flags.Bool("confirm-clear", false, "confirm permanent removal of the local credential file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*configPath) == "" || !*confirm {
		_, _ = fmt.Fprintln(errOut, "--config and --confirm-clear are required")
		return 2
	}
	cfg, err := sensorconfig.Load(*configPath)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	if os.Getenv(cfg.CredentialEnv) != "" {
		_, _ = fmt.Fprintln(errOut, "credential environment override is active; unset it before clearing the file")
		return 1
	}
	if err := credential.Clear(cfg.CredentialPath); err != nil {
		_, _ = fmt.Fprintln(errOut, "failed to clear protected sensor credential")
		return 1
	}
	return writeSafeCredentialResult(out, "credential-cleared", cfg.SiteID, cfg.SensorID, "unconfigured", errOut)
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
	token, _, authErr := resolveAuthentication(cfg, resolvedSensorID)
	if authErr != nil {
		_, _ = fmt.Fprintln(errOut, "sensor credential is unavailable or invalid")
		return 1
	}
	if token == "" && selectedTokenEnv != cfg.TokenEnv {
		token = os.Getenv(selectedTokenEnv)
	}
	ctx, cancel := contextWithTimeout(*timeout)
	defer cancel()
	return runSensor(ctx, cfg, resolvedSensorID, sensorreplay.NewSource(sensorreplay.DemoObservedAt), token, out, errOut)
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
		writeDegradedStatus(cfg, cfg.SensorID, err, true)
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	resolvedSensorID, err := resolveSensorID(cfg, *sensorID, "")
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	token, _, authErr := resolveAuthentication(cfg, resolvedSensorID)
	if authErr != nil {
		writeDegradedStatus(cfg, resolvedSensorID, authErr, false)
		_, _ = fmt.Fprintln(errOut, "sensor credential is unavailable or invalid")
		return 1
	}
	source, err := capture.NewLive(cfg.CaptureInterface)
	if err != nil {
		writeDegradedStatus(cfg, resolvedSensorID, err, true)
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	ctx, stop := contextWithSignals()
	defer stop()
	return runSensor(ctx, cfg, resolvedSensorID, source, token, out, errOut)
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
	var persistCancel context.CancelFunc
	var persistDone <-chan struct{}
	if cfg.CaptureMode == sensor.CaptureModeLive {
		if err := sensorstatus.Write(cfg.StatusPath, tracker.Snapshot()); err != nil {
			_, _ = fmt.Fprintln(errOut, "sensor status path is unavailable")
			return 1
		}
		persistContext, cancel := context.WithCancel(context.Background())
		persistCancel = cancel
		done := make(chan struct{})
		persistDone = done
		go func() {
			defer close(done)
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-persistContext.Done():
					return
				case <-ticker.C:
					_ = sensorstatus.Write(cfg.StatusPath, tracker.Snapshot())
				}
			}
		}()
	}
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
	if persistCancel != nil {
		persistCancel()
		<-persistDone
		if statusErr := sensorstatus.Write(cfg.StatusPath, state); statusErr != nil && err == nil {
			err = errors.New("persist final sensor status")
		}
	}
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

func writeDegradedStatus(cfg sensorconfig.Config, sensorID string, cause error, captureFailure bool) {
	if cfg.CaptureMode != sensor.CaptureModeLive || strings.TrimSpace(cfg.StatusPath) == "" {
		return
	}
	snapshot := health.Snapshot{
		Running: false, Version: version.Number, SiteID: cfg.SiteID, SensorID: sensorID,
		CaptureMode: cfg.CaptureMode, CaptureInterface: cfg.CaptureInterface,
	}
	if captureFailure {
		snapshot.LastCaptureError = scrubError(cause.Error())
	} else {
		snapshot.LastHubError = scrubError(cause.Error())
	}
	_ = sensorstatus.Write(cfg.StatusPath, snapshot)
}

func resolveAuthentication(cfg sensorconfig.Config, sensorID string) (string, string, error) {
	if value := os.Getenv(cfg.CredentialEnv); value != "" {
		if !credential.ValidSensorCredential(value) {
			return "", "bound-environment", errors.New("sensor credential environment override is invalid")
		}
		return value, "bound-environment", nil
	}
	record, err := credential.Load(cfg.CredentialPath)
	if err == nil {
		if record.SiteID != cfg.SiteID || (sensorID != "" && record.SensorID != sensorID) {
			return "", "bound-file", errors.New("sensor credential file belongs to a different identity")
		}
		return record.Credential, "bound-file", nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", "bound-file", err
	}
	if value := os.Getenv(cfg.TokenEnv); value != "" {
		return value, "development-shared", nil
	}
	return "", "unconfigured", nil
}

func readSecretInput(environmentName, filePath string, fromStdin, enrollment bool) (string, error) {
	environmentName = strings.TrimSpace(environmentName)
	if len(environmentName) > 128 || !environmentNamePattern.MatchString(environmentName) {
		return "", errors.New("secret environment must name a valid environment variable")
	}
	environmentValue := os.Getenv(environmentName)
	sources := 0
	if environmentValue != "" {
		sources++
	}
	if strings.TrimSpace(filePath) != "" {
		sources++
	}
	if fromStdin {
		sources++
	}
	if sources != 1 {
		return "", errors.New("provide exactly one protected secret source using environment, file, or standard input")
	}
	value := environmentValue
	if filePath != "" {
		var err error
		value, err = credential.ReadSecretFile(filePath, enrollment)
		if err != nil {
			return "", err
		}
	}
	if fromStdin {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, credential.MaxSecretBytes+2))
		if err != nil || len(data) > credential.MaxSecretBytes+1 {
			return "", errors.New("failed to read bounded secret from standard input")
		}
		value = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	}
	valid := credential.ValidSensorCredential(value)
	if enrollment {
		valid = credential.ValidEnrollmentToken(value)
	}
	if !valid {
		return "", errors.New("provided secret has an invalid format")
	}
	return value, nil
}

func writeSafeCredentialResult(out io.Writer, status, siteID, sensorID, authMode string, errOut io.Writer) int {
	result := struct {
		Status             string `json:"status"`
		SiteID             string `json:"site_id"`
		SensorID           string `json:"sensor_id,omitempty"`
		AuthenticationMode string `json:"authentication_mode"`
	}{
		Status: status, SiteID: siteID, SensorID: sensorID, AuthenticationMode: authMode,
	}
	if err := writeJSON(out, result); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
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
