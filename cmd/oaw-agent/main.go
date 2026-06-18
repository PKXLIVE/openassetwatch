package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	agentconfig "github.com/openassetwatch/openassetwatch/internal/agent/config"
	agentidentity "github.com/openassetwatch/openassetwatch/internal/agent/identity"
	agentinstallplan "github.com/openassetwatch/openassetwatch/internal/agent/installplan"
	agentpaths "github.com/openassetwatch/openassetwatch/internal/agent/paths"
	agentserviceplan "github.com/openassetwatch/openassetwatch/internal/agent/serviceplan"
	"github.com/openassetwatch/openassetwatch/internal/collector"
	"github.com/openassetwatch/openassetwatch/internal/config"
	"github.com/openassetwatch/openassetwatch/internal/output"
	"github.com/openassetwatch/openassetwatch/pkg/models"
	"github.com/openassetwatch/openassetwatch/pkg/version"
)

var collectLocalInventory = collector.CollectLocalInventory
var submitHTTPClient = func() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}
var defaultAgentPaths = agentpaths.DefaultAgentPaths
var readOSRelease = os.ReadFile

const localInventorySubmitPath = "/api/v1/collections/local-inventory"
const agentCheckInPath = "/api/v1/agents/check-in"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "collect" {
		return runCollect(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "submit" {
		return runSubmit(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "check-in" {
		return runCheckIn(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "identity" {
		return runIdentity(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "config" {
		return runConfig(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "paths" {
		return runPaths(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "doctor" {
		return runDoctor(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "status" {
		return runStatus(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "service" {
		return runService(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "install" {
		return runInstall(args[1:], stdout, stderr)
	}

	var configPath string
	var siteID string
	var showVersion bool

	flags := flag.NewFlagSet("oaw-agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&configPath, "config", "", "path to an OAW agent JSON config")
	flags.StringVar(&siteID, "site-id", "", "safe site identifier")
	flags.BoolVar(&showVersion, "version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if showVersion {
		fmt.Fprintln(stdout, version.String())
		return 0
	}

	cfg, err := loadAgentConfig(configPath, siteID)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	if err := output.WriteJSON(stdout, collectLocalInventory(cfg.SiteID)); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func runCollect(args []string, stdout io.Writer, stderr io.Writer) int {
	var configPath string
	var identityPath string
	var outputPath string
	var once bool
	var siteID string

	flags := flag.NewFlagSet("oaw-agent collect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.BoolVar(&once, "once", false, "run one passive local inventory collection")
	flags.StringVar(&configPath, "config", "", "path to an OAW agent JSON config")
	flags.StringVar(&identityPath, "identity-file", "", "optional non-secret local agent identity JSON file")
	flags.StringVar(&outputPath, "output", "", "optional local file path for JSON output")
	flags.StringVar(&siteID, "site-id", "", "safe site identifier")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if !once {
		fmt.Fprintln(stderr, "oaw-agent collect requires --once")
		return 2
	}

	cfg, identity, err := loadCollectConfig(configPath, siteID, identityPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	writer := stdout
	var file *os.File
	if outputPath != "" {
		file, err = os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		defer file.Close()
		writer = file
	}

	inventory := collectLocalInventory(cfg.SiteID)
	if identity != nil {
		applyCollectionIdentity(&inventory, *identity)
	}
	if err := output.WriteJSON(writer, inventory); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func runCheckIn(args []string, stdout io.Writer, stderr io.Writer) int {
	var configPath string
	var identityPath string
	var serverURL string

	flags := flag.NewFlagSet("oaw-agent check-in", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&configPath, "config", "", "optional non-secret local agent config JSON file")
	flags.StringVar(&identityPath, "identity-file", "", "non-secret local agent identity JSON file")
	flags.StringVar(&serverURL, "server-url", "", "explicit OpenAssetWatch backend URL")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	var err error
	serverURL, err = resolveBackendServerURL(serverURL, configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	identityPath, explicitIdentityPath, err := resolveCheckInIdentityPath(identityPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	identity, err := readAgentIdentityFile(identityPath, explicitIdentityPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	body, err := json.Marshal(buildAgentCheckInPayload(identity))
	if err != nil {
		fmt.Fprintln(stderr, "failed to build check-in payload")
		return 1
	}

	statusCode, err := postJSON(context.Background(), submitHTTPClient(), serverURL, agentCheckInPath, body)
	if err != nil {
		fmt.Fprintf(stderr, "check-in failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "agent check-in accepted: HTTP %d\n", statusCode)
	return 0
}

func runIdentity(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "init" {
		fmt.Fprintln(stderr, "oaw-agent identity requires init")
		return 2
	}
	return runIdentityInit(args[1:], stdout, stderr)
}

func runIdentityInit(args []string, stdout io.Writer, stderr io.Writer) int {
	var deploymentID string
	var outputPath string
	var siteID string
	var tenantID string

	flags := flag.NewFlagSet("oaw-agent identity init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&deploymentID, "deployment-id", "", "optional deployment GUID from installer or enrollment input")
	flags.StringVar(&outputPath, "output", "", "local identity JSON output path")
	flags.StringVar(&siteID, "site-id", "", "required safe site identifier")
	flags.StringVar(&tenantID, "tenant-id", "", "optional tenant identifier")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if outputPath == "" {
		fmt.Fprintln(stderr, "oaw-agent identity init requires --output")
		return 2
	}

	if _, err := agentidentity.CreateFile(outputPath, agentidentity.CreateParams{
		SiteID:       siteID,
		DeploymentID: deploymentID,
		TenantID:     tenantID,
	}, time.Now().UTC()); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	fmt.Fprintln(stdout, "created local agent identity file")
	return 0
}

func runConfig(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "init" {
		fmt.Fprintln(stderr, "oaw-agent config requires init")
		return 2
	}
	return runConfigInit(args[1:], stdout, stderr)
}

func runService(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "oaw-agent service requires plan or template")
		return 2
	}
	switch args[0] {
	case "plan":
		return runServicePlan(args[1:], stdout, stderr)
	case "template":
		return runServiceTemplate(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "oaw-agent service requires plan or template")
		return 2
	}
}

func runServicePlan(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("oaw-agent service plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "oaw-agent service plan does not accept positional arguments")
		return 2
	}

	plan := buildCurrentServicePlan()
	if err := output.WriteJSON(stdout, plan); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func runServiceTemplate(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("oaw-agent service template", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "oaw-agent service template does not accept positional arguments")
		return 2
	}

	template := agentserviceplan.BuildTemplate(buildCurrentServicePlan())
	if err := output.WriteJSON(stdout, template); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func buildCurrentServicePlan() agentserviceplan.Plan {
	var osRelease []byte
	if runtime.GOOS == "linux" {
		if data, err := readOSRelease("/etc/os-release"); err == nil {
			osRelease = data
		}
	}
	return agentserviceplan.Build(runtime.GOOS, defaultAgentPaths(), osRelease)
}

func runInstall(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "plan" {
		fmt.Fprintln(stderr, "oaw-agent install requires plan")
		return 2
	}
	return runInstallPlan(args[1:], stdout, stderr)
}

func runInstallPlan(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("oaw-agent install plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "oaw-agent install plan does not accept positional arguments")
		return 2
	}

	plan := buildCurrentInstallPlan()
	if err := output.WriteJSON(stdout, plan); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func buildCurrentInstallPlan() agentinstallplan.Plan {
	var osRelease []byte
	if runtime.GOOS == "linux" {
		if data, err := readOSRelease("/etc/os-release"); err == nil {
			osRelease = data
		}
	}
	return agentinstallplan.Build(runtime.GOOS, runtime.GOARCH, defaultAgentPaths(), osRelease)
}

func runConfigInit(args []string, stdout io.Writer, stderr io.Writer) int {
	var outputPath string
	var serverURL string
	var siteID string

	flags := flag.NewFlagSet("oaw-agent config init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&outputPath, "output", "", "local config JSON output path")
	flags.StringVar(&serverURL, "server-url", "", "OpenAssetWatch backend URL")
	flags.StringVar(&siteID, "site-id", "", "safe site identifier")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if outputPath == "" {
		fmt.Fprintln(stderr, "oaw-agent config init requires --output")
		return 2
	}
	if config.IsQuarantinedPath(outputPath) {
		fmt.Fprintf(stderr, "refusing to write agent config to quarantined path: %s\n", outputPath)
		return 2
	}

	if _, err := agentconfig.CreateFile(outputPath, agentconfig.CreateParams{
		ServerURL: serverURL,
		SiteID:    siteID,
	}); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	fmt.Fprintln(stdout, "created local agent config file")
	return 0
}

func runSubmit(args []string, stdout io.Writer, stderr io.Writer) int {
	var configPath string
	var filePath string
	var serverURL string

	flags := flag.NewFlagSet("oaw-agent submit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&configPath, "config", "", "optional non-secret local agent config JSON file")
	flags.StringVar(&filePath, "file", "", "local inventory JSON file to submit")
	flags.StringVar(&serverURL, "server-url", "", "explicit OpenAssetWatch backend URL")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if filePath == "" {
		fmt.Fprintln(stderr, "oaw-agent submit requires --file")
		return 2
	}

	var err error
	serverURL, err = resolveBackendServerURL(serverURL, configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintln(stderr, "failed to read collection file")
		return 1
	}
	if !json.Valid(data) {
		fmt.Fprintln(stderr, "collection file must contain valid JSON")
		return 2
	}

	statusCode, err := postJSON(context.Background(), submitHTTPClient(), serverURL, localInventorySubmitPath, data)
	if err != nil {
		fmt.Fprintf(stderr, "submit failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "submitted local inventory collection: HTTP %d\n", statusCode)
	return 0
}

type doctorReport struct {
	OK       bool          `json:"ok"`
	Checks   []doctorCheck `json:"checks"`
	Warnings []string      `json:"warnings"`
	Errors   []string      `json:"errors"`
}

type doctorCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Path    string `json:"path,omitempty"`
	Source  string `json:"source,omitempty"`
	Message string `json:"message,omitempty"`
}

type statusReport struct {
	OK       bool         `json:"ok"`
	Paths    statusPaths  `json:"paths"`
	Exists   statusExists `json:"exists"`
	Warnings []string     `json:"warnings"`
	Errors   []string     `json:"errors"`
}

type statusPaths struct {
	Config      string `json:"config"`
	ConfigSrc   string `json:"config_source"`
	Identity    string `json:"identity"`
	IdentitySrc string `json:"identity_source"`
	LogDir      string `json:"log_dir"`
	StatusFile  string `json:"status_file"`
}

type statusExists struct {
	Config     bool `json:"config"`
	Identity   bool `json:"identity"`
	LogDir     bool `json:"log_dir"`
	LastStatus bool `json:"last_status"`
}

func runDoctor(args []string, stdout io.Writer, stderr io.Writer) int {
	var configPath string
	var identityPath string

	flags := flag.NewFlagSet("oaw-agent doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&configPath, "config", "", "optional non-secret local agent config JSON file")
	flags.StringVar(&identityPath, "identity-file", "", "optional non-secret local agent identity JSON file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "oaw-agent doctor does not accept positional arguments")
		return 2
	}

	report := buildDoctorReport(configPath, identityPath)
	if err := output.WriteJSON(stdout, report); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if !report.OK {
		return 1
	}
	return 0
}

func runStatus(args []string, stdout io.Writer, stderr io.Writer) int {
	var configPath string
	var identityPath string

	flags := flag.NewFlagSet("oaw-agent status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&configPath, "config", "", "optional non-secret local agent config JSON file")
	flags.StringVar(&identityPath, "identity-file", "", "optional non-secret local agent identity JSON file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "oaw-agent status does not accept positional arguments")
		return 2
	}

	report := buildStatusReport(configPath, identityPath)
	if err := output.WriteJSON(stdout, report); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if !report.OK {
		return 1
	}
	return 0
}

func buildDoctorReport(configPath string, identityPath string) doctorReport {
	report := doctorReport{
		Checks:   []doctorCheck{},
		Warnings: []string{},
		Errors:   []string{},
	}

	defaults := defaultAgentPaths()
	resolvedConfigPath, configSource := resolveDoctorPath(configPath, defaults.ConfigPath)
	resolvedIdentityPath, identitySource := resolveDoctorPath(identityPath, defaults.IdentityPath)

	configPathOK := strings.TrimSpace(resolvedConfigPath) != ""
	report.addCheck("config_path_resolved", configPathOK, resolvedConfigPath, configSource, boolMessage(configPathOK, "config path resolved", "config path is unavailable"))
	if !configPathOK {
		report.addError("config path is unavailable")
	}

	identityPathOK := strings.TrimSpace(resolvedIdentityPath) != ""
	report.addCheck("identity_path_resolved", identityPathOK, resolvedIdentityPath, identitySource, boolMessage(identityPathOK, "identity path resolved", "identity path is unavailable"))
	if !identityPathOK {
		report.addError("identity path is unavailable")
	}

	if configPathOK {
		report.inspectConfig(resolvedConfigPath)
	}
	if identityPathOK {
		report.inspectIdentity(resolvedIdentityPath)
	}

	report.OK = len(report.Errors) == 0
	return report
}

func buildStatusReport(configPath string, identityPath string) statusReport {
	defaults := defaultAgentPaths()
	resolvedConfigPath, configSource := resolveDoctorPath(configPath, defaults.ConfigPath)
	resolvedIdentityPath, identitySource := resolveDoctorPath(identityPath, defaults.IdentityPath)

	report := statusReport{
		Paths: statusPaths{
			Config:      resolvedConfigPath,
			ConfigSrc:   configSource,
			Identity:    resolvedIdentityPath,
			IdentitySrc: identitySource,
			LogDir:      strings.TrimSpace(defaults.LogDir),
			StatusFile:  strings.TrimSpace(defaults.StatusPath),
		},
		Warnings: []string{},
		Errors:   []string{},
	}

	report.inspectStatusFile("config", resolvedConfigPath, true)
	report.inspectStatusFile("identity", resolvedIdentityPath, true)
	report.inspectLogDir(report.Paths.LogDir)
	report.inspectStatusFile("last_status", report.Paths.StatusFile, false)

	report.OK = len(report.Errors) == 0
	return report
}

func (report *statusReport) inspectStatusFile(name string, path string, required bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		message := name + " path is unavailable"
		if required {
			report.addStatusError(message)
		} else {
			report.addStatusWarning(message)
		}
		return
	}
	if config.IsQuarantinedPath(path) {
		message := name + " path is not allowed"
		if required {
			report.addStatusError(message)
		} else {
			report.addStatusWarning(message)
		}
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			message := name + " file is missing"
			if required {
				report.addStatusError(message)
			} else {
				report.addStatusWarning(message)
			}
			return
		}
		message := name + " file could not be inspected"
		if required {
			report.addStatusError(message)
		} else {
			report.addStatusWarning(message)
		}
		return
	}
	if info.IsDir() {
		message := name + " path is a directory"
		if required {
			report.addStatusError(message)
		} else {
			report.addStatusWarning(message)
		}
		return
	}

	switch name {
	case "config":
		report.Exists.Config = true
	case "identity":
		report.Exists.Identity = true
	case "last_status":
		report.Exists.LastStatus = true
	}
}

func (report *statusReport) inspectLogDir(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		report.addStatusWarning("log path is unavailable")
		return
	}
	if config.IsQuarantinedPath(path) {
		report.addStatusWarning("log path is not allowed")
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			report.addStatusWarning("log directory is missing")
			return
		}
		report.addStatusWarning("log directory could not be inspected")
		return
	}
	if !info.IsDir() {
		report.addStatusWarning("log path is not a directory")
		return
	}
	report.Exists.LogDir = true
}

func (report *statusReport) addStatusError(message string) {
	report.Errors = append(report.Errors, message)
}

func (report *statusReport) addStatusWarning(message string) {
	report.Warnings = append(report.Warnings, message)
}

func resolveDoctorPath(explicitPath string, defaultPath string) (string, string) {
	if strings.TrimSpace(explicitPath) != "" {
		return strings.TrimSpace(explicitPath), "explicit"
	}
	return strings.TrimSpace(defaultPath), "default"
}

func (report *doctorReport) inspectConfig(path string) {
	if config.IsQuarantinedPath(path) {
		report.addCheck("config_file_exists", false, path, "", "config path is not allowed")
		report.addError("config path is not allowed")
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			report.addCheck("config_file_exists", false, path, "", "config file is missing")
			report.addError("config file is missing")
			return
		}
		report.addCheck("config_file_exists", false, path, "", "config file could not be inspected")
		report.addError("config file could not be inspected")
		return
	}
	if info.IsDir() {
		report.addCheck("config_file_exists", false, path, "", "config path is a directory")
		report.addError("config path is a directory")
		return
	}
	report.addCheck("config_file_exists", true, path, "", "config file exists")

	data, err := os.ReadFile(path)
	if err != nil {
		report.addCheck("config_file_parses", false, path, "", "config file could not be read")
		report.addError("config file could not be read")
		return
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		report.addCheck("config_file_parses", false, path, "", "config file is malformed JSON")
		report.addError("config file is malformed JSON")
		return
	}
	report.addCheck("config_file_parses", true, path, "", "config file parses")

	serverURL, hasServerURL := jsonStringField(raw, "server_url")
	report.addCheck("config_has_server_url", hasServerURL, path, "", boolMessage(hasServerURL, "config contains server_url", "config server_url is missing"))
	if !hasServerURL {
		report.addError("config server_url is missing")
	} else if err := agentconfig.ValidateServerURL(serverURL); err != nil {
		report.addCheck("config_server_url_valid", false, path, "", "config server_url is invalid")
		report.addError("config server_url is invalid")
	} else {
		report.addCheck("config_server_url_valid", true, path, "", "config server_url is valid")
	}

	_, hasSiteID := jsonStringField(raw, "site_id")
	report.addCheck("config_has_site_id", hasSiteID, path, "", boolMessage(hasSiteID, "config contains site_id", "config site_id is missing"))
	if !hasSiteID {
		report.addError("config site_id is missing")
	}
}

func (report *doctorReport) inspectIdentity(path string) {
	if config.IsQuarantinedPath(path) {
		report.addCheck("identity_file_exists", false, path, "", "identity path is not allowed")
		report.addError("identity path is not allowed")
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			report.addCheck("identity_file_exists", false, path, "", "identity file is missing")
			report.addError("identity file is missing")
			return
		}
		report.addCheck("identity_file_exists", false, path, "", "identity file could not be inspected")
		report.addError("identity file could not be inspected")
		return
	}
	if info.IsDir() {
		report.addCheck("identity_file_exists", false, path, "", "identity path is a directory")
		report.addError("identity path is a directory")
		return
	}
	report.addCheck("identity_file_exists", true, path, "", "identity file exists")

	data, err := os.ReadFile(path)
	if err != nil {
		report.addCheck("identity_file_parses", false, path, "", "identity file could not be read")
		report.addError("identity file could not be read")
		return
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		report.addCheck("identity_file_parses", false, path, "", "identity file is malformed JSON")
		report.addError("identity file is malformed JSON")
		return
	}
	report.addCheck("identity_file_parses", true, path, "", "identity file parses")

	_, hasSiteID := jsonStringField(raw, "site_id")
	report.addCheck("identity_has_site_id", hasSiteID, path, "", boolMessage(hasSiteID, "identity contains site_id", "identity site_id is missing"))
	if !hasSiteID {
		report.addError("identity site_id is missing")
	}

	_, hasAgentID := jsonStringField(raw, "agent_id")
	report.addCheck("identity_has_agent_id", hasAgentID, path, "", boolMessage(hasAgentID, "identity contains agent_id", "identity agent_id is missing"))
	if !hasAgentID {
		report.addError("identity agent_id is missing")
	}
}

func (report *doctorReport) addCheck(name string, ok bool, path string, source string, message string) {
	report.Checks = append(report.Checks, doctorCheck{
		Name:    name,
		OK:      ok,
		Path:    path,
		Source:  source,
		Message: message,
	})
}

func (report *doctorReport) addError(message string) {
	report.Errors = append(report.Errors, message)
}

func jsonStringField(raw map[string]json.RawMessage, name string) (string, bool) {
	value, ok := raw[name]
	if !ok {
		return "", false
	}
	var decoded string
	if err := json.Unmarshal(value, &decoded); err != nil {
		return "", false
	}
	decoded = strings.TrimSpace(decoded)
	return decoded, decoded != ""
}

func boolMessage(ok bool, yes string, no string) string {
	if ok {
		return yes
	}
	return no
}

func loadCollectConfig(configPath string, siteID string, identityPath string) (config.Config, *agentidentity.Identity, error) {
	cfg := config.Default(config.ModeAgent)
	cfg.Mode = config.ModeAgent

	cliSiteID := strings.TrimSpace(siteID)
	agentCfg, agentCfgLoaded, err := loadAgentFileConfig(configPath, false)
	if err != nil {
		return config.Config{}, nil, err
	}
	if agentCfgLoaded {
		cfg.SiteID = agentCfg.SiteID
	}

	identityPath = strings.TrimSpace(identityPath)
	if identityPath == "" && cliSiteID == "" && configPath == "" {
		defaultIdentityPath := defaultAgentPaths().IdentityPath
		if defaultIdentityPath != "" {
			if _, err := os.Stat(defaultIdentityPath); err == nil {
				identityPath = defaultIdentityPath
			} else if errors.Is(err, os.ErrNotExist) {
				defaultConfig, loaded, err := loadAgentFileConfig("", true)
				if err != nil {
					return config.Config{}, nil, err
				}
				if loaded {
					cfg.SiteID = defaultConfig.SiteID
					if err := cfg.Validate(); err != nil {
						return config.Config{}, nil, err
					}
					return cfg, nil, nil
				}
				return config.Config{}, nil, fmt.Errorf("default identity file not found at %s and default config file not found at %s; pass --site-id, --identity-file, or --config", defaultIdentityPath, defaultAgentPaths().ConfigPath)
			} else {
				return config.Config{}, nil, fmt.Errorf("read default identity file: %w", err)
			}
		}
		defaultConfig, loaded, err := loadAgentFileConfig("", true)
		if err != nil {
			return config.Config{}, nil, err
		}
		if loaded {
			cfg.SiteID = defaultConfig.SiteID
			if err := cfg.Validate(); err != nil {
				return config.Config{}, nil, err
			}
			return cfg, nil, nil
		}
	}

	if identityPath == "" {
		if cliSiteID != "" {
			cfg.SiteID = cliSiteID
		}
		if err := cfg.Validate(); err != nil {
			return config.Config{}, nil, err
		}
		return cfg, nil, nil
	}

	if config.IsQuarantinedPath(identityPath) {
		return config.Config{}, nil, fmt.Errorf("refusing to load identity from quarantined path: %s", identityPath)
	}

	identity, err := agentidentity.ReadFile(identityPath)
	if err != nil {
		return config.Config{}, nil, err
	}
	identity.SiteID = strings.TrimSpace(identity.SiteID)
	identity.TenantID = strings.TrimSpace(identity.TenantID)
	identity.DeploymentID = strings.TrimSpace(identity.DeploymentID)
	identity.AgentID = strings.TrimSpace(identity.AgentID)

	if cliSiteID != "" && cliSiteID != identity.SiteID {
		return config.Config{}, nil, fmt.Errorf("site_id from --site-id conflicts with identity file site_id")
	}
	if cliSiteID == "" && agentCfgLoaded && cfg.SiteID != "" && cfg.SiteID != identity.SiteID {
		return config.Config{}, nil, fmt.Errorf("site_id from config conflicts with identity file site_id")
	}

	cfg.SiteID = identity.SiteID
	if err := cfg.Validate(); err != nil {
		return config.Config{}, nil, err
	}
	return cfg, &identity, nil
}

func loadAgentFileConfig(configPath string, useDefault bool) (agentconfig.Config, bool, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		if !useDefault {
			return agentconfig.Config{}, false, nil
		}
		configPath = strings.TrimSpace(defaultAgentPaths().ConfigPath)
		if configPath == "" {
			return agentconfig.Config{}, false, nil
		}
		if _, err := os.Stat(configPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return agentconfig.Config{}, false, nil
			}
			return agentconfig.Config{}, false, fmt.Errorf("read default agent config file: %w", err)
		}
	}

	if config.IsQuarantinedPath(configPath) {
		return agentconfig.Config{}, false, fmt.Errorf("refusing to load config from quarantined path: %s", configPath)
	}

	cfg, err := agentconfig.ReadFile(configPath)
	if err != nil {
		return agentconfig.Config{}, false, err
	}
	return cfg, true, nil
}

func resolveBackendServerURL(serverURL string, configPath string) (string, error) {
	serverURL = strings.TrimSpace(serverURL)
	if serverURL != "" {
		return serverURL, nil
	}

	cfg, loaded, err := loadAgentFileConfig(configPath, true)
	if err != nil {
		return "", err
	}
	if loaded {
		return cfg.ServerURL, nil
	}

	defaultConfigPath := strings.TrimSpace(defaultAgentPaths().ConfigPath)
	if strings.TrimSpace(configPath) != "" {
		return "", fmt.Errorf("server-url is required; config file %s did not provide server_url", configPath)
	}
	if defaultConfigPath == "" {
		return "", errors.New("server-url is required; default config path is not available; pass --server-url or --config")
	}
	return "", fmt.Errorf("server-url is required; default config file not found at %s; pass --server-url or --config", defaultConfigPath)
}

func runPaths(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("oaw-agent paths", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "oaw-agent paths does not accept positional arguments")
		return 2
	}

	if err := output.WriteJSON(stdout, defaultAgentPaths()); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func loadAgentConfig(configPath string, siteID string) (config.Config, error) {
	cfg := config.Default(config.ModeAgent)
	if configPath != "" {
		loaded, err := config.LoadJSON(configPath)
		if err != nil {
			return config.Config{}, err
		}
		cfg = loaded
	}
	cfg.Mode = config.ModeAgent
	if siteID != "" {
		cfg.SiteID = siteID
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

func applyCollectionIdentity(inventory *models.Inventory, identity agentidentity.Identity) {
	inventory.SiteID = identity.SiteID
	inventory.TenantID = identity.TenantID
	inventory.DeploymentID = identity.DeploymentID
	inventory.AgentID = identity.AgentID

	for index := range inventory.Assets {
		inventory.Assets[index].SiteID = identity.SiteID
	}
}

func buildAgentCheckInPayload(identity agentidentity.Identity) map[string]any {
	payload := map[string]any{
		"site_id":       strings.TrimSpace(identity.SiteID),
		"agent_id":      strings.TrimSpace(identity.AgentID),
		"agent_version": version.Number,
		"platform": map[string]string{
			"os":           runtime.GOOS,
			"architecture": runtime.GOARCH,
		},
	}
	if tenantID := strings.TrimSpace(identity.TenantID); tenantID != "" {
		payload["tenant_id"] = tenantID
	}
	if deploymentID := strings.TrimSpace(identity.DeploymentID); deploymentID != "" {
		payload["deployment_id"] = deploymentID
	}
	if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
		payload["hostname"] = strings.TrimSpace(hostname)
	}
	return payload
}

func resolveCheckInIdentityPath(identityPath string) (string, bool, error) {
	identityPath = strings.TrimSpace(identityPath)
	if identityPath != "" {
		return identityPath, true, nil
	}

	defaultIdentityPath := strings.TrimSpace(defaultAgentPaths().IdentityPath)
	if defaultIdentityPath == "" {
		return "", false, errors.New("default identity path is not available; pass --identity-file")
	}
	return defaultIdentityPath, false, nil
}

func readAgentIdentityFile(identityPath string, explicit bool) (agentidentity.Identity, error) {
	if config.IsQuarantinedPath(identityPath) {
		return agentidentity.Identity{}, fmt.Errorf("refusing to load identity from quarantined path: %s", identityPath)
	}

	identity, err := agentidentity.ReadFile(identityPath)
	if err == nil {
		return identity, nil
	}
	if !explicit && errors.Is(err, os.ErrNotExist) {
		return agentidentity.Identity{}, fmt.Errorf("default identity file not found at %s; run oaw-agent paths or pass --identity-file", identityPath)
	}
	return agentidentity.Identity{}, err
}

func postJSON(ctx context.Context, client *http.Client, serverURL string, path string, body []byte) (int, error) {
	if client == nil {
		client = submitHTTPClient()
	}

	endpoint, err := backendEndpointURL(serverURL, path)
	if err != nil {
		return 0, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("failed to build submit request")
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return 0, errors.New("request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return response.StatusCode, fmt.Errorf("backend returned HTTP status %d", response.StatusCode)
	}
	return response.StatusCode, nil
}

func backendEndpointURL(serverURL string, path string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("server-url must include http or https scheme and host")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("server-url must use http or https")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("server-url must not include query or fragment")
	}
	if parsed.User != nil {
		return "", errors.New("server-url must not include credentials")
	}

	parsed.Path = strings.TrimRight(parsed.Path, "/") + path
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}
