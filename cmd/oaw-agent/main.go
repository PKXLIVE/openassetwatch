package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	agentconfig "github.com/openassetwatch/openassetwatch/internal/agent/config"
	agentcredential "github.com/openassetwatch/openassetwatch/internal/agent/credential"
	agentcredentialacl "github.com/openassetwatch/openassetwatch/internal/agent/credentialacl"
	agenthubclient "github.com/openassetwatch/openassetwatch/internal/agent/hubclient"
	agentidentity "github.com/openassetwatch/openassetwatch/internal/agent/identity"
	agentinstallplan "github.com/openassetwatch/openassetwatch/internal/agent/installplan"
	agentpaths "github.com/openassetwatch/openassetwatch/internal/agent/paths"
	agentserviceplan "github.com/openassetwatch/openassetwatch/internal/agent/serviceplan"
	agentsupervisor "github.com/openassetwatch/openassetwatch/internal/agent/supervisor"
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
var repairDefaultCredentialACL = func() error {
	return agentcredentialacl.RepairDefault()
}

const localInventorySubmitPath = "/api/v1/collections/local-inventory"
const agentCheckInPath = "/api/v1/agents/check-in"
const runOnceInventoryFile = "last-inventory.json"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "repair-private-state-acl" {
		if len(args) != 1 {
			fmt.Fprintln(stderr, "repair-private-state-acl accepts no arguments")
			return 2
		}
		if err := repairDefaultCredentialACL(); err != nil {
			fmt.Fprintln(stderr, "private state ACL repair failed")
			return 1
		}
		return 0
	}
	if len(args) > 0 && args[0] == "enroll" {
		return runEnroll(args[1:], os.Stdin, stdout, stderr)
	}
	if len(args) > 0 && args[0] == "credential-status" {
		return runCredentialStatus(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "replace-credential" {
		return runReplaceCredential(args[1:], stderr)
	}
	if len(args) > 0 && args[0] == "clear-credential" {
		return runClearCredential(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "collect" {
		return runCollect(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "submit" {
		return runSubmit(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "run-once" {
		return runRunOnce(args[1:], stdout, stderr)
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
	var credentialPath string
	var identityPath string
	var serverURL string

	flags := flag.NewFlagSet("oaw-agent check-in", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&configPath, "config", "", "optional non-secret local agent config JSON file")
	flags.StringVar(&credentialPath, "credential-file", "", "protected endpoint-agent credential record")
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

	credentialRecord, credentialFound, err := loadOptionalAgentCredential(credentialPath)
	if err != nil {
		fmt.Fprintln(stderr, "failed to load endpoint-agent credential")
		return 1
	}
	statusCode := 0
	if credentialFound {
		if err := validateCredentialIdentity(credentialRecord, identity); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		client, clientErr := agenthubclient.New(serverURL)
		if clientErr != nil {
			fmt.Fprintln(stderr, clientErr)
			return 2
		}
		statusCode, err = client.CheckIn(
			context.Background(),
			credentialRecord.Credential,
			buildBoundAgentCheckInPayload(identity),
		)
	} else {
		statusCode, err = postJSON(context.Background(), submitHTTPClient(), serverURL, agentCheckInPath, body)
	}
	if err != nil {
		fmt.Fprintf(stderr, "check-in failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "agent check-in accepted: HTTP %d\n", statusCode)
	return 0
}

func runEnroll(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	var configPath string
	var credentialPath string
	var displayName string
	var enrollmentTokenFile string
	var enrollmentTokenStdin bool
	var identityPath string
	var installationID string
	var serverURL string

	flags := flag.NewFlagSet("oaw-agent enroll", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&configPath, "config", "", "optional non-secret local agent config JSON file")
	flags.StringVar(&credentialPath, "credential-file", "", "protected endpoint-agent credential output")
	flags.StringVar(&displayName, "display-name", "", "optional bounded agent display name")
	flags.StringVar(&enrollmentTokenFile, "enrollment-token-file", "", "protected one-time enrollment token file")
	flags.BoolVar(&enrollmentTokenStdin, "enrollment-token-stdin", false, "read the one-time enrollment token from stdin")
	flags.StringVar(&identityPath, "identity-file", "", "non-secret authoritative identity output")
	flags.StringVar(&installationID, "installation-id", "", "optional reviewed deployment identifier")
	flags.StringVar(&serverURL, "server-url", "", "explicit OpenAssetWatch backend URL")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if (enrollmentTokenFile == "") == !enrollmentTokenStdin {
		fmt.Fprintln(stderr, "choose exactly one enrollment token input")
		return 2
	}
	var err error
	serverURL, err = resolveBackendServerURL(serverURL, configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if strings.TrimSpace(credentialPath) == "" {
		credentialPath = defaultAgentPaths().CredentialPath
	}
	if strings.TrimSpace(identityPath) == "" {
		identityPath = defaultAgentPaths().IdentityPath
	}
	if config.IsQuarantinedPath(credentialPath) || config.IsQuarantinedPath(identityPath) {
		fmt.Fprintln(stderr, "refusing to use a quarantined agent state path")
		return 2
	}
	if err := agentcredential.EnsureAbsent(credentialPath); err != nil {
		fmt.Fprintln(stderr, "endpoint-agent credential output is not empty")
		return 1
	}
	if _, err := os.Lstat(identityPath); err == nil {
		fmt.Fprintln(stderr, "agent identity file already exists")
		return 1
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, "agent identity output is unavailable")
		return 1
	}
	token := ""
	if enrollmentTokenFile != "" {
		token, err = agentcredential.ReadSecretFile(enrollmentTokenFile, true)
	} else {
		data, readErr := io.ReadAll(io.LimitReader(stdin, agentcredential.MaxSecretBytes+2))
		if readErr != nil || len(data) > agentcredential.MaxSecretBytes+1 {
			err = errors.New("read enrollment token")
		} else {
			token = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
			if !agentcredential.ValidEnrollmentToken(token) {
				err = errors.New("invalid enrollment token")
			}
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "failed to read a valid enrollment token")
		return 1
	}
	client, err := agenthubclient.New(serverURL)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	response, err := client.Enroll(context.Background(), agenthubclient.EnrollmentRequest{
		EnrollmentToken: token,
		InstallationID:  strings.TrimSpace(installationID),
		DisplayName:     strings.TrimSpace(displayName),
		AgentVersion:    version.Number,
		Platform:        runtime.GOOS,
		Architecture:    runtime.GOARCH,
		AgentType:       "endpoint-agent",
	})
	token = ""
	if err != nil {
		fmt.Fprintln(stderr, "endpoint-agent enrollment failed")
		return 1
	}
	record := agentcredential.Record{
		SchemaVersion: agentcredential.SchemaVersion,
		SiteID:        response.SiteID, AgentID: response.AgentID,
		DeploymentID: response.DeploymentID, AgentType: response.AgentType,
		CredentialID: response.CredentialID, Credential: response.AgentCredential,
		IssuedAt: response.IssuedAt,
	}
	if err := agentcredential.Write(credentialPath, record, false); err != nil {
		fmt.Fprintln(stderr, "failed to store endpoint-agent credential")
		return 1
	}
	identity := agentidentity.Identity{
		AgentID: response.AgentID, SiteID: response.SiteID,
		DeploymentID: response.DeploymentID,
		CreatedAt:    response.IssuedAt, UpdatedAt: response.IssuedAt,
	}
	if err := agentidentity.WriteFile(identityPath, identity); err != nil {
		fmt.Fprintln(stderr, "credential stored; failed to store non-secret agent identity")
		return 1
	}
	fmt.Fprintln(stdout, "endpoint-agent enrollment completed; credential stored securely")
	return 0
}

func runCredentialStatus(args []string, stdout io.Writer, stderr io.Writer) int {
	var path string
	flags := flag.NewFlagSet("oaw-agent credential-status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&path, "credential-file", "", "protected endpoint-agent credential record")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	record, found, err := loadOptionalAgentCredential(path)
	if err != nil || !found {
		fmt.Fprintln(stderr, "endpoint-agent credential is unavailable")
		return 1
	}
	status := map[string]any{
		"configured": true, "schema_version": record.SchemaVersion,
		"site_id": record.SiteID, "agent_id": record.AgentID,
		"deployment_id": record.DeploymentID, "agent_type": record.AgentType,
		"credential_id": record.CredentialID, "issued_at": record.IssuedAt,
	}
	if err := output.WriteJSON(stdout, status); err != nil {
		fmt.Fprintln(stderr, "failed to write credential status")
		return 1
	}
	return 0
}

func runReplaceCredential(args []string, stderr io.Writer) int {
	var credentialID string
	var newCredentialFile string
	var path string
	flags := flag.NewFlagSet("oaw-agent replace-credential", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&credentialID, "credential-id", "", "server-issued replacement credential ID")
	flags.StringVar(&newCredentialFile, "new-credential-file", "", "protected replacement credential value file")
	flags.StringVar(&path, "credential-file", "", "protected endpoint-agent credential record")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	current, found, err := loadOptionalAgentCredential(path)
	if err != nil || !found || newCredentialFile == "" || credentialID == "" {
		fmt.Fprintln(stderr, "current and replacement credential inputs are required")
		return 2
	}
	value, err := agentcredential.ReadSecretFile(newCredentialFile, false)
	if err != nil {
		fmt.Fprintln(stderr, "replacement credential input is invalid")
		return 1
	}
	current.Credential = value
	current.CredentialID = credentialID
	current.IssuedAt = time.Now().UTC()
	if strings.TrimSpace(path) == "" {
		path = defaultAgentPaths().CredentialPath
	}
	if err := agentcredential.Write(path, current, true); err != nil {
		fmt.Fprintln(stderr, "failed to replace endpoint-agent credential")
		return 1
	}
	return 0
}

func runClearCredential(args []string, stdout io.Writer, stderr io.Writer) int {
	var confirm bool
	var path string
	flags := flag.NewFlagSet("oaw-agent clear-credential", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.BoolVar(&confirm, "confirm-clear", false, "confirm permanent local credential removal")
	flags.StringVar(&path, "credential-file", "", "protected endpoint-agent credential record")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if !confirm {
		fmt.Fprintln(stderr, "clear-credential requires --confirm-clear")
		return 2
	}
	if strings.TrimSpace(path) == "" {
		path = defaultAgentPaths().CredentialPath
	}
	if err := agentcredential.Clear(path); err != nil {
		fmt.Fprintln(stderr, "failed to clear endpoint-agent credential")
		return 1
	}
	fmt.Fprintln(stdout, "endpoint-agent credential cleared")
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
		fmt.Fprintln(stderr, "oaw-agent service requires plan, template, or run")
		return 2
	}
	switch args[0] {
	case "plan":
		return runServicePlan(args[1:], stdout, stderr)
	case "template":
		return runServiceTemplate(args[1:], stdout, stderr)
	case "run":
		return runServiceRun(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "oaw-agent service requires plan, template, or run")
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

func runServiceRun(args []string, stdout io.Writer, stderr io.Writer) int {
	var configPath string
	var identityPath string
	var outputDir string

	flags := flag.NewFlagSet("oaw-agent service run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&configPath, "config", "", "non-secret local agent config JSON file")
	flags.StringVar(&identityPath, "identity-file", "", "non-secret local agent identity JSON file")
	flags.StringVar(&outputDir, "output-dir", "", "local runtime output directory")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "oaw-agent service run does not accept positional arguments")
		return 2
	}

	defaults := defaultAgentPaths()
	resolvedConfigPath, _ := resolveDoctorPath(configPath, defaults.ConfigPath)
	resolvedIdentityPath, _ := resolveDoctorPath(identityPath, defaults.IdentityPath)
	outputDir = strings.TrimSpace(outputDir)
	if outputDir == "" {
		outputDir = defaultRunOnceOutputDir()
	}

	options := agentsupervisor.Options{
		ConfigPath:      resolvedConfigPath,
		IdentityPath:    resolvedIdentityPath,
		OutputDir:       outputDir,
		StatusPath:      defaults.StatusPath,
		InitialDelay:    0,
		SuccessInterval: time.Hour,
		RetryBase:       5 * time.Minute,
		MaxRetryDelay:   time.Hour,
		Jitter:          30 * time.Second,
		ShutdownTimeout: 30 * time.Second,
		ServiceName:     defaultServiceName(),
	}
	cycle := func(ctx context.Context) agentsupervisor.CycleResult {
		report := executeRunOnceContext(ctx, resolvedConfigPath, resolvedIdentityPath, outputDir)
		if report.OK {
			return agentsupervisor.CycleResult{OK: true, LastInventoryPath: report.InventoryPath}
		}
		return agentsupervisor.CycleResult{
			OK:                false,
			ErrorCategory:     categorizeRunOnceFailure(report),
			ErrorMessage:      summarizeRunOnceFailure(report),
			LastInventoryPath: report.InventoryPath,
		}
	}

	return runServiceRuntimeForCommand(options, cycle, stdout, stderr)
}

func defaultServiceName() string {
	switch runtime.GOOS {
	case "windows":
		return "OpenAssetWatchAgent"
	case "darwin":
		return "com.openassetwatch.agent"
	default:
		return "openassetwatch-agent"
	}
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
	var credentialPath string
	var filePath string
	var serverURL string

	flags := flag.NewFlagSet("oaw-agent submit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&configPath, "config", "", "optional non-secret local agent config JSON file")
	flags.StringVar(&credentialPath, "credential-file", "", "protected endpoint-agent credential record")
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

	credentialRecord, credentialFound, err := loadOptionalAgentCredential(credentialPath)
	if err != nil {
		fmt.Fprintln(stderr, "failed to load endpoint-agent credential")
		return 1
	}
	statusCode := 0
	if credentialFound {
		var inventory models.Inventory
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&inventory); err != nil {
			fmt.Fprintln(stderr, "collection file is not a supported endpoint inventory")
			return 2
		}
		if strings.TrimSpace(inventory.SiteID) != "" && inventory.SiteID != credentialRecord.SiteID {
			fmt.Fprintln(stderr, "collection site conflicts with endpoint-agent credential")
			return 2
		}
		client, clientErr := agenthubclient.New(serverURL)
		if clientErr != nil {
			fmt.Fprintln(stderr, clientErr)
			return 2
		}
		statusCode, err = client.SubmitInventory(
			context.Background(),
			credentialRecord.Credential,
			buildEndpointInventoryPayload(inventory, credentialRecord),
		)
	} else {
		statusCode, err = postJSON(context.Background(), submitHTTPClient(), serverURL, localInventorySubmitPath, data)
	}
	if err != nil {
		fmt.Fprintf(stderr, "submit failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "submitted inventory collection: HTTP %d\n", statusCode)
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

type runOnceReport struct {
	OK            bool         `json:"ok"`
	ConfigPath    string       `json:"config_path"`
	IdentityPath  string       `json:"identity_path"`
	OutputDir     string       `json:"output_dir"`
	InventoryPath string       `json:"inventory_path,omitempty"`
	Preflight     doctorReport `json:"preflight"`
	CheckIn       runOnceStep  `json:"check_in"`
	Collect       runOnceStep  `json:"collect"`
	Submit        runOnceStep  `json:"submit"`
	Warnings      []string     `json:"warnings"`
	Errors        []string     `json:"errors"`
}

type runOnceStep struct {
	OK         bool   `json:"ok"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Message    string `json:"message,omitempty"`
}

func runRunOnce(args []string, stdout io.Writer, stderr io.Writer) int {
	var configPath string
	var identityPath string
	var outputDir string

	flags := flag.NewFlagSet("oaw-agent run-once", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&configPath, "config", "", "non-secret local agent config JSON file")
	flags.StringVar(&identityPath, "identity-file", "", "non-secret local agent identity JSON file")
	flags.StringVar(&outputDir, "output-dir", "", "local runtime output directory")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "oaw-agent run-once does not accept positional arguments")
		return 2
	}

	report := executeRunOnce(configPath, identityPath, outputDir)
	if err := output.WriteJSON(stdout, report); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if !report.OK {
		return 1
	}
	return 0
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

func executeRunOnce(configPath string, identityPath string, outputDir string) runOnceReport {
	return executeRunOnceContext(context.Background(), configPath, identityPath, outputDir)
}

func executeRunOnceContext(ctx context.Context, configPath string, identityPath string, outputDir string) runOnceReport {
	defaults := defaultAgentPaths()
	resolvedConfigPath, _ := resolveDoctorPath(configPath, defaults.ConfigPath)
	resolvedIdentityPath, _ := resolveDoctorPath(identityPath, defaults.IdentityPath)
	outputDir = strings.TrimSpace(outputDir)
	if outputDir == "" {
		outputDir = defaultRunOnceOutputDir()
	}

	report := runOnceReport{
		ConfigPath:   resolvedConfigPath,
		IdentityPath: resolvedIdentityPath,
		OutputDir:    outputDir,
		Preflight:    buildDoctorReport(configPath, identityPath),
		Warnings:     []string{},
		Errors:       []string{},
	}
	if !report.Preflight.OK {
		report.Errors = append(report.Errors, "preflight checks failed")
		return report
	}

	agentCfg, loaded, err := loadAgentFileConfig(configPath, true)
	if err != nil {
		report.Errors = append(report.Errors, "load config failed: "+err.Error())
		return report
	}
	if !loaded {
		report.Errors = append(report.Errors, "config file is required")
		return report
	}

	identity, err := readAgentIdentityFile(resolvedIdentityPath, strings.TrimSpace(identityPath) != "")
	if err != nil {
		report.Errors = append(report.Errors, "load identity failed: "+err.Error())
		return report
	}
	if strings.TrimSpace(identity.SiteID) != strings.TrimSpace(agentCfg.SiteID) {
		report.Errors = append(report.Errors, "config site_id conflicts with identity file site_id")
		return report
	}
	credentialRecord, credentialFound, err := loadOptionalAgentCredential("")
	if err != nil {
		report.Errors = append(report.Errors, "load endpoint-agent credential failed")
		return report
	}
	if credentialFound {
		if err := validateCredentialIdentity(credentialRecord, identity); err != nil {
			report.Errors = append(report.Errors, err.Error())
			return report
		}
	}

	checkInBody, err := json.Marshal(buildAgentCheckInPayload(identity))
	if err != nil {
		report.Errors = append(report.Errors, "build check-in payload failed")
		return report
	}
	statusCode := 0
	if credentialFound {
		client, clientErr := agenthubclient.New(agentCfg.ServerURL)
		if clientErr != nil {
			report.Errors = append(report.Errors, clientErr.Error())
			return report
		}
		statusCode, err = client.CheckIn(ctx, credentialRecord.Credential, buildBoundAgentCheckInPayload(identity))
	} else {
		statusCode, err = postJSON(ctx, submitHTTPClient(), agentCfg.ServerURL, agentCheckInPath, checkInBody)
	}
	if err != nil {
		report.CheckIn = runOnceStep{OK: false, HTTPStatus: statusCode, Message: "check-in failed"}
		report.Errors = append(report.Errors, "check-in failed: "+err.Error())
		return report
	}
	report.CheckIn = runOnceStep{OK: true, HTTPStatus: statusCode, Message: "check-in accepted"}

	inventory := collectLocalInventory(agentCfg.SiteID)
	applyCollectionIdentity(&inventory, identity)
	inventoryData, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		report.Collect = runOnceStep{OK: false, Message: "collection marshal failed"}
		report.Errors = append(report.Errors, "collection marshal failed")
		return report
	}
	inventoryData = append(inventoryData, '\n')

	if strings.TrimSpace(outputDir) == "" {
		report.Collect = runOnceStep{OK: false, Message: "output directory is required"}
		report.Errors = append(report.Errors, "output directory is required")
		return report
	}
	if config.IsQuarantinedPath(outputDir) {
		report.Collect = runOnceStep{OK: false, Message: "output directory is not allowed"}
		report.Errors = append(report.Errors, "output directory is not allowed")
		return report
	}
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		report.Collect = runOnceStep{OK: false, Message: "output directory could not be created"}
		report.Errors = append(report.Errors, "output directory could not be created")
		return report
	}
	inventoryPath := filepath.Join(outputDir, runOnceInventoryFile)
	if err := os.WriteFile(inventoryPath, inventoryData, 0o600); err != nil {
		report.Collect = runOnceStep{OK: false, Message: "inventory file could not be written"}
		report.Errors = append(report.Errors, "inventory file could not be written")
		return report
	}
	report.InventoryPath = inventoryPath
	report.Collect = runOnceStep{OK: true, Message: "local inventory collected"}

	if credentialFound {
		client, clientErr := agenthubclient.New(agentCfg.ServerURL)
		if clientErr != nil {
			report.Submit = runOnceStep{OK: false, Message: "inventory submit failed"}
			report.Errors = append(report.Errors, "inventory submit failed")
			return report
		}
		statusCode, err = client.SubmitInventory(
			ctx,
			credentialRecord.Credential,
			buildEndpointInventoryPayload(inventory, credentialRecord),
		)
	} else {
		statusCode, err = postJSON(ctx, submitHTTPClient(), agentCfg.ServerURL, localInventorySubmitPath, inventoryData)
	}
	if err != nil {
		report.Submit = runOnceStep{OK: false, HTTPStatus: statusCode, Message: "inventory submit failed"}
		report.Errors = append(report.Errors, "inventory submit failed: "+err.Error())
		return report
	}
	report.Submit = runOnceStep{OK: true, HTTPStatus: statusCode, Message: "inventory submitted"}
	report.OK = true
	return report
}

func defaultRunOnceOutputDir() string {
	defaults := defaultAgentPaths()
	if strings.TrimSpace(defaults.StateDir) != "" {
		return defaults.StateDir
	}
	return filepath.Join(string(filepath.Separator), "var", "lib", "openassetwatch", "agent")
}

func categorizeRunOnceFailure(report runOnceReport) string {
	switch {
	case !report.Preflight.OK:
		return "preflight"
	case !report.CheckIn.OK && report.CheckIn.Message != "":
		return "check_in"
	case !report.Collect.OK && report.Collect.Message != "":
		return "collect"
	case !report.Submit.OK && report.Submit.Message != "":
		return "submit"
	default:
		return "runtime"
	}
}

func summarizeRunOnceFailure(report runOnceReport) string {
	if len(report.Errors) == 0 {
		return "agent cycle failed"
	}
	return strings.Join(report.Errors, "; ")
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

func buildBoundAgentCheckInPayload(identity agentidentity.Identity) map[string]any {
	payload := map[string]any{
		"site_id": identity.SiteID, "agent_id": identity.AgentID,
		"agent_type": "endpoint-agent", "agent_version": version.Number,
		"platform": runtime.GOOS, "architecture": runtime.GOARCH,
		"supported_capabilities":   []string{"check-in", "endpoint-inventory-v1", "native-software-inventory-v1"},
		"inventory_schema_version": "oaw.endpoint-inventory.v1",
		"health":                   "healthy", "observed_at": time.Now().UTC(),
	}
	if identity.DeploymentID != "" {
		payload["deployment_id"] = identity.DeploymentID
	}
	if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
		payload["hostname"] = strings.TrimSpace(hostname)
	}
	return payload
}

func buildEndpointInventoryPayload(inventory models.Inventory, record agentcredential.Record) map[string]any {
	assets := make([]map[string]any, 0, len(inventory.Assets))
	for _, asset := range inventory.Assets {
		interfaces := make([]map[string]any, 0, len(asset.PrimaryInterfaces))
		for _, networkInterface := range asset.PrimaryInterfaces {
			addresses := make([]map[string]string, 0, len(networkInterface.IPAddresses))
			for _, address := range networkInterface.IPAddresses {
				item := map[string]string{"address": address.Address}
				if address.Family == "ipv4" || address.Family == "ipv6" {
					item["family"] = address.Family
				}
				addresses = append(addresses, item)
			}
			item := map[string]any{"name": networkInterface.Name, "ip_addresses": addresses}
			if networkInterface.MACAddress != "" {
				item["mac_address"] = networkInterface.MACAddress
			}
			interfaces = append(interfaces, item)
		}
		evidence := make([]map[string]any, 0, 8)
		if asset.Hostname != "" {
			evidence = append(evidence, map[string]any{"kind": "hostname", "value": asset.Hostname, "method": "endpoint-inventory", "confidence": 0.95})
		}
		if asset.OS != "" {
			evidence = append(evidence, map[string]any{"kind": "operating-system", "value": asset.OS, "method": "endpoint-inventory", "confidence": 0.9})
		}
		item := map[string]any{
			"interfaces": interfaces, "evidence": evidence,
			"components": asset.Components, "management_capabilities": []string{},
		}
		for key, value := range map[string]string{
			"asset_id": asset.AssetID, "hostname": asset.Hostname, "fqdn": asset.FQDN,
			"os": asset.OS, "platform": asset.Platform, "architecture": asset.Architecture,
		} {
			if strings.TrimSpace(value) != "" {
				item[key] = value
			}
		}
		assets = append(assets, item)
	}
	canonical, _ := json.Marshal(inventory)
	digest := sha256.Sum256(canonical)
	observedAt := inventory.CollectedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	limitations := make([]string, 0, len(inventory.SoftwareSources))
	for _, source := range inventory.SoftwareSources {
		if source.Status != "complete" {
			limitations = append(limitations, "software-source-"+source.SourceID+"-"+source.Status)
		}
	}
	return map[string]any{
		"schema_version":     "oaw.endpoint-inventory.v1",
		"inventory_batch_id": fmt.Sprintf("batch_%x", digest[:16]),
		"observed_at":        observedAt.UTC(), "inventory_mode": "complete",
		"site_id": record.SiteID, "agent_id": record.AgentID,
		"deployment_id": emptyStringAsNil(record.DeploymentID),
		"agent_type":    "endpoint-agent", "agent_version": version.Number,
		"platform": runtime.GOOS, "architecture": runtime.GOARCH,
		"supported_capabilities": []string{"endpoint-inventory-v1", "native-software-inventory-v1"},
		"collection_limitations": limitations,
		"software_sources":       inventory.SoftwareSources,
		"assets":                 assets,
	}
}

func emptyStringAsNil(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func loadOptionalAgentCredential(path string) (agentcredential.Record, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = strings.TrimSpace(defaultAgentPaths().CredentialPath)
	}
	if path == "" {
		return agentcredential.Record{}, false, nil
	}
	if config.IsQuarantinedPath(path) {
		return agentcredential.Record{}, false, errors.New("credential path is quarantined")
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return agentcredential.Record{}, false, nil
	} else if err != nil {
		return agentcredential.Record{}, false, errors.New("inspect credential file")
	}
	record, err := agentcredential.Load(path)
	if err != nil {
		return agentcredential.Record{}, false, err
	}
	return record, true, nil
}

func validateCredentialIdentity(record agentcredential.Record, identity agentidentity.Identity) error {
	if record.SiteID != strings.TrimSpace(identity.SiteID) ||
		record.AgentID != strings.TrimSpace(identity.AgentID) ||
		record.DeploymentID != strings.TrimSpace(identity.DeploymentID) ||
		record.AgentType != "endpoint-agent" {
		return errors.New("credential binding conflicts with local agent identity")
	}
	return nil
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
