package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentconfig "github.com/openassetwatch/openassetwatch/internal/agent/config"
	agentidentity "github.com/openassetwatch/openassetwatch/internal/agent/identity"
	agentinstallplan "github.com/openassetwatch/openassetwatch/internal/agent/installplan"
	agentpaths "github.com/openassetwatch/openassetwatch/internal/agent/paths"
	agentserviceplan "github.com/openassetwatch/openassetwatch/internal/agent/serviceplan"
	"github.com/openassetwatch/openassetwatch/pkg/models"
	"github.com/openassetwatch/openassetwatch/pkg/schema"
)

func TestRunCollectOnceWritesJSONToStdout(t *testing.T) {
	restore := stubCollector(t)
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect", "--once", "--site-id", "site-test"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run collect code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("run collect stderr = %q, want empty", stderr.String())
	}

	var inventory models.Inventory
	if err := json.Unmarshal(stdout.Bytes(), &inventory); err != nil {
		t.Fatalf("collect output is not JSON: %v\n%s", err, stdout.String())
	}
	if inventory.SchemaVersion != schema.InventorySchemaVersion {
		t.Fatalf("schema_version = %q, want %q", inventory.SchemaVersion, schema.InventorySchemaVersion)
	}
	if len(inventory.Assets) != 1 || inventory.Assets[0].SiteID != "site-test" {
		t.Fatalf("unexpected assets: %+v", inventory.Assets)
	}
}

func TestRunCollectOnceWritesJSONToOutputFile(t *testing.T) {
	restore := stubCollector(t)
	defer restore()

	outputPath := filepath.Join(t.TempDir(), "inventory.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect", "--once", "--site-id", "site-test", "--output", outputPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run collect code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("run collect stdout = %q, want empty when --output is used", stdout.String())
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var inventory models.Inventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatalf("output file is not JSON: %v\n%s", err, string(data))
	}
	if len(inventory.Assets) != 1 || inventory.Assets[0].Hostname != "fixture-host" {
		t.Fatalf("unexpected output inventory: %+v", inventory)
	}
}

func TestRunCollectLoadsIdentityFields(t *testing.T) {
	restore := stubCollector(t)
	defer restore()
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: writeIdentityFile(t, agentidentity.Identity{
			AgentID:   "33333333-3333-4333-8333-333333333333",
			SiteID:    "site-default",
			CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
			UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		}),
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	})
	defer restorePaths()

	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:      "22222222-2222-4222-8222-222222222222",
		DeploymentID: "11111111-1111-4111-8111-111111111111",
		SiteID:       "site-identity",
		TenantID:     "tenant-example",
		CreatedAt:    time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect", "--once", "--identity-file", identityPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run collect code = %d, stderr = %q", code, stderr.String())
	}

	var inventory models.Inventory
	if err := json.Unmarshal(stdout.Bytes(), &inventory); err != nil {
		t.Fatalf("collect output is not JSON: %v\n%s", err, stdout.String())
	}
	if inventory.SiteID != "site-identity" {
		t.Fatalf("site_id = %q, want identity site_id", inventory.SiteID)
	}
	if inventory.TenantID != "tenant-example" {
		t.Fatalf("tenant_id = %q, want tenant-example", inventory.TenantID)
	}
	if inventory.DeploymentID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("deployment_id = %q", inventory.DeploymentID)
	}
	if inventory.AgentID != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("agent_id = %q", inventory.AgentID)
	}
	if len(inventory.Assets) != 1 || inventory.Assets[0].SiteID != "site-identity" {
		t.Fatalf("asset site_id was not updated from identity: %+v", inventory.Assets)
	}
}

func TestRunCollectLoadsDefaultIdentityWithoutSiteID(t *testing.T) {
	restore := stubCollector(t)
	defer restore()

	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:      "22222222-2222-4222-8222-222222222222",
		DeploymentID: "11111111-1111-4111-8111-111111111111",
		SiteID:       "site-default",
		TenantID:     "tenant-example",
		CreatedAt:    time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: identityPath,
		ConfigPath:   filepath.Join(t.TempDir(), "config.json"),
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect", "--once"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run collect code = %d, stderr = %q", code, stderr.String())
	}

	var inventory models.Inventory
	if err := json.Unmarshal(stdout.Bytes(), &inventory); err != nil {
		t.Fatalf("collect output is not JSON: %v\n%s", err, stdout.String())
	}
	if inventory.SiteID != "site-default" {
		t.Fatalf("site_id = %q, want default identity site_id", inventory.SiteID)
	}
	if inventory.AgentID != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("agent_id = %q", inventory.AgentID)
	}
}

func TestRunCollectMissingDefaultIdentityFailsClearly(t *testing.T) {
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: filepath.Join(t.TempDir(), "missing-identity.json"),
		ConfigPath:   filepath.Join(t.TempDir(), "config.json"),
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect", "--once"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run collect without site_id or default identity returned success")
	}
	if !strings.Contains(stderr.String(), "default identity file not found") {
		t.Fatalf("stderr = %q, want missing default identity error", stderr.String())
	}
}

func TestRunCollectUsesDefaultConfigSiteID(t *testing.T) {
	restore := stubCollector(t)
	defer restore()

	configPath := writeAgentConfigFile(t, agentconfig.Config{
		ServerURL: "http://localhost:8000",
		SiteID:    "site-config",
	})
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: filepath.Join(t.TempDir(), "missing-identity.json"),
		ConfigPath:   configPath,
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect", "--once"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run collect code = %d, stderr = %q", code, stderr.String())
	}

	var inventory models.Inventory
	if err := json.Unmarshal(stdout.Bytes(), &inventory); err != nil {
		t.Fatalf("collect output is not JSON: %v\n%s", err, stdout.String())
	}
	if inventory.SiteID != "site-config" {
		t.Fatalf("site_id = %q, want config site_id", inventory.SiteID)
	}
}

func TestRunCollectExplicitSiteIDOverridesConfig(t *testing.T) {
	restore := stubCollector(t)
	defer restore()

	configPath := writeAgentConfigFile(t, agentconfig.Config{
		ServerURL: "http://localhost:8000",
		SiteID:    "site-config",
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect", "--once", "--config", configPath, "--site-id", "site-cli"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run collect code = %d, stderr = %q", code, stderr.String())
	}

	var inventory models.Inventory
	if err := json.Unmarshal(stdout.Bytes(), &inventory); err != nil {
		t.Fatalf("collect output is not JSON: %v\n%s", err, stdout.String())
	}
	if inventory.SiteID != "site-cli" {
		t.Fatalf("site_id = %q, want CLI site_id", inventory.SiteID)
	}
}

func TestRunCollectRejectsConflictingSiteID(t *testing.T) {
	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-identity",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect", "--once", "--site-id", "site-other", "--identity-file", identityPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run collect returned success for conflicting site_id")
	}
	if !strings.Contains(stderr.String(), "conflicts with identity file site_id") {
		t.Fatalf("stderr = %q, want conflict error", stderr.String())
	}
}

func TestRunCollectAcceptsMatchingSiteID(t *testing.T) {
	restore := stubCollector(t)
	defer restore()

	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-identity",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect", "--once", "--site-id", "site-identity", "--identity-file", identityPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run collect code = %d, stderr = %q", code, stderr.String())
	}
}

func TestRunCollectKeepsMissingDeploymentIDEmpty(t *testing.T) {
	restore := stubCollector(t)
	defer restore()

	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-identity",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect", "--once", "--identity-file", identityPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run collect code = %d, stderr = %q", code, stderr.String())
	}

	var inventory models.Inventory
	if err := json.Unmarshal(stdout.Bytes(), &inventory); err != nil {
		t.Fatalf("collect output is not JSON: %v\n%s", err, stdout.String())
	}
	if inventory.DeploymentID != "" {
		t.Fatalf("deployment_id = %q, want empty", inventory.DeploymentID)
	}
	if inventory.AgentID == "" {
		t.Fatal("agent_id should come from identity file")
	}
}

func TestRunCollectIdentityFileDoesNotLeakUnknownSecret(t *testing.T) {
	restore := stubCollector(t)
	defer restore()

	secret := "identity-secret-token-value"
	identityPath := filepath.Join(t.TempDir(), "identity.json")
	body := []byte(`{
  "agent_id": "22222222-2222-4222-8222-222222222222",
  "site_id": "site-identity",
  "created_at": "2026-06-17T12:00:00Z",
  "updated_at": "2026-06-17T12:00:00Z",
  "enrollment_token": "` + secret + `"
}`)
	if err := os.WriteFile(identityPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect", "--once", "--identity-file", identityPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run collect code = %d, stderr = %q", code, stderr.String())
	}

	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, secret) {
		t.Fatalf("collect output leaked token-like value: %q", combined)
	}
}

func TestRunCollectRequiresOnce(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"collect"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run collect without --once returned success")
	}
}

func TestRunIdentityInitCreatesIdentityFile(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "identity.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"identity", "init", "--site-id", "site-local", "--output", outputPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run identity init code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "created local agent identity file") {
		t.Fatalf("stdout = %q, want creation message", stdout.String())
	}

	identity, err := agentidentity.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if identity.AgentID == "" {
		t.Fatal("agent_id is empty")
	}
	if identity.SiteID != "site-local" {
		t.Fatalf("site_id = %q, want site-local", identity.SiteID)
	}
}

func TestRunIdentityInitPreservesSuppliedDeploymentID(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "identity.json")
	deploymentID := "11111111-1111-4111-8111-111111111111"

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"identity", "init",
		"--site-id", "site-local",
		"--deployment-id", deploymentID,
		"--output", outputPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run identity init code = %d, stderr = %q", code, stderr.String())
	}

	identity, err := agentidentity.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if identity.DeploymentID != deploymentID {
		t.Fatalf("deployment_id = %q, want %q", identity.DeploymentID, deploymentID)
	}
}

func TestRunIdentityInitDoesNotFabricateDeploymentID(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "identity.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"identity", "init", "--site-id", "site-local", "--output", outputPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run identity init code = %d, stderr = %q", code, stderr.String())
	}

	identity, err := agentidentity.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if identity.DeploymentID != "" {
		t.Fatalf("deployment_id = %q, want empty", identity.DeploymentID)
	}
}

func TestRunIdentityInitRejectsEmptySiteID(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "identity.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"identity", "init", "--site-id", "   ", "--output", outputPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run identity init returned success for empty site_id")
	}
	if !strings.Contains(stderr.String(), "site_id is required") {
		t.Fatalf("stderr = %q, want site_id error", stderr.String())
	}
}

func TestRunConfigInitCreatesNonSecretConfigFile(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "agent", "config.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"config", "init",
		"--server-url", "http://localhost:8000",
		"--site-id", "site-local",
		"--output", outputPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run config init code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "created local agent config file") {
		t.Fatalf("stdout = %q, want creation message", stdout.String())
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 {
		t.Fatalf("config fields = %v, want only server_url and site_id", fields)
	}
	if _, ok := fields["server_url"]; !ok {
		t.Fatalf("missing server_url in %s", string(data))
	}
	if _, ok := fields["site_id"]; !ok {
		t.Fatalf("missing site_id in %s", string(data))
	}

	combined := strings.ToLower(stdout.String() + stderr.String() + string(data))
	for _, forbidden := range []string{"token", "secret", "password", "api_key", "credential"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("config init output included forbidden term %q: %s", forbidden, combined)
		}
	}
}

func TestRunConfigInitRejectsInvalidURL(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "config.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"config", "init",
		"--server-url", "http://user:secret@localhost:8000",
		"--site-id", "site-local",
		"--output", outputPath,
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run config init returned success for URL credentials")
	}
	if strings.Contains(stdout.String()+stderr.String(), "secret") {
		t.Fatalf("config init output leaked URL credential: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "must not include credentials") {
		t.Fatalf("stderr = %q, want credential rejection", stderr.String())
	}
	if _, err := os.Stat(outputPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("config file should not exist after invalid init, stat err = %v", err)
	}
}

func TestRunDoctorReportsMissingFilesClearly(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "missing-config.json")
	identityPath := filepath.Join(tempDir, "missing-identity.json")
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: identityPath,
		ConfigPath:   configPath,
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"doctor"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run doctor returned success for missing files")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty JSON-only diagnostics", stderr.String())
	}

	report := decodeDoctorReport(t, stdout.Bytes())
	if report.OK {
		t.Fatalf("doctor report ok = true, want false: %+v", report)
	}
	if !containsString(report.Errors, "config file is missing") {
		t.Fatalf("errors = %v, want missing config", report.Errors)
	}
	if !containsString(report.Errors, "identity file is missing") {
		t.Fatalf("errors = %v, want missing identity", report.Errors)
	}
	if check := findDoctorCheck(t, report, "config_file_exists"); check.OK {
		t.Fatalf("config_file_exists check = %+v, want failure", check)
	}
	if check := findDoctorCheck(t, report, "identity_file_exists"); check.OK {
		t.Fatalf("identity_file_exists check = %+v, want failure", check)
	}
	if _, err := os.Stat(configPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("doctor should not create config file, stat err = %v", err)
	}
	if _, err := os.Stat(identityPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("doctor should not create identity file, stat err = %v", err)
	}
}

func TestRunDoctorParsesValidConfigAndIdentity(t *testing.T) {
	configPath := writeAgentConfigFile(t, agentconfig.Config{
		ServerURL: "http://localhost:8000",
		SiteID:    "site-local",
	})
	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-local",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: identityPath,
		ConfigPath:   configPath,
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"doctor"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run doctor code = %d, stderr = %q, stdout = %q", code, stderr.String(), stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	report := decodeDoctorReport(t, stdout.Bytes())
	if !report.OK {
		t.Fatalf("doctor report ok = false: %+v", report)
	}
	for _, name := range []string{
		"config_file_parses",
		"identity_file_parses",
		"config_has_server_url",
		"config_has_site_id",
		"identity_has_site_id",
		"identity_has_agent_id",
	} {
		if check := findDoctorCheck(t, report, name); !check.OK {
			t.Fatalf("%s check = %+v, want ok", name, check)
		}
	}
}

func TestRunDoctorReportsMalformedConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"server_url":`), 0o600); err != nil {
		t.Fatal(err)
	}
	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-local",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"doctor", "--config", configPath, "--identity-file", identityPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run doctor returned success for malformed config")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	report := decodeDoctorReport(t, stdout.Bytes())
	if check := findDoctorCheck(t, report, "config_file_parses"); check.OK {
		t.Fatalf("config_file_parses check = %+v, want failure", check)
	}
	if !containsString(report.Errors, "config file is malformed JSON") {
		t.Fatalf("errors = %v, want malformed config", report.Errors)
	}
}

func TestRunDoctorReportsMalformedIdentity(t *testing.T) {
	configPath := writeAgentConfigFile(t, agentconfig.Config{
		ServerURL: "http://localhost:8000",
		SiteID:    "site-local",
	})
	identityPath := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(identityPath, []byte(`{"agent_id":`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"doctor", "--config", configPath, "--identity-file", identityPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run doctor returned success for malformed identity")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	report := decodeDoctorReport(t, stdout.Bytes())
	if check := findDoctorCheck(t, report, "identity_file_parses"); check.OK {
		t.Fatalf("identity_file_parses check = %+v, want failure", check)
	}
	if !containsString(report.Errors, "identity file is malformed JSON") {
		t.Fatalf("errors = %v, want malformed identity", report.Errors)
	}
}

func TestRunDoctorExplicitPathsOverrideDefaults(t *testing.T) {
	explicitConfigPath := writeAgentConfigFile(t, agentconfig.Config{
		ServerURL: "http://localhost:8000",
		SiteID:    "site-explicit",
	})
	explicitIdentityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-explicit",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: filepath.Join(t.TempDir(), "missing-default-identity.json"),
		ConfigPath:   filepath.Join(t.TempDir(), "missing-default-config.json"),
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"doctor", "--config", explicitConfigPath, "--identity-file", explicitIdentityPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run doctor code = %d, stderr = %q, stdout = %q", code, stderr.String(), stdout.String())
	}

	report := decodeDoctorReport(t, stdout.Bytes())
	configPathCheck := findDoctorCheck(t, report, "config_path_resolved")
	if configPathCheck.Source != "explicit" || configPathCheck.Path != explicitConfigPath {
		t.Fatalf("config_path_resolved = %+v", configPathCheck)
	}
	identityPathCheck := findDoctorCheck(t, report, "identity_path_resolved")
	if identityPathCheck.Source != "explicit" || identityPathCheck.Path != explicitIdentityPath {
		t.Fatalf("identity_path_resolved = %+v", identityPathCheck)
	}
}

func TestRunDoctorOutputContainsNoTokenOrSecretTerms(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "oaw-doctor-output-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.json")
	if err := agentconfig.WriteFile(configPath, agentconfig.Config{
		ServerURL: "http://localhost:8000",
		SiteID:    "site-local",
	}); err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(tempDir, "identity.json")
	if err := agentidentity.WriteFile(identityPath, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-local",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"doctor", "--config", configPath, "--identity-file", identityPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run doctor code = %d, stderr = %q", code, stderr.String())
	}

	combined := strings.ToLower(stdout.String() + stderr.String())
	for _, forbidden := range []string{"token", "secret", "password", "credential"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("doctor output included forbidden term %q: %s", forbidden, combined)
		}
	}
}

func TestRunStatusReportsJSONOnly(t *testing.T) {
	tempDir := t.TempDir()
	configPath := writeAgentConfigFile(t, agentconfig.Config{
		ServerURL: "http://localhost:8000",
		SiteID:    "site-local",
	})
	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-local",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})
	logDir := filepath.Join(tempDir, "logs")
	if err := os.Mkdir(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(logDir, "status.json")
	if err := os.WriteFile(statusPath, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: identityPath,
		ConfigPath:   configPath,
		LogDir:       logDir,
		StatusPath:   statusPath,
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"status"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run status code = %d, stderr = %q, stdout = %q", code, stderr.String(), stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty JSON-only status", stderr.String())
	}

	report := decodeStatusReport(t, stdout.Bytes())
	if !report.OK {
		t.Fatalf("status report ok = false: %+v", report)
	}
	if !report.Exists.Config || !report.Exists.Identity || !report.Exists.LogDir || !report.Exists.LastStatus {
		t.Fatalf("status existence flags = %+v", report.Exists)
	}
}

func TestRunStatusExplicitPathsOverrideDefaults(t *testing.T) {
	explicitConfigPath := writeAgentConfigFile(t, agentconfig.Config{
		ServerURL: "http://localhost:8000",
		SiteID:    "site-explicit",
	})
	explicitIdentityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-explicit",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})
	tempDir := t.TempDir()
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: filepath.Join(tempDir, "missing-default-identity.json"),
		ConfigPath:   filepath.Join(tempDir, "missing-default-config.json"),
		LogDir:       filepath.Join(tempDir, "logs"),
		StatusPath:   filepath.Join(tempDir, "logs", "status.json"),
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"status", "--config", explicitConfigPath, "--identity-file", explicitIdentityPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run status code = %d, stderr = %q, stdout = %q", code, stderr.String(), stdout.String())
	}

	report := decodeStatusReport(t, stdout.Bytes())
	if report.Paths.ConfigSrc != "explicit" || report.Paths.Config != explicitConfigPath {
		t.Fatalf("config path = %+v", report.Paths)
	}
	if report.Paths.IdentitySrc != "explicit" || report.Paths.Identity != explicitIdentityPath {
		t.Fatalf("identity path = %+v", report.Paths)
	}
}

func TestRunStatusReportsMissingFilesClearly(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "missing-config.json")
	identityPath := filepath.Join(tempDir, "missing-identity.json")
	logDir := filepath.Join(tempDir, "logs")
	statusPath := filepath.Join(logDir, "status.json")
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: identityPath,
		ConfigPath:   configPath,
		LogDir:       logDir,
		StatusPath:   statusPath,
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"status"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run status returned success for missing setup files")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty JSON-only status", stderr.String())
	}

	report := decodeStatusReport(t, stdout.Bytes())
	if report.OK {
		t.Fatalf("status report ok = true, want false: %+v", report)
	}
	if !containsString(report.Errors, "config file is missing") {
		t.Fatalf("errors = %v, want missing config", report.Errors)
	}
	if !containsString(report.Errors, "identity file is missing") {
		t.Fatalf("errors = %v, want missing identity", report.Errors)
	}
	if report.Exists.Config || report.Exists.Identity || report.Exists.LogDir || report.Exists.LastStatus {
		t.Fatalf("status existence flags = %+v, want all false", report.Exists)
	}
}

func TestRunStatusDoesNotCreateFilesOrDirectories(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "missing-config.json")
	identityPath := filepath.Join(tempDir, "missing-identity.json")
	logDir := filepath.Join(tempDir, "logs")
	statusPath := filepath.Join(logDir, "status.json")
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: identityPath,
		ConfigPath:   configPath,
		LogDir:       logDir,
		StatusPath:   statusPath,
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	_ = run([]string{"status"}, &stdout, &stderr)

	for _, path := range []string{configPath, identityPath, logDir, statusPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("status should not create %s, stat err = %v", path, err)
		}
	}
}

func TestRunStatusOutputContainsNoTokenOrSecretTerms(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "oaw-status-output-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.json")
	if err := agentconfig.WriteFile(configPath, agentconfig.Config{
		ServerURL: "http://localhost:8000",
		SiteID:    "site-local",
	}); err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(tempDir, "identity.json")
	if err := agentidentity.WriteFile(identityPath, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-local",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	logDir := filepath.Join(tempDir, "logs")
	if err := os.Mkdir(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(logDir, "status.json")
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: identityPath,
		ConfigPath:   configPath,
		LogDir:       logDir,
		StatusPath:   statusPath,
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"status"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run status code = %d, stderr = %q", code, stderr.String())
	}

	combined := strings.ToLower(stdout.String() + stderr.String())
	for _, forbidden := range []string{"token", "secret", "password", "credential"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("status output included forbidden term %q: %s", forbidden, combined)
		}
	}
}

func TestRunCheckInPostsIdentityPayload(t *testing.T) {
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: writeIdentityFile(t, agentidentity.Identity{
			AgentID:   "33333333-3333-4333-8333-333333333333",
			SiteID:    "site-default",
			CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
			UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		}),
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	})
	defer restorePaths()

	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:      "22222222-2222-4222-8222-222222222222",
		DeploymentID: "11111111-1111-4111-8111-111111111111",
		SiteID:       "site-local",
		TenantID:     "tenant-example",
		CreatedAt:    time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})

	var gotMethod string
	var gotPath string
	var gotContentType string
	var gotPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer server.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"check-in", "--identity-file", identityPath, "--server-url", server.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run check-in code = %d, stderr = %q", code, stderr.String())
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/agents/check-in" {
		t.Fatalf("path = %q, want agent check-in path", gotPath)
	}
	if gotContentType != "application/json" {
		t.Fatalf("content-type = %q, want application/json", gotContentType)
	}
	if gotPayload["site_id"] != "site-local" {
		t.Fatalf("site_id = %v", gotPayload["site_id"])
	}
	if gotPayload["tenant_id"] != "tenant-example" {
		t.Fatalf("tenant_id = %v", gotPayload["tenant_id"])
	}
	if gotPayload["deployment_id"] != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("deployment_id = %v", gotPayload["deployment_id"])
	}
	if gotPayload["agent_id"] != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("agent_id = %v", gotPayload["agent_id"])
	}
	if _, ok := gotPayload["agent_version"].(string); !ok {
		t.Fatalf("agent_version = %T, want string", gotPayload["agent_version"])
	}
	if _, ok := gotPayload["platform"].(map[string]any); !ok {
		t.Fatalf("platform = %T, want object", gotPayload["platform"])
	}
	if _, ok := gotPayload["enrollment_token"]; ok {
		t.Fatalf("check-in sent enrollment_token: %+v", gotPayload)
	}
	if !strings.Contains(stdout.String(), "HTTP 202") {
		t.Fatalf("stdout = %q, want success status", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunCheckInUsesDefaultIdentityPath(t *testing.T) {
	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:      "22222222-2222-4222-8222-222222222222",
		DeploymentID: "11111111-1111-4111-8111-111111111111",
		SiteID:       "site-default",
		TenantID:     "tenant-example",
		CreatedAt:    time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: identityPath,
		ConfigPath:   filepath.Join(t.TempDir(), "config.json"),
	})
	defer restorePaths()

	var gotPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"check-in", "--server-url", server.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run check-in code = %d, stderr = %q", code, stderr.String())
	}
	if gotPayload["site_id"] != "site-default" {
		t.Fatalf("site_id = %v, want site-default", gotPayload["site_id"])
	}
	if gotPayload["agent_id"] != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("agent_id = %v", gotPayload["agent_id"])
	}
}

func TestRunCheckInUsesConfigServerURLWhenFlagOmitted(t *testing.T) {
	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-local",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})

	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	configPath := writeAgentConfigFile(t, agentconfig.Config{
		ServerURL: server.URL,
		SiteID:    "site-config",
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"check-in", "--identity-file", identityPath, "--config", configPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run check-in code = %d, stderr = %q", code, stderr.String())
	}
	if gotPath != "/api/v1/agents/check-in" {
		t.Fatalf("path = %q, want agent check-in path", gotPath)
	}
}

func TestRunCheckInRequiresServerURL(t *testing.T) {
	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-local",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: identityPath,
		ConfigPath:   filepath.Join(t.TempDir(), "missing-config.json"),
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"check-in", "--identity-file", identityPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run check-in without --server-url returned success")
	}
	if !strings.Contains(stderr.String(), "server-url is required") {
		t.Fatalf("stderr = %q, want missing server-url error", stderr.String())
	}
}

func TestRunCheckInMissingDefaultIdentityFailsClearly(t *testing.T) {
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: filepath.Join(t.TempDir(), "missing-identity.json"),
		ConfigPath:   filepath.Join(t.TempDir(), "config.json"),
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"check-in", "--server-url", "http://127.0.0.1:8080"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run check-in without identity file returned success")
	}
	if !strings.Contains(stderr.String(), "default identity file not found") {
		t.Fatalf("stderr = %q, want missing default identity error", stderr.String())
	}
}

func TestRunCheckInDoesNotSendEnrollmentToken(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "identity.json")
	secret := "identity-secret-token-value"
	body := []byte(`{
  "agent_id": "22222222-2222-4222-8222-222222222222",
  "site_id": "site-local",
  "created_at": "2026-06-17T12:00:00Z",
  "updated_at": "2026-06-17T12:00:00Z",
  "enrollment_token": "` + secret + `"
}`)
	if err := os.WriteFile(identityPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"check-in", "--identity-file", identityPath, "--server-url", server.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run check-in code = %d, stderr = %q", code, stderr.String())
	}

	combined := stdout.String() + stderr.String() + string(gotBody)
	if strings.Contains(combined, secret) || strings.Contains(string(gotBody), "enrollment_token") {
		t.Fatalf("check-in leaked token-like value or field: %q", combined)
	}
}

func TestRunCheckInHandlesNon2xxResponseCleanly(t *testing.T) {
	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-local",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})
	secret := "response-secret-token-value"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(secret))
	}))
	defer server.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"check-in", "--identity-file", identityPath, "--server-url", server.URL}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run check-in returned success for non-2xx response")
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, secret) {
		t.Fatalf("check-in output leaked token-like value: %q", combined)
	}
	if !strings.Contains(stderr.String(), "HTTP status 500") {
		t.Fatalf("stderr = %q, want safe HTTP status error", stderr.String())
	}
}

func TestRunCheckInHandlesTimeoutCleanly(t *testing.T) {
	restore := stubSubmitHTTPClient(t, 1*time.Millisecond)
	defer restore()

	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-local",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"check-in", "--identity-file", identityPath, "--server-url", server.URL}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run check-in returned success for timeout")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty on timeout", stdout.String())
	}
	if !strings.Contains(stderr.String(), "request failed") {
		t.Fatalf("stderr = %q, want safe request failure", stderr.String())
	}
}

func TestRunCheckInRejectsURLCredentials(t *testing.T) {
	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-local",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"check-in", "--identity-file", identityPath, "--server-url", "http://user:secret@127.0.0.1:8080"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run check-in returned success for URL credentials")
	}
	if strings.Contains(stdout.String()+stderr.String(), "secret") {
		t.Fatalf("check-in output leaked URL credential: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "must not include credentials") {
		t.Fatalf("stderr = %q, want URL credentials error", stderr.String())
	}
}

func TestRunOncePerformsCheckInCollectAndSubmit(t *testing.T) {
	restore := stubCollector(t)
	defer restore()

	outputDir := t.TempDir()
	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:      "22222222-2222-4222-8222-222222222222",
		DeploymentID: "11111111-1111-4111-8111-111111111111",
		SiteID:       "site-local",
		TenantID:     "tenant-example",
		CreatedAt:    time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})

	var checkInBody map[string]any
	var inventoryBody models.Inventory
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		switch r.URL.Path {
		case agentCheckInPath:
			if err := json.NewDecoder(r.Body).Decode(&checkInBody); err != nil {
				t.Errorf("decode check-in: %v", err)
			}
			w.WriteHeader(http.StatusAccepted)
		case localInventorySubmitPath:
			if err := json.NewDecoder(r.Body).Decode(&inventoryBody); err != nil {
				t.Errorf("decode inventory: %v", err)
			}
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	configPath := writeAgentConfigFile(t, agentconfig.Config{
		ServerURL: server.URL,
		SiteID:    "site-local",
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"run-once", "--config", configPath, "--identity-file", identityPath, "--output-dir", outputDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run-once code = %d, stderr = %q, stdout = %q", code, stderr.String(), stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty JSON-only output", stderr.String())
	}

	report := decodeRunOnceReport(t, stdout.Bytes())
	if !report.OK || !report.CheckIn.OK || !report.Collect.OK || !report.Submit.OK {
		t.Fatalf("run-once report = %+v, want all steps ok", report)
	}
	if report.CheckIn.HTTPStatus != http.StatusAccepted || report.Submit.HTTPStatus != http.StatusAccepted {
		t.Fatalf("http statuses = check-in %d submit %d", report.CheckIn.HTTPStatus, report.Submit.HTTPStatus)
	}
	if report.InventoryPath != filepath.Join(outputDir, runOnceInventoryFile) {
		t.Fatalf("inventory_path = %q", report.InventoryPath)
	}
	if _, err := os.Stat(report.InventoryPath); err != nil {
		t.Fatalf("inventory file missing: %v", err)
	}
	if len(paths) != 2 || paths[0] != agentCheckInPath || paths[1] != localInventorySubmitPath {
		t.Fatalf("paths = %v, want check-in then inventory submit", paths)
	}
	if checkInBody["site_id"] != "site-local" || checkInBody["agent_id"] != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("check-in body = %+v", checkInBody)
	}
	if inventoryBody.SiteID != "site-local" || inventoryBody.AgentID != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("inventory identity fields = %+v", inventoryBody)
	}
}

func TestRunOnceFailsClosedWhenPreflightFails(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "missing-config.json")
	identityPath := filepath.Join(tempDir, "missing-identity.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"run-once", "--config", configPath, "--identity-file", identityPath, "--output-dir", tempDir}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run-once returned success with missing config and identity")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty JSON-only failure", stderr.String())
	}

	report := decodeRunOnceReport(t, stdout.Bytes())
	if report.OK {
		t.Fatalf("run-once report ok = true: %+v", report)
	}
	if !containsString(report.Errors, "preflight checks failed") {
		t.Fatalf("errors = %v, want preflight failure", report.Errors)
	}
	if report.CheckIn.OK || report.Collect.OK || report.Submit.OK {
		t.Fatalf("steps should not run after preflight failure: %+v", report)
	}
}

func TestRunOnceFailsClosedWhenSubmitFailsWithoutLeakingBody(t *testing.T) {
	restore := stubCollector(t)
	defer restore()

	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-local",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})
	secret := "submit-response-secret-value"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case agentCheckInPath:
			w.WriteHeader(http.StatusAccepted)
		case localInventorySubmitPath:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(secret))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	configPath := writeAgentConfigFile(t, agentconfig.Config{
		ServerURL: server.URL,
		SiteID:    "site-local",
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"run-once", "--config", configPath, "--identity-file", identityPath, "--output-dir", t.TempDir()}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run-once returned success when submit failed")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty JSON-only failure", stderr.String())
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, secret) {
		t.Fatalf("run-once output leaked response body: %q", combined)
	}
	report := decodeRunOnceReport(t, stdout.Bytes())
	if report.OK || !report.CheckIn.OK || !report.Collect.OK || report.Submit.OK {
		t.Fatalf("run-once report = %+v, want submit failure after check-in and collect", report)
	}
	if report.Submit.HTTPStatus != http.StatusInternalServerError {
		t.Fatalf("submit status = %d, want 500", report.Submit.HTTPStatus)
	}
}

func TestRunPathsPrintsDefaultPathsOnly(t *testing.T) {
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: filepath.Join("C:\\ProgramData", "OpenAssetWatch", "agent", "identity.json"),
		ConfigPath:   filepath.Join("C:\\ProgramData", "OpenAssetWatch", "agent", "config.json"),
		LogDir:       filepath.Join("C:\\ProgramData", "OpenAssetWatch", "agent", "logs"),
		StatusPath:   filepath.Join("C:\\ProgramData", "OpenAssetWatch", "agent", "logs", "status.json"),
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"paths"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run paths code = %d, stderr = %q", code, stderr.String())
	}

	var paths agentpaths.AgentPaths
	if err := json.Unmarshal(stdout.Bytes(), &paths); err != nil {
		t.Fatalf("paths output is not JSON: %v\n%s", err, stdout.String())
	}
	if paths.IdentityPath == "" || paths.ConfigPath == "" {
		t.Fatalf("paths output missing defaults: %+v", paths)
	}
	if paths.LogDir == "" || paths.StatusPath == "" {
		t.Fatalf("paths output missing log/status defaults: %+v", paths)
	}

	combined := strings.ToLower(stdout.String() + stderr.String())
	for _, forbidden := range []string{"token", "secret", "password", "enrollment"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("paths output included forbidden term %q: %s", forbidden, stdout.String())
		}
	}
}

func TestRunServicePlanPrintsJSONOnly(t *testing.T) {
	tempDir := t.TempDir()
	paths := agentpaths.AgentPaths{
		IdentityPath: filepath.Join(tempDir, "identity.json"),
		ConfigPath:   filepath.Join(tempDir, "config.json"),
		LogDir:       filepath.Join(tempDir, "logs"),
		StatusPath:   filepath.Join(tempDir, "logs", "status.json"),
	}
	restorePaths := stubDefaultAgentPaths(t, paths)
	defer restorePaths()
	restoreOSRelease := stubOSReleaseReader(t, []byte("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n"), nil)
	defer restoreOSRelease()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"service", "plan"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run service plan code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty JSON-only output", stderr.String())
	}

	plan := decodeServicePlan(t, stdout.Bytes())
	if plan.OS == "" || plan.ServiceTarget == "" || plan.ServiceName == "" {
		t.Fatalf("service plan missing target details: %+v", plan)
	}
	if plan.ConfigPath != paths.ConfigPath || plan.IdentityPath != paths.IdentityPath || plan.LogDir != paths.LogDir || plan.StatusPath != paths.StatusPath {
		t.Fatalf("service plan paths = %+v, want %+v", plan, paths)
	}
}

func TestRunServicePlanDoesNotCreateFilesOrDirectories(t *testing.T) {
	tempDir := t.TempDir()
	paths := agentpaths.AgentPaths{
		IdentityPath: filepath.Join(tempDir, "identity.json"),
		ConfigPath:   filepath.Join(tempDir, "config.json"),
		LogDir:       filepath.Join(tempDir, "logs"),
		StatusPath:   filepath.Join(tempDir, "logs", "status.json"),
	}
	restorePaths := stubDefaultAgentPaths(t, paths)
	defer restorePaths()
	restoreOSRelease := stubOSReleaseReader(t, []byte("ID=ubuntu\nID_LIKE=debian\n"), nil)
	defer restoreOSRelease()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"service", "plan"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run service plan code = %d, stderr = %q", code, stderr.String())
	}

	for _, path := range []string{paths.ConfigPath, paths.IdentityPath, paths.LogDir, paths.StatusPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("service plan should not create %s, stat err = %v", path, err)
		}
	}
}

func TestRunServicePlanOutputContainsNoTokenOrSecretTerms(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "oaw-service-plan-output-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: filepath.Join(tempDir, "identity.json"),
		ConfigPath:   filepath.Join(tempDir, "config.json"),
		LogDir:       filepath.Join(tempDir, "logs"),
		StatusPath:   filepath.Join(tempDir, "logs", "status.json"),
	})
	defer restorePaths()
	restoreOSRelease := stubOSReleaseReader(t, []byte("ID=ubuntu\nID_LIKE=debian\n"), nil)
	defer restoreOSRelease()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"service", "plan"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run service plan code = %d, stderr = %q", code, stderr.String())
	}

	combined := strings.ToLower(stdout.String() + stderr.String())
	for _, forbidden := range []string{"token", "secret", "password", "credential"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("service plan output included forbidden term %q: %s", forbidden, combined)
		}
	}
}

func TestRunServiceTemplatePrintsJSONOnly(t *testing.T) {
	tempDir := t.TempDir()
	paths := agentpaths.AgentPaths{
		IdentityPath: filepath.Join(tempDir, "identity.json"),
		ConfigPath:   filepath.Join(tempDir, "config.json"),
		LogDir:       filepath.Join(tempDir, "logs"),
		StatusPath:   filepath.Join(tempDir, "logs", "status.json"),
	}
	restorePaths := stubDefaultAgentPaths(t, paths)
	defer restorePaths()
	restoreOSRelease := stubOSReleaseReader(t, []byte("ID=ubuntu\nID_LIKE=debian\n"), nil)
	defer restoreOSRelease()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"service", "template"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run service template code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty JSON-only output", stderr.String())
	}

	template := decodeServiceTemplate(t, stdout.Bytes())
	if template.ServiceTarget == "" || template.ServiceName == "" || template.TemplateType == "" || template.Template == "" {
		t.Fatalf("service template missing fields: %+v", template)
	}
	for _, want := range []string{paths.ConfigPath, paths.IdentityPath, paths.LogDir, paths.StatusPath} {
		if !strings.Contains(template.Template, want) {
			t.Fatalf("service template missing path %q:\n%s", want, template.Template)
		}
	}
}

func TestRunServiceTemplateDoesNotCreateFilesOrDirectories(t *testing.T) {
	tempDir := t.TempDir()
	paths := agentpaths.AgentPaths{
		IdentityPath: filepath.Join(tempDir, "identity.json"),
		ConfigPath:   filepath.Join(tempDir, "config.json"),
		LogDir:       filepath.Join(tempDir, "logs"),
		StatusPath:   filepath.Join(tempDir, "logs", "status.json"),
	}
	restorePaths := stubDefaultAgentPaths(t, paths)
	defer restorePaths()
	restoreOSRelease := stubOSReleaseReader(t, []byte("ID=ubuntu\nID_LIKE=debian\n"), nil)
	defer restoreOSRelease()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"service", "template"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run service template code = %d, stderr = %q", code, stderr.String())
	}

	for _, path := range []string{paths.ConfigPath, paths.IdentityPath, paths.LogDir, paths.StatusPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("service template should not create %s, stat err = %v", path, err)
		}
	}
}

func TestRunServiceTemplateOutputContainsNoTokenOrSecretTerms(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "oaw-service-template-output-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: filepath.Join(tempDir, "identity.json"),
		ConfigPath:   filepath.Join(tempDir, "config.json"),
		LogDir:       filepath.Join(tempDir, "logs"),
		StatusPath:   filepath.Join(tempDir, "logs", "status.json"),
	})
	defer restorePaths()
	restoreOSRelease := stubOSReleaseReader(t, []byte("ID=ubuntu\nID_LIKE=debian\n"), nil)
	defer restoreOSRelease()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"service", "template"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run service template code = %d, stderr = %q", code, stderr.String())
	}

	combined := strings.ToLower(stdout.String() + stderr.String())
	for _, forbidden := range []string{"token", "secret", "password", "credential"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("service template output included forbidden term %q: %s", forbidden, combined)
		}
	}
}

func TestRunInstallPlanPrintsJSONOnly(t *testing.T) {
	tempDir := t.TempDir()
	paths := agentpaths.AgentPaths{
		IdentityPath: filepath.Join(tempDir, "identity.json"),
		ConfigPath:   filepath.Join(tempDir, "config.json"),
		LogDir:       filepath.Join(tempDir, "logs"),
		StatusPath:   filepath.Join(tempDir, "logs", "status.json"),
	}
	restorePaths := stubDefaultAgentPaths(t, paths)
	defer restorePaths()
	restoreOSRelease := stubOSReleaseReader(t, []byte("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n"), nil)
	defer restoreOSRelease()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"install", "plan"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run install plan code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty JSON-only output", stderr.String())
	}

	plan := decodeInstallPlan(t, stdout.Bytes())
	if plan.OS == "" || plan.Arch == "" || plan.RecommendedPackageType == "" || plan.InstallModel == "" {
		t.Fatalf("install plan missing recommendation details: %+v", plan)
	}
	if plan.ConfigPath != paths.ConfigPath || plan.IdentityPath != paths.IdentityPath || plan.LogDir != paths.LogDir || plan.StatusPath != paths.StatusPath {
		t.Fatalf("install plan paths = %+v, want %+v", plan, paths)
	}
	if len(plan.PackageValidationExpectations) == 0 || len(plan.Warnings) == 0 {
		t.Fatalf("install plan missing validation expectations or warnings: %+v", plan)
	}
}

func TestRunInstallPlanDoesNotCreateFilesOrDirectories(t *testing.T) {
	tempDir := t.TempDir()
	paths := agentpaths.AgentPaths{
		IdentityPath: filepath.Join(tempDir, "identity.json"),
		ConfigPath:   filepath.Join(tempDir, "config.json"),
		LogDir:       filepath.Join(tempDir, "logs"),
		StatusPath:   filepath.Join(tempDir, "logs", "status.json"),
	}
	restorePaths := stubDefaultAgentPaths(t, paths)
	defer restorePaths()
	restoreOSRelease := stubOSReleaseReader(t, []byte("ID=ubuntu\nID_LIKE=debian\n"), nil)
	defer restoreOSRelease()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"install", "plan"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run install plan code = %d, stderr = %q", code, stderr.String())
	}

	for _, path := range []string{paths.ConfigPath, paths.IdentityPath, paths.LogDir, paths.StatusPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("install plan should not create %s, stat err = %v", path, err)
		}
	}
}

func TestRunInstallPlanOutputContainsNoTokenOrSecretTerms(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "oaw-install-plan-output-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: filepath.Join(tempDir, "identity.json"),
		ConfigPath:   filepath.Join(tempDir, "config.json"),
		LogDir:       filepath.Join(tempDir, "logs"),
		StatusPath:   filepath.Join(tempDir, "logs", "status.json"),
	})
	defer restorePaths()
	restoreOSRelease := stubOSReleaseReader(t, []byte("ID=ubuntu\nID_LIKE=debian\n"), nil)
	defer restoreOSRelease()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"install", "plan"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run install plan code = %d, stderr = %q", code, stderr.String())
	}

	combined := strings.ToLower(stdout.String() + stderr.String())
	for _, forbidden := range []string{"token", "secret", "password", "credential"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("install plan output included forbidden term %q: %s", forbidden, combined)
		}
	}
}

func TestRunSubmitPostsCollectionJSON(t *testing.T) {
	body := []byte(`{"schema_version":"oaw.inventory.v1","site_id":"site-test","assets":[]}`)
	filePath := writeTempJSON(t, body)

	var gotMethod string
	var gotPath string
	var gotContentType string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer server.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"submit", "--file", filePath, "--server-url", server.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run submit code = %d, stderr = %q", code, stderr.String())
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/collections/local-inventory" {
		t.Fatalf("path = %q, want local inventory ingestion path", gotPath)
	}
	if gotContentType != "application/json" {
		t.Fatalf("content-type = %q, want application/json", gotContentType)
	}
	if string(gotBody) != string(body) {
		t.Fatalf("body changed\ngot:  %s\nwant: %s", string(gotBody), string(body))
	}
	if !strings.Contains(stdout.String(), "HTTP 202") {
		t.Fatalf("stdout = %q, want success status", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunSubmitUsesConfigServerURLWhenFlagOmitted(t *testing.T) {
	body := []byte(`{"schema_version":"oaw.inventory.v1","site_id":"site-test","assets":[]}`)
	filePath := writeTempJSON(t, body)

	var gotPath string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	configPath := writeAgentConfigFile(t, agentconfig.Config{
		ServerURL: server.URL,
		SiteID:    "site-config",
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"submit", "--file", filePath, "--config", configPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run submit code = %d, stderr = %q", code, stderr.String())
	}
	if gotPath != "/api/v1/collections/local-inventory" {
		t.Fatalf("path = %q, want local inventory ingestion path", gotPath)
	}
	if string(gotBody) != string(body) {
		t.Fatalf("body changed\ngot:  %s\nwant: %s", string(gotBody), string(body))
	}
}

func TestRunSubmitExplicitServerURLOverridesConfig(t *testing.T) {
	body := []byte(`{"schema_version":"oaw.inventory.v1","site_id":"site-test","assets":[]}`)
	filePath := writeTempJSON(t, body)

	var configServerHit bool
	configServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		configServerHit = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer configServer.Close()

	var cliServerHit bool
	cliServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cliServerHit = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer cliServer.Close()

	configPath := writeAgentConfigFile(t, agentconfig.Config{
		ServerURL: configServer.URL,
		SiteID:    "site-config",
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"submit", "--file", filePath, "--config", configPath, "--server-url", cliServer.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run submit code = %d, stderr = %q", code, stderr.String())
	}
	if !cliServerHit {
		t.Fatal("CLI server URL was not used")
	}
	if configServerHit {
		t.Fatal("config server URL was used despite explicit --server-url")
	}
}

func TestRunSubmitAppendsEndpointToServerBasePath(t *testing.T) {
	body := []byte(`{"schema_version":"oaw.inventory.v1","site_id":"site-test","assets":[]}`)
	filePath := writeTempJSON(t, body)

	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"submit", "--file", filePath, "--server-url", server.URL + "/oaw"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run submit code = %d, stderr = %q", code, stderr.String())
	}
	if gotPath != "/oaw/api/v1/collections/local-inventory" {
		t.Fatalf("path = %q, want endpoint appended to base path", gotPath)
	}
}

func TestRunSubmitHandlesNon2xxResponseCleanly(t *testing.T) {
	secret := "sensitive-token-value"
	filePath := writeTempJSON(t, []byte(`{"schema_version":"oaw.inventory.v1","site_id":"site-test","enrollment_token":"`+secret+`","assets":[]}`))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(secret))
	}))
	defer server.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"submit", "--file", filePath, "--server-url", server.URL}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run submit returned success for non-2xx response")
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, secret) {
		t.Fatalf("submit output leaked token-like value: %q", combined)
	}
	if !strings.Contains(stderr.String(), "HTTP status 500") {
		t.Fatalf("stderr = %q, want safe HTTP status error", stderr.String())
	}
}

func TestRunSubmitHandlesTimeoutCleanly(t *testing.T) {
	restore := stubSubmitHTTPClient(t, 1*time.Millisecond)
	defer restore()

	filePath := writeTempJSON(t, []byte(`{"schema_version":"oaw.inventory.v1","site_id":"site-test","assets":[]}`))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"submit", "--file", filePath, "--server-url", server.URL}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run submit returned success for timeout")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty on timeout", stdout.String())
	}
	if !strings.Contains(stderr.String(), "request failed") {
		t.Fatalf("stderr = %q, want safe request failure", stderr.String())
	}
}

func TestRunSubmitRejectsMissingServerURL(t *testing.T) {
	filePath := writeTempJSON(t, []byte(`{"schema_version":"oaw.inventory.v1","site_id":"site-test","assets":[]}`))
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: filepath.Join(t.TempDir(), "identity.json"),
		ConfigPath:   filepath.Join(t.TempDir(), "missing-config.json"),
	})
	defer restorePaths()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"submit", "--file", filePath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run submit without --server-url returned success")
	}
	if !strings.Contains(stderr.String(), "server-url is required") {
		t.Fatalf("stderr = %q, want missing server-url error", stderr.String())
	}
}

func TestRunSubmitRejectsInvalidJSONFile(t *testing.T) {
	filePath := writeTempJSON(t, []byte(`{"schema_version":`))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"submit", "--file", filePath, "--server-url", "http://127.0.0.1:8080"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run submit returned success for invalid JSON")
	}
	if !strings.Contains(stderr.String(), "valid JSON") {
		t.Fatalf("stderr = %q, want JSON validation error", stderr.String())
	}
}

func stubCollector(t *testing.T) func() {
	t.Helper()
	previous := collectLocalInventory
	collectedAt := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	collectLocalInventory = func(siteID string) models.Inventory {
		return models.Inventory{
			SchemaVersion: schema.InventorySchemaVersion,
			SiteID:        siteID,
			CollectedAt:   collectedAt,
			Assets: []models.Asset{
				{
					AssetID:      "local-host",
					SiteID:       siteID,
					Hostname:     "fixture-host",
					OS:           "windows",
					Platform:     "windows/amd64",
					Architecture: "amd64",
					Host: &models.HostObservation{
						Hostname:    "fixture-host",
						Source:      "fixture",
						CollectedAt: collectedAt,
					},
					PlatformInfo: &models.PlatformObservation{
						OS:                 "windows",
						Platform:           "windows/amd64",
						Architecture:       "amd64",
						ArchitectureFamily: "x86_64",
						Source:             "fixture",
						CollectedAt:        collectedAt,
					},
					PrimaryInterfaces: []models.NetworkInterface{
						{
							Name:        "Ethernet",
							MACAddress:  "00:11:22:33:44:55",
							Flags:       []string{"up", "broadcast"},
							IPAddresses: []models.IPAddressObservation{{Address: "192.0.2.10", Family: "ipv4", Interface: "Ethernet", Source: "fixture", CollectedAt: collectedAt}},
							Source:      "fixture",
							CollectedAt: collectedAt,
						},
					},
					IPAddresses:      []models.IPAddressObservation{{Address: "192.0.2.10", Family: "ipv4", Interface: "Ethernet", Source: "fixture", CollectedAt: collectedAt}},
					MACAddresses:     []models.MACAddressObservation{{Address: "00:11:22:33:44:55", Interface: "Ethernet", Source: "fixture", CollectedAt: collectedAt}},
					NetworkNeighbors: []models.NetworkNeighbor{{IPAddress: "192.0.2.1", MACAddress: "66:77:88:99:aa:bb", Interface: "Ethernet", Source: "fixture", Sources: []string{"fixture"}, CollectedAt: collectedAt}},
				},
			},
		}
	}
	return func() {
		collectLocalInventory = previous
	}
}

func stubSubmitHTTPClient(t *testing.T, timeout time.Duration) func() {
	t.Helper()
	previous := submitHTTPClient
	submitHTTPClient = func() *http.Client {
		return &http.Client{Timeout: timeout}
	}
	return func() {
		submitHTTPClient = previous
	}
}

func writeTempJSON(t *testing.T, body []byte) string {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), "collection.json")
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func writeIdentityFile(t *testing.T, identity agentidentity.Identity) string {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), "identity.json")
	if err := agentidentity.WriteFile(filePath, identity); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func writeAgentConfigFile(t *testing.T, cfg agentconfig.Config) string {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), "config.json")
	if err := agentconfig.WriteFile(filePath, cfg); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func decodeDoctorReport(t *testing.T, data []byte) doctorReport {
	t.Helper()
	var report doctorReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("doctor output is not JSON: %v\n%s", err, string(data))
	}
	return report
}

func decodeStatusReport(t *testing.T, data []byte) statusReport {
	t.Helper()
	var report statusReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("status output is not JSON: %v\n%s", err, string(data))
	}
	return report
}

func decodeRunOnceReport(t *testing.T, data []byte) runOnceReport {
	t.Helper()
	var report runOnceReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("run-once output is not JSON: %v\n%s", err, string(data))
	}
	return report
}

func decodeServicePlan(t *testing.T, data []byte) agentserviceplan.Plan {
	t.Helper()
	var plan agentserviceplan.Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatalf("service plan output is not JSON: %v\n%s", err, string(data))
	}
	return plan
}

func decodeInstallPlan(t *testing.T, data []byte) agentinstallplan.Plan {
	t.Helper()
	var plan agentinstallplan.Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatalf("install plan output is not JSON: %v\n%s", err, string(data))
	}
	return plan
}

func decodeServiceTemplate(t *testing.T, data []byte) agentserviceplan.Template {
	t.Helper()
	var template agentserviceplan.Template
	if err := json.Unmarshal(data, &template); err != nil {
		t.Fatalf("service template output is not JSON: %v\n%s", err, string(data))
	}
	return template
}

func findDoctorCheck(t *testing.T, report doctorReport, name string) doctorCheck {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("doctor report missing check %q: %+v", name, report.Checks)
	return doctorCheck{}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func stubDefaultAgentPaths(t *testing.T, paths agentpaths.AgentPaths) func() {
	t.Helper()
	previous := defaultAgentPaths
	defaultAgentPaths = func() agentpaths.AgentPaths {
		return paths
	}
	return func() {
		defaultAgentPaths = previous
	}
}

func stubOSReleaseReader(t *testing.T, data []byte, err error) func() {
	t.Helper()
	previous := readOSRelease
	readOSRelease = func(string) ([]byte, error) {
		return data, err
	}
	return func() {
		readOSRelease = previous
	}
}
