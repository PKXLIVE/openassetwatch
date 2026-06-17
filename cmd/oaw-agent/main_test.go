package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentidentity "github.com/openassetwatch/openassetwatch/internal/agent/identity"
	agentpaths "github.com/openassetwatch/openassetwatch/internal/agent/paths"
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

func TestRunCheckInRequiresServerURL(t *testing.T) {
	identityPath := writeIdentityFile(t, agentidentity.Identity{
		AgentID:   "22222222-2222-4222-8222-222222222222",
		SiteID:    "site-local",
		CreatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"check-in", "--identity-file", identityPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run check-in without --server-url returned success")
	}
	if !strings.Contains(stderr.String(), "requires --server-url") {
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

func TestRunPathsPrintsDefaultPathsOnly(t *testing.T) {
	restorePaths := stubDefaultAgentPaths(t, agentpaths.AgentPaths{
		IdentityPath: filepath.Join("C:\\ProgramData", "OpenAssetWatch", "agent", "identity.json"),
		ConfigPath:   filepath.Join("C:\\ProgramData", "OpenAssetWatch", "agent", "config.json"),
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

	combined := strings.ToLower(stdout.String() + stderr.String())
	for _, forbidden := range []string{"token", "secret", "password", "enrollment"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("paths output included forbidden term %q: %s", forbidden, stdout.String())
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

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"submit", "--file", filePath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("run submit without --server-url returned success")
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
