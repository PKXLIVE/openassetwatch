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
