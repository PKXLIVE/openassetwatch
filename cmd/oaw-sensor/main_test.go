package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openassetwatch/openassetwatch/internal/sensor/credential"
)

func privateTempDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	// macOS exposes its temporary directory through /var, which is a system
	// symlink to /private/var. Canonicalize the test fixture root so tests of a
	// safe configuration do not trip the production symlink-ancestor guard.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve test temporary directory: %v", err)
	}
	path = resolved
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("secure test temporary directory: %v", err)
	}
	return path
}

func TestRunVersionAndProfile(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--version"}, &out, &errOut); code != 0 {
		t.Fatalf("version exit code = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "OpenAssetWatch") {
		t.Fatalf("version output = %q", out.String())
	}
	out.Reset()
	if code := run([]string{"profile", "--site-id", "site-demo", "--sensor-id", "sensor-demo"}, &out, &errOut); code != 0 {
		t.Fatalf("profile exit code = %d: %s", code, errOut.String())
	}
	var profile map[string]any
	if err := json.Unmarshal(out.Bytes(), &profile); err != nil {
		t.Fatalf("profile JSON: %v", err)
	}
	if profile["site_id"] != "site-demo" || profile["sensor_id"] != "sensor-demo" {
		t.Fatalf("profile = %#v", profile)
	}
}

func TestRunValidateConfig(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "sensor.json")
	contents := `{"hub_url":"http://127.0.0.1:8000","site_id":"site-demo","sensor_name":"Demo","capture_mode":"synthetic","identity_path":"` + filepath.ToSlash(filepath.Join(privateTempDir(t), "identity.json")) + `","spool_path":"` + filepath.ToSlash(filepath.Join(privateTempDir(t), "spool")) + `","token_env":"OPENASSETWATCH_COLLECTOR_TOKEN","batch_size":10,"batch_interval_seconds":1,"request_timeout_seconds":5,"retry_initial_seconds":1,"retry_max_seconds":2,"spool_max_items":10,"spool_max_bytes":1048576,"aggregation_max_devices":10,"aggregation_ttl_seconds":60}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"validate", "--config", path}, &out, &errOut); code != 0 {
		t.Fatalf("validate exit code = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"valid": true`) {
		t.Fatalf("validate output = %s", out.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"config", "validate", "--config", path}, &out, &errOut); code != 0 {
		t.Fatalf("config validate exit code = %d: %s", code, errOut.String())
	}
}

func TestOperationalCommandsAreBoundedAndDoNotCaptureImplicitly(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"interface", "list"}, &out, &errOut); code != 0 {
		t.Fatalf("interface list exit code = %d: %s", code, errOut.String())
	}
	for _, forbidden := range []string{"packet_bytes", "raw_packet", "payload", "authorization"} {
		if strings.Contains(strings.ToLower(out.String()), forbidden) {
			t.Fatalf("interface list output contains %q: %s", forbidden, out.String())
		}
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"interface", "validate"}, &out, &errOut); code != 2 {
		t.Fatalf("interface validate without explicit interface exit code = %d", code)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"capture-check", "--interface", "explicit-test-interface"}, &out, &errOut); code != 2 {
		t.Fatalf("capture-check without duration exit code = %d", code)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"capture-check", "--duration", "1s"}, &out, &errOut); code != 2 {
		t.Fatalf("capture-check without interface exit code = %d", code)
	}
	if code := run([]string{"service"}, &out, &errOut); code != 2 {
		t.Fatalf("service without run exit code = %d", code)
	}
}

func TestMissingLiveInterfaceProducesPersistentBoundedHealth(t *testing.T) {
	stateDir := privateTempDir(t)
	configDir := privateTempDir(t)
	configPath := filepath.Join(configDir, "sensor.json")
	statusPath := filepath.Join(stateDir, "status.json")
	configBody := fmt.Sprintf(
		`{"hub_url":"http://127.0.0.1:8000","site_id":"site-test","sensor_id":"sensor-test","sensor_name":"Sensor Test","capture_mode":"live","capture_interface":"oaw-interface-does-not-exist","identity_path":%q,"credential_path":%q,"spool_path":%q,"status_path":%q,"credential_env":"OPENASSETWATCH_SENSOR_CREDENTIAL","token_env":"OPENASSETWATCH_COLLECTOR_TOKEN","batch_size":10,"batch_interval_seconds":1,"request_timeout_seconds":5,"retry_initial_seconds":1,"retry_max_seconds":2,"spool_max_items":10,"spool_max_bytes":1048576,"aggregation_max_devices":10,"aggregation_ttl_seconds":60}`,
		filepath.Join(stateDir, "identity.json"),
		filepath.Join(stateDir, "credential.json"),
		filepath.Join(stateDir, "spool"),
		statusPath,
	)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"service", "run", "--config", configPath}, &out, &errOut); code != 1 {
		t.Fatalf("service run exit code = %d: stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
	if strings.Contains(strings.ToLower(errOut.String()), "credential") {
		t.Fatalf("missing interface was misreported as a credential error: %s", errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"health", "--config", configPath}, &out, &errOut); code != 0 {
		t.Fatalf("health exit code = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"running": false`) ||
		!strings.Contains(out.String(), `"capture_interface": "oaw-interface-does-not-exist"`) ||
		!strings.Contains(out.String(), `"last_capture_error"`) {
		t.Fatalf("degraded health output = %s", out.String())
	}
	for _, forbidden := range []string{"packet_bytes", "raw_packet", "authorization", "sensor_credential"} {
		if strings.Contains(strings.ToLower(out.String()+errOut.String()), forbidden) {
			t.Fatalf("health output contains forbidden value %q", forbidden)
		}
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"spool", "status", "--config", configPath}, &out, &errOut); code != 0 {
		t.Fatalf("spool status exit code = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"items": 0`) {
		t.Fatalf("spool status output = %s", out.String())
	}
}

func TestRunStatusIsNonRunningAndDoesNotExposeToken(t *testing.T) {
	t.Setenv("OPENASSETWATCH_COLLECTOR_TOKEN", "status-secret-value")
	var out, errOut bytes.Buffer
	if code := run([]string{"status"}, &out, &errOut); code != 0 {
		t.Fatalf("status exit code = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"status": "not-running"`) || !strings.Contains(out.String(), `"authentication_mode": "development-shared"`) {
		t.Fatalf("status output = %s", out.String())
	}
	if strings.Contains(out.String(), "status-secret-value") {
		t.Fatalf("status disclosed token value: %s", out.String())
	}
}

func TestRunStatusUsesCredentialEnvironmentWithoutDisclosingIt(t *testing.T) {
	value := "oaw_sensor_v1." + strings.Repeat("a", 32) + "." + strings.Repeat("B", 43)
	t.Setenv(credential.EnvironmentName, value)
	t.Setenv("OPENASSETWATCH_COLLECTOR_TOKEN", "")
	var out, errOut bytes.Buffer
	if code := run([]string{"status"}, &out, &errOut); code != 0 {
		t.Fatalf("status exit code = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"authentication_mode": "bound-environment"`) {
		t.Fatalf("status output = %s", out.String())
	}
	if strings.Contains(out.String(), value) || strings.Contains(errOut.String(), value) {
		t.Fatal("status disclosed the credential environment value")
	}
}

func TestRunEnrollStoresCredentialWithoutPrintingSecrets(t *testing.T) {
	enrollmentToken := "oaw_enroll_v1." + strings.Repeat("a", 32) + "." + strings.Repeat("B", 43)
	sensorCredential := "oaw_sensor_v1." + strings.Repeat("c", 32) + "." + strings.Repeat("D", 43)
	replacementCredential := "oaw_sensor_v1." + strings.Repeat("e", 32) + "." + strings.Repeat("F", 43)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/sensors/enroll" || request.Method != http.MethodPost {
			http.Error(writer, "not found", http.StatusNotFound)
			return
		}
		var body struct {
			EnrollmentToken string `json:"enrollment_token"`
			SensorID        string `json:"sensor_id"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil ||
			body.EnrollmentToken != enrollmentToken || body.SensorID != "sensor-test" {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(
			writer,
			`{"status":"enrolled","site_id":"site-test","sensor_id":"sensor-test","sensor_type":"passive-network-sensor","credential_id":"scred_%s","sensor_credential":%q,"issued_at":"2026-07-29T12:00:00Z"}`,
			strings.Repeat("1", 32), sensorCredential,
		)
	}))
	defer server.Close()

	stateDir := privateTempDir(t)
	configPath := filepath.Join(privateTempDir(t), "sensor.json")
	credentialPath := filepath.Join(stateDir, "credential.json")
	configBody := fmt.Sprintf(
		`{"hub_url":%q,"site_id":"site-test","sensor_id":"sensor-test","sensor_name":"Sensor Test","capture_mode":"synthetic","identity_path":%q,"credential_path":%q,"spool_path":%q,"credential_env":"OPENASSETWATCH_SENSOR_CREDENTIAL","token_env":"OPENASSETWATCH_COLLECTOR_TOKEN","batch_size":10,"batch_interval_seconds":1,"request_timeout_seconds":5,"retry_initial_seconds":1,"retry_max_seconds":2,"spool_max_items":10,"spool_max_bytes":1048576,"aggregation_max_devices":10,"aggregation_ttl_seconds":60}`,
		server.URL,
		filepath.Join(stateDir, "identity.json"),
		credentialPath,
		filepath.Join(stateDir, "spool"),
	)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(credential.EnrollmentTokenEnv, enrollmentToken)
	var out, errOut bytes.Buffer
	if code := run([]string{"enroll", "--config", configPath}, &out, &errOut); code != 0 {
		t.Fatalf("enroll exit code = %d: stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String(), enrollmentToken) || strings.Contains(out.String(), sensorCredential) ||
		strings.Contains(errOut.String(), enrollmentToken) || strings.Contains(errOut.String(), sensorCredential) {
		t.Fatal("enrollment command disclosed secret material")
	}
	stored, err := credential.Load(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Credential != sensorCredential || stored.SensorID != "sensor-test" {
		t.Fatal("enrollment command did not store the bound credential")
	}

	t.Setenv(credential.EnvironmentName, replacementCredential)
	out.Reset()
	errOut.Reset()
	if code := run([]string{"replace-credential", "--config", configPath}, &out, &errOut); code != 0 {
		t.Fatalf("replace exit code = %d: stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String(), replacementCredential) || strings.Contains(errOut.String(), replacementCredential) {
		t.Fatal("credential replacement disclosed the new secret")
	}
	t.Setenv(credential.EnvironmentName, "")
	stored, err = credential.Load(credentialPath)
	if err != nil || stored.Credential != replacementCredential {
		t.Fatalf("replacement credential was not stored: record=%#v err=%v", stored, err)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"clear-credential", "--config", configPath, "--confirm-clear"}, &out, &errOut); code != 0 {
		t.Fatalf("clear exit code = %d: stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
	if _, err := credential.Load(credentialPath); !os.IsNotExist(err) {
		t.Fatalf("credential still exists after clear: %v", err)
	}
}

func TestRunRejectsHubIncompatibleIdentifiersAndInvalidTokenEnvironment(t *testing.T) {
	for name, args := range map[string][]string{
		"profile site":      {"profile", "--site-id", "bad/site"},
		"profile sensor":    {"profile", "--sensor-id", "bad sensor"},
		"demo sensor":       {"demo", "--sensor-id", "bad/sensor"},
		"token environment": {"demo", "--token-env", "BAD=VALUE"},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(args, &out, &errOut); code != 2 {
				t.Fatalf("run(%v) exit code = %d, stderr=%s", args, code, errOut.String())
			}
		})
	}
}

func TestRunDemoUsesSyntheticSourceAndHub(t *testing.T) {
	var batchID string
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/observations/batches" || request.Method != http.MethodPost {
			http.Error(writer, "not found", http.StatusNotFound)
			return
		}
		var body struct {
			ObservationBatchID string `json:"observation_batch_id"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.ObservationBatchID == "" {
			http.Error(writer, "invalid body", http.StatusBadRequest)
			return
		}
		requests++
		if batchID == "" {
			batchID = body.ObservationBatchID
		} else if batchID != body.ObservationBatchID {
			t.Errorf("replay batch ID changed: %q != %q", body.ObservationBatchID, batchID)
		}
		status := "accepted"
		message := "normalized outbound observation batch accepted"
		if requests > 1 {
			status = "duplicate"
			message = "observation batch was already stored; no duplicate asset evidence was added"
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(
			writer,
			`{"status":%q,"observation_batch_id":%q,"storage_id":1,"site_id":"site-demo","sensor_id":"sensor-demo","received_at":"2026-07-21T12:00:01Z","observed_asset_count":1,"normalized_asset_count":1,"message":%q}`,
			status, body.ObservationBatchID, message,
		)
	}))
	defer server.Close()

	for attempt := 0; attempt < 2; attempt++ {
		var out, errOut bytes.Buffer
		if code := run([]string{"demo", "--hub-url", server.URL, "--site-id", "site-demo", "--sensor-id", "sensor-demo", "--spool-dir", privateTempDir(t), "--timeout", "5s"}, &out, &errOut); code != 0 {
			t.Fatalf("demo attempt %d exit code = %d: stderr=%s stdout=%s", attempt+1, code, errOut.String(), out.String())
		}
		if !strings.Contains(out.String(), `"batches_sent": 1`) {
			t.Fatalf("demo health = %s", out.String())
		}
		if strings.Contains(out.String(), `"last_successful_upload": "2025-01-01T00:00:00Z"`) {
			t.Fatalf("demo used logical replay time for operational health: %s", out.String())
		}
		if strings.Contains(out.String(), "raw_packet") || strings.Contains(out.String(), "packet_bytes") || strings.Contains(out.String(), "Authorization") {
			t.Fatalf("demo output disclosed raw packet or authorization data: %s", out.String())
		}
	}
	if requests != 2 || batchID == "" {
		t.Fatalf("hub received %d requests with batch ID %q", requests, batchID)
	}
}
