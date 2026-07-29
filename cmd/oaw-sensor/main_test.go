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
)

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
	path := filepath.Join(t.TempDir(), "sensor.json")
	contents := `{"hub_url":"http://127.0.0.1:8000","site_id":"site-demo","sensor_name":"Demo","capture_mode":"synthetic","identity_path":"` + filepath.ToSlash(filepath.Join(t.TempDir(), "identity.json")) + `","spool_path":"` + filepath.ToSlash(filepath.Join(t.TempDir(), "spool")) + `","token_env":"OPENASSETWATCH_COLLECTOR_TOKEN","batch_size":10,"batch_interval_seconds":1,"request_timeout_seconds":5,"retry_initial_seconds":1,"retry_max_seconds":2,"spool_max_items":10,"spool_max_bytes":1048576,"aggregation_max_devices":10,"aggregation_ttl_seconds":60}`
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
}

func TestRunStatusIsNonRunningAndDoesNotExposeToken(t *testing.T) {
	t.Setenv("OPENASSETWATCH_COLLECTOR_TOKEN", "status-secret-value")
	var out, errOut bytes.Buffer
	if code := run([]string{"status"}, &out, &errOut); code != 0 {
		t.Fatalf("status exit code = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"status": "not-running"`) || !strings.Contains(out.String(), `"collector_token_available": true`) {
		t.Fatalf("status output = %s", out.String())
	}
	if strings.Contains(out.String(), "status-secret-value") {
		t.Fatalf("status disclosed token value: %s", out.String())
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
		if code := run([]string{"demo", "--hub-url", server.URL, "--site-id", "site-demo", "--sensor-id", "sensor-demo", "--spool-dir", t.TempDir(), "--timeout", "5s"}, &out, &errOut); code != 0 {
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
