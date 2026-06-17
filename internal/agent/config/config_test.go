package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateFileWritesOnlyNonSecretFields(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "agent", "config.json")

	cfg, err := CreateFile(outputPath, CreateParams{
		ServerURL: "http://localhost:8000",
		SiteID:    "site-local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerURL != "http://localhost:8000" || cfg.SiteID != "site-local" {
		t.Fatalf("config = %+v", cfg)
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
		t.Fatalf("fields = %v, want only server_url and site_id", fields)
	}
	for _, field := range []string{"server_url", "site_id"} {
		if _, ok := fields[field]; !ok {
			t.Fatalf("missing field %q in %s", field, string(data))
		}
	}

	combined := strings.ToLower(string(data))
	for _, forbidden := range []string{"token", "secret", "password", "api_key", "credential"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("config output contains forbidden term %q: %s", forbidden, string(data))
		}
	}
}

func TestValidateServerURLRejectsUnsafeValues(t *testing.T) {
	tests := []string{
		"",
		"localhost:8000",
		"ftp://localhost:8000",
		"http://user:secret@localhost:8000",
		"http://localhost:8000?x=1",
		"http://localhost:8000#fragment",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if err := ValidateServerURL(input); err == nil {
				t.Fatalf("ValidateServerURL(%q) returned nil", input)
			}
		})
	}
}

func TestReadFileRejectsSecretLikeFields(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{
  "server_url": "http://localhost:8000",
  "site_id": "site-local",
  "enrollment_token": "do-not-store"
}`)
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ReadFile(configPath)
	if err == nil {
		t.Fatal("ReadFile returned nil for config with secret-like field")
	}
	if !strings.Contains(err.Error(), "must not contain secret field") {
		t.Fatalf("error = %q", err.Error())
	}
}
