package config

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func privateConfigDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateHubURLAppliesOutboundSecurityPolicy(t *testing.T) {
	for _, value := range []string{
		"http://localhost:8000",
		"http://127.0.0.1:8000",
		"http://[::1]:8000",
		"http://host.docker.internal:8000",
		"https://hub.example.test",
	} {
		if err := ValidateHubURL(value); err != nil {
			t.Errorf("ValidateHubURL(%q) unexpected error: %v", value, err)
		}
	}
	for _, value := range []string{
		"http://192.0.2.10:8000",
		"http://127.0.0.2:8000",
		"http://169.254.169.254/latest",
		"https://169.254.169.254",
		"https://100.100.100.200",
		"http://metadata.google.internal",
		"https://user:secret@hub.example.test",
		"https://hub.example.test/path",
		"https://hub.example.test?token=secret",
		"https://hub.example.test/#fragment",
		"file:///tmp/hub",
		"not-a-url",
	} {
		if err := ValidateHubURL(value); err == nil {
			t.Errorf("ValidateHubURL(%q) unexpectedly succeeded", value)
		}
	}
}

func TestConfigIdentifierParityAndAbsoluteLimits(t *testing.T) {
	cfg := Default()
	cfg.SiteID = "site.demo-1"
	cfg.SensorID = "sensor:demo-1"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	cfg.SiteID = "site:invalid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted a site identifier rejected by the hub")
	}
	cfg = Default()
	cfg.SiteID = "site"
	cfg.SensorID = "sensor/invalid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted a sensor identifier rejected by the hub")
	}
	cfg = Default()
	cfg.SiteID = "site"
	cfg.SpoolMaxItems = 10001
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted a spool item count above the scan-safe maximum")
	}
	cfg = Default()
	cfg.SiteID = "site"
	cfg.CaptureInterface = "../unsafe"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted an unsafe capture interface")
	}
	cfg = Default()
	cfg.SiteID = "site"
	cfg.IdentityPath = " identity.json"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted an ambiguous identity path")
	}
	cfg = Default()
	cfg.SiteID = "site"
	cfg.CredentialEnv = "ARBITRARY_SENSOR_SECRET"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted an arbitrary credential environment name")
	}
}

func TestForbiddenHubIPRejectsResolvedMetadataAndSpecialNetworks(t *testing.T) {
	for _, value := range []string{
		"0.0.0.0",
		"169.254.1.1",
		"169.254.169.254",
		"169.254.170.2",
		"100.100.100.200",
		"224.0.0.1",
		"fd00:ec2::254",
		"fe80::1",
	} {
		if !ForbiddenHubIP(net.ParseIP(value)) {
			t.Errorf("ForbiddenHubIP(%q) = false", value)
		}
	}
	for _, value := range []string{"127.0.0.1", "::1", "10.0.0.10", "192.0.2.10"} {
		if ForbiddenHubIP(net.ParseIP(value)) {
			t.Errorf("ForbiddenHubIP(%q) = true", value)
		}
	}
}

func TestLoadRejectsTrailingJSONUnknownFieldsAndNonRegularFiles(t *testing.T) {
	valid := `{"hub_url":"http://127.0.0.1:8000","site_id":"site-demo","sensor_name":"Demo","capture_mode":"synthetic","identity_path":"identity.json","spool_path":"spool","token_env":"OPENASSETWATCH_COLLECTOR_TOKEN","batch_size":10,"batch_interval_seconds":1,"request_timeout_seconds":5,"retry_initial_seconds":1,"retry_max_seconds":2,"spool_max_items":10,"spool_max_bytes":1048576,"aggregation_max_devices":10,"aggregation_ttl_seconds":60}`
	for name, contents := range map[string]string{
		"trailing JSON": valid + `{}`,
		"unknown field": strings.TrimSuffix(valid, "}") + `,"token":"secret"}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(privateConfigDir(t), "sensor.json")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load() unexpectedly succeeded")
			}
		})
	}

	directory := filepath.Join(privateConfigDir(t), "sensor.json")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(directory); err == nil {
		t.Fatal("Load() accepted a directory as configuration")
	}
}

func TestLoadRejectsSymlinkWhenPlatformSupportsIt(t *testing.T) {
	parent := privateConfigDir(t)
	target := filepath.Join(parent, "target.json")
	link := filepath.Join(parent, "sensor.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("Load() accepted a symlink")
	}
}
