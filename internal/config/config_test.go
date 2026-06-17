package config

import "testing"

func TestValidateAcceptsAgentWithSiteID(t *testing.T) {
	cfg := Default(ModeAgent)
	cfg.SiteID = "site-1"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestValidateRejectsMissingScope(t *testing.T) {
	cfg := Default(ModeAgent)

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate returned nil error")
	}
}

func TestValidateRejectsUnknownMode(t *testing.T) {
	cfg := Default(Mode("unknown"))
	cfg.SiteID = "site-1"

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate returned nil error")
	}
}

func TestIsQuarantinedPath(t *testing.T) {
	paths := []string{
		"configs/quarantine/unsafe.json",
		"configs\\quarantine\\unsafe.json",
		"/opt/openassetwatch/configs/quarantine/unsafe.json",
	}

	for _, path := range paths {
		if !IsQuarantinedPath(path) {
			t.Fatalf("IsQuarantinedPath(%q) = false", path)
		}
	}
}

func TestIsQuarantinedPathAllowsActiveConfigs(t *testing.T) {
	if IsQuarantinedPath("configs/connectors/external_exposure_summary.json") {
		t.Fatal("active connector config was treated as quarantined")
	}
}
