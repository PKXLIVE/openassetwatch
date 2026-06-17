package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNewCreatesAgentID(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

	identity, err := New(CreateParams{SiteID: "site-local"}, now)
	if err != nil {
		t.Fatal(err)
	}

	if identity.AgentID == "" {
		t.Fatal("agent_id is empty")
	}
	if len(identity.AgentID) != 36 {
		t.Fatalf("agent_id length = %d, want UUID length", len(identity.AgentID))
	}
	if identity.SiteID != "site-local" {
		t.Fatalf("site_id = %q, want site-local", identity.SiteID)
	}
	if !identity.CreatedAt.Equal(now) || !identity.UpdatedAt.Equal(now) {
		t.Fatalf("timestamps = %s / %s, want %s", identity.CreatedAt, identity.UpdatedAt, now)
	}
}

func TestNewPreservesSuppliedDeploymentID(t *testing.T) {
	identity, err := New(CreateParams{
		SiteID:       "site-local",
		DeploymentID: "11111111-1111-4111-8111-111111111111",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if identity.DeploymentID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("deployment_id = %q", identity.DeploymentID)
	}
}

func TestNewDoesNotFabricateDeploymentID(t *testing.T) {
	identity, err := New(CreateParams{SiteID: "site-local"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if identity.DeploymentID != "" {
		t.Fatalf("deployment_id = %q, want empty when not supplied", identity.DeploymentID)
	}
}

func TestIdentityDoesNotStoreEnrollmentToken(t *testing.T) {
	identity, err := New(CreateParams{SiteID: "site-local"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "enrollment_token") {
		t.Fatalf("identity JSON included enrollment_token: %s", string(data))
	}
}

func TestReadExistingIdentityFile(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "identity.json")
	created, err := CreateFile(path, CreateParams{
		SiteID:       "site-local",
		DeploymentID: "11111111-1111-4111-8111-111111111111",
		TenantID:     "tenant-example",
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	read, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if read != created {
		t.Fatalf("read identity = %+v, want %+v", read, created)
	}
}

func TestNewRejectsInvalidSiteID(t *testing.T) {
	for _, siteID := range []string{"", "   "} {
		t.Run("site_id_"+siteID, func(t *testing.T) {
			_, err := New(CreateParams{SiteID: siteID}, time.Now())
			if err == nil {
				t.Fatal("New returned nil error for invalid site_id")
			}
		})
	}
}

func TestCreateFileUsesRestrictedPermissionsWhereSupported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACL semantics are not represented by os.FileMode permission bits")
	}

	path := filepath.Join(t.TempDir(), "identity.json")
	if _, err := CreateFile(path, CreateParams{SiteID: "site-local"}, time.Now()); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("identity file permissions = %v, want no group/other bits", info.Mode().Perm())
	}
}

func TestCreateFileRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if _, err := CreateFile(path, CreateParams{SiteID: "site-local"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateFile(path, CreateParams{SiteID: "site-local"}, time.Now()); err == nil {
		t.Fatal("CreateFile overwrote an existing identity file")
	}
}
