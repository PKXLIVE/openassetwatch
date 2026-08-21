package credential

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testAgentCredential(character string) string {
	return "oaw_agent_v1." + strings.Repeat("a", 32) + "." + strings.Repeat(character, 43)
}

func testRecord(character string) Record {
	return Record{
		SchemaVersion: SchemaVersion,
		SiteID:        "site-test", AgentID: "agent_" + strings.Repeat("1", 32),
		DeploymentID: "deployment-test", AgentType: "endpoint-agent",
		CredentialID: "acred_" + strings.Repeat(character, 32),
		Credential:   testAgentCredential(character),
		IssuedAt:     time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
	}
}

func TestWriteLoadReplaceAndClearAgentCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "credential.json")
	if err := Write(path, testRecord("a"), false); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.Credential != testAgentCredential("a") {
		t.Fatalf("load = %+v, %v", loaded, err)
	}
	if err := Write(path, testRecord("b"), true); err != nil {
		t.Fatal(err)
	}
	loaded, err = Load(path)
	if err != nil || loaded.Credential != testAgentCredential("b") {
		t.Fatalf("replacement load = %+v, %v", loaded, err)
	}
	if err := Clear(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("credential still exists: %v", err)
	}
}

func TestInvalidReplacementPreservesExistingCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "credential.json")
	if err := Write(path, testRecord("a"), false); err != nil {
		t.Fatal(err)
	}
	invalid := testRecord("b")
	invalid.Credential = "oaw_sensor_v1." + strings.Repeat("b", 80)
	if err := Write(path, invalid, true); err == nil {
		t.Fatal("invalid replacement succeeded")
	}
	loaded, err := Load(path)
	if err != nil || loaded.Credential != testAgentCredential("a") {
		t.Fatalf("existing credential was not preserved: %+v, %v", loaded, err)
	}
}

func TestCredentialRejectsSymlinkAndHardLink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "credential.json")
	if err := os.Symlink(target, symlink); err == nil {
		if _, err := Load(symlink); err == nil {
			t.Fatal("symlink credential was accepted")
		}
	}
	hardTarget := filepath.Join(root, "hard-target.json")
	if err := Write(hardTarget, testRecord("a"), false); err != nil {
		t.Fatal(err)
	}
	hardLink := filepath.Join(root, "hard-link.json")
	if err := os.Link(hardTarget, hardLink); err == nil {
		if _, err := Load(hardLink); err == nil && runtime.GOOS != "windows" {
			t.Fatal("multiply linked credential was accepted")
		}
	}
}
