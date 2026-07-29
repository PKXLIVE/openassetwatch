package credential

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testCredential(character string) string {
	return "oaw_sensor_v1." + strings.Repeat(character, 32) + "." + strings.Repeat(strings.ToUpper(character), 43)
}

func testRecord(character string) Record {
	return Record{
		SchemaVersion: SchemaVersion,
		SiteID:        "site-test",
		SensorID:      "sensor-test",
		SensorType:    "passive-network-sensor",
		Credential:    testCredential(character),
		IssuedAt:      time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
	}
}

func TestWriteLoadReplaceAndClearCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.json")
	if err := EnsureAbsent(path); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, testRecord("a"), false); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Credential != testCredential("a") {
		t.Fatal("loaded credential did not match the stored value")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("credential mode = %o, want 600", info.Mode().Perm())
		}
	}
	if err := Write(path, testRecord("b"), true); err != nil {
		t.Fatal(err)
	}
	loaded, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Credential != testCredential("b") {
		t.Fatal("atomic replacement did not publish the new credential")
	}
	if err := Clear(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load after Clear error = %v, want not-exist", err)
	}
}

func TestCredentialRejectsSymlinkAndHardLink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "credential.json")
	if err := Write(target, testRecord("a"), false); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "credential-link.json")
	if err := os.Symlink(target, symlink); err == nil {
		if _, loadErr := Load(symlink); loadErr == nil {
			t.Fatal("symlinked credential unexpectedly loaded")
		}
	}
	hardlink := filepath.Join(root, "credential-hardlink.json")
	if err := os.Link(target, hardlink); err == nil {
		if _, loadErr := Load(target); loadErr == nil && runtime.GOOS != "windows" {
			t.Fatal("multiply linked credential unexpectedly loaded")
		}
	}
}

func TestProtectedTokenFileIsBoundedAndValidated(t *testing.T) {
	root := t.TempDir()
	tokenPath := filepath.Join(root, "enrollment-token")
	token := "oaw_enroll_v1." + strings.Repeat("a", 32) + "." + strings.Repeat("B", 43)
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := ReadSecretFile(tokenPath, true)
	if err != nil {
		t.Fatal(err)
	}
	if value != token {
		t.Fatal("protected token file returned the wrong value")
	}
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("x", MaxSecretBytes+2)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecretFile(tokenPath, true); err == nil {
		t.Fatal("oversized token file unexpectedly succeeded")
	}
}
