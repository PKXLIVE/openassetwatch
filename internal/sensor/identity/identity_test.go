package identity

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func privateTempDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("secure test temporary directory: %v", err)
	}
	return path
}

func TestLoadOrCreatePersistsStableBoundedIdentity(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "identity.json")
	first, created, err := LoadOrCreate(path, "site-demo")
	if err != nil || !created {
		t.Fatalf("LoadOrCreate() = %+v, %t, %v", first, created, err)
	}
	second, created, err := LoadOrCreate(path, "site-demo")
	if err != nil || created {
		t.Fatalf("second LoadOrCreate() = %+v, %t, %v", second, created, err)
	}
	if first != second || !strings.HasPrefix(first.SensorID, "sensor-") || len(first.SensorID) > 160 {
		t.Fatalf("identity was not stable and bounded: %+v != %+v", first, second)
	}
	if _, _, err := LoadOrCreate(path, "other-site"); err == nil {
		t.Fatal("persisted identity was silently reused for another site")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("identity permissions = %o, want owner-only", info.Mode().Perm())
	}
}

func TestIdentityRejectsInvalidSitesAndTrailingJSON(t *testing.T) {
	if _, _, err := LoadOrCreate(filepath.Join(privateTempDir(t), "identity.json"), "bad/site"); err == nil {
		t.Fatal("LoadOrCreate() accepted invalid site ID")
	}

	parent := privateTempDir(t)
	path := filepath.Join(parent, "identity.json")
	contents := `{"schema_version":"oaw.sensor-identity.v1","site_id":"site-demo","sensor_id":"sensor-demo"}{}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(path, "site-demo"); err == nil {
		t.Fatal("LoadOrCreate() accepted trailing JSON")
	}
}

func TestIdentityRejectsSymlinksWhenPlatformSupportsIt(t *testing.T) {
	linkParent := privateTempDir(t)
	target := filepath.Join(linkParent, "target.json")
	link := filepath.Join(linkParent, "identity.json")
	if err := os.WriteFile(target, []byte(`{"schema_version":"oaw.sensor-identity.v1","site_id":"site-demo","sensor_id":"sensor-demo"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if _, _, err := LoadOrCreate(link, "site-demo"); err == nil {
		t.Fatal("LoadOrCreate() accepted a symlink")
	}
}
