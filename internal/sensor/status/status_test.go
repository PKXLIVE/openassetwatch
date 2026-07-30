package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/openassetwatch/openassetwatch/internal/sensor/health"
)

func privateTempDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("secure test temporary directory: %v", err)
	}
	return path
}

func TestWriteLoadAndReplaceBoundedStatus(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "status.json")
	snapshot := health.Snapshot{
		Running: true, SiteID: "site-demo", SensorID: "sensor-demo",
		CaptureMode: "live", CaptureInterface: "eth1", PacketsObserved: 10,
	}
	if err := Write(path, snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.Running = false
	snapshot.PacketsObserved = 11
	if err := Write(path, snapshot); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Running || loaded.PacketsObserved != 11 || loaded.CaptureInterface != "eth1" {
		t.Fatalf("loaded status = %+v", loaded)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("status mode = %o, want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"credential", "authorization", "raw_packet", "packet_bytes"} {
		if strings.Contains(strings.ToLower(string(data)), forbidden) {
			t.Fatalf("status contains forbidden field %q", forbidden)
		}
	}
}

func TestLoadRejectsSymlinkHardLinkAndTrailingData(t *testing.T) {
	root := privateTempDir(t)
	target := filepath.Join(root, "status.json")
	if err := Write(target, health.Snapshot{SiteID: "site-demo"}); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "status-link.json")
	if err := os.Symlink(target, link); err == nil {
		if _, err := Load(link); err == nil {
			t.Fatal("Load() accepted a symlink")
		}
	}
	if runtime.GOOS != "windows" {
		hardLink := filepath.Join(root, "status-hardlink.json")
		if err := os.Link(target, hardLink); err == nil {
			if _, err := Load(target); err == nil {
				t.Fatal("Load() accepted a multiply-linked status file")
			}
			if err := os.Remove(hardLink); err != nil {
				t.Fatal(err)
			}
		}
	}
	data, err := json.Marshal(health.Snapshot{SiteID: "site-demo"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, append(data, []byte(`{}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(target); err == nil {
		t.Fatal("Load() accepted trailing JSON")
	}
}
