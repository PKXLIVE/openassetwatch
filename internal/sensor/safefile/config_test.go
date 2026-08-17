package safefile

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestOpenRootControlledConfigRejectsSymlinkAndHardLink(t *testing.T) {
	root := privateConfigDir(t)
	target := filepath.Join(root, "sensor.json")
	if err := os.WriteFile(target, []byte(`{"safe":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := OpenRootControlledConfig(target, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()

	link := filepath.Join(root, "sensor-link.json")
	if err := os.Symlink(target, link); err == nil {
		if _, err := OpenRootControlledConfig(link, 1024); err == nil {
			t.Fatal("OpenRootControlledConfig() accepted a symlink")
		}
	}
	if runtime.GOOS != "windows" {
		hardLink := filepath.Join(root, "sensor-hardlink.json")
		if err := os.Link(target, hardLink); err == nil {
			if _, err := OpenRootControlledConfig(target, 1024); err == nil {
				t.Fatal("OpenRootControlledConfig() accepted a multiply-linked file")
			}
		}
	}
}
