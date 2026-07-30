//go:build linux || darwin

package safefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRootControlledConfigAcceptsGroupReadableRootStyleMode(t *testing.T) {
	parent := privateConfigDir(t)
	configDir := filepath.Join(parent, "sensor")
	if err := os.Mkdir(configDir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configDir, "sensor.json")
	if err := os.WriteFile(path, []byte(`{"safe":true}`), 0o640); err != nil {
		t.Fatal(err)
	}
	file, err := OpenRootControlledConfig(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
}

func TestOpenRootControlledConfigRejectsUnsafeModesAndAncestor(t *testing.T) {
	t.Run("other-accessible directory", func(t *testing.T) {
		parent := privateConfigDir(t)
		configDir := filepath.Join(parent, "sensor")
		if err := os.Mkdir(configDir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(configDir, "sensor.json")
		if err := os.WriteFile(path, []byte(`{"safe":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenRootControlledConfig(path, 1024); err == nil {
			t.Fatal("OpenRootControlledConfig() accepted an other-accessible config directory")
		}
	})
	t.Run("other-readable file", func(t *testing.T) {
		configDir := privateConfigDir(t)
		path := filepath.Join(configDir, "sensor.json")
		if err := os.WriteFile(path, []byte(`{"safe":true}`), 0o604); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenRootControlledConfig(path, 1024); err == nil {
			t.Fatal("OpenRootControlledConfig() accepted an other-readable config")
		}
	})
	t.Run("writable ancestor", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "unsafe")
		if err := os.Mkdir(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		configDir := filepath.Join(parent, "sensor")
		if err := os.Mkdir(configDir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(configDir, "sensor.json")
		if err := os.WriteFile(path, []byte(`{"safe":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenRootControlledConfig(path, 1024); err == nil {
			t.Fatal("OpenRootControlledConfig() accepted a writable ancestor")
		}
	})
}
