//go:build linux || darwin

package safefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenPrivateRootRejectsWritableNonStickyParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPrivateRoot(filepath.Join(parent, "spool"), true); err == nil {
		t.Fatal("OpenPrivateRoot() accepted a group/other-writable parent")
	}
}
