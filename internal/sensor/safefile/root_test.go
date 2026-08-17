package safefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenPrivateRootCreatesNestedDirectoriesSafely(t *testing.T) {
	path := filepath.Join(t.TempDir(), "one", "two", "three")
	root, err := OpenPrivateRoot(path, true)
	if err != nil {
		t.Fatalf("OpenPrivateRoot() error = %v", err)
	}
	defer root.Close()
	info, err := root.Stat(".")
	if err != nil || !info.IsDir() {
		t.Fatalf("private root = %+v, %v", info, err)
	}
}

func TestOpenPrivateRootRejectsFilesystemRoot(t *testing.T) {
	absolute, err := filepath.Abs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	volumeRoot := filepath.VolumeName(absolute) + string(filepath.Separator)
	if _, err := OpenPrivateRoot(volumeRoot, false); err == nil {
		t.Fatalf("OpenPrivateRoot(%q) accepted a filesystem root", volumeRoot)
	}
}

func TestOpenPrivateRootRejectsIntermediateSymlinkWhenSupported(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if _, err := OpenPrivateRoot(filepath.Join(link, "child"), true); err == nil {
		t.Fatal("OpenPrivateRoot() accepted an intermediate symlink")
	}
}
