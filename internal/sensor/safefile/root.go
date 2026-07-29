package safefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func OpenPrivateRoot(path string, create bool) (*os.Root, error) {
	cleaned := filepath.Clean(path)
	if path == "" || filepath.Dir(cleaned) == cleaned {
		return nil, errors.New("private path must name a directory below a safe parent")
	}
	if create {
		if err := createPrivateDirectory(path); err != nil {
			return nil, fmt.Errorf("create private directory: %w", err)
		}
	}
	initial, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect private directory: %w", err)
	}
	if initial.Mode()&os.ModeSymlink != 0 || !initial.IsDir() {
		return nil, errors.New("private path must be a non-symlink directory")
	}
	if err := validateParentDirectory(filepath.Dir(filepath.Clean(path))); err != nil {
		return nil, err
	}
	if err := ValidateOwnerAndMode(initial, true); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open private directory: %w", err)
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(initial, opened) {
		_ = root.Close()
		return nil, errors.New("private directory changed while opening")
	}
	if err := ValidateOwnerAndMode(opened, true); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

func createPrivateDirectory(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	cursor := filepath.Clean(absolute)
	missing := make([]string, 0, 4)
	var existing os.FileInfo
	for {
		existing, err = os.Lstat(cursor)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return errors.New("private directory has no existing safe ancestor")
		}
		missing = append(missing, filepath.Base(cursor))
		cursor = parent
	}
	if existing.Mode()&os.ModeSymlink != 0 || !existing.IsDir() {
		return errors.New("private directory ancestor must be a non-symlink directory")
	}
	if err := ValidateParentOwnerAndMode(existing); err != nil {
		return err
	}
	root, err := os.OpenRoot(cursor)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(existing, opened) {
		return errors.New("private directory ancestor changed while opening")
	}
	for index := len(missing) - 1; index >= 0; index-- {
		name := missing[index]
		if err := root.Mkdir(name, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		before, err := root.Lstat(name)
		if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			return errors.New("created private path component is not a safe directory")
		}
		if err := ValidateOwnerAndMode(before, true); err != nil {
			return err
		}
		next, err := root.OpenRoot(name)
		if err != nil {
			return err
		}
		after, err := next.Stat(".")
		if err != nil || !os.SameFile(before, after) {
			_ = next.Close()
			return errors.New("private path component changed while opening")
		}
		if err := root.Close(); err != nil {
			_ = next.Close()
			return err
		}
		root = next
	}
	return nil
}

func ValidateOpenedFile(before, after os.FileInfo) error {
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return errors.New("queue entry must be a regular non-symlink file")
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return errors.New("sensor file changed while opening")
	}
	if before.Size() != after.Size() {
		return errors.New("sensor file size changed while opening")
	}
	if err := ValidateOwnerAndMode(after, false); err != nil {
		return err
	}
	if links := LinkCount(before); links > 1 || (links == 1 && LinkCount(after) != 1) {
		return errors.New("sensor file must have exactly one hard link")
	}
	return nil
}

// validateParentDirectory prevents an attacker who can write the parent from
// replacing the private root between creation and open. On POSIX, a sticky
// world-writable system temporary directory is accepted because it prevents
// deleting entries owned by another user; ordinary group/other-writable
// parents are rejected. Platform-specific ownership checks are intentionally
// kept in ownership_*.go.
func validateParentDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private parent directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("private parent path must be a non-symlink directory")
	}
	if err := ValidateParentOwnerAndMode(info); err != nil {
		return err
	}
	return nil
}
