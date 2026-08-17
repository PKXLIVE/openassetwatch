package safefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// OpenRootControlledConfig opens a bounded service configuration file without
// following the final path component. Unlike OpenPrivateRoot, it permits the
// root-owned, service-group-readable layout used by the Linux systemd unit.
// Private identity, credential, spool, and status files continue to use the
// stricter current-user-only helpers.
func OpenRootControlledConfig(path string, maxBytes int64) (*os.File, error) {
	cleaned := filepath.Clean(path)
	if path == "" || maxBytes < 1 || filepath.Base(cleaned) == "." || filepath.Dir(cleaned) == cleaned {
		return nil, errors.New("sensor config path must name a bounded file")
	}
	parent := filepath.Dir(cleaned)
	initialParent, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("inspect sensor config directory: %w", err)
	}
	if initialParent.Mode()&os.ModeSymlink != 0 || !initialParent.IsDir() {
		return nil, errors.New("sensor config directory must be a non-symlink directory")
	}
	if err := ValidateConfigDirectory(initialParent); err != nil {
		return nil, err
	}
	if err := validateConfigAncestors(filepath.Dir(parent)); err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, fmt.Errorf("open sensor config directory: %w", err)
	}
	defer root.Close()
	openedParent, err := root.Stat(".")
	if err != nil || !os.SameFile(initialParent, openedParent) {
		return nil, errors.New("sensor config directory changed while opening")
	}
	if err := ValidateConfigDirectory(openedParent); err != nil {
		return nil, err
	}

	name := filepath.Base(cleaned)
	before, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect sensor config: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("sensor config must be a regular non-symlink file")
	}
	if before.Size() < 1 || before.Size() > maxBytes {
		return nil, fmt.Errorf("sensor config must contain 1 to %d bytes", maxBytes)
	}
	if err := ValidateConfigFile(before); err != nil {
		return nil, err
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open sensor config: %w", err)
	}
	after, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat sensor config: %w", err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) || before.Size() != after.Size() {
		_ = file.Close()
		return nil, errors.New("sensor config changed while opening")
	}
	if err := ValidateConfigFile(after); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateConfigAncestors(path string) error {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect sensor config ancestor: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("sensor config ancestor must be a non-symlink directory")
		}
		if err := ValidateConfigAncestor(info); err != nil {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}
