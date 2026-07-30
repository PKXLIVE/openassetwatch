// Package status persists a bounded, secret-free operational sensor snapshot.
package status

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/openassetwatch/openassetwatch/internal/sensor/health"
	"github.com/openassetwatch/openassetwatch/internal/sensor/safefile"
)

const MaxBytes = 64 << 10

func Write(path string, snapshot health.Snapshot) error {
	root, name, err := open(path, true)
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := json.Marshal(snapshot)
	if err != nil {
		return errors.New("marshal sensor status")
	}
	if len(data) > MaxBytes-1 {
		return errors.New("sensor status exceeds size limit")
	}
	data = append(data, '\n')
	suffix, err := randomSuffix()
	if err != nil {
		return err
	}
	tempName := ".status-" + suffix + ".tmp"
	file, err := root.OpenFile(tempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create sensor status temporary file: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = root.Remove(tempName)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return errors.New("write sensor status")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || safefile.LinkCount(info) > 1 {
		_ = file.Close()
		return errors.New("sensor status temporary file failed validation")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("sync sensor status")
	}
	if err := file.Close(); err != nil {
		return errors.New("close sensor status")
	}
	if existing, statErr := root.Lstat(name); statErr == nil {
		if existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() || safefile.LinkCount(existing) > 1 {
			return errors.New("existing sensor status file is unsafe")
		}
		if err := safefile.ValidateOwnerAndMode(existing, false); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if err := root.Rename(tempName, name); err != nil {
		return fmt.Errorf("publish sensor status atomically: %w", err)
	}
	cleanup = false
	return syncDirectory(root)
}

func Load(path string) (health.Snapshot, error) {
	root, name, err := open(path, false)
	if err != nil {
		return health.Snapshot{}, err
	}
	defer root.Close()
	before, err := root.Lstat(name)
	if err != nil {
		return health.Snapshot{}, err
	}
	if before.Size() < 1 || before.Size() > MaxBytes {
		return health.Snapshot{}, errors.New("sensor status has invalid size")
	}
	file, err := root.Open(name)
	if err != nil {
		return health.Snapshot{}, errors.New("open sensor status")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return health.Snapshot{}, errors.New("inspect sensor status")
	}
	if err := safefile.ValidateOpenedFile(before, after); err != nil {
		return health.Snapshot{}, err
	}
	decoder := json.NewDecoder(io.LimitReader(file, MaxBytes))
	decoder.DisallowUnknownFields()
	var snapshot health.Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return health.Snapshot{}, errors.New("decode sensor status")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return health.Snapshot{}, errors.New("sensor status contains trailing data")
	}
	return snapshot, nil
}

func open(path string, create bool) (*os.Root, string, error) {
	cleaned := filepath.Clean(path)
	if strings.TrimSpace(path) == "" || filepath.Dir(cleaned) == cleaned {
		return nil, "", errors.New("sensor status path must name a file below a private directory")
	}
	root, err := safefile.OpenPrivateRoot(filepath.Dir(cleaned), create)
	if err != nil {
		return nil, "", fmt.Errorf("open sensor status directory: %w", err)
	}
	name := filepath.Base(cleaned)
	if name == "" || name == "." || strings.ContainsAny(name, `/\`) {
		_ = root.Close()
		return nil, "", errors.New("sensor status path has an invalid file name")
	}
	return root, name, nil
}

func randomSuffix() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate sensor status temporary name")
	}
	return hex.EncodeToString(value), nil
}

func syncDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return syncDirectoryFile(directory)
}
