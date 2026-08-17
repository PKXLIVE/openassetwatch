package identity

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/openassetwatch/openassetwatch/internal/sensor/safefile"
)

var (
	siteIdentifierPattern   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	sensorIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
)

type Identity struct {
	SchemaVersion string `json:"schema_version"`
	SiteID        string `json:"site_id"`
	SensorID      string `json:"sensor_id"`
}

func LoadOrCreate(path, siteID string) (Identity, bool, error) {
	siteID = strings.TrimSpace(siteID)
	if !siteIdentifierPattern.MatchString(siteID) || len(siteID) > 128 {
		return Identity{}, false, errors.New("site ID is invalid")
	}
	parent := filepath.Dir(path)
	root, err := safefile.OpenPrivateRoot(parent, true)
	if err != nil {
		return Identity{}, false, err
	}
	defer root.Close()
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return Identity{}, false, errors.New("identity path must name a file")
	}
	identity, err := read(root, name)
	if err == nil {
		if identity.SiteID != siteID {
			return Identity{}, false, errors.New("persisted sensor identity belongs to a different site")
		}
		return identity, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Identity{}, false, err
	}
	sensorID, err := randomSensorID()
	if err != nil {
		return Identity{}, false, err
	}
	identity = Identity{SchemaVersion: "oaw.sensor-identity.v1", SiteID: siteID, SensorID: sensorID}
	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return Identity{}, false, fmt.Errorf("marshal sensor identity: %w", err)
	}
	data = append(data, '\n')
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			loaded, readErr := read(root, name)
			if readErr != nil {
				return Identity{}, false, readErr
			}
			if loaded.SiteID != siteID {
				return Identity{}, false, errors.New("persisted sensor identity belongs to a different site")
			}
			return loaded, false, nil
		}
		return Identity{}, false, fmt.Errorf("create sensor identity: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = root.Remove(name)
		return Identity{}, false, fmt.Errorf("write sensor identity: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = root.Remove(name)
		return Identity{}, false, fmt.Errorf("sync sensor identity: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = root.Remove(name)
		return Identity{}, false, fmt.Errorf("close sensor identity: %w", err)
	}
	if err := syncRootDirectory(root); err != nil {
		return Identity{}, false, fmt.Errorf("sync sensor identity directory: %w", err)
	}
	return identity, true, nil
}

func read(root *os.Root, name string) (Identity, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return Identity{}, err
	}
	if before.Size() > 16<<10 {
		return Identity{}, errors.New("sensor identity exceeds 16 KiB")
	}
	file, err := root.Open(name)
	if err != nil {
		return Identity{}, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return Identity{}, err
	}
	if err := safefile.ValidateOpenedFile(before, after); err != nil {
		return Identity{}, err
	}
	decoder := json.NewDecoder(io.LimitReader(file, 16<<10))
	decoder.DisallowUnknownFields()
	var identity Identity
	if err := decoder.Decode(&identity); err != nil {
		return Identity{}, fmt.Errorf("decode sensor identity: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Identity{}, errors.New("decode sensor identity: trailing JSON data is not allowed")
	}
	if identity.SchemaVersion != "oaw.sensor-identity.v1" || !siteIdentifierPattern.MatchString(identity.SiteID) || !sensorIdentifierPattern.MatchString(identity.SensorID) || len(identity.SiteID) > 128 || len(identity.SensorID) > 160 {
		return Identity{}, errors.New("sensor identity is invalid")
	}
	return identity, nil
}

func randomSensorID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate sensor identity: %w", err)
	}
	return "sensor-" + hex.EncodeToString(bytes), nil
}
