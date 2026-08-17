package credential

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
	"time"

	"github.com/openassetwatch/openassetwatch/internal/sensor/safefile"
)

const (
	SchemaVersion      = "oaw.sensor-credential.v1"
	EnvironmentName    = "OPENASSETWATCH_SENSOR_CREDENTIAL"
	EnrollmentTokenEnv = "OPENASSETWATCH_SENSOR_ENROLLMENT_TOKEN"
	MaxSecretBytes     = 256
)

var (
	sensorCredentialPattern = regexp.MustCompile(`^oaw_sensor_v1\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$`)
	enrollmentTokenPattern  = regexp.MustCompile(`^oaw_enroll_v1\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$`)
	siteIdentifierPattern   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	sensorIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
)

type Record struct {
	SchemaVersion string    `json:"schema_version"`
	SiteID        string    `json:"site_id"`
	SensorID      string    `json:"sensor_id"`
	SensorType    string    `json:"sensor_type"`
	Credential    string    `json:"credential"`
	IssuedAt      time.Time `json:"issued_at"`
}

func (record Record) Validate() error {
	if record.SchemaVersion != SchemaVersion {
		return errors.New("sensor credential record schema is invalid")
	}
	if !siteIdentifierPattern.MatchString(record.SiteID) || len(record.SiteID) > 128 {
		return errors.New("sensor credential site binding is invalid")
	}
	if !sensorIdentifierPattern.MatchString(record.SensorID) || len(record.SensorID) > 160 {
		return errors.New("sensor credential identity binding is invalid")
	}
	if record.SensorType != "passive-network-sensor" {
		return errors.New("sensor credential type binding is invalid")
	}
	if !ValidSensorCredential(record.Credential) {
		return errors.New("sensor credential value is invalid")
	}
	if record.IssuedAt.IsZero() {
		return errors.New("sensor credential issuance time is required")
	}
	return nil
}

func ValidSensorCredential(value string) bool {
	return len(value) <= MaxSecretBytes && sensorCredentialPattern.MatchString(value)
}

func ValidEnrollmentToken(value string) bool {
	return len(value) <= MaxSecretBytes && enrollmentTokenPattern.MatchString(value)
}

func Load(path string) (Record, error) {
	root, name, err := openRootAndName(path, false)
	if err != nil {
		return Record{}, err
	}
	defer root.Close()
	return readRecord(root, name)
}

func EnsureAbsent(path string) error {
	root, name, err := openRootAndName(path, true)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Lstat(name); err == nil {
		return errors.New("sensor credential file already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect sensor credential file: %w", err)
	}
	return nil
}

func Write(path string, record Record, replace bool) error {
	if err := record.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return errors.New("marshal sensor credential record")
	}
	data = append(data, '\n')
	root, name, err := openRootAndName(path, true)
	if err != nil {
		return err
	}
	defer root.Close()

	if before, statErr := root.Lstat(name); statErr == nil {
		if !replace {
			return errors.New("sensor credential file already exists")
		}
		if _, readErr := readRecord(root, name); readErr != nil {
			return fmt.Errorf("validate existing sensor credential file: %w", readErr)
		}
		if before.Mode()&os.ModeSymlink != 0 {
			return errors.New("sensor credential file must not be a symlink")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect sensor credential file: %w", statErr)
	}

	suffix, err := randomSuffix()
	if err != nil {
		return err
	}
	tempName := ".credential-" + suffix + ".tmp"
	file, err := root.OpenFile(tempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create sensor credential temporary file: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = root.Remove(tempName)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return errors.New("write sensor credential file")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || safefile.LinkCount(info) > 1 {
		_ = file.Close()
		return errors.New("sensor credential temporary file failed regular-file validation")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("sync sensor credential file")
	}
	if err := file.Close(); err != nil {
		return errors.New("close sensor credential file")
	}
	if err := root.Rename(tempName, name); err != nil {
		return fmt.Errorf("publish sensor credential atomically: %w", err)
	}
	cleanup = false
	return syncRootDirectory(root)
}

func Clear(path string) error {
	root, name, err := openRootAndName(path, false)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := readRecord(root, name); err != nil {
		return err
	}
	if err := root.Remove(name); err != nil {
		return fmt.Errorf("remove sensor credential file: %w", err)
	}
	return syncRootDirectory(root)
}

func ReadSecretFile(path string, enrollment bool) (string, error) {
	root, name, err := openRootAndName(path, false)
	if err != nil {
		return "", err
	}
	defer root.Close()
	before, err := root.Lstat(name)
	if err != nil {
		return "", fmt.Errorf("inspect protected token file: %w", err)
	}
	if before.Size() > MaxSecretBytes+2 {
		return "", errors.New("protected token file is too large")
	}
	file, err := root.Open(name)
	if err != nil {
		return "", errors.New("open protected token file")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return "", errors.New("inspect protected token file")
	}
	if err := safefile.ValidateOpenedFile(before, after); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxSecretBytes+2))
	if err != nil || len(data) > MaxSecretBytes+1 {
		return "", errors.New("read protected token file")
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	valid := ValidSensorCredential(value)
	if enrollment {
		valid = ValidEnrollmentToken(value)
	}
	if !valid {
		return "", errors.New("protected token file contains an invalid value")
	}
	return value, nil
}

func readRecord(root *os.Root, name string) (Record, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return Record{}, err
	}
	if before.Size() > 4<<10 {
		return Record{}, errors.New("sensor credential file exceeds 4 KiB")
	}
	file, err := root.Open(name)
	if err != nil {
		return Record{}, errors.New("open sensor credential file")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return Record{}, errors.New("inspect sensor credential file")
	}
	if err := safefile.ValidateOpenedFile(before, after); err != nil {
		return Record{}, err
	}
	decoder := json.NewDecoder(io.LimitReader(file, 4<<10))
	decoder.DisallowUnknownFields()
	var record Record
	if err := decoder.Decode(&record); err != nil {
		return Record{}, errors.New("decode sensor credential file")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Record{}, errors.New("sensor credential file contains trailing data")
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func openRootAndName(path string, create bool) (*os.Root, string, error) {
	if strings.TrimSpace(path) == "" || len(path) > 4096 {
		return nil, "", errors.New("sensor credential path is invalid")
	}
	name := filepath.Base(filepath.Clean(path))
	if name == "." || name == string(filepath.Separator) || name == "" {
		return nil, "", errors.New("sensor credential path must name a file")
	}
	root, err := safefile.OpenPrivateRoot(filepath.Dir(filepath.Clean(path)), create)
	if err != nil {
		return nil, "", fmt.Errorf("open sensor credential directory: %w", err)
	}
	return root, name, nil
}

func randomSuffix() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate sensor credential temporary name")
	}
	return hex.EncodeToString(value), nil
}
