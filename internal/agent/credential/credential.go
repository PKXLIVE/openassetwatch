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
	SchemaVersion      = "oaw.agent-credential.v1"
	EnvironmentName    = "OPENASSETWATCH_AGENT_CREDENTIAL"
	EnrollmentTokenEnv = "OPENASSETWATCH_AGENT_ENROLLMENT_TOKEN"
	MaxSecretBytes     = 256
)

var (
	agentCredentialPattern = regexp.MustCompile(`^oaw_agent_v1\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$`)
	enrollmentTokenPattern = regexp.MustCompile(`^oaw_agent_enroll_v1\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$`)
	siteIdentifierPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	agentIdentifierPattern = regexp.MustCompile(`^agent_[0-9a-f]{32}$`)
	credentialIDPattern    = regexp.MustCompile(`^acred_[0-9a-f]{32}$`)
)

type Record struct {
	SchemaVersion string    `json:"schema_version"`
	SiteID        string    `json:"site_id"`
	AgentID       string    `json:"agent_id"`
	DeploymentID  string    `json:"deployment_id,omitempty"`
	AgentType     string    `json:"agent_type"`
	CredentialID  string    `json:"credential_id"`
	Credential    string    `json:"credential"`
	IssuedAt      time.Time `json:"issued_at"`
}

func (record Record) Validate() error {
	if record.SchemaVersion != SchemaVersion {
		return errors.New("agent credential record schema is invalid")
	}
	if !siteIdentifierPattern.MatchString(record.SiteID) || len(record.SiteID) > 128 {
		return errors.New("agent credential site binding is invalid")
	}
	if !agentIdentifierPattern.MatchString(record.AgentID) {
		return errors.New("agent credential identity binding is invalid")
	}
	if record.DeploymentID != "" && len(record.DeploymentID) > 160 {
		return errors.New("agent credential deployment binding is invalid")
	}
	if record.AgentType != "endpoint-agent" {
		return errors.New("agent credential type binding is invalid")
	}
	if !credentialIDPattern.MatchString(record.CredentialID) {
		return errors.New("agent credential identifier is invalid")
	}
	if !ValidAgentCredential(record.Credential) {
		return errors.New("agent credential value is invalid")
	}
	if record.IssuedAt.IsZero() {
		return errors.New("agent credential issuance time is required")
	}
	return nil
}

func ValidAgentCredential(value string) bool {
	return len(value) <= MaxSecretBytes && agentCredentialPattern.MatchString(value)
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
		return errors.New("agent credential file already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect agent credential file")
	}
	return nil
}

func Write(path string, record Record, replace bool) error {
	if err := record.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return errors.New("marshal agent credential record")
	}
	data = append(data, '\n')
	root, name, err := openRootAndName(path, true)
	if err != nil {
		return err
	}
	defer root.Close()

	if before, statErr := root.Lstat(name); statErr == nil {
		if !replace {
			return errors.New("agent credential file already exists")
		}
		if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || safefile.LinkCount(before) > 1 {
			return errors.New("agent credential file failed regular-file validation")
		}
		if _, readErr := readRecord(root, name); readErr != nil {
			return errors.New("existing agent credential file is invalid")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errors.New("inspect agent credential file")
	}

	suffix, err := randomSuffix()
	if err != nil {
		return err
	}
	tempName := ".agent-credential-" + suffix + ".tmp"
	file, err := root.OpenFile(tempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create agent credential temporary file")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = root.Remove(tempName)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return errors.New("write agent credential file")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || safefile.LinkCount(info) > 1 {
		_ = file.Close()
		return errors.New("agent credential temporary file failed regular-file validation")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("sync agent credential file")
	}
	if err := file.Close(); err != nil {
		return errors.New("close agent credential file")
	}
	if err := root.Rename(tempName, name); err != nil {
		return errors.New("publish agent credential atomically")
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
		return errors.New("remove agent credential file")
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
	if err != nil || before.Size() > MaxSecretBytes+2 {
		return "", errors.New("protected token file is unavailable or too large")
	}
	file, err := root.Open(name)
	if err != nil {
		return "", errors.New("open protected token file")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || safefile.ValidateOpenedFile(before, after) != nil {
		return "", errors.New("protected token file failed validation")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxSecretBytes+2))
	if err != nil || len(data) > MaxSecretBytes+1 {
		return "", errors.New("read protected token file")
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	valid := ValidAgentCredential(value)
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
	if err != nil || before.Size() > 4<<10 {
		return Record{}, errors.New("agent credential file is unavailable or too large")
	}
	file, err := root.Open(name)
	if err != nil {
		return Record{}, errors.New("open agent credential file")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || safefile.ValidateOpenedFile(before, after) != nil {
		return Record{}, errors.New("agent credential file failed validation")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 4<<10))
	decoder.DisallowUnknownFields()
	var record Record
	if err := decoder.Decode(&record); err != nil {
		return Record{}, errors.New("decode agent credential file")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Record{}, errors.New("agent credential file contains trailing data")
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func openRootAndName(path string, create bool) (*os.Root, string, error) {
	if strings.TrimSpace(path) == "" || len(path) > 4096 {
		return nil, "", errors.New("agent credential path is invalid")
	}
	name := filepath.Base(filepath.Clean(path))
	if name == "." || name == string(filepath.Separator) || name == "" {
		return nil, "", errors.New("agent credential path must name a file")
	}
	root, err := safefile.OpenPrivateRoot(filepath.Dir(filepath.Clean(path)), create)
	if err != nil {
		return nil, "", fmt.Errorf("open agent credential directory: %w", err)
	}
	return root, name, nil
}

func randomSuffix() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate agent credential temporary name")
	}
	return hex.EncodeToString(value), nil
}
