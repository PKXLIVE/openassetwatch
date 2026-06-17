package identity

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Identity is the durable non-secret local identity for an installed agent.
// It intentionally excludes enrollment tokens, license keys, and other secrets.
type Identity struct {
	AgentID      string    `json:"agent_id"`
	DeploymentID string    `json:"deployment_id,omitempty"`
	SiteID       string    `json:"site_id"`
	TenantID     string    `json:"tenant_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type CreateParams struct {
	SiteID       string
	DeploymentID string
	TenantID     string
}

func New(params CreateParams, now time.Time) (Identity, error) {
	siteID := strings.TrimSpace(params.SiteID)
	if siteID == "" {
		return Identity{}, errors.New("site_id is required")
	}

	agentID, err := newAgentID()
	if err != nil {
		return Identity{}, err
	}

	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	return Identity{
		AgentID:      agentID,
		DeploymentID: strings.TrimSpace(params.DeploymentID),
		SiteID:       siteID,
		TenantID:     strings.TrimSpace(params.TenantID),
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

func CreateFile(path string, params CreateParams, now time.Time) (Identity, error) {
	identity, err := New(params, now)
	if err != nil {
		return Identity{}, err
	}
	if err := WriteFile(path, identity); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func ReadFile(path string) (Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, err
	}

	var identity Identity
	if err := json.Unmarshal(data, &identity); err != nil {
		return Identity{}, err
	}
	if err := identity.Validate(); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func WriteFile(path string, identity Identity) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("identity output path is required")
	}
	if err := identity.Validate(); err != nil {
		return err
	}

	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	return err
}

func (identity Identity) Validate() error {
	if strings.TrimSpace(identity.SiteID) == "" {
		return errors.New("site_id is required")
	}
	if strings.TrimSpace(identity.AgentID) == "" {
		return errors.New("agent_id is required")
	}
	if identity.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	if identity.UpdatedAt.IsZero() {
		return errors.New("updated_at is required")
	}
	return nil
}

func newAgentID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate agent_id: %w", err)
	}

	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
