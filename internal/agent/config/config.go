package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Config stores non-secret local agent defaults only.
type Config struct {
	ServerURL string `json:"server_url"`
	SiteID    string `json:"site_id"`
}

type CreateParams struct {
	ServerURL string
	SiteID    string
}

func New(params CreateParams) (Config, error) {
	cfg := Config{
		ServerURL: strings.TrimSpace(params.ServerURL),
		SiteID:    strings.TrimSpace(params.SiteID),
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func CreateFile(path string, params CreateParams) (Config, error) {
	cfg, err := New(params)
	if err != nil {
		return Config{}, err
	}
	if err := WriteFile(path, cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func ReadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return Config{}, fmt.Errorf("parse agent config: %w", err)
	}
	for field := range fields {
		if isSecretLikeField(field) {
			return Config{}, fmt.Errorf("agent config must not contain secret field %q", field)
		}
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse agent config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func WriteFile(path string, cfg Config) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("config output path is required")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
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

func (cfg Config) Validate() error {
	if strings.TrimSpace(cfg.ServerURL) == "" {
		return errors.New("server_url is required")
	}
	if strings.TrimSpace(cfg.SiteID) == "" {
		return errors.New("site_id is required")
	}
	return ValidateServerURL(cfg.ServerURL)
}

func ValidateServerURL(serverURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("server_url must include http or https scheme and host")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("server_url must use http or https")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("server_url must not include query or fragment")
	}
	if parsed.User != nil {
		return errors.New("server_url must not include credentials")
	}
	return nil
}

func isSecretLikeField(field string) bool {
	normalized := strings.ToLower(strings.TrimSpace(field))
	switch {
	case normalized == "token":
		return true
	case strings.Contains(normalized, "token"):
		return true
	case strings.Contains(normalized, "secret"):
		return true
	case strings.Contains(normalized, "password"):
		return true
	case strings.Contains(normalized, "credential"):
		return true
	case strings.Contains(normalized, "api_key"):
		return true
	case strings.Contains(normalized, "apikey"):
		return true
	}
	return false
}
