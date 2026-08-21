package hubclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	agentcredential "github.com/openassetwatch/openassetwatch/internal/agent/credential"
)

const (
	agentCredentialHeader = "X-OpenAssetWatch-Agent-Credential"
	enrollmentPath        = "/api/v1/agents/enroll"
	checkInPath           = "/api/v1/agents/check-in"
	inventoryPath         = "/api/v1/agents/inventory"
	maxResponseBytes      = 64 << 10
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

type EnrollmentRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	InstallationID  string `json:"installation_id,omitempty"`
	DisplayName     string `json:"display_name,omitempty"`
	AgentVersion    string `json:"agent_version,omitempty"`
	Platform        string `json:"platform,omitempty"`
	Architecture    string `json:"architecture,omitempty"`
	AgentType       string `json:"agent_type"`
}

type EnrollmentResponse struct {
	Status          string    `json:"status"`
	SiteID          string    `json:"site_id"`
	AgentID         string    `json:"agent_id"`
	DeploymentID    string    `json:"deployment_id,omitempty"`
	AgentType       string    `json:"agent_type"`
	CredentialID    string    `json:"credential_id"`
	AgentCredential string    `json:"agent_credential"`
	IssuedAt        time.Time `json:"issued_at"`
}

type ResponseError struct {
	StatusCode int
}

func (err *ResponseError) Error() string {
	return fmt.Sprintf("hub returned HTTP status %d", err.StatusCode)
}

func New(baseURL string) (*Client, error) {
	parsed, err := validatedBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Client{
		baseURL: parsed.String(),
		httpClient: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func NewWithHTTPClient(baseURL string, client *http.Client) (*Client, error) {
	parsed, err := validatedBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("HTTP client is required")
	}
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{baseURL: parsed.String(), httpClient: &clone}, nil
}

func (client *Client) Enroll(ctx context.Context, request EnrollmentRequest) (EnrollmentResponse, error) {
	if !agentcredential.ValidEnrollmentToken(request.EnrollmentToken) {
		return EnrollmentResponse{}, errors.New("enrollment token is invalid")
	}
	var response EnrollmentResponse
	if err := client.post(ctx, enrollmentPath, request, "", &response); err != nil {
		return EnrollmentResponse{}, err
	}
	if response.Status != "enrolled" || response.AgentType != "endpoint-agent" ||
		response.SiteID == "" || response.AgentID == "" || response.CredentialID == "" ||
		response.IssuedAt.IsZero() || !agentcredential.ValidAgentCredential(response.AgentCredential) {
		return EnrollmentResponse{}, errors.New("hub enrollment response is invalid")
	}
	return response, nil
}

func (client *Client) CheckIn(ctx context.Context, credential string, payload any) (int, error) {
	return client.postStatus(ctx, checkInPath, payload, credential)
}

func (client *Client) SubmitInventory(ctx context.Context, credential string, payload any) (int, error) {
	return client.postStatus(ctx, inventoryPath, payload, credential)
}

func (client *Client) postStatus(ctx context.Context, path string, payload any, credential string) (int, error) {
	if !agentcredential.ValidAgentCredential(credential) {
		return 0, errors.New("agent credential is invalid")
	}
	return client.doPost(ctx, path, payload, credential, nil)
}

func (client *Client) post(ctx context.Context, path string, payload any, credential string, destination any) error {
	_, err := client.doPost(ctx, path, payload, credential, destination)
	return err
}

func (client *Client) doPost(ctx context.Context, path string, payload any, credential string, destination any) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, errors.New("encode hub request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("build hub request")
	}
	request.Header.Set("Content-Type", "application/json")
	if credential != "" {
		request.Header.Set(agentCredentialHeader, credential)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return 0, errors.New("hub request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		return response.StatusCode, &ResponseError{StatusCode: response.StatusCode}
	}
	if destination == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes+1))
		return response.StatusCode, nil
	}
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return response.StatusCode, errors.New("decode hub response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return response.StatusCode, errors.New("hub response contains trailing data")
	}
	return response.StatusCode, nil
}

func validatedBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("server URL must include scheme and host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("server URL must not include credentials, query, or fragment")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return nil, errors.New("server URL must use HTTPS outside loopback development")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
