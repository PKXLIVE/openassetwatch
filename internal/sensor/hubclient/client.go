package hubclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	sensorconfig "github.com/openassetwatch/openassetwatch/internal/sensor/config"
	"github.com/openassetwatch/openassetwatch/internal/sensor/contract"
	"github.com/openassetwatch/openassetwatch/internal/sensor/credential"
)

const (
	ObservationPath      = "/api/v1/observations/batches"
	EnrollmentPath       = "/api/v1/sensors/enroll"
	CollectorTokenHeader = "X-OpenAssetWatch-Collector-Token"
	maxResponseBytes     = 64 << 10
	maxEnrollmentBytes   = 8 << 10
)

type Client struct {
	baseURL  string
	endpoint string
	token    string
	http     *http.Client
}

type Acknowledgement struct {
	Status               string    `json:"status"`
	ObservationBatchID   string    `json:"observation_batch_id"`
	StorageID            int       `json:"storage_id"`
	SiteID               string    `json:"site_id"`
	SensorID             string    `json:"sensor_id"`
	ReceivedAt           time.Time `json:"received_at"`
	ObservedAssetCount   int       `json:"observed_asset_count"`
	NormalizedAssetCount int       `json:"normalized_asset_count"`
	Message              string    `json:"message"`
}

type EnrollmentRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	SensorID        string `json:"sensor_id"`
	SensorName      string `json:"sensor_name"`
	SensorType      string `json:"sensor_type"`
	SensorVersion   string `json:"sensor_version,omitempty"`
	Platform        string `json:"platform,omitempty"`
}

type EnrollmentResponse struct {
	Status           string    `json:"status"`
	SiteID           string    `json:"site_id"`
	SensorID         string    `json:"sensor_id"`
	SensorType       string    `json:"sensor_type"`
	CredentialID     string    `json:"credential_id"`
	SensorCredential string    `json:"sensor_credential"`
	IssuedAt         time.Time `json:"issued_at"`
}

type DeliveryError struct {
	StatusCode int
	Class      string
	Retryable  bool
	message    string
}

func (e *DeliveryError) Error() string { return e.message }

func New(hubURL, token string, timeout time.Duration) (*Client, error) {
	if err := sensorconfig.ValidateHubURL(hubURL); err != nil {
		return nil, err
	}
	if err := validateToken(token); err != nil {
		return nil, err
	}
	if timeout <= 0 || timeout > 2*time.Minute {
		return nil, errors.New("hub request timeout is outside supported bounds")
	}
	parsed, _ := url.Parse(strings.TrimSpace(hubURL))
	baseURL := parsed.String()
	parsed.Path = ObservationPath
	connectTimeout := min(timeout, 5*time.Second)
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport is unavailable")
	}
	transport := baseTransport.Clone()
	transport.Proxy = nil
	transport.DialContext = secureDialContext(&net.Dialer{
		Timeout:   connectTimeout,
		KeepAlive: 30 * time.Second,
	})
	transport.TLSHandshakeTimeout = connectTimeout
	transport.ResponseHeaderTimeout = timeout
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Client{baseURL: baseURL, endpoint: parsed.String(), token: token, http: client}, nil
}

func secureDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("hub address is invalid")
		}
		resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(resolved) == 0 {
			return nil, errors.New("hub address resolution failed")
		}
		for _, candidate := range resolved {
			if sensorconfig.ForbiddenHubIP(candidate.IP) {
				return nil, errors.New("hub address resolved to a forbidden network")
			}
		}
		var lastErr error
		for _, candidate := range resolved {
			connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
			if dialErr == nil {
				return connection, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
}

func validateToken(token string) error {
	if len(token) > 4096 || strings.TrimSpace(token) != token {
		return errors.New("collector token is invalid")
	}
	for _, character := range token {
		if character < 0x21 || character == 0x7f {
			return errors.New("collector token is invalid")
		}
	}
	return nil
}

func (c *Client) Send(ctx context.Context, batch contract.Batch) (Acknowledgement, error) {
	body, err := contract.Marshal(batch)
	if err != nil {
		return Acknowledgement{}, &DeliveryError{Class: "validation", message: "observation batch validation failed"}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return Acknowledgement{}, &DeliveryError{Class: "validation", message: "failed to create hub request"}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if c.token != "" {
		request.Header.Set(CollectorTokenHeader, c.token)
	}
	response, err := c.http.Do(request)
	if err != nil {
		class := "network"
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			class = "timeout"
		}
		return Acknowledgement{}, &DeliveryError{Class: class, Retryable: true, message: "hub request failed"}
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil {
		return Acknowledgement{}, &DeliveryError{StatusCode: response.StatusCode, Class: "network", Retryable: true, message: "failed to read hub acknowledgement"}
	}
	if len(responseBody) > maxResponseBytes {
		return Acknowledgement{}, &DeliveryError{StatusCode: response.StatusCode, Class: "protocol", message: "hub acknowledgement exceeds size limit"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Acknowledgement{}, classifyStatus(response.StatusCode)
	}
	var acknowledgement Acknowledgement
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&acknowledgement); err != nil {
		return Acknowledgement{}, &DeliveryError{StatusCode: response.StatusCode, Class: "protocol", message: "hub returned an invalid acknowledgement"}
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Acknowledgement{}, &DeliveryError{StatusCode: response.StatusCode, Class: "protocol", message: "hub returned an invalid acknowledgement"}
	}
	if err := validateAcknowledgement(acknowledgement, batch); err != nil {
		return Acknowledgement{}, &DeliveryError{StatusCode: response.StatusCode, Class: "protocol", message: err.Error()}
	}
	return acknowledgement, nil
}

func (c *Client) Enroll(ctx context.Context, enrollment EnrollmentRequest) (EnrollmentResponse, error) {
	if !credential.ValidEnrollmentToken(enrollment.EnrollmentToken) {
		return EnrollmentResponse{}, &DeliveryError{Class: "validation", message: "sensor enrollment input is invalid"}
	}
	if err := contract.ValidateSensorID(enrollment.SensorID); err != nil {
		return EnrollmentResponse{}, &DeliveryError{Class: "validation", message: "sensor enrollment input is invalid"}
	}
	if strings.TrimSpace(enrollment.SensorName) == "" || len(enrollment.SensorName) > 160 ||
		enrollment.SensorType != "passive-network-sensor" || len(enrollment.SensorVersion) > 80 ||
		len(enrollment.Platform) > 80 {
		return EnrollmentResponse{}, &DeliveryError{Class: "validation", message: "sensor enrollment input is invalid"}
	}
	body, err := json.Marshal(enrollment)
	if err != nil || len(body) > maxEnrollmentBytes {
		return EnrollmentResponse{}, &DeliveryError{Class: "validation", message: "sensor enrollment input is invalid"}
	}
	parsed, _ := url.Parse(c.baseURL)
	parsed.Path = EnrollmentPath
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return EnrollmentResponse{}, &DeliveryError{Class: "validation", message: "failed to create sensor enrollment request"}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		class := "network"
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			class = "timeout"
		}
		return EnrollmentResponse{}, &DeliveryError{Class: class, Retryable: true, message: "sensor enrollment request failed"}
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil {
		return EnrollmentResponse{}, &DeliveryError{StatusCode: response.StatusCode, Class: "network", Retryable: true, message: "failed to read sensor enrollment response"}
	}
	if len(responseBody) > maxResponseBytes {
		return EnrollmentResponse{}, &DeliveryError{StatusCode: response.StatusCode, Class: "protocol", message: "sensor enrollment response exceeds size limit"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return EnrollmentResponse{}, classifyStatus(response.StatusCode)
	}
	var result EnrollmentResponse
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return EnrollmentResponse{}, &DeliveryError{StatusCode: response.StatusCode, Class: "protocol", message: "hub returned an invalid sensor enrollment response"}
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return EnrollmentResponse{}, &DeliveryError{StatusCode: response.StatusCode, Class: "protocol", message: "hub returned an invalid sensor enrollment response"}
	}
	if result.Status != "enrolled" || result.SensorID != enrollment.SensorID ||
		result.SensorType != enrollment.SensorType || result.SiteID == "" ||
		result.CredentialID == "" || result.IssuedAt.IsZero() ||
		!credential.ValidSensorCredential(result.SensorCredential) {
		return EnrollmentResponse{}, &DeliveryError{StatusCode: response.StatusCode, Class: "protocol", message: "hub returned an invalid sensor enrollment response"}
	}
	return result, nil
}

func validateAcknowledgement(ack Acknowledgement, batch contract.Batch) error {
	if ack.Status != "accepted" && ack.Status != "duplicate" {
		return errors.New("hub returned an unrecognized acknowledgement")
	}
	if ack.ObservationBatchID != batch.ObservationBatchID {
		return errors.New("hub acknowledgement batch ID does not match")
	}
	if ack.SiteID != batch.SiteID {
		return errors.New("hub acknowledgement site ID does not match")
	}
	if ack.SensorID != batch.SensorID {
		return errors.New("hub acknowledgement sensor ID does not match")
	}
	if ack.StorageID <= 0 {
		return errors.New("hub acknowledgement storage ID is invalid")
	}
	if ack.ReceivedAt.IsZero() {
		return errors.New("hub acknowledgement received_at is required")
	}
	if ack.ObservedAssetCount != len(batch.Assets) || ack.ObservedAssetCount < 0 || ack.ObservedAssetCount > contract.MaxAssets {
		return errors.New("hub acknowledgement observed asset count does not match")
	}
	if ack.NormalizedAssetCount < 0 || ack.NormalizedAssetCount > ack.ObservedAssetCount {
		return errors.New("hub acknowledgement normalized asset count is invalid")
	}
	if strings.TrimSpace(ack.Message) == "" || len(ack.Message) > 512 {
		return errors.New("hub acknowledgement message is invalid")
	}
	return nil
}

func classifyStatus(status int) error {
	errorValue := &DeliveryError{StatusCode: status}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		errorValue.Class = "authentication"
		errorValue.message = fmt.Sprintf("hub authentication rejected (HTTP %d)", status)
	case status == http.StatusRequestTimeout:
		errorValue.Class = "timeout"
		errorValue.Retryable = true
		errorValue.message = fmt.Sprintf("hub request is retryable (HTTP %d)", status)
	case status == http.StatusTooManyRequests:
		errorValue.Class = "rate-limit"
		errorValue.Retryable = true
		errorValue.message = "hub rate limit requires a retry (HTTP 429)"
	case status >= 500 && status <= 599:
		errorValue.Class = "server"
		errorValue.Retryable = true
		errorValue.message = fmt.Sprintf("hub service error is retryable (HTTP %d)", status)
	case status >= 300 && status <= 399:
		errorValue.Class = "redirect"
		errorValue.message = fmt.Sprintf("hub redirect was refused (HTTP %d)", status)
	default:
		errorValue.Class = "validation"
		errorValue.message = fmt.Sprintf("hub rejected observation batch (HTTP %d)", status)
	}
	return errorValue
}

func Retryable(err error) (bool, string) {
	var delivery *DeliveryError
	if errors.As(err, &delivery) {
		return delivery.Retryable, delivery.Class
	}
	return false, "unknown"
}

func Backoff(attempt int, initial, maximum time.Duration) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if initial <= 0 {
		initial = time.Second
	}
	if maximum < initial {
		maximum = initial
	}
	delay := initial
	for index := 0; index < attempt && delay < maximum; index++ {
		if delay > maximum/2 {
			delay = maximum
			break
		}
		delay *= 2
	}
	if delay > maximum {
		delay = maximum
	}
	// Add up to 25 percent positive jitter without a process-global PRNG.
	jitterLimit := uint64(delay / 4)
	if jitterLimit == 0 {
		return delay
	}
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return delay
	}
	jitter := time.Duration(binary.BigEndian.Uint64(value[:]) % (jitterLimit + 1))
	if delay > maximum-jitter {
		return maximum
	}
	return delay + jitter
}
