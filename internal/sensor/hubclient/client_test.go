package hubclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sensorconfig "github.com/openassetwatch/openassetwatch/internal/sensor/config"
	"github.com/openassetwatch/openassetwatch/internal/sensor/contract"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testBatch() contract.Batch {
	return contract.Batch{
		SchemaVersion:      contract.SchemaVersion,
		ObservationBatchID: "sensor-home:20260720T120000Z:0001",
		SiteID:             "home-site",
		SensorID:           "sensor-home",
		SensorName:         "Home Passive Sensor",
		SensorType:         "passive-network-sensor",
		SensorVersion:      "0.1.0",
		ObservedAt:         time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC),
		ObservationSource:  "passive-network",
		DeliveryState:      "live",
		Confidence:         0.9,
		Assets: []contract.Asset{{
			AssetID: "mac-02005e100001", Hostname: "router", PrimaryIP: "192.0.2.1",
			MAC: "02:00:5e:10:00:01", Evidence: []contract.Evidence{{
				Protocol: "dns", Kind: "query-name", Value: "router.example.test", Confidence: 0.8,
			}},
		}},
	}
}

func TestSendAcceptsExactBackendAcknowledgement(t *testing.T) {
	batch := testBatch()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != ObservationPath {
			t.Errorf("request path = %q, want %q", request.URL.Path, ObservationPath)
		}
		if got := request.Header.Get(CollectorTokenHeader); got != "collector-test-token" {
			t.Errorf("collector token header = %q", got)
		}
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		asset := payload["assets"].([]any)[0].(map[string]any)
		if _, ok := asset["evidence"]; !ok {
			t.Error("request omitted evidence")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"accepted","observation_batch_id":"sensor-home:20260720T120000Z:0001","storage_id":7,"site_id":"home-site","sensor_id":"sensor-home","received_at":"2026-07-20T12:00:01Z","observed_asset_count":1,"normalized_asset_count":1,"message":"normalized outbound observation batch accepted"}`))
	}))
	defer server.Close()

	client, err := New(server.URL, "collector-test-token", time.Second)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ack, err := client.Send(context.Background(), batch)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if ack.Status != "accepted" || ack.StorageID != 7 || ack.SiteID != batch.SiteID || ack.SensorID != batch.SensorID {
		t.Fatalf("acknowledgement = %+v", ack)
	}
}

func TestSendAcceptsDuplicateAcknowledgement(t *testing.T) {
	batch := testBatch()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"duplicate","observation_batch_id":"sensor-home:20260720T120000Z:0001","storage_id":7,"site_id":"home-site","sensor_id":"sensor-home","received_at":"2026-07-20T12:00:01Z","observed_asset_count":1,"normalized_asset_count":1,"message":"observation batch was already stored; no duplicate asset evidence was added"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, "", time.Second)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ack, err := client.Send(context.Background(), batch)
	if err != nil || ack.Status != "duplicate" {
		t.Fatalf("Send() = %+v, %v", ack, err)
	}
}

func TestSendRejectsMismatchedOrIncompleteAcknowledgement(t *testing.T) {
	for name, response := range map[string]string{
		"wrong batch":              `{"status":"accepted","observation_batch_id":"other-batch","storage_id":7,"site_id":"home-site","sensor_id":"sensor-home","received_at":"2026-07-20T12:00:01Z","observed_asset_count":1,"normalized_asset_count":1,"message":"ok"}`,
		"missing documented field": `{"status":"accepted","observation_batch_id":"sensor-home:20260720T120000Z:0001","storage_id":7,"site_id":"home-site","sensor_id":"sensor-home","received_at":"2026-07-20T12:00:01Z","observed_asset_count":1,"normalized_asset_count":1}`,
		"unknown field":            `{"status":"accepted","observation_batch_id":"sensor-home:20260720T120000Z:0001","storage_id":7,"site_id":"home-site","sensor_id":"sensor-home","received_at":"2026-07-20T12:00:01Z","observed_asset_count":1,"normalized_asset_count":1,"message":"ok","future_field":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(response))
			}))
			defer server.Close()
			client, err := New(server.URL, "", time.Second)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			_, err = client.Send(context.Background(), testBatch())
			if err == nil {
				t.Fatal("Send() unexpectedly succeeded")
			}
			var delivery *DeliveryError
			if !errors.As(err, &delivery) || delivery.Class != "protocol" {
				t.Fatalf("error = %T %v", err, err)
			}
		})
	}
}

func TestSendRejectsOversizedResponseWithoutEchoingBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", maxResponseBytes+1)))
	}))
	defer server.Close()
	client, err := New(server.URL, "secret-token", time.Second)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = client.Send(context.Background(), testBatch())
	if err == nil || !strings.Contains(err.Error(), "exceeds size limit") || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("unexpected error = %v", err)
	}
}

func TestSendClassifiesPermanentAndRetryableStatuses(t *testing.T) {
	tests := map[string]struct {
		status    int
		class     string
		retryable bool
	}{
		"unauthorized":  {http.StatusUnauthorized, "authentication", false},
		"forbidden":     {http.StatusForbidden, "authentication", false},
		"bad request":   {http.StatusBadRequest, "validation", false},
		"unprocessable": {http.StatusUnprocessableEntity, "validation", false},
		"timeout":       {http.StatusRequestTimeout, "timeout", true},
		"rate limit":    {http.StatusTooManyRequests, "rate-limit", true},
		"server":        {http.StatusServiceUnavailable, "server", true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				http.Error(writer, "sensitive upstream response body", test.status)
			}))
			defer server.Close()
			client, err := New(server.URL, "collector-test-token", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Send(context.Background(), testBatch())
			var delivery *DeliveryError
			if !errors.As(err, &delivery) {
				t.Fatalf("Send() error = %T %v", err, err)
			}
			if delivery.Class != test.class || delivery.Retryable != test.retryable {
				t.Fatalf("classification = %+v", delivery)
			}
			if strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "collector-test-token") {
				t.Fatalf("error leaked response or token: %v", err)
			}
		})
	}
}

func TestSendRefusesRedirectWithoutLeakingCollectorToken(t *testing.T) {
	redirectedRequests := 0
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		redirectedRequests++
		if request.Header.Get(CollectorTokenHeader) != "" {
			t.Error("redirected request leaked collector token")
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	client, err := New(origin.URL, "collector-test-token", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Send(context.Background(), testBatch())
	var delivery *DeliveryError
	if !errors.As(err, &delivery) || delivery.Class != "redirect" || delivery.Retryable {
		t.Fatalf("redirect error = %T %v", err, err)
	}
	if redirectedRequests != 0 {
		t.Fatalf("redirect target received %d request(s)", redirectedRequests)
	}
}

func TestEnrollUsesBoundedOneTimeExchangeAndValidatesIdentity(t *testing.T) {
	enrollmentToken := "oaw_enroll_v1." + strings.Repeat("a", 32) + "." + strings.Repeat("B", 43)
	sensorCredential := "oaw_sensor_v1." + strings.Repeat("c", 32) + "." + strings.Repeat("D", 43)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != EnrollmentPath || request.Method != http.MethodPost {
			http.Error(writer, "not found", http.StatusNotFound)
			return
		}
		if request.Header.Get(CollectorTokenHeader) != "" {
			t.Error("enrollment token was incorrectly copied into the authentication header")
		}
		var body EnrollmentRequest
		decoder := json.NewDecoder(io.LimitReader(request.Body, maxEnrollmentBytes+1))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || body.EnrollmentToken != enrollmentToken {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(
			writer,
			`{"status":"enrolled","site_id":"site-test","sensor_id":"sensor-test","sensor_type":"passive-network-sensor","credential_id":"scred_%s","sensor_credential":%q,"issued_at":"2026-07-29T12:00:00Z"}`,
			strings.Repeat("e", 32), sensorCredential,
		)
	}))
	defer server.Close()

	client, err := New(server.URL, "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Enroll(context.Background(), EnrollmentRequest{
		EnrollmentToken: enrollmentToken,
		SensorID:        "sensor-test",
		SensorName:      "Sensor Test",
		SensorType:      "passive-network-sensor",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.SiteID != "site-test" || response.SensorCredential != sensorCredential {
		t.Fatalf("enrollment response = %#v", response)
	}
}

func TestEnrollBlocksOneTimeCredentialOverNonLoopbackHTTPBeforeRequest(t *testing.T) {
	enrollmentToken := "oaw_enroll_v1." + strings.Repeat("a", 32) + "." + strings.Repeat("B", 43)
	client, err := New("http://host.docker.internal:8000", "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	requestCount := 0
	client.credentialHTTP.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		requestCount++
		return nil, errors.New("unexpected outbound request")
	})

	_, err = client.Enroll(context.Background(), EnrollmentRequest{
		EnrollmentToken: enrollmentToken,
		SensorID:        "sensor-test",
		SensorName:      "Sensor Test",
		SensorType:      "passive-network-sensor",
	})
	var delivery *DeliveryError
	if !errors.As(err, &delivery) || delivery.Class != "validation" || delivery.Retryable {
		t.Fatalf("Enroll() error = %T %v", err, err)
	}
	if err.Error() != sensorconfig.ErrCollectorTokenTransport.Error() {
		t.Fatalf("Enroll() error = %v", err)
	}
	if strings.Contains(err.Error(), enrollmentToken) {
		t.Fatal("Enroll() error leaked the enrollment token")
	}
	if requestCount != 0 {
		t.Fatalf("Enroll() attempted %d outbound request(s)", requestCount)
	}
}

func TestClientRejectsInvalidTokensWithoutEchoingThem(t *testing.T) {
	for _, token := range []string{" leading", "trailing ", "line\nbreak", strings.Repeat("x", 4097)} {
		if _, err := New("http://127.0.0.1:8000", token, time.Second); err == nil {
			t.Errorf("New() accepted invalid token of length %d", len(token))
		} else if strings.Contains(err.Error(), token) {
			t.Errorf("error echoed invalid token")
		}
	}
}

func TestClientEnforcesCollectorTokenTransportPolicyWithoutEchoingToken(t *testing.T) {
	const token = "collector-token-value-that-must-not-appear"
	for _, hubURL := range []string{
		"https://hub.example.test",
		"http://localhost:8000",
		"http://127.0.0.1:8000",
		"http://127.0.0.2:8000",
		"http://[::1]:8000",
	} {
		if _, err := New(hubURL, token, time.Second); err != nil {
			t.Errorf("New(%q) unexpected error: %v", hubURL, err)
		}
	}
	for _, hubURL := range []string{
		"http://192.0.2.10:8000",
		"http://hub.example.test:8000",
		"http://host.docker.internal:8000",
		"not-a-url",
	} {
		_, err := New(hubURL, token, time.Second)
		if !errors.Is(err, sensorconfig.ErrCollectorTokenTransport) {
			t.Errorf("New(%q) error = %v", hubURL, err)
		}
		if err != nil && strings.Contains(err.Error(), token) {
			t.Errorf("New(%q) error leaked token", hubURL)
		}
	}
}
