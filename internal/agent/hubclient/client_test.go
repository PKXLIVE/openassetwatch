package hubclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func agentCredential() string {
	return "oaw_agent_v1." + strings.Repeat("a", 32) + "." + strings.Repeat("B", 43)
}

func TestClientRejectsCleartextOutsideLoopbackAndURLCredentials(t *testing.T) {
	for _, value := range []string{
		"http://192.0.2.10:8000",
		"https://user:secret@example.test",
		"https://example.test?redirect=https://elsewhere.test",
	} {
		if _, err := New(value); err == nil {
			t.Fatalf("unsafe URL accepted: %s", value)
		}
	}
}

func TestAuthenticatedRequestsUseFixedPathHeaderAndBoundedResponse(t *testing.T) {
	var gotPath string
	var gotCredential string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		gotPath = request.URL.Path
		gotCredential = request.Header.Get(agentCredentialHeader)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"status":"accepted"}`))
	}))
	defer server.Close()
	client, err := NewWithHTTPClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.CheckIn(context.Background(), agentCredential(), map[string]string{"health": "healthy"})
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if gotPath != checkInPath || gotCredential != agentCredential() {
		t.Fatalf("path=%q credential-present=%v", gotPath, gotCredential != "")
	}
}

func TestEnrollmentResponseIsStrictAndCredentialIsNeverSentAsAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" || request.Header.Get(agentCredentialHeader) != "" {
			t.Fatal("enrollment request included a credential header")
		}
		var requestBody map[string]any
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(response).Encode(EnrollmentResponse{
			Status: "enrolled", SiteID: "site-test",
			AgentID:   "agent_" + strings.Repeat("1", 32),
			AgentType: "endpoint-agent", CredentialID: "acred_" + strings.Repeat("2", 32),
			AgentCredential: agentCredential(), IssuedAt: time.Now().UTC(),
		})
	}))
	defer server.Close()
	client, err := NewWithHTTPClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Enroll(context.Background(), EnrollmentRequest{
		EnrollmentToken: "oaw_agent_enroll_v1." + strings.Repeat("a", 32) + "." + strings.Repeat("C", 43),
		AgentType:       "endpoint-agent",
	})
	if err != nil || response.AgentID == "" {
		t.Fatalf("response=%+v err=%v", response, err)
	}
}
