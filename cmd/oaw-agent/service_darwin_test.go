//go:build darwin

package main

import (
	"strings"
	"testing"
)

func TestDarwinServiceLoggerSanitizesSensitiveValues(t *testing.T) {
	got := sanitizeLogMessage("failed with token=abc123 and request body omitted")
	for _, forbidden := range []string{"abc123", "token", "request body"} {
		if strings.Contains(strings.ToLower(got), forbidden) {
			t.Fatalf("sanitizeLogMessage(%q) leaked %q as %q", "failed with token=abc123 and request body omitted", forbidden, got)
		}
	}
	if !strings.Contains(got, "[redacted]") {
		t.Fatalf("sanitizeLogMessage did not include redaction marker: %q", got)
	}
}
