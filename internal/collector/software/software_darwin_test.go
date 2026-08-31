//go:build darwin

package software

import (
	"testing"
	"time"
)

func TestPkgutilParsersRetainOnlyReceiptEvidence(t *testing.T) {
	receipts, malformed, truncated := parsePkgutilList([]byte("com.fictional.agent\n-invalid\ncom.fictional.agent\n"))
	if len(receipts) != 1 || receipts[0] != "com.fictional.agent" || malformed != 1 || truncated {
		t.Fatalf("receipts=%v malformed=%d truncated=%t", receipts, malformed, truncated)
	}
	component, ok := parsePkgutilInfo([]byte(
		"package-id: com.fictional.agent\nversion: 2.1.0\nvolume: /\nlocation: Library/Fictional\ninstall-time: 1\n",
	), receipts[0], time.Now().UTC())
	if !ok || component.Name != "com.fictional.agent" || component.Version != "2.1.0" {
		t.Fatalf("component=%+v ok=%t", component, ok)
	}
	if len(component.Metadata) != 1 || component.Metadata["install_state"] != "receipt-present" {
		t.Fatalf("unreviewed pkgutil metadata retained: %+v", component.Metadata)
	}
}
