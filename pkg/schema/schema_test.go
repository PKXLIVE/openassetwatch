package schema

import "testing"

func TestToolFieldPolicy(t *testing.T) {
	if !IsAllowedToolField("site_id") {
		t.Fatal("site_id should be allowed")
	}
	if !IsForbiddenToolField("command") {
		t.Fatal("command should be forbidden")
	}
	if IsAllowedToolField("command") {
		t.Fatal("command should not be allowed")
	}
}
