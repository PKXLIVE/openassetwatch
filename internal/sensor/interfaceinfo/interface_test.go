package interfaceinfo

import (
	"strings"
	"testing"
)

func TestListIsBoundedAndPayloadFree(t *testing.T) {
	values, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(values) > MaxInterfaces {
		t.Fatalf("interface count = %d", len(values))
	}
	for _, value := range values {
		if value.Name == "" || strings.ContainsAny(value.Name, `/\`) {
			t.Fatalf("unsafe interface record = %+v", value)
		}
	}
}

func TestValidateRequiresExplicitSafeExistingName(t *testing.T) {
	for _, value := range []string{"", " eth0", "../eth0", "bad/name", strings.Repeat("x", 65)} {
		if _, err := Validate(value); err == nil {
			t.Errorf("Validate(%q) unexpectedly succeeded", value)
		}
	}
	result, err := Validate("oaw-interface-that-does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	if result.Exists || result.Valid || len(result.Warnings) == 0 {
		t.Fatalf("missing interface result = %+v", result)
	}
}
