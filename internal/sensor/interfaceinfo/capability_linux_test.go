//go:build linux

package interfaceinfo

import "testing"

func TestParseEffectiveCapabilities(t *testing.T) {
	value, ok := parseEffectiveCapabilities("Name:\ttest\nCapEff:\t0000000000002000\n")
	if !ok || value != 1<<capNetRaw {
		t.Fatalf("parseEffectiveCapabilities() = %x, %t", value, ok)
	}
	if _, ok := parseEffectiveCapabilities("CapEff:\tnot-hex\n"); ok {
		t.Fatal("parseEffectiveCapabilities() accepted invalid hex")
	}
	if _, ok := parseEffectiveCapabilities("Name:\ttest\n"); ok {
		t.Fatal("parseEffectiveCapabilities() accepted a missing field")
	}
}

func TestParseLinuxInterfaceFlags(t *testing.T) {
	flags, err := parseLinuxInterfaceFlags("0x1103\n")
	if err != nil {
		t.Fatal(err)
	}
	if flags&linuxInterfacePromiscuous == 0 {
		t.Fatal("expected IFF_PROMISC to be detected")
	}
	if _, err := parseLinuxInterfaceFlags("not-flags"); err == nil {
		t.Fatal("expected malformed flags to be rejected")
	}
}
