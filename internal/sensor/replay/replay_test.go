package replay

import (
	"testing"

	"github.com/openassetwatch/openassetwatch/internal/sensor/decode"
)

func TestSyntheticPacketsCoverSupportedProtocols(t *testing.T) {
	packets := SyntheticPackets(DemoObservedAt)
	if len(packets) != 6 {
		t.Fatalf("fixture count = %d, want 6", len(packets))
	}
	seen := make(map[string]bool)
	seenVLAN := false
	for index, packet := range packets {
		evidence, err := decode.Frame(packet.Data, packet.ObservedAt)
		if err != nil {
			t.Fatalf("fixture %d decode: %v", index, err)
		}
		for _, item := range evidence {
			seen[item.Protocol] = true
			seenVLAN = seenVLAN || item.VLANID != nil && *item.VLANID == 100
		}
	}
	for _, protocol := range []string{"arp", "dhcpv4", "dns", "mdns", "ssdp", "nbns"} {
		if !seen[protocol] {
			t.Errorf("protocol %q was not represented", protocol)
		}
	}
	if !seenVLAN {
		t.Error("synthetic replay did not exercise 802.1Q VLAN decoding")
	}
}

func TestSyntheticPacketsAreDeterministicAndDefensivelyCopied(t *testing.T) {
	first := SyntheticPackets(DemoObservedAt)
	second := SyntheticPackets(DemoObservedAt)
	if len(first) != len(second) {
		t.Fatalf("fixture lengths differ: %d and %d", len(first), len(second))
	}
	for index := range first {
		if !first[index].ObservedAt.Equal(second[index].ObservedAt) {
			t.Fatalf("fixture %d timestamp changed", index)
		}
		if string(first[index].Data) != string(second[index].Data) {
			t.Fatalf("fixture %d bytes are not deterministic", index)
		}
	}
	first[0].Data[0] ^= 0xff
	third := SyntheticPackets(DemoObservedAt)
	if string(first[0].Data) == string(third[0].Data) {
		t.Fatal("mutating a returned frame changed future fixture output")
	}
}
