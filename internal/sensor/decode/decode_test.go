package decode

import (
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"
)

var (
	testMAC = net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}
	testAt  = time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
)

func ethernetForTest(etherType uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], testMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)
	return frame
}

func ipv4UDPForTest(sourcePort, destinationPort uint16, data []byte) []byte {
	udp := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], data)
	packet := make([]byte, 20+len(udp))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8], packet[9] = 64, 17
	copy(packet[12:16], net.IPv4(192, 0, 2, 10).To4())
	copy(packet[16:20], net.IPv4(224, 0, 0, 251).To4())
	copy(packet[20:], udp)
	return packet
}

func TestFrameRejectsTruncationOversizeAndNestedVLAN(t *testing.T) {
	oversized := make([]byte, maxFrameBytes+1)
	nested := ethernetForTest(0x8100, []byte{
		0, 1, 0x81, 0x00,
		0, 2, 0x81, 0x00,
		0, 3, 0x08, 0x06,
	})
	tests := map[string][]byte{
		"truncated Ethernet": make([]byte, 13),
		"oversized frame":    oversized,
		"truncated VLAN":     ethernetForTest(0x8100, []byte{0, 1, 8}),
		"nested VLAN":        nested,
		"invalid IPv4":       ethernetForTest(0x0800, []byte{0x45}),
	}
	for name, frame := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Frame(frame, testAt); err == nil {
				t.Fatal("Frame() unexpectedly succeeded")
			}
		})
	}

	evidence, err := Frame(ethernetForTest(0x86dd, make([]byte, 40)), testAt)
	if err != nil || len(evidence) != 0 {
		t.Fatalf("unexpected EtherType = %#v, %v", evidence, err)
	}
}

func TestDNSRejectsCompressionLoopsPointersLabelsAndRecordFloods(t *testing.T) {
	for name, message := range map[string][]byte{
		"self pointer":         {0xc0, 0x00},
		"out of range":         {0xc0, 0xff},
		"invalid label bits":   {0x40, 0x00},
		"truncated label":      {0x03, 'a'},
		"truncated pointer":    {0xc0},
		"empty sanitized name": {0x01, '\n', 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := readDNSName(message, 0); err == nil {
				t.Fatal("readDNSName() unexpectedly succeeded")
			}
		})
	}

	flood := make([]byte, 12)
	binary.BigEndian.PutUint16(flood[4:6], maxDNSRecords+1)
	if _, err := decodeDNS(flood, "dns", testMAC.String(), "192.0.2.10", nil, testAt); err == nil {
		t.Fatal("decodeDNS() accepted excessive record count")
	}

	label := strings.Repeat("a", 63)
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[4:6], 1)
	for index := 0; index < 5; index++ {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0, 0, 1, 0, 1)
	if _, err := decodeDNS(message, "dns", testMAC.String(), "192.0.2.10", nil, testAt); err == nil {
		t.Fatal("decodeDNS() accepted a name longer than 255 characters")
	}
}

func TestDHCPRejectsMalformedOptions(t *testing.T) {
	for name, options := range map[string][]byte{
		"missing length": {12},
		"truncated":      {12, 4, 'a'},
		"option flood":   make([]byte, 129),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseDHCPOptions(options); err == nil {
				t.Fatal("parseDHCPOptions() unexpectedly succeeded")
			}
		})
	}
}

func TestSSDPLocationIsBoundedNormalizedAndNeverCredentialBearing(t *testing.T) {
	if value, ok := normalizeSSDPLocation("http://user:password@device.local/desc.xml"); ok || value != "" {
		t.Fatalf("credential-bearing LOCATION accepted as %q", value)
	}
	value, ok := normalizeSSDPLocation("http://device.local/desc.xml?token=secret#fragment")
	if !ok || value != "http://device.local/desc.xml" {
		t.Fatalf("normalized LOCATION = %q, %t", value, ok)
	}
	if value, ok := normalizeSSDPLocation("http://device.local/desc.xml?" + strings.Repeat("q", maxSSDPQueryBytes+1)); ok || value != "" {
		t.Fatalf("oversized query LOCATION accepted as %q", value)
	}
	if value, ok := normalizeSSDPLocation("file:///etc/passwd"); ok || value != "" {
		t.Fatalf("non-HTTP LOCATION accepted as %q", value)
	}

	message := "NOTIFY * HTTP/1.1\r\nLOCATION: http://device.local/desc.xml?tracking=1#fragment\r\nSERVER: demo\r\n\r\n"
	items, err := decodeSSDP([]byte(message), testMAC.String(), "192.0.2.10", nil, testAt)
	if err != nil {
		t.Fatalf("decodeSSDP() error = %v", err)
	}
	for _, item := range items {
		if strings.Contains(item.Value, "?") || strings.Contains(item.Value, "#") || strings.Contains(item.Value, "@") {
			t.Fatalf("unsafe SSDP evidence persisted: %+v", item)
		}
	}
	if _, err := decodeSSDP([]byte("INVALID\r\n"), testMAC.String(), "192.0.2.10", nil, testAt); err == nil {
		t.Fatal("decodeSSDP() accepted malformed start line")
	}
	oversizedLine := "NOTIFY * HTTP/1.1\r\nSERVER: " + strings.Repeat("x", maxSSDPLineBytes+1)
	if _, err := decodeSSDP([]byte(oversizedLine), testMAC.String(), "192.0.2.10", nil, testAt); err == nil {
		t.Fatal("decodeSSDP() accepted oversized header line")
	}
}

func TestNBNSRejectsInvalidNames(t *testing.T) {
	for _, value := range []string{"short", strings.Repeat("Z", 32), strings.Repeat("A", 32)} {
		if _, err := decodeNetBIOSName(value); err == nil {
			t.Errorf("decodeNetBIOSName(%q) unexpectedly succeeded", value)
		}
	}
}

func TestRandomMalformedFramesNeverPanic(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	for index := 0; index < 1000; index++ {
		frame := make([]byte, random.Intn(512))
		_, _ = random.Read(frame)
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("Frame() panicked for malformed seed %d: %v", index, recovered)
				}
			}()
			_, _ = Frame(frame, testAt)
		}()
	}
}

func TestFrameDecodesTaggedProtocolEvidence(t *testing.T) {
	dns := make([]byte, 12)
	binary.BigEndian.PutUint16(dns[4:6], 1)
	dns = append(dns, 4, 'd', 'e', 'm', 'o', 5, 'l', 'o', 'c', 'a', 'l', 0, 0, 1, 0, 1)
	inner := ipv4UDPForTest(5353, 5353, dns)
	frame := ethernetForTest(0x8100, append([]byte{0, 100, 0x08, 0x00}, inner...))
	items, err := Frame(frame, testAt)
	if err != nil {
		t.Fatalf("Frame() error = %v", err)
	}
	if len(items) == 0 || items[0].VLANID == nil || *items[0].VLANID != 100 || items[0].Protocol != "mdns" {
		t.Fatalf("tagged evidence = %+v", items)
	}
}
