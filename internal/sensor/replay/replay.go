// Package replay provides bounded, deterministic packet fixtures for sensor
// demonstrations and tests. Fixtures are synthetic bytes only; they are never
// read from an interface and are not persisted by this package.
package replay

import (
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/openassetwatch/openassetwatch/internal/sensor/capture"
)

const (
	// MaxFrames is the largest fixture set produced by this package.
	MaxFrames = 16
	// MaxFrameBytes mirrors the decoder/capture bound and protects callers that
	// accidentally append a fixture to another replay set.
	MaxFrameBytes = capture.MaxFrameBytes
	// DemoObservedAt anchors replay timestamps, making its batch ID stable.
	DemoObservedAtUnix = 1735689600
)

var DemoObservedAt = time.Unix(DemoObservedAtUnix, 0).UTC()

var (
	demoMAC   = net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x20, 0x30}
	demoIP    = net.IPv4(192, 0, 2, 40)
	broadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

// SyntheticPackets returns a stable set of Ethernet frames covering every
// protocol currently decoded by the passive sensor. Timestamps are derived
// from observedAt and are deterministic for a given input.
func SyntheticPackets(observedAt time.Time) []capture.Packet {
	base := observedAt.UTC()
	if base.IsZero() {
		base = time.Unix(0, 0).UTC()
	}
	frames := [][]byte{
		arpFrame(),
		dhcpFrame(),
		dnsFrame(53, "dns", "printer.example.test"),
		dnsFrame(5353, "mdns", "printer.local"),
		ssdpFrame(),
		nbnsFrame(),
	}
	packets := make([]capture.Packet, 0, len(frames))
	for index, frame := range frames {
		frame = vlanFrame(frame, 100)
		// Defensive copying makes the returned fixture set safe for callers to
		// mutate while preserving deterministic output from this function.
		data := append([]byte(nil), frame...)
		packets = append(packets, capture.Packet{Data: data, ObservedAt: base.Add(time.Duration(index) * time.Millisecond)})
	}
	return packets
}

func vlanFrame(frame []byte, vlanID uint16) []byte {
	if len(frame) < 14 {
		return nil
	}
	tagged := make([]byte, len(frame)+4)
	copy(tagged[0:12], frame[0:12])
	binary.BigEndian.PutUint16(tagged[12:14], 0x8100)
	binary.BigEndian.PutUint16(tagged[14:16], vlanID&0x0fff)
	copy(tagged[16:18], frame[12:14])
	copy(tagged[18:], frame[14:])
	return tagged
}

// NewSource returns a synthetic source backed by SyntheticPackets.
func NewSource(observedAt time.Time) *capture.Synthetic {
	return capture.NewSynthetic(SyntheticPackets(observedAt))
}

func ethernet(src, dst net.HardwareAddr, etherType uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)
	return frame
}

func arpFrame() []byte {
	payload := make([]byte, 28)
	binary.BigEndian.PutUint16(payload[0:2], 1)      // Ethernet
	binary.BigEndian.PutUint16(payload[2:4], 0x0800) // IPv4
	payload[4], payload[5] = 6, 4
	binary.BigEndian.PutUint16(payload[6:8], 1) // request
	copy(payload[8:14], demoMAC)
	copy(payload[14:18], demoIP.To4())
	copy(payload[18:24], make([]byte, 6))
	copy(payload[24:28], net.IPv4(192, 0, 2, 1).To4())
	return ethernet(demoMAC, broadcast, 0x0806, payload)
}

func dhcpFrame() []byte {
	// BOOTP fixed header (236 bytes), DHCP magic cookie, then bounded options.
	payload := make([]byte, 240)
	payload[0], payload[1], payload[2], payload[3] = 1, 1, 6, 0
	copy(payload[28:34], demoMAC)
	copy(payload[16:20], demoIP.To4())
	copy(payload[236:240], []byte{99, 130, 83, 99})
	options := []byte{50, 4, 192, 0, 2, 40, 12, byte(len("oaw-demo")), 'o', 'a', 'w', '-', 'd', 'e', 'm', 'o', 60, 8, 'o', 'a', 'w', '-', 'd', 'e', 'm', 'o', 255}
	return ethernet(demoMAC, broadcast, 0x0800, ipv4UDP(net.IPv4zero, net.IPv4bcast, 68, 67, append(payload, options...)))
}

func dnsFrame(port uint16, protocol, name string) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], 0x1234)
	binary.BigEndian.PutUint16(message[2:4], 0x8400)
	binary.BigEndian.PutUint16(message[4:6], 1) // one question
	binary.BigEndian.PutUint16(message[6:8], 1) // one answer
	for _, label := range strings.Split(name, ".") {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0, 0, 1, 0, 1) // A/IN
	message = append(message,
		0xc0, 0x0c, // pointer to the question name
		0, 1, // A
		0, 1, // IN
		0, 0, 0, 120, // TTL
		0, 4,
	)
	message = append(message, demoIP.To4()...)
	_ = protocol
	return ethernet(demoMAC, broadcast, 0x0800, ipv4UDP(demoIP, net.IPv4(224, 0, 0, 251), 40000, port, message))
}

func ssdpFrame() []byte {
	message := "NOTIFY * HTTP/1.1\r\nLOCATION: http://device.local:80/device.xml\r\nSERVER: OpenAssetWatch-Demo/1.0\r\nNT: upnp:rootdevice\r\nUSN: uuid:oaw-demo::upnp:rootdevice\r\n\r\n"
	return ethernet(demoMAC, broadcast, 0x0800, ipv4UDP(demoIP, net.IPv4(239, 255, 255, 250), 40001, 1900, []byte(message)))
}

func nbnsFrame() []byte {
	// NBNS uses the DNS wire name encoding. The decoder only needs a bounded
	// question name, so a minimal query is sufficient for the fixture.
	encoded := encodeNetBIOSName("OAW-DEMO")
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], 0x4321)
	binary.BigEndian.PutUint16(message[4:6], 1)
	message = append(message, byte(len(encoded)))
	message = append(message, encoded...)
	message = append(message, 0, 0x20, 0, 1) // NB (0x20), IN
	return ethernet(demoMAC, broadcast, 0x0800, ipv4UDP(demoIP, net.IPv4bcast, 40002, 137, message))
}

func encodeNetBIOSName(name string) []byte {
	name = strings.ToUpper(name)
	if len(name) > 15 {
		name = name[:15]
	}
	name = name + strings.Repeat(" ", 15-len(name)) + "\x00"
	encoded := make([]byte, 32)
	for index, value := range []byte(name) {
		encoded[index*2] = 'A' + (value >> 4)
		encoded[index*2+1] = 'A' + (value & 0x0f)
	}
	return encoded
}

func ipv4UDP(src, dst net.IP, srcPort, dstPort uint16, data []byte) []byte {
	udp := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	// UDP checksum is optional for IPv4 and deliberately left zero in a
	// synthetic fixture; the passive decoder does not rely on it.
	ip := make([]byte, 20+len(udp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	copy(ip[20:], udp)
	copy(ip[20+8:], data)
	return ip
}
