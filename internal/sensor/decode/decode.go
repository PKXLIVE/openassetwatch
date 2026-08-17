package decode

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxFrameBytes   = 65535
	maxUDPPayload   = 16384
	maxProtocolData = 8192
)

type Evidence struct {
	MAC        string
	IP         string
	Hostname   string
	Protocol   string
	Kind       string
	Value      string
	VLANID     *int
	Confidence float64
	ObservedAt time.Time
}

type ethernetFrame struct {
	sourceMAC net.HardwareAddr
	destMAC   net.HardwareAddr
	etherType uint16
	payload   []byte
	vlanID    *int
}

func Frame(frame []byte, observedAt time.Time) ([]Evidence, error) {
	if len(frame) < 14 {
		return nil, errors.New("truncated Ethernet frame")
	}
	if len(frame) > maxFrameBytes {
		return nil, errors.New("Ethernet frame exceeds size limit")
	}
	parsed, err := parseEthernet(frame)
	if err != nil {
		return nil, err
	}
	switch parsed.etherType {
	case 0x0806:
		return decodeARP(parsed, observedAt)
	case 0x0800:
		return decodeIPv4(parsed, observedAt)
	default:
		return nil, nil
	}
}

func parseEthernet(frame []byte) (ethernetFrame, error) {
	parsed := ethernetFrame{
		destMAC:   append(net.HardwareAddr(nil), frame[0:6]...),
		sourceMAC: append(net.HardwareAddr(nil), frame[6:12]...),
		etherType: binary.BigEndian.Uint16(frame[12:14]),
		payload:   frame[14:],
	}
	for tags := 0; parsed.etherType == 0x8100 || parsed.etherType == 0x88a8; tags++ {
		if tags >= 2 {
			return ethernetFrame{}, errors.New("too many nested VLAN tags")
		}
		if len(parsed.payload) < 4 {
			return ethernetFrame{}, errors.New("truncated VLAN tag")
		}
		vlan := int(binary.BigEndian.Uint16(parsed.payload[0:2]) & 0x0fff)
		parsed.vlanID = &vlan
		parsed.etherType = binary.BigEndian.Uint16(parsed.payload[2:4])
		parsed.payload = parsed.payload[4:]
	}
	return parsed, nil
}

func decodeARP(frame ethernetFrame, observedAt time.Time) ([]Evidence, error) {
	payload := frame.payload
	if len(payload) < 28 {
		return nil, errors.New("truncated ARP packet")
	}
	if binary.BigEndian.Uint16(payload[0:2]) != 1 || binary.BigEndian.Uint16(payload[2:4]) != 0x0800 || payload[4] != 6 || payload[5] != 4 {
		return nil, errors.New("unsupported ARP address format")
	}
	operation := binary.BigEndian.Uint16(payload[6:8])
	if operation != 1 && operation != 2 {
		return nil, errors.New("unsupported ARP operation")
	}
	mac := net.HardwareAddr(payload[8:14]).String()
	ip := net.IP(payload[14:18]).String()
	if !validMAC(mac) || net.ParseIP(ip) == nil {
		return nil, errors.New("invalid ARP sender identity")
	}
	kind := "request"
	if operation == 2 {
		kind = "reply"
	}
	return []Evidence{{
		MAC: mac, IP: ip, Protocol: "arp", Kind: kind, Value: ip,
		VLANID: frame.vlanID, Confidence: 0.9, ObservedAt: observedAt.UTC(),
	}}, nil
}

func decodeIPv4(frame ethernetFrame, observedAt time.Time) ([]Evidence, error) {
	payload := frame.payload
	if len(payload) < 20 || payload[0]>>4 != 4 {
		return nil, errors.New("truncated or invalid IPv4 packet")
	}
	headerLength := int(payload[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(payload) {
		return nil, errors.New("invalid IPv4 header length")
	}
	totalLength := int(binary.BigEndian.Uint16(payload[2:4]))
	if totalLength < headerLength || totalLength > len(payload) {
		return nil, errors.New("invalid IPv4 total length")
	}
	if payload[9] != 17 {
		return nil, nil
	}
	udp := payload[headerLength:totalLength]
	if len(udp) < 8 {
		return nil, errors.New("truncated UDP datagram")
	}
	udpLength := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLength < 8 || udpLength > len(udp) || udpLength-8 > maxUDPPayload {
		return nil, errors.New("invalid or oversized UDP length")
	}
	sourcePort := binary.BigEndian.Uint16(udp[0:2])
	destPort := binary.BigEndian.Uint16(udp[2:4])
	data := udp[8:udpLength]
	sourceIP := net.IP(payload[12:16]).String()
	mac := frame.sourceMAC.String()
	if !validMAC(mac) {
		return nil, errors.New("invalid Ethernet source MAC")
	}
	switch {
	case sourcePort == 67 || sourcePort == 68 || destPort == 67 || destPort == 68:
		return decodeDHCP(data, frame.vlanID, observedAt)
	case sourcePort == 5353 || destPort == 5353:
		return decodeDNS(data, "mdns", mac, sourceIP, frame.vlanID, observedAt)
	case sourcePort == 53 || destPort == 53:
		return decodeDNS(data, "dns", mac, sourceIP, frame.vlanID, observedAt)
	case sourcePort == 1900 || destPort == 1900:
		return decodeSSDP(data, mac, sourceIP, frame.vlanID, observedAt)
	case sourcePort == 137 || destPort == 137:
		return decodeNBNS(data, mac, sourceIP, frame.vlanID, observedAt)
	default:
		return nil, nil
	}
}

func clean(value string, limit int) string {
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "")
	}
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u007f' {
			return -1
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8.RuneStart(value[limit]) {
		limit--
	}
	return strings.TrimSpace(value[:limit])
}

func validMAC(value string) bool {
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 {
		return false
	}
	zero := true
	for _, octet := range mac {
		zero = zero && octet == 0
	}
	return !zero
}

func protocolEvidence(mac, ip, protocol, kind, value string, vlanID *int, confidence float64, observedAt time.Time) Evidence {
	return Evidence{
		MAC: mac, IP: ip, Protocol: protocol, Kind: clean(kind, 64), Value: clean(value, 512),
		VLANID: vlanID, Confidence: confidence, ObservedAt: observedAt.UTC(),
	}
}

func requireDataLimit(data []byte) error {
	if len(data) > maxProtocolData {
		return fmt.Errorf("protocol payload exceeds %d bytes", maxProtocolData)
	}
	return nil
}
