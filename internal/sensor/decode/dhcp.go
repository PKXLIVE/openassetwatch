package decode

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"
)

var dhcpMagicCookie = []byte{99, 130, 83, 99}

func decodeDHCP(data []byte, vlanID *int, observedAt time.Time) ([]Evidence, error) {
	if len(data) < 240 || !bytes.Equal(data[236:240], dhcpMagicCookie) {
		return nil, errors.New("truncated or invalid DHCPv4 message")
	}
	hardwareLength := int(data[2])
	if hardwareLength != 6 {
		return nil, errors.New("unsupported DHCPv4 hardware address length")
	}
	mac := net.HardwareAddr(data[28:34]).String()
	if !validMAC(mac) {
		return nil, errors.New("invalid DHCPv4 client MAC")
	}
	options, err := parseDHCPOptions(data[240:])
	if err != nil {
		return nil, err
	}
	evidence := make([]Evidence, 0, 4)
	ip := ""
	if requested := options[50]; len(requested) == 4 {
		ip = net.IP(requested).String()
		evidence = append(evidence, protocolEvidence(mac, ip, "dhcpv4", "requested-ip", ip, vlanID, 0.75, observedAt))
	} else if yiaddr := net.IP(data[16:20]); !yiaddr.Equal(net.IPv4zero) {
		ip = yiaddr.String()
		evidence = append(evidence, protocolEvidence(mac, ip, "dhcpv4", "assigned-ip", ip, vlanID, 0.9, observedAt))
	}
	if hostname := clean(string(options[12]), 255); hostname != "" {
		item := protocolEvidence(mac, ip, "dhcpv4", "client-hostname", hostname, vlanID, 0.9, observedAt)
		item.Hostname = hostname
		evidence = append(evidence, item)
	}
	if vendor := clean(string(options[60]), 160); vendor != "" {
		evidence = append(evidence, protocolEvidence(mac, ip, "dhcpv4", "vendor-class", vendor, vlanID, 0.65, observedAt))
	}
	if len(evidence) == 0 {
		evidence = append(evidence, protocolEvidence(mac, ip, "dhcpv4", "client", mac, vlanID, 0.7, observedAt))
	}
	return evidence, nil
}

func parseDHCPOptions(data []byte) (map[byte][]byte, error) {
	options := make(map[byte][]byte)
	for offset, count := 0, 0; offset < len(data) && count < 128; count++ {
		code := data[offset]
		offset++
		if code == 0 {
			continue
		}
		if code == 255 {
			return options, nil
		}
		if offset >= len(data) {
			return nil, errors.New("truncated DHCPv4 option length")
		}
		length := int(data[offset])
		offset++
		if length > 512 || offset+length > len(data) {
			return nil, errors.New("truncated or oversized DHCPv4 option")
		}
		if _, exists := options[code]; !exists {
			options[code] = append([]byte(nil), data[offset:offset+length]...)
		}
		offset += length
	}
	if len(data) > 0 {
		return nil, fmt.Errorf("DHCPv4 options exceed bounded option count")
	}
	return options, nil
}
