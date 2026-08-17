package decode

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const maxDNSRecords = 64

type dnsRecord struct {
	name   string
	type_  uint16
	data   []byte
	offset int
}

func decodeDNS(data []byte, protocol, mac, sourceIP string, vlanID *int, observedAt time.Time) ([]Evidence, error) {
	if err := requireDataLimit(data); err != nil {
		return nil, err
	}
	if len(data) < 12 {
		return nil, errors.New("truncated DNS message")
	}
	questionCount := int(binary.BigEndian.Uint16(data[4:6]))
	answerCount := int(binary.BigEndian.Uint16(data[6:8]))
	authorityCount := int(binary.BigEndian.Uint16(data[8:10]))
	additionalCount := int(binary.BigEndian.Uint16(data[10:12]))
	if questionCount+answerCount+authorityCount+additionalCount > maxDNSRecords {
		return nil, errors.New("DNS record count exceeds limit")
	}
	offset := 12
	evidence := make([]Evidence, 0, min(questionCount+answerCount, 16))
	for index := 0; index < questionCount; index++ {
		name, next, err := readDNSName(data, offset)
		if err != nil {
			return nil, err
		}
		if next+4 > len(data) {
			return nil, errors.New("truncated DNS question")
		}
		offset = next + 4
		if name != "" && len(evidence) < 16 {
			evidence = append(evidence, protocolEvidence(mac, sourceIP, protocol, "query-name", name, vlanID, 0.4, observedAt))
		}
	}
	totalRecords := answerCount + authorityCount + additionalCount
	for index := 0; index < totalRecords; index++ {
		name, next, err := readDNSName(data, offset)
		if err != nil {
			return nil, err
		}
		if next+10 > len(data) {
			return nil, errors.New("truncated DNS resource record")
		}
		recordType := binary.BigEndian.Uint16(data[next : next+2])
		rdataLength := int(binary.BigEndian.Uint16(data[next+8 : next+10]))
		rdataOffset := next + 10
		if rdataLength > 4096 || rdataOffset+rdataLength > len(data) {
			return nil, errors.New("truncated or oversized DNS resource data")
		}
		record := dnsRecord{name: name, type_: recordType, data: data[rdataOffset : rdataOffset+rdataLength], offset: rdataOffset}
		items, err := dnsRecordEvidence(data, record, protocol, mac, sourceIP, vlanID, observedAt)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if len(evidence) >= 32 {
				break
			}
			evidence = append(evidence, item)
		}
		offset = rdataOffset + rdataLength
	}
	return evidence, nil
}

func dnsRecordEvidence(message []byte, record dnsRecord, protocol, mac, sourceIP string, vlanID *int, observedAt time.Time) ([]Evidence, error) {
	switch record.type_ {
	case 1:
		if len(record.data) != 4 {
			return nil, errors.New("invalid DNS A record length")
		}
		address := net.IP(record.data).String()
		item := protocolEvidence(mac, sourceIP, protocol, "address-record", record.name+"="+address, vlanID, 0.75, observedAt)
		if protocol == "mdns" && address == sourceIP {
			item.IP = address
			item.Hostname = record.name
			item.Confidence = 0.85
		}
		return []Evidence{item}, nil
	case 5, 12:
		name, _, err := readDNSName(message, record.offset)
		if err != nil {
			return nil, err
		}
		kind := "canonical-name"
		if record.type_ == 12 {
			kind = "service-name"
		}
		return []Evidence{protocolEvidence(mac, sourceIP, protocol, kind, name, vlanID, 0.65, observedAt)}, nil
	case 33:
		if len(record.data) < 7 {
			return nil, errors.New("truncated DNS SRV record")
		}
		target, _, err := readDNSName(message, record.offset+6)
		if err != nil {
			return nil, err
		}
		port := binary.BigEndian.Uint16(record.data[4:6])
		value := fmt.Sprintf("%s:%d", target, port)
		return []Evidence{protocolEvidence(mac, sourceIP, protocol, "service-target", value, vlanID, 0.65, observedAt)}, nil
	default:
		return nil, nil
	}
}

func readDNSName(data []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(data) {
		return "", 0, errors.New("DNS name offset is out of bounds")
	}
	labels := make([]string, 0, 8)
	visited := make(map[int]struct{})
	cursor := offset
	next := -1
	for steps := 0; steps < 32; steps++ {
		if cursor >= len(data) {
			return "", 0, errors.New("truncated DNS name")
		}
		length := int(data[cursor])
		if length == 0 {
			cursor++
			if next < 0 {
				next = cursor
			}
			name := clean(strings.Join(labels, "."), 255)
			return name, next, nil
		}
		if length&0xc0 == 0xc0 {
			if cursor+1 >= len(data) {
				return "", 0, errors.New("truncated DNS compression pointer")
			}
			pointer := (length&0x3f)<<8 | int(data[cursor+1])
			if pointer >= len(data) {
				return "", 0, errors.New("DNS compression pointer is out of bounds")
			}
			if _, exists := visited[pointer]; exists {
				return "", 0, errors.New("DNS compression pointer loop")
			}
			visited[pointer] = struct{}{}
			if next < 0 {
				next = cursor + 2
			}
			cursor = pointer
			continue
		}
		if length&0xc0 != 0 || length > 63 {
			return "", 0, errors.New("invalid DNS label length")
		}
		cursor++
		if cursor+length > len(data) {
			return "", 0, errors.New("truncated DNS label")
		}
		label := clean(string(data[cursor:cursor+length]), 63)
		if label == "" {
			return "", 0, errors.New("empty DNS label after sanitization")
		}
		labels = append(labels, label)
		if len(strings.Join(labels, ".")) > 255 {
			return "", 0, errors.New("DNS name exceeds 255 characters")
		}
		cursor += length
	}
	return "", 0, errors.New("DNS name exceeds compression or label limit")
}

func decodeNBNS(data []byte, mac, sourceIP string, vlanID *int, observedAt time.Time) ([]Evidence, error) {
	if err := requireDataLimit(data); err != nil {
		return nil, err
	}
	if len(data) < 12 {
		return nil, errors.New("truncated NBNS message")
	}
	count := int(binary.BigEndian.Uint16(data[4:6])) + int(binary.BigEndian.Uint16(data[6:8]))
	if count == 0 || count > maxDNSRecords {
		return nil, errors.New("invalid NBNS name count")
	}
	name, _, err := readDNSName(data, 12)
	if err != nil {
		return nil, err
	}
	hostname, err := decodeNetBIOSName(strings.Split(name, ".")[0])
	if err != nil {
		return nil, err
	}
	item := protocolEvidence(mac, sourceIP, "nbns", "netbios-name", hostname, vlanID, 0.75, observedAt)
	item.Hostname = hostname
	return []Evidence{item}, nil
}

func decodeNetBIOSName(value string) (string, error) {
	if len(value) != 32 {
		return "", errors.New("invalid encoded NetBIOS name length")
	}
	decoded := make([]byte, 16)
	for index := 0; index < 16; index++ {
		high := value[index*2]
		low := value[index*2+1]
		if high < 'A' || high > 'P' || low < 'A' || low > 'P' {
			return "", errors.New("invalid encoded NetBIOS name")
		}
		decoded[index] = (high-'A')<<4 | (low - 'A')
	}
	name := clean(strings.TrimSpace(string(decoded[:15])), 15)
	if name == "" {
		return "", errors.New("empty decoded NetBIOS name")
	}
	return name, nil
}
