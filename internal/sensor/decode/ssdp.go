package decode

import (
	"errors"
	"net/url"
	"strings"
	"time"
)

const (
	maxSSDPLineBytes     = 1024
	maxSSDPMetadataBytes = 256
	maxSSDPQueryBytes    = 128
)

func decodeSSDP(data []byte, mac, sourceIP string, vlanID *int, observedAt time.Time) ([]Evidence, error) {
	if err := requireDataLimit(data); err != nil {
		return nil, err
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || len(lines) > 64 {
		return nil, errors.New("invalid SSDP line count")
	}
	if len(lines[0]) == 0 || len(lines[0]) > 128 {
		return nil, errors.New("invalid SSDP start line")
	}
	first := strings.ToUpper(clean(lines[0], 128))
	if !(strings.HasPrefix(first, "NOTIFY ") || strings.HasPrefix(first, "M-SEARCH ") || strings.HasPrefix(first, "HTTP/1.1 ")) {
		return nil, errors.New("unsupported SSDP start line")
	}
	allowed := map[string]string{
		"LOCATION": "location",
		"SERVER":   "server",
		"ST":       "search-target",
		"NT":       "notification-type",
		"USN":      "unique-service-name",
	}
	evidence := make([]Evidence, 0, len(allowed))
	for _, line := range lines[1:] {
		if len(line) > maxSSDPLineBytes {
			return nil, errors.New("SSDP header line exceeds limit")
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		if len(name) == 0 || len(name) > 64 {
			continue
		}
		kind, wanted := allowed[strings.ToUpper(strings.TrimSpace(name))]
		if !wanted {
			continue
		}
		value = clean(value, maxSSDPMetadataBytes)
		if value == "" {
			continue
		}
		if kind == "location" {
			var ok bool
			value, ok = normalizeSSDPLocation(value)
			if !ok {
				continue
			}
		}
		// LOCATION is evidence only. Neither the sensor nor the hub dereferences it.
		evidence = append(evidence, protocolEvidence(mac, sourceIP, "ssdp", kind, value, vlanID, 0.6, observedAt))
		if len(evidence) >= 8 {
			break
		}
	}
	return evidence, nil
}

// normalizeSSDPLocation treats LOCATION as untrusted evidence. It is never
// fetched. Userinfo, fragments, and query strings are removed so credentials
// and tracking data cannot be persisted in an observation batch.
func normalizeSSDPLocation(value string) (string, bool) {
	if len(value) == 0 || len(value) > maxSSDPLineBytes {
		return "", false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Opaque != "" {
		return "", false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	if len(parsed.RawQuery) > maxSSDPQueryBytes {
		return "", false
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.RawFragment = ""
	result := clean(parsed.String(), maxSSDPMetadataBytes)
	return result, result != ""
}
