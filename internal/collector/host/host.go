package host

import (
	"os"
	"strings"
	"time"

	"github.com/openassetwatch/openassetwatch/pkg/models"
)

const sourceHostname = "os_hostname"

func Detect() models.HostObservation {
	return DetectAt(time.Now().UTC())
}

func DetectAt(collectedAt time.Time) models.HostObservation {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	hostname = strings.TrimSpace(hostname)

	return models.HostObservation{
		Hostname:    hostname,
		FQDN:        fqdnFromHostname(hostname),
		Source:      sourceHostname,
		CollectedAt: collectedAt,
	}
}

func fqdnFromHostname(hostname string) string {
	value := strings.Trim(strings.TrimSpace(hostname), ".")
	if !strings.Contains(value, ".") {
		return ""
	}
	return value
}
