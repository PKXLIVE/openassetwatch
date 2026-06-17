package platform

import (
	"runtime"
	"strings"
	"time"

	"github.com/openassetwatch/openassetwatch/pkg/models"
)

const sourceRuntime = "go_runtime"

func Detect() models.PlatformObservation {
	return DetectAt(time.Now().UTC())
}

func DetectAt(collectedAt time.Time) models.PlatformObservation {
	arch := strings.ToLower(runtime.GOARCH)
	osName := strings.ToLower(runtime.GOOS)

	return models.PlatformObservation{
		OS:                 osName,
		Platform:           osName + "/" + arch,
		Architecture:       arch,
		ArchitectureFamily: ArchitectureFamily(arch),
		Source:             sourceRuntime,
		CollectedAt:        collectedAt,
	}
}

func ArchitectureFamily(architecture string) string {
	switch strings.ToLower(strings.TrimSpace(architecture)) {
	case "amd64", "x64", "x86_64":
		return "x86_64"
	case "386", "i386", "i686", "x86":
		return "x86"
	case "arm64", "arm64e", "aarch64":
		return "arm64"
	case "arm", "armel", "armhf", "armv5", "armv5l", "armv6", "armv6l", "armv7", "armv7a", "armv7l":
		return "arm"
	default:
		if architecture == "" {
			return "unknown"
		}
		return strings.ToLower(strings.TrimSpace(architecture))
	}
}
