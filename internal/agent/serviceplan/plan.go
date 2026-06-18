package serviceplan

import (
	"path"
	"runtime"
	"strconv"
	"strings"

	agentpaths "github.com/openassetwatch/openassetwatch/internal/agent/paths"
)

const (
	ServiceName = "openassetwatch-agent"
)

type Plan struct {
	OS                    string           `json:"os"`
	ServiceTarget         string           `json:"service_target"`
	ServiceName           string           `json:"service_name"`
	BinaryPath            string           `json:"binary_path"`
	ConfigPath            string           `json:"config_path"`
	IdentityPath          string           `json:"identity_path"`
	LogDir                string           `json:"log_dir"`
	StatusPath            string           `json:"status_file_path"`
	ServiceDefinitionPath string           `json:"service_definition_path,omitempty"`
	LinuxDeployment       *LinuxDeployment `json:"linux_deployment,omitempty"`
	Notes                 []string         `json:"notes"`
}

type LinuxDeployment struct {
	OSReleasePath  string   `json:"os_release_path"`
	ID             string   `json:"id,omitempty"`
	IDLike         []string `json:"id_like,omitempty"`
	VersionID      string   `json:"version_id,omitempty"`
	PackageFamily  string   `json:"package_family"`
	Recommendation string   `json:"recommendation"`
}

type OSRelease struct {
	ID        string
	IDLike    []string
	VersionID string
}

func Build(goos string, paths agentpaths.AgentPaths, osReleaseData []byte) Plan {
	goos = strings.TrimSpace(goos)
	if goos == "" {
		goos = runtime.GOOS
	}

	plan := Plan{
		OS:           goos,
		ServiceName:  ServiceName,
		ConfigPath:   strings.TrimSpace(paths.ConfigPath),
		IdentityPath: strings.TrimSpace(paths.IdentityPath),
		LogDir:       strings.TrimSpace(paths.LogDir),
		StatusPath:   strings.TrimSpace(paths.StatusPath),
		Notes: []string{
			"plan only; no files, directories, services, schedules, or packages are modified",
		},
	}

	switch goos {
	case "windows":
		plan.ServiceTarget = "Windows Service"
		plan.ServiceName = "OpenAssetWatchAgent"
		plan.BinaryPath = `C:\Program Files\OpenAssetWatch\oaw-agent.exe`
	case "linux":
		plan.ServiceTarget = "systemd"
		plan.BinaryPath = path.Join("/", "usr", "bin", "oaw-agent")
		plan.ServiceDefinitionPath = path.Join("/", "etc", "systemd", "system", "openassetwatch-agent.service")
		osRelease := ParseOSRelease(osReleaseData)
		family, recommendation := LinuxPackageFamily(osRelease)
		plan.LinuxDeployment = &LinuxDeployment{
			OSReleasePath:  "/etc/os-release",
			ID:             osRelease.ID,
			IDLike:         osRelease.IDLike,
			VersionID:      osRelease.VersionID,
			PackageFamily:  family,
			Recommendation: recommendation,
		}
	case "darwin":
		plan.ServiceTarget = "launchd"
		plan.ServiceName = "com.openassetwatch.agent"
		plan.BinaryPath = path.Join("/", "usr", "local", "bin", "oaw-agent")
		plan.ServiceDefinitionPath = path.Join("/", "Library", "LaunchDaemons", "com.openassetwatch.agent.plist")
	default:
		plan.ServiceTarget = "manual"
		plan.BinaryPath = "oaw-agent"
		plan.Notes = append(plan.Notes, "service target is not defined for this operating system")
	}

	return plan
}

func ParseOSRelease(data []byte) OSRelease {
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if decoded, err := strconv.Unquote(value); err == nil {
			value = decoded
		}
		values[key] = value
	}

	return OSRelease{
		ID:        strings.ToLower(strings.TrimSpace(values["ID"])),
		IDLike:    splitOSReleaseList(values["ID_LIKE"]),
		VersionID: strings.TrimSpace(values["VERSION_ID"]),
	}
}

func LinuxPackageFamily(osRelease OSRelease) (string, string) {
	ids := append([]string{osRelease.ID}, osRelease.IDLike...)
	if containsAny(ids, "debian", "ubuntu") {
		return "deb", "signed deb package"
	}
	if containsAny(ids, "rhel", "rocky", "almalinux", "centos", "fedora", "suse", "opensuse", "opensuse-leap", "sles") {
		return "rpm", "signed rpm package"
	}
	return "tar.gz/manual", "signed tar.gz archive or manual install"
}

func splitOSReleaseList(value string) []string {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(value)))
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func containsAny(values []string, candidates ...string) bool {
	for _, value := range values {
		for _, candidate := range candidates {
			if value == candidate {
				return true
			}
		}
	}
	return false
}
