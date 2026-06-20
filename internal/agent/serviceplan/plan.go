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
	StateDir              string           `json:"state_dir"`
	LogDir                string           `json:"log_dir"`
	StatusPath            string           `json:"status_file_path"`
	ServiceDefinitionPath string           `json:"service_definition_path,omitempty"`
	LinuxDeployment       *LinuxDeployment `json:"linux_deployment,omitempty"`
	Notes                 []string         `json:"notes"`
}

type Template struct {
	ServiceTarget string   `json:"service_target"`
	ServiceName   string   `json:"service_name"`
	TemplateType  string   `json:"template_type"`
	Template      string   `json:"template"`
	Warnings      []string `json:"warnings"`
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
		StateDir:     strings.TrimSpace(paths.StateDir),
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
		plan.BinaryPath = `C:\Program Files\OpenAssetWatch\Agent\bin\oaw-agent.exe`
		plan.ServiceDefinitionPath = "Windows Service Control Manager: OpenAssetWatchAgent"
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

func BuildTemplate(plan Plan) Template {
	warnings := []string{
		"template only; this command does not install, start, stop, schedule, or modify services",
		"review and adapt the template before any future signed installer or administrator action",
	}

	switch plan.OS {
	case "windows":
		return Template{
			ServiceTarget: plan.ServiceTarget,
			ServiceName:   plan.ServiceName,
			TemplateType:  "windows_service_metadata",
			Template:      windowsTemplate(plan),
			Warnings:      warnings,
		}
	case "linux":
		return Template{
			ServiceTarget: plan.ServiceTarget,
			ServiceName:   plan.ServiceName,
			TemplateType:  "systemd_unit",
			Template:      systemdTemplate(plan),
			Warnings:      warnings,
		}
	case "darwin":
		return Template{
			ServiceTarget: plan.ServiceTarget,
			ServiceName:   plan.ServiceName,
			TemplateType:  "launchd_plist",
			Template:      launchdTemplate(plan),
			Warnings:      warnings,
		}
	default:
		return Template{
			ServiceTarget: plan.ServiceTarget,
			ServiceName:   plan.ServiceName,
			TemplateType:  "manual_plan",
			Template:      manualTemplate(plan),
			Warnings:      warnings,
		}
	}
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

func windowsTemplate(plan Plan) string {
	return strings.Join([]string{
		"# OpenAssetWatch Agent Windows Service metadata template",
		"# Text only. This command does not run New-Service, sc.exe, or service control commands.",
		"ServiceName: " + plan.ServiceName,
		"DisplayName: OpenAssetWatch Agent",
		"ServiceTarget: " + plan.ServiceTarget,
		"BinaryPath: \"" + plan.BinaryPath + "\" service run --config \"" + plan.ConfigPath + "\" --identity-file \"" + plan.IdentityPath + "\" --output-dir \"" + plan.StateDir + "\"",
		"ConfigPath: " + plan.ConfigPath,
		"IdentityPath: " + plan.IdentityPath,
		"StateDirectory: " + plan.StateDir,
		"LogDirectory: " + plan.LogDir,
		"StatusFile: " + plan.StatusPath,
		"StartupType: Automatic delayed start through MSI or administrator action",
		"RestartPolicy: Bounded recovery for process failure; runtime failures degrade and retry internally",
		"# Example administrator action, not executed by oaw-agent service template:",
		"# New-Service -Name \"" + plan.ServiceName + "\" -BinaryPathName \"<reviewed binary path>\" -StartupType Automatic",
	}, "\n")
}

func systemdTemplate(plan Plan) string {
	return strings.Join([]string{
		"# OpenAssetWatch Agent future systemd unit template",
		"# Text only. This command does not write unit files or run systemctl.",
		"[Unit]",
		"Description=OpenAssetWatch Agent",
		"Documentation=https://github.com/PKXLIVE/openassetwatch",
		"After=network-online.target",
		"Wants=network-online.target",
		"",
		"[Service]",
		"Type=simple",
		"User=openassetwatch",
		"Group=openassetwatch",
		"ExecStart=" + plan.BinaryPath + " service run --config " + plan.ConfigPath + " --identity-file " + plan.IdentityPath,
		"Restart=on-failure",
		"RestartSec=300",
		"NoNewPrivileges=true",
		"PrivateTmp=true",
		"ProtectSystem=strict",
		"ReadWritePaths=" + plan.LogDir,
		"Environment=OAW_AGENT_STATUS_FILE=" + plan.StatusPath,
		"# Scheduling is intentionally not configured in this template.",
		"# Future service mode should use conservative bounded retry/backoff.",
		"",
		"[Install]",
		"WantedBy=multi-user.target",
	}, "\n")
}

func launchdTemplate(plan Plan) string {
	return strings.Join([]string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`,
		`<!-- OpenAssetWatch Agent future launchd plist template. Text only; this command does not write plist files or run launchctl. -->`,
		`<plist version="1.0">`,
		`<dict>`,
		`  <key>Label</key>`,
		`  <string>` + plan.ServiceName + `</string>`,
		`  <key>ProgramArguments</key>`,
		`  <array>`,
		`    <string>` + plan.BinaryPath + `</string>`,
		`    <string>service</string>`,
		`    <string>run</string>`,
		`    <string>--config</string>`,
		`    <string>` + plan.ConfigPath + `</string>`,
		`    <string>--identity-file</string>`,
		`    <string>` + plan.IdentityPath + `</string>`,
		`  </array>`,
		`  <key>RunAtLoad</key>`,
		`  <false/>`,
		`  <key>KeepAlive</key>`,
		`  <false/>`,
		`  <key>StandardOutPath</key>`,
		`  <string>` + path.Join(plan.LogDir, "agent.out.log") + `</string>`,
		`  <key>StandardErrorPath</key>`,
		`  <string>` + path.Join(plan.LogDir, "agent.err.log") + `</string>`,
		`  <!-- Status file: ` + plan.StatusPath + ` -->`,
		`  <!-- Scheduling is intentionally not configured in this template. -->`,
		`</dict>`,
		`</plist>`,
	}, "\n")
}

func manualTemplate(plan Plan) string {
	return strings.Join([]string{
		"# OpenAssetWatch Agent manual service planning template",
		"# Text only. This command does not install, start, stop, or schedule services.",
		"ServiceName: " + plan.ServiceName,
		"ServiceTarget: " + plan.ServiceTarget,
		"BinaryPath: " + plan.BinaryPath,
		"ConfigPath: " + plan.ConfigPath,
		"IdentityPath: " + plan.IdentityPath,
		"LogDirectory: " + plan.LogDir,
		"StatusFile: " + plan.StatusPath,
	}, "\n")
}
