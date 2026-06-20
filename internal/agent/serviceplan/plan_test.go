package serviceplan

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	agentpaths "github.com/openassetwatch/openassetwatch/internal/agent/paths"
)

func TestBuildDetectsServiceTargetByOS(t *testing.T) {
	paths := fixturePaths(t)
	tests := []struct {
		goos          string
		wantTarget    string
		wantName      string
		wantDefSuffix string
	}{
		{goos: "windows", wantTarget: "Windows Service", wantName: "OpenAssetWatchAgent"},
		{goos: "linux", wantTarget: "systemd", wantName: "openassetwatch-agent", wantDefSuffix: path.Join("etc", "systemd", "system", "openassetwatch-agent.service")},
		{goos: "darwin", wantTarget: "launchd", wantName: "com.openassetwatch.agent", wantDefSuffix: path.Join("Library", "LaunchDaemons", "com.openassetwatch.agent.plist")},
	}

	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			plan := Build(tt.goos, paths, nil)
			if plan.ServiceTarget != tt.wantTarget {
				t.Fatalf("service target = %q, want %q", plan.ServiceTarget, tt.wantTarget)
			}
			if plan.ServiceName != tt.wantName {
				t.Fatalf("service name = %q, want %q", plan.ServiceName, tt.wantName)
			}
			if plan.BinaryPath == "" {
				t.Fatal("binary path is empty")
			}
			if tt.wantDefSuffix != "" && !strings.HasSuffix(plan.ServiceDefinitionPath, tt.wantDefSuffix) {
				t.Fatalf("service definition path = %q, want suffix %q", plan.ServiceDefinitionPath, tt.wantDefSuffix)
			}
		})
	}
}

func TestBuildReportsPlannedPaths(t *testing.T) {
	paths := fixturePaths(t)
	plan := Build("linux", paths, nil)

	if plan.ConfigPath != paths.ConfigPath {
		t.Fatalf("config path = %q, want %q", plan.ConfigPath, paths.ConfigPath)
	}
	if plan.IdentityPath != paths.IdentityPath {
		t.Fatalf("identity path = %q, want %q", plan.IdentityPath, paths.IdentityPath)
	}
	if plan.LogDir != paths.LogDir {
		t.Fatalf("log dir = %q, want %q", plan.LogDir, paths.LogDir)
	}
	if plan.StatusPath != paths.StatusPath {
		t.Fatalf("status path = %q, want %q", plan.StatusPath, paths.StatusPath)
	}
}

func TestLinuxPackageFamilyMapping(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "ubuntu", data: "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n", want: "deb"},
		{name: "debian", data: "ID=debian\nVERSION_ID=12\n", want: "deb"},
		{name: "rhel", data: "ID=rhel\nVERSION_ID=9\n", want: "rpm"},
		{name: "rocky", data: "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n", want: "rpm"},
		{name: "alma", data: "ID=almalinux\nID_LIKE=\"rhel centos fedora\"\n", want: "rpm"},
		{name: "centos", data: "ID=centos\nID_LIKE=rhel\n", want: "rpm"},
		{name: "fedora", data: "ID=fedora\n", want: "rpm"},
		{name: "suse", data: "ID=sles\nID_LIKE=suse\n", want: "rpm"},
		{name: "opensuse", data: "ID=opensuse-leap\nID_LIKE=\"suse opensuse\"\n", want: "rpm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osRelease := ParseOSRelease([]byte(tt.data))
			got, _ := LinuxPackageFamily(osRelease)
			if got != tt.want {
				t.Fatalf("package family = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUnknownLinuxMapsToManualArchive(t *testing.T) {
	osRelease := ParseOSRelease([]byte("ID=exampleos\nVERSION_ID=1\n"))
	got, recommendation := LinuxPackageFamily(osRelease)
	if got != "tar.gz/manual" {
		t.Fatalf("package family = %q, want tar.gz/manual", got)
	}
	if !strings.Contains(recommendation, "manual") {
		t.Fatalf("recommendation = %q, want manual fallback", recommendation)
	}
}

func TestBuildTemplateMapsCurrentOSTarget(t *testing.T) {
	paths := fixturePaths(t)
	tests := []struct {
		goos         string
		wantTarget   string
		wantTemplate string
	}{
		{goos: "windows", wantTarget: "Windows Service", wantTemplate: "windows_service_metadata"},
		{goos: "linux", wantTarget: "systemd", wantTemplate: "systemd_unit"},
		{goos: "darwin", wantTarget: "launchd", wantTemplate: "launchd_plist"},
	}

	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			template := BuildTemplate(Build(tt.goos, paths, nil))
			if template.ServiceTarget != tt.wantTarget {
				t.Fatalf("service target = %q, want %q", template.ServiceTarget, tt.wantTarget)
			}
			if template.TemplateType != tt.wantTemplate {
				t.Fatalf("template type = %q, want %q", template.TemplateType, tt.wantTemplate)
			}
			if template.ServiceName == "" || template.Template == "" {
				t.Fatalf("template missing service name or content: %+v", template)
			}
		})
	}
}

func TestSystemdTemplateContainsExpectedSafeFields(t *testing.T) {
	plan := Build("linux", fixturePaths(t), []byte("ID=ubuntu\nID_LIKE=debian\n"))
	template := BuildTemplate(plan)

	for _, want := range []string{
		"[Unit]",
		"[Service]",
		"ExecStart=" + plan.BinaryPath,
		"--config " + plan.ConfigPath,
		"--identity-file " + plan.IdentityPath,
		"ReadWritePaths=" + plan.LogDir,
		"Environment=OAW_AGENT_STATUS_FILE=" + plan.StatusPath,
		"Scheduling is intentionally not configured",
	} {
		if !strings.Contains(template.Template, want) {
			t.Fatalf("systemd template missing %q:\n%s", want, template.Template)
		}
	}
}

func TestWindowsTemplateIsPlanTextOnly(t *testing.T) {
	plan := Build("windows", fixturePaths(t), nil)
	template := BuildTemplate(plan)

	for _, want := range []string{
		"Text only",
		"does not run New-Service",
		"ServiceName: " + plan.ServiceName,
		"BinaryPath:",
		plan.ConfigPath,
		plan.IdentityPath,
		plan.LogDir,
		plan.StatusPath,
	} {
		if !strings.Contains(template.Template, want) {
			t.Fatalf("windows template missing %q:\n%s", want, template.Template)
		}
	}
}

func TestLaunchdTemplateContainsExpectedSafeFields(t *testing.T) {
	plan := Build("darwin", fixturePaths(t), nil)
	template := BuildTemplate(plan)
	if plan.BinaryPath != DarwinBinaryPath {
		t.Fatalf("darwin binary path = %q, want %q", plan.BinaryPath, DarwinBinaryPath)
	}

	for _, want := range []string{
		"<plist version=\"1.0\">",
		"<string>" + plan.ServiceName + "</string>",
		"<string>" + plan.BinaryPath + "</string>",
		"<string>service</string>",
		"<string>run</string>",
		"<string>--config</string>",
		"<string>" + plan.ConfigPath + "</string>",
		"<string>--identity-file</string>",
		"<string>" + plan.IdentityPath + "</string>",
		"<string>--output-dir</string>",
		"<string>" + plan.StateDir + "</string>",
		"<key>UserName</key>",
		"<string>_openassetwatch</string>",
		"<key>GroupName</key>",
		"<key>RunAtLoad</key>",
		"<true/>",
		"<key>KeepAlive</key>",
		"<key>ThrottleInterval</key>",
		"<integer>60</integer>",
		"<key>ProcessType</key>",
		"<string>Background</string>",
		"<key>ExitTimeOut</key>",
		"<integer>30</integer>",
		"<key>WorkingDirectory</key>",
		"<key>Umask</key>",
		"<string>027</string>",
		"<string>/dev/null</string>",
		"Status file: " + plan.StatusPath,
		"No shell, StartInterval, StartCalendarInterval, or sensitive environment values are configured",
	} {
		if !strings.Contains(template.Template, want) {
			t.Fatalf("launchd template missing %q:\n%s", want, template.Template)
		}
	}
	for _, forbidden := range []string{"<key>StartInterval</key>", "<key>StartCalendarInterval</key>", "/bin/sh", "<key>Crashed</key>", "KeepAlive</key>\n  <false/>"} {
		if strings.Contains(template.Template, forbidden) {
			t.Fatalf("launchd template contains forbidden %q:\n%s", forbidden, template.Template)
		}
	}
}

func TestPlanOutputContainsNoTokenOrSecretTerms(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "oaw-plan-output-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	paths := agentpaths.AgentPaths{
		IdentityPath: filepath.Join(tempDir, "identity.json"),
		ConfigPath:   filepath.Join(tempDir, "config.json"),
		StateDir:     filepath.Join(tempDir, "state"),
		LogDir:       filepath.Join(tempDir, "logs"),
		StatusPath:   filepath.Join(tempDir, "logs", "status.json"),
	}
	plan := Build("linux", paths, []byte("ID=ubuntu\nID_LIKE=debian\n"))
	combined := strings.ToLower(plan.OS + plan.ServiceTarget + plan.ServiceName + plan.BinaryPath + plan.ConfigPath + plan.IdentityPath + plan.LogDir + plan.StatusPath + plan.ServiceDefinitionPath)
	for _, note := range plan.Notes {
		combined += strings.ToLower(note)
	}
	if plan.LinuxDeployment != nil {
		combined += strings.ToLower(plan.LinuxDeployment.OSReleasePath + plan.LinuxDeployment.ID + strings.Join(plan.LinuxDeployment.IDLike, "") + plan.LinuxDeployment.VersionID + plan.LinuxDeployment.PackageFamily + plan.LinuxDeployment.Recommendation)
	}

	for _, forbidden := range []string{"token", "secret", "password", "credential"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("plan output included forbidden term %q: %s", forbidden, combined)
		}
	}
}

func TestTemplateOutputContainsNoTokenOrSecretTerms(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "oaw-template-output-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	paths := agentpaths.AgentPaths{
		IdentityPath: filepath.Join(tempDir, "identity.json"),
		ConfigPath:   filepath.Join(tempDir, "config.json"),
		StateDir:     filepath.Join(tempDir, "state"),
		LogDir:       filepath.Join(tempDir, "logs"),
		StatusPath:   filepath.Join(tempDir, "logs", "status.json"),
	}
	template := BuildTemplate(Build("linux", paths, []byte("ID=ubuntu\nID_LIKE=debian\n")))
	combined := strings.ToLower(template.ServiceTarget + template.ServiceName + template.TemplateType + template.Template + strings.Join(template.Warnings, ""))

	for _, forbidden := range []string{"token", "secret", "password", "credential"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("template output included forbidden term %q: %s", forbidden, combined)
		}
	}
}

func fixturePaths(t *testing.T) agentpaths.AgentPaths {
	t.Helper()
	base := t.TempDir()
	return agentpaths.AgentPaths{
		IdentityPath: filepath.Join(base, "identity.json"),
		ConfigPath:   filepath.Join(base, "config.json"),
		StateDir:     filepath.Join(base, "state"),
		LogDir:       filepath.Join(base, "logs"),
		StatusPath:   filepath.Join(base, "logs", "status.json"),
	}
}
