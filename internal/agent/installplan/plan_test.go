package installplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentpaths "github.com/openassetwatch/openassetwatch/internal/agent/paths"
)

func TestBuildWindowsRecommendation(t *testing.T) {
	plan := Build("windows", "amd64", fixturePaths(t), nil)

	if plan.RecommendedPackageType != "msi" {
		t.Fatalf("package type = %q, want msi", plan.RecommendedPackageType)
	}
	if !strings.Contains(plan.InstallModel, "enterprise deployment") {
		t.Fatalf("install model = %q, want enterprise deployment", plan.InstallModel)
	}
	if plan.BinaryPathExpectation == "" || plan.ConfigPath == "" || plan.IdentityPath == "" {
		t.Fatalf("windows plan missing paths: %+v", plan)
	}
}

func TestBuildMacOSRecommendation(t *testing.T) {
	plan := Build("darwin", "arm64", fixturePaths(t), nil)

	if plan.RecommendedPackageType != "pkg" {
		t.Fatalf("package type = %q, want pkg", plan.RecommendedPackageType)
	}
	if !strings.Contains(plan.InstallModel, "signed and notarized") {
		t.Fatalf("install model = %q, want signed/notarized package", plan.InstallModel)
	}
	if !strings.Contains(plan.ServiceDefinitionPath, "LaunchDaemons") {
		t.Fatalf("service definition path = %q, want launchd path", plan.ServiceDefinitionPath)
	}
}

func TestBuildLinuxPackageRecommendation(t *testing.T) {
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
			plan := Build("linux", "amd64", fixturePaths(t), []byte(tt.data))
			if plan.RecommendedPackageType != tt.want {
				t.Fatalf("package type = %q, want %q", plan.RecommendedPackageType, tt.want)
			}
			if plan.LinuxDistribution == nil {
				t.Fatal("linux distribution details are missing")
			}
			if plan.LinuxDistribution.RecommendedPackageType != tt.want {
				t.Fatalf("linux distribution package type = %q, want %q", plan.LinuxDistribution.RecommendedPackageType, tt.want)
			}
		})
	}
}

func TestBuildUnknownLinuxMapsToManualArchive(t *testing.T) {
	plan := Build("linux", "amd64", fixturePaths(t), []byte("ID=exampleos\nVERSION_ID=1\n"))
	if plan.RecommendedPackageType != "tar.gz/manual" {
		t.Fatalf("package type = %q, want tar.gz/manual", plan.RecommendedPackageType)
	}
	if !strings.Contains(plan.InstallModel, "manual install") {
		t.Fatalf("install model = %q, want manual install fallback", plan.InstallModel)
	}
}

func TestBuildReportsExpectedPaths(t *testing.T) {
	paths := fixturePaths(t)
	plan := Build("linux", "amd64", paths, []byte("ID=ubuntu\nID_LIKE=debian\n"))

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
	if plan.BinaryPathExpectation == "" || plan.ServiceDefinitionPath == "" {
		t.Fatalf("plan missing binary or service definition path: %+v", plan)
	}
}

func TestBuildOutputContainsNoTokenOrSecretTerms(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "oaw-install-plan-output-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	paths := agentpaths.AgentPaths{
		IdentityPath: filepath.Join(tempDir, "identity.json"),
		ConfigPath:   filepath.Join(tempDir, "config.json"),
		LogDir:       filepath.Join(tempDir, "logs"),
		StatusPath:   filepath.Join(tempDir, "logs", "status.json"),
	}
	plan := Build("linux", "amd64", paths, []byte("ID=ubuntu\nID_LIKE=debian\n"))

	combined := strings.ToLower(plan.OS + plan.Arch + plan.RecommendedPackageType + plan.InstallModel + plan.BinaryPathExpectation + plan.ConfigPath + plan.IdentityPath + plan.LogDir + plan.StatusPath + plan.ServiceDefinitionPath + strings.Join(plan.PackageValidationExpectations, "") + strings.Join(plan.Warnings, ""))
	if plan.LinuxDistribution != nil {
		combined += strings.ToLower(plan.LinuxDistribution.OSReleasePath + plan.LinuxDistribution.ID + strings.Join(plan.LinuxDistribution.IDLike, "") + plan.LinuxDistribution.VersionID + plan.LinuxDistribution.RecommendedPackageType)
	}

	for _, forbidden := range []string{"token", "secret", "password", "credential"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("install plan output included forbidden term %q: %s", forbidden, combined)
		}
	}
}

func fixturePaths(t *testing.T) agentpaths.AgentPaths {
	t.Helper()
	base := t.TempDir()
	return agentpaths.AgentPaths{
		IdentityPath: filepath.Join(base, "identity.json"),
		ConfigPath:   filepath.Join(base, "config.json"),
		LogDir:       filepath.Join(base, "logs"),
		StatusPath:   filepath.Join(base, "logs", "status.json"),
	}
}
