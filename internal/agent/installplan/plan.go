package installplan

import (
	"runtime"
	"strings"

	agentpaths "github.com/openassetwatch/openassetwatch/internal/agent/paths"
	"github.com/openassetwatch/openassetwatch/internal/agent/serviceplan"
)

type Plan struct {
	OS                            string             `json:"os"`
	Arch                          string             `json:"arch"`
	RecommendedPackageType        string             `json:"recommended_package_type"`
	InstallModel                  string             `json:"install_model"`
	BinaryPathExpectation         string             `json:"binary_path_expectation"`
	ConfigPath                    string             `json:"config_path"`
	IdentityPath                  string             `json:"identity_path"`
	StateDir                      string             `json:"state_dir"`
	LogDir                        string             `json:"log_dir"`
	StatusPath                    string             `json:"status_file_path"`
	ServiceDefinitionPath         string             `json:"service_definition_path,omitempty"`
	PackageValidationExpectations []string           `json:"package_validation_expectations"`
	Warnings                      []string           `json:"warnings"`
	LinuxDistribution             *LinuxDistribution `json:"linux_distribution,omitempty"`
}

type LinuxDistribution struct {
	OSReleasePath          string   `json:"os_release_path"`
	ID                     string   `json:"id,omitempty"`
	IDLike                 []string `json:"id_like,omitempty"`
	VersionID              string   `json:"version_id,omitempty"`
	RecommendedPackageType string   `json:"recommended_package_type"`
}

func Build(goos string, goarch string, paths agentpaths.AgentPaths, osReleaseData []byte) Plan {
	goos = strings.TrimSpace(goos)
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch = strings.TrimSpace(goarch)
	if goarch == "" {
		goarch = runtime.GOARCH
	}

	service := serviceplan.Build(goos, paths, osReleaseData)
	plan := Plan{
		OS:                    goos,
		Arch:                  goarch,
		BinaryPathExpectation: service.BinaryPath,
		ConfigPath:            service.ConfigPath,
		IdentityPath:          service.IdentityPath,
		StateDir:              service.StateDir,
		LogDir:                service.LogDir,
		StatusPath:            service.StatusPath,
		ServiceDefinitionPath: service.ServiceDefinitionPath,
		PackageValidationExpectations: []string{
			"verify artifact signature",
			"verify checksum against a trusted release manifest",
			"confirm operating system and architecture match this plan",
			"confirm artifact version and release channel are approved",
			"perform install through administrator-controlled deployment",
		},
		Warnings: []string{
			"plan only; this command does not install, upgrade, remove, or modify software",
			"no files, directories, service definitions, schedules, or package metadata are created",
			"package-manager and service-manager commands require separate administrator action",
		},
	}

	switch goos {
	case "windows":
		plan.RecommendedPackageType = "msi"
		plan.InstallModel = "signed MSI or enterprise deployment"
	case "linux":
		release := serviceplan.ParseOSRelease(osReleaseData)
		packageType, recommendation := serviceplan.LinuxPackageFamily(release)
		plan.RecommendedPackageType = packageType
		plan.InstallModel = recommendation
		plan.LinuxDistribution = &LinuxDistribution{
			OSReleasePath:          "/etc/os-release",
			ID:                     release.ID,
			IDLike:                 release.IDLike,
			VersionID:              release.VersionID,
			RecommendedPackageType: packageType,
		}
	case "darwin":
		plan.RecommendedPackageType = "pkg"
		plan.InstallModel = "signed and notarized macOS package"
	default:
		plan.RecommendedPackageType = "manual"
		plan.InstallModel = "manual binary install"
	}

	return plan
}
