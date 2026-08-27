//go:build darwin

package software

import (
	"bufio"
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/openassetwatch/openassetwatch/pkg/models"
)

func collectPlatform(ctx context.Context, observedAt time.Time) platformResult {
	status := models.SoftwareSourceResult{
		SourceID: "macos-pkgutil", Platform: "darwin", Status: "unsupported", ObservedAt: observedAt,
		Limitations: []string{"machine-receipts-only", "application-bundles-not-collected"},
	}
	executable := fixedExecutable("/usr/sbin/pkgutil")
	if executable == "" {
		status.ErrorCode = "pkgutil-unavailable"
		return platformResult{sources: []models.SoftwareSourceResult{status}}
	}
	output, err := runFixedCommand(ctx, executable, "--pkgs")
	if err != nil {
		status.Status = "failed"
		status.ErrorCode = "pkgutil-list-failed"
		if ctx.Err() != nil {
			status.ErrorCode = "command-timeout"
		}
		return platformResult{sources: []models.SoftwareSourceResult{status}}
	}
	receipts, malformed, truncated := parsePkgutilList(output)
	components := make([]models.SoftwareComponent, 0, len(receipts))
	status.Status = "complete"
	for _, receipt := range receipts {
		info, infoErr := runFixedCommand(ctx, executable, "--pkg-info", receipt)
		if infoErr != nil {
			status.Status = "partial"
			status.ErrorCode = "pkgutil-info-failed"
			continue
		}
		component, ok := parsePkgutilInfo(info, receipt, observedAt)
		if !ok {
			malformed++
			status.Status = "partial"
			continue
		}
		components = append(components, component)
	}
	if malformed > 0 {
		status.Status = "partial"
		status.Limitations = append(status.Limitations, "malformed-records-skipped")
	}
	if truncated {
		status.Status = "partial"
		status.Truncated = true
		status.ErrorCode = "package-count-limit"
		status.Limitations = append(status.Limitations, "package-count-limit")
	}
	return platformResult{components: components, sources: []models.SoftwareSourceResult{status}}
}

func parsePkgutilList(output []byte) ([]string, int, bool) {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 4096), 4096)
	values := make([]string, 0)
	malformed := 0
	seen := make(map[string]bool)
	for scanner.Scan() {
		receipt := boundedText(scanner.Text(), MaxRecordIDBytes)
		if receipt == "" || strings.HasPrefix(receipt, "-") {
			malformed++
			continue
		}
		if seen[receipt] {
			continue
		}
		if len(values) >= MaxPackages {
			return values, malformed, true
		}
		seen[receipt] = true
		values = append(values, receipt)
	}
	if scanner.Err() != nil {
		malformed++
	}
	return values, malformed, false
}

func parsePkgutilInfo(output []byte, receipt string, observedAt time.Time) (models.SoftwareComponent, bool) {
	fields := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 4096), 4096)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "package-id" || key == "version" || key == "volume" || key == "location" {
			fields[key] = strings.TrimSpace(value)
		}
	}
	packageID := fields["package-id"]
	if packageID == "" {
		packageID = receipt
	}
	if boundedText(packageID, MaxRecordIDBytes) == "" {
		return models.SoftwareComponent{}, false
	}
	return models.SoftwareComponent{
		ComponentType: "operating-system-package", Ecosystem: "generic",
		Name: packageID, Version: fields["version"], PackageManager: "pkgutil",
		InstallScope: "system", CollectionSource: "macos-pkgutil",
		SourceRecordID: packageID, EvidenceMethod: "pkgutil-native-query",
		ObservedAt: observedAt, Confidence: 0.9,
		Metadata: map[string]string{"install_state": "receipt-present"},
	}, true
}
