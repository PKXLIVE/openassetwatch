//go:build linux

package software

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/openassetwatch/openassetwatch/pkg/models"
)

type linuxSource struct {
	id         string
	ecosystem  string
	executable string
	arguments  []string
	parser     func([]byte, string, time.Time) ([]models.SoftwareComponent, int)
}

func collectPlatform(ctx context.Context, observedAt time.Time) platformResult {
	sources := []linuxSource{
		{
			id: "linux-dpkg", ecosystem: "deb",
			executable: fixedExecutable("/usr/bin/dpkg-query", "/bin/dpkg-query"),
			arguments:  []string{"-W", "-f=${binary:Package}\t${Version}\t${Architecture}\n"},
			parser:     parseDpkgOutput,
		},
		{
			id: "linux-rpm", ecosystem: "rpm",
			executable: fixedExecutable("/usr/bin/rpm", "/bin/rpm"),
			arguments:  []string{"-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n"},
			parser:     parseRPMOutput,
		},
	}
	return collectLinuxSources(ctx, observedAt, sources, runFixedCommand)
}

func collectLinuxSources(
	ctx context.Context,
	observedAt time.Time,
	sources []linuxSource,
	runner func(context.Context, string, ...string) ([]byte, error),
) platformResult {
	result := platformResult{}
	for _, source := range sources {
		status := models.SoftwareSourceResult{
			SourceID: source.id, Platform: "linux", Status: "unsupported", ObservedAt: observedAt,
		}
		if source.executable == "" {
			status.ErrorCode = "package-manager-unavailable"
			result.sources = append(result.sources, status)
			continue
		}
		output, err := runner(ctx, source.executable, source.arguments...)
		if err != nil && !errors.Is(err, errOutputLimit) {
			status.Status = "failed"
			status.ErrorCode = "command-failed"
			if errors.Is(err, context.DeadlineExceeded) {
				status.ErrorCode = "command-timeout"
			}
			result.sources = append(result.sources, status)
			continue
		}
		components, malformed := source.parser(output, source.id, observedAt)
		status.Status = "complete"
		if malformed > 0 {
			status.Status = "partial"
			status.Limitations = append(status.Limitations, "malformed-records-skipped")
		}
		if errors.Is(err, errOutputLimit) {
			status.Status = "partial"
			status.Truncated = true
			status.ErrorCode = "output-limit"
			status.Limitations = append(status.Limitations, "output-truncated")
		}
		result.components = append(result.components, components...)
		result.sources = append(result.sources, status)
	}
	return result
}

func parseDpkgOutput(output []byte, sourceID string, observedAt time.Time) ([]models.SoftwareComponent, int) {
	return parseLinuxRows(output, sourceID, "deb", "dpkg", observedAt, false)
}

func parseRPMOutput(output []byte, sourceID string, observedAt time.Time) ([]models.SoftwareComponent, int) {
	return parseLinuxRows(output, sourceID, "rpm", "rpm", observedAt, true)
}

func parseLinuxRows(output []byte, sourceID, ecosystem, manager string, observedAt time.Time, normalizeEpoch bool) ([]models.SoftwareComponent, int) {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 4096), 4096)
	components := make([]models.SoftwareComponent, 0)
	malformed := 0
	lines := 0
	for scanner.Scan() {
		lines++
		if lines > MaxSourceLines {
			malformed++
			break
		}
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 3 {
			malformed++
			continue
		}
		name := strings.TrimSpace(fields[0])
		version := strings.TrimSpace(fields[1])
		architecture := strings.TrimSpace(fields[2])
		if normalizeEpoch {
			version = strings.TrimPrefix(version, "(none):")
			version = strings.TrimPrefix(version, "0:")
		}
		if separator := strings.LastIndex(name, ":"); ecosystem == "deb" && separator > 0 {
			if architecture == "" {
				architecture = name[separator+1:]
			}
			name = name[:separator]
		}
		components = append(components, models.SoftwareComponent{
			ComponentType: "operating-system-package", Ecosystem: ecosystem,
			Name: name, Version: version, Architecture: architecture,
			PackageManager: manager, InstallScope: "system",
			CollectionSource: sourceID, SourceRecordID: name + ":" + architecture,
			EvidenceMethod: manager + "-native-query", ObservedAt: observedAt, Confidence: 0.95,
		})
	}
	if scanner.Err() != nil {
		malformed++
	}
	return components, malformed
}
