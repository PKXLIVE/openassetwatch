//go:build windows

package software

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/openassetwatch/openassetwatch/pkg/models"
	"golang.org/x/sys/windows/registry"
)

const windowsUninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

type windowsRegistryRecord struct {
	name      string
	version   string
	publisher string
	recordID  string
	sourceID  string
}

type windowsRegistrySource struct {
	id   string
	view uint32
}

func collectPlatform(ctx context.Context, observedAt time.Time) platformResult {
	result := platformResult{}
	for _, source := range []windowsRegistrySource{
		{id: "windows-uninstall-64", view: registry.WOW64_64KEY},
		{id: "windows-uninstall-32", view: registry.WOW64_32KEY},
	} {
		status := models.SoftwareSourceResult{
			SourceID: source.id, Platform: "windows", Status: "complete", ObservedAt: observedAt,
			Limitations: []string{"machine-scope-only", "user-hives-not-collected"},
		}
		records, skipped, truncated, err := readWindowsRegistrySource(ctx, source)
		if err != nil {
			status.Status = "failed"
			status.ErrorCode = "registry-query-failed"
			if errors.Is(err, registry.ErrNotExist) {
				status.Status = "unsupported"
				status.ErrorCode = "registry-view-unavailable"
			}
			if errors.Is(err, context.DeadlineExceeded) {
				status.ErrorCode = "collection-timeout"
			}
			result.sources = append(result.sources, status)
			continue
		}
		if skipped > 0 {
			status.Status = "partial"
			status.Limitations = append(status.Limitations, "malformed-records-skipped")
		}
		if truncated {
			status.Status = "partial"
			status.Truncated = true
			status.ErrorCode = "registry-record-limit"
			status.Limitations = append(status.Limitations, "package-count-limit")
		}
		for _, record := range records {
			component, ok := windowsRecordComponent(record, observedAt)
			if !ok {
				status.Status = "partial"
				status.Limitations = append(status.Limitations, "malformed-records-skipped")
				continue
			}
			result.components = append(result.components, component)
		}
		result.sources = append(result.sources, status)
	}
	return result
}

func readWindowsRegistrySource(ctx context.Context, source windowsRegistrySource) ([]windowsRegistryRecord, int, bool, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsUninstallKey, registry.READ|source.view)
	if err != nil {
		return nil, 0, false, err
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(MaxSourceLines + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, false, err
	}
	truncated := len(names) > MaxSourceLines
	if truncated {
		names = names[:MaxSourceLines]
	}
	records := make([]windowsRegistryRecord, 0, min(len(names), MaxPackages))
	skipped := 0
	for _, subkeyName := range names {
		if err := ctx.Err(); err != nil {
			return records, skipped, truncated, err
		}
		if len(records) >= MaxPackages {
			truncated = true
			break
		}
		key, openErr := registry.OpenKey(root, subkeyName, registry.QUERY_VALUE|source.view)
		if openErr != nil {
			skipped++
			continue
		}
		name, _, nameErr := key.GetStringValue("DisplayName")
		version, _, _ := key.GetStringValue("DisplayVersion")
		publisher, _, _ := key.GetStringValue("Publisher")
		_ = key.Close()
		if nameErr != nil || boundedText(name, MaxNameBytes) == "" || boundedText(subkeyName, MaxRecordIDBytes) == "" {
			skipped++
			continue
		}
		records = append(records, windowsRegistryRecord{
			name: name, version: version, publisher: publisher, recordID: subkeyName,
			sourceID: source.id,
		})
	}
	return records, skipped, truncated, nil
}

func windowsRecordComponent(record windowsRegistryRecord, observedAt time.Time) (models.SoftwareComponent, bool) {
	component := boundedComponent(models.SoftwareComponent{
		ComponentType: "application", Ecosystem: "generic", Name: record.name,
		Version: record.version, Vendor: record.publisher,
		PackageManager: "windows-registry", InstallScope: "system",
		CollectionSource: record.sourceID, SourceRecordID: record.recordID,
		EvidenceMethod: "windows-uninstall-registry", ObservedAt: observedAt, Confidence: 0.9,
	}, observedAt)
	return component, component.Name != "" && component.SourceRecordID != ""
}
