package software

import (
	"context"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/openassetwatch/openassetwatch/pkg/models"
)

const (
	MaxPackages        = 2000
	MaxSourceLines     = 5000
	MaxCommandOutput   = 8 << 20
	MaxDiagnosticBytes = 4096
	MaxNameBytes       = 240
	MaxVersionBytes    = 160
	MaxVendorBytes     = 160
	MaxRecordIDBytes   = 240
	CollectionTimeout  = 20 * time.Second
)

type platformResult struct {
	components []models.SoftwareComponent
	sources    []models.SoftwareSourceResult
}

// CollectAt enumerates installed software through only the reviewed native
// sources compiled for the current platform.
func CollectAt(parent context.Context, observedAt time.Time) ([]models.SoftwareComponent, []models.SoftwareSourceResult) {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	ctx, cancel := context.WithTimeout(parent, CollectionTimeout)
	defer cancel()
	result := collectPlatform(ctx, observedAt.UTC())
	return finalize(result, observedAt.UTC())
}

func finalize(result platformResult, observedAt time.Time) ([]models.SoftwareComponent, []models.SoftwareSourceResult) {
	bySource := make(map[string]*models.SoftwareSourceResult, len(result.sources))
	for index := range result.sources {
		source := &result.sources[index]
		source.SourceID = boundedToken(source.SourceID, 64)
		source.Platform = boundedToken(source.Platform, 32)
		if source.ObservedAt.IsZero() {
			source.ObservedAt = observedAt
		}
		if source.Status != "complete" && source.Status != "partial" && source.Status != "unsupported" && source.Status != "failed" {
			source.Status = "failed"
			source.ErrorCode = "invalid-source-status"
		}
		source.ErrorCode = boundedToken(source.ErrorCode, 80)
		source.Limitations = boundedLimitations(source.Limitations)
		source.RecordCount = 0
		bySource[source.SourceID] = source
	}

	components := make([]models.SoftwareComponent, 0, min(len(result.components), MaxPackages))
	seen := make(map[string]struct{}, len(result.components))
	sort.Slice(result.components, func(i, j int) bool {
		left := result.components[i]
		right := result.components[j]
		return strings.Join([]string{left.CollectionSource, strings.ToLower(left.Name), left.Version, left.Architecture, left.SourceRecordID}, "\x00") <
			strings.Join([]string{right.CollectionSource, strings.ToLower(right.Name), right.Version, right.Architecture, right.SourceRecordID}, "\x00")
	})
	for _, component := range result.components {
		component = boundedComponent(component, observedAt)
		source := bySource[component.CollectionSource]
		if source == nil || source.Status == "failed" || source.Status == "unsupported" {
			continue
		}
		if component.Name == "" || component.SourceRecordID == "" {
			markPartial(source, "malformed-records-skipped")
			continue
		}
		key := strings.Join([]string{
			component.CollectionSource, strings.ToLower(component.Ecosystem), strings.ToLower(component.Name),
			component.Version, strings.ToLower(component.Architecture), component.InstallScope,
		}, "\x00")
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		if len(components) >= MaxPackages {
			markPartial(bySource[component.CollectionSource], "package-count-limit")
			if source := bySource[component.CollectionSource]; source != nil {
				source.Truncated = true
			}
			continue
		}
		seen[key] = struct{}{}
		components = append(components, component)
		source.RecordCount++
	}
	sort.Slice(components, func(i, j int) bool {
		left := components[i]
		right := components[j]
		return strings.Join([]string{left.CollectionSource, strings.ToLower(left.Name), left.Version, left.Architecture, left.SourceRecordID}, "\x00") <
			strings.Join([]string{right.CollectionSource, strings.ToLower(right.Name), right.Version, right.Architecture, right.SourceRecordID}, "\x00")
	})
	sort.Slice(result.sources, func(i, j int) bool { return result.sources[i].SourceID < result.sources[j].SourceID })
	return components, result.sources
}

func markPartial(source *models.SoftwareSourceResult, limitation string) {
	if source == nil || source.Status == "failed" || source.Status == "unsupported" {
		return
	}
	source.Status = "partial"
	source.Limitations = boundedLimitations(append(source.Limitations, limitation))
}

func boundedComponent(value models.SoftwareComponent, observedAt time.Time) models.SoftwareComponent {
	value.ComponentType = boundedToken(value.ComponentType, 40)
	if value.ComponentType == "" {
		value.ComponentType = "application"
	}
	value.Ecosystem = boundedToken(value.Ecosystem, 40)
	if value.Ecosystem == "" {
		value.Ecosystem = "generic"
	}
	value.Name = boundedText(value.Name, MaxNameBytes)
	value.Version = boundedText(value.Version, MaxVersionBytes)
	value.Vendor = boundedText(value.Vendor, MaxVendorBytes)
	value.Architecture = boundedToken(value.Architecture, 40)
	value.PackageManager = boundedToken(value.PackageManager, 48)
	value.PackageURL = boundedText(value.PackageURL, 600)
	value.InstallScope = boundedToken(value.InstallScope, 40)
	if value.InstallScope == "" {
		value.InstallScope = "system"
	}
	value.CollectionSource = boundedToken(value.CollectionSource, 64)
	value.SourceRecordID = boundedText(value.SourceRecordID, MaxRecordIDBytes)
	value.EvidenceMethod = boundedToken(value.EvidenceMethod, 64)
	if value.ObservedAt.IsZero() {
		value.ObservedAt = observedAt
	}
	if value.Confidence < 0 || value.Confidence > 1 {
		value.Confidence = 0.8
	}
	value.Metadata = boundedMetadata(value.Metadata)
	return value
}

func boundedText(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return ""
		}
	}
	if len(value) > maximum {
		return ""
	}
	return value
}

func boundedToken(value string, maximum int) string {
	value = strings.ToLower(boundedText(value, maximum))
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || strings.ContainsRune("._-", character)) {
			return ""
		}
	}
	return value
}

func boundedMetadata(value map[string]string) map[string]string {
	allowed := map[string]bool{"edition": true, "install_state": true, "language": true, "release": true}
	result := make(map[string]string)
	for key, item := range value {
		if !allowed[key] || len(result) >= 4 {
			continue
		}
		if safe := boundedText(item, 160); safe != "" {
			result[key] = safe
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func boundedLimitations(values []string) []string {
	result := make([]string, 0, min(len(values), 8))
	seen := make(map[string]bool)
	for _, value := range values {
		value = boundedToken(value, 120)
		if value == "" || seen[value] || len(result) >= 8 {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
