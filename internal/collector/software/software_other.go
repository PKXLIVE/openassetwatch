//go:build !windows && !linux && !darwin

package software

import (
	"context"
	"runtime"
	"time"

	"github.com/openassetwatch/openassetwatch/pkg/models"
)

func collectPlatform(_ context.Context, observedAt time.Time) platformResult {
	return platformResult{sources: []models.SoftwareSourceResult{{
		SourceID: "native-package-manager", Platform: runtime.GOOS,
		Status: "unsupported", ObservedAt: observedAt,
		ErrorCode: "platform-unsupported",
	}}}
}
