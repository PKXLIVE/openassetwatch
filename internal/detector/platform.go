package detector

import (
	"os"
	"runtime"

	"github.com/openassetwatch/openassetwatch/pkg/models"
)

func LocalAsset(siteID string) models.Asset {
	hostname, _ := os.Hostname()
	platform := runtime.GOOS + "/" + runtime.GOARCH

	return models.Asset{
		AssetID:  "local-host",
		SiteID:   siteID,
		Hostname: hostname,
		Platform: platform,
		Evidence: []models.Evidence{
			{
				Source:     "local_platform",
				Summary:    "Local platform metadata collected without active probing",
				Confidence: "high",
			},
		},
	}
}
