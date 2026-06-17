package agent

import (
	"time"

	"github.com/openassetwatch/openassetwatch/internal/config"
	"github.com/openassetwatch/openassetwatch/pkg/models"
	"github.com/openassetwatch/openassetwatch/pkg/version"
)

func BuildHeartbeat(cfg config.Config) models.CollectorHeartbeat {
	return models.CollectorHeartbeat{
		SiteID:      cfg.SiteID,
		AgentID:     cfg.AgentID,
		Mode:        string(config.ModeAgent),
		Version:     version.Number,
		CheckedInAt: time.Now().UTC(),
	}
}
