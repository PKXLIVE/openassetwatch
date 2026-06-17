package updater

type Plan struct {
	CurrentVersion string `json:"current_version"`
	TargetVersion  string `json:"target_version,omitempty"`
	Action         string `json:"action"`
}

func NoopPlan(currentVersion string) Plan {
	return Plan{
		CurrentVersion: currentVersion,
		Action:         "none",
	}
}
