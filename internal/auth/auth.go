package auth

type TokenReference struct {
	EnvVar string `json:"env_var"`
}

func (ref TokenReference) IsConfigured() bool {
	return ref.EnvVar != ""
}
