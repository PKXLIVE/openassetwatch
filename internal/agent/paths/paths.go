package paths

import (
	"os"
	"path/filepath"
	"runtime"
)

type AgentPaths struct {
	IdentityPath string `json:"default_agent_identity_path"`
	ConfigPath   string `json:"default_agent_config_path"`
}

func DefaultAgentPaths() AgentPaths {
	dir := defaultAgentDir()
	return AgentPaths{
		IdentityPath: filepath.Join(dir, "identity.json"),
		ConfigPath:   filepath.Join(dir, "config.json"),
	}
}

func DefaultIdentityPath() string {
	return DefaultAgentPaths().IdentityPath
}

func DefaultConfigPath() string {
	return DefaultAgentPaths().ConfigPath
}

func defaultAgentDir() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "OpenAssetWatch", "agent")
	}
	return filepath.Join(string(filepath.Separator), "etc", "openassetwatch", "agent")
}
