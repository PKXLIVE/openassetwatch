package paths

import (
	"os"
	"path/filepath"
	"runtime"
)

type AgentPaths struct {
	IdentityPath string `json:"default_agent_identity_path"`
	ConfigPath   string `json:"default_agent_config_path"`
	LogDir       string `json:"default_agent_log_dir"`
	StatusPath   string `json:"default_agent_status_path"`
}

func DefaultAgentPaths() AgentPaths {
	dir := defaultAgentDir()
	logDir := defaultAgentLogDir()
	return AgentPaths{
		IdentityPath: filepath.Join(dir, "identity.json"),
		ConfigPath:   filepath.Join(dir, "config.json"),
		LogDir:       logDir,
		StatusPath:   filepath.Join(logDir, "status.json"),
	}
}

func DefaultIdentityPath() string {
	return DefaultAgentPaths().IdentityPath
}

func DefaultConfigPath() string {
	return DefaultAgentPaths().ConfigPath
}

func DefaultLogDir() string {
	return DefaultAgentPaths().LogDir
}

func DefaultStatusPath() string {
	return DefaultAgentPaths().StatusPath
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

func defaultAgentLogDir() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "OpenAssetWatch", "agent", "logs")
	}
	return filepath.Join(string(filepath.Separator), "var", "log", "openassetwatch", "agent")
}
