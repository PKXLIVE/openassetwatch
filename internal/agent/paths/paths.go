package paths

import (
	"os"
	"path/filepath"
	"runtime"
)

type AgentPaths struct {
	IdentityPath string `json:"default_agent_identity_path"`
	ConfigPath   string `json:"default_agent_config_path"`
	StateDir     string `json:"default_agent_state_dir"`
	LogDir       string `json:"default_agent_log_dir"`
	StatusPath   string `json:"default_agent_status_path"`
}

func DefaultAgentPaths() AgentPaths {
	dir := defaultAgentDir()
	stateDir := defaultAgentStateDir()
	logDir := defaultAgentLogDir()
	return AgentPaths{
		IdentityPath: defaultIdentityPath(dir),
		ConfigPath:   defaultConfigPath(dir),
		StateDir:     stateDir,
		LogDir:       logDir,
		StatusPath:   defaultStatusPath(stateDir, logDir),
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

func DefaultStateDir() string {
	return DefaultAgentPaths().StateDir
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
		return filepath.Join(programData, "OpenAssetWatch", "Agent")
	}
	return filepath.Join(string(filepath.Separator), "etc", "openassetwatch", "agent")
}

func defaultIdentityPath(dir string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(dir, "identity", "identity.json")
	}
	return filepath.Join(dir, "identity.json")
}

func defaultConfigPath(dir string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(dir, "config", "config.json")
	}
	return filepath.Join(dir, "config.json")
}

func defaultAgentStateDir() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "OpenAssetWatch", "Agent", "state")
	}
	return filepath.Join(string(filepath.Separator), "var", "lib", "openassetwatch", "agent")
}

func defaultAgentLogDir() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "OpenAssetWatch", "Agent", "logs")
	}
	return filepath.Join(string(filepath.Separator), "var", "log", "openassetwatch", "agent")
}

func defaultStatusPath(stateDir string, logDir string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(stateDir, "status.json")
	}
	return filepath.Join(logDir, "status.json")
}
