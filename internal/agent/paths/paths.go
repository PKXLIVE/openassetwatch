package paths

import (
	"os"
	"path"
	"runtime"
	"strings"
)

type AgentPaths struct {
	IdentityPath string `json:"default_agent_identity_path"`
	ConfigPath   string `json:"default_agent_config_path"`
	StateDir     string `json:"default_agent_state_dir"`
	LogDir       string `json:"default_agent_log_dir"`
	StatusPath   string `json:"default_agent_status_path"`
}

func DefaultAgentPaths() AgentPaths {
	return AgentPathsForOS(runtime.GOOS, os.Getenv)
}

func AgentPathsForOS(goos string, getenv func(string) string) AgentPaths {
	goos = strings.TrimSpace(goos)
	if goos == "" {
		goos = runtime.GOOS
	}
	if getenv == nil {
		getenv = os.Getenv
	}

	dir := defaultAgentDir(goos, getenv)
	stateDir := defaultAgentStateDir(goos, getenv)
	logDir := defaultAgentLogDir(goos, getenv)
	return AgentPaths{
		IdentityPath: defaultIdentityPath(goos, dir),
		ConfigPath:   defaultConfigPath(goos, dir),
		StateDir:     stateDir,
		LogDir:       logDir,
		StatusPath:   defaultStatusPath(goos, stateDir, logDir),
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

func defaultAgentDir(goos string, getenv func(string) string) string {
	switch goos {
	case "windows":
		programData := getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return windowsPathJoin(programData, "OpenAssetWatch", "Agent")
	case "darwin":
		return path.Join("/", "Library", "Application Support", "OpenAssetWatch", "Agent")
	default:
		return path.Join("/", "etc", "openassetwatch", "agent")
	}
}

func defaultIdentityPath(goos string, dir string) string {
	switch goos {
	case "windows":
		return windowsPathJoin(dir, "identity", "identity.json")
	case "darwin":
		return path.Join(dir, "identity", "identity.json")
	default:
		return path.Join(dir, "identity.json")
	}
}

func defaultConfigPath(goos string, dir string) string {
	switch goos {
	case "windows":
		return windowsPathJoin(dir, "config", "config.json")
	case "darwin":
		return path.Join(dir, "config", "config.json")
	default:
		return path.Join(dir, "config.json")
	}
}

func defaultAgentStateDir(goos string, getenv func(string) string) string {
	switch goos {
	case "windows":
		programData := getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return windowsPathJoin(programData, "OpenAssetWatch", "Agent", "state")
	case "darwin":
		return path.Join("/", "Library", "Application Support", "OpenAssetWatch", "Agent", "state")
	default:
		return path.Join("/", "var", "lib", "openassetwatch", "agent")
	}
}

func defaultAgentLogDir(goos string, getenv func(string) string) string {
	switch goos {
	case "windows":
		programData := getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return windowsPathJoin(programData, "OpenAssetWatch", "Agent", "logs")
	case "darwin":
		return path.Join("/", "Library", "Logs", "OpenAssetWatch", "Agent")
	default:
		return path.Join("/", "var", "log", "openassetwatch", "agent")
	}
}

func defaultStatusPath(goos string, stateDir string, logDir string) string {
	switch goos {
	case "windows":
		return windowsPathJoin(stateDir, "status.json")
	case "darwin":
		return path.Join(stateDir, "status.json")
	default:
		return path.Join(logDir, "status.json")
	}
}

func windowsPathJoin(base string, parts ...string) string {
	base = strings.TrimRight(base, `\/`)
	cleaned := []string{base}
	for _, part := range parts {
		part = strings.Trim(part, `\/`)
		if part != "" {
			cleaned = append(cleaned, part)
		}
	}
	return strings.Join(cleaned, `\`)
}
