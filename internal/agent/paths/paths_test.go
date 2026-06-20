package paths

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultIdentityPathResolvesForOS(t *testing.T) {
	got := DefaultIdentityPath()
	if got == "" {
		t.Fatal("default identity path is empty")
	}

	switch runtime.GOOS {
	case "windows":
		if !strings.HasSuffix(got, filepath.Join("OpenAssetWatch", "Agent", "identity", "identity.json")) {
			t.Fatalf("windows identity path = %q", got)
		}
		return
	case "darwin":
		want := filepath.Join(string(filepath.Separator), "Library", "Application Support", "OpenAssetWatch", "Agent", "identity", "identity.json")
		if got != want {
			t.Fatalf("darwin identity path = %q, want %q", got, want)
		}
		return
	default:
		want := filepath.Join(string(filepath.Separator), "etc", "openassetwatch", "agent", "identity.json")
		if got != want {
			t.Fatalf("identity path = %q, want %q", got, want)
		}
	}
}

func TestDefaultLogAndStatusPathsResolveForOS(t *testing.T) {
	logDir := DefaultLogDir()
	stateDir := DefaultStateDir()
	statusPath := DefaultStatusPath()
	if logDir == "" {
		t.Fatal("default log path is empty")
	}
	if stateDir == "" {
		t.Fatal("default state path is empty")
	}
	if statusPath == "" {
		t.Fatal("default status path is empty")
	}

	switch runtime.GOOS {
	case "windows":
		if !strings.HasSuffix(logDir, filepath.Join("OpenAssetWatch", "Agent", "logs")) {
			t.Fatalf("windows log path = %q", logDir)
		}
		if !strings.HasSuffix(stateDir, filepath.Join("OpenAssetWatch", "Agent", "state")) {
			t.Fatalf("windows state path = %q", stateDir)
		}
		if !strings.HasSuffix(statusPath, filepath.Join("OpenAssetWatch", "Agent", "state", "status.json")) {
			t.Fatalf("windows status path = %q", statusPath)
		}
		return
	case "darwin":
		wantLogDir := filepath.Join(string(filepath.Separator), "Library", "Logs", "OpenAssetWatch", "Agent")
		if logDir != wantLogDir {
			t.Fatalf("darwin log path = %q, want %q", logDir, wantLogDir)
		}
		wantStateDir := filepath.Join(string(filepath.Separator), "Library", "Application Support", "OpenAssetWatch", "Agent", "state")
		if stateDir != wantStateDir {
			t.Fatalf("darwin state path = %q, want %q", stateDir, wantStateDir)
		}
		wantStatusPath := filepath.Join(wantStateDir, "status.json")
		if statusPath != wantStatusPath {
			t.Fatalf("darwin status path = %q, want %q", statusPath, wantStatusPath)
		}
	default:
		wantLogDir := filepath.Join(string(filepath.Separator), "var", "log", "openassetwatch", "agent")
		if logDir != wantLogDir {
			t.Fatalf("log path = %q, want %q", logDir, wantLogDir)
		}
		wantStatusPath := filepath.Join(wantLogDir, "status.json")
		if statusPath != wantStatusPath {
			t.Fatalf("status path = %q, want %q", statusPath, wantStatusPath)
		}
	}
}

func TestDefaultAgentPathsIncludeOnlyPaths(t *testing.T) {
	paths := DefaultAgentPaths()
	if paths.IdentityPath == "" || paths.ConfigPath == "" || paths.StateDir == "" || paths.LogDir == "" || paths.StatusPath == "" {
		t.Fatalf("default paths must be populated: %+v", paths)
	}
	combined := strings.ToLower(paths.IdentityPath + paths.ConfigPath + paths.StateDir + paths.LogDir + paths.StatusPath)
	for _, forbidden := range []string{"token", "secret", "password", "enrollment"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("default paths include forbidden term %q: %+v", forbidden, paths)
		}
	}
}

func TestAgentPathsForOS(t *testing.T) {
	tests := []struct {
		name string
		goos string
		env  map[string]string
		want AgentPaths
	}{
		{
			name: "windows",
			goos: "windows",
			env:  map[string]string{"ProgramData": `D:\ProgramData`},
			want: AgentPaths{
				IdentityPath: `D:\ProgramData\OpenAssetWatch\Agent\identity\identity.json`,
				ConfigPath:   `D:\ProgramData\OpenAssetWatch\Agent\config\config.json`,
				StateDir:     `D:\ProgramData\OpenAssetWatch\Agent\state`,
				LogDir:       `D:\ProgramData\OpenAssetWatch\Agent\logs`,
				StatusPath:   `D:\ProgramData\OpenAssetWatch\Agent\state\status.json`,
			},
		},
		{
			name: "linux",
			goos: "linux",
			want: AgentPaths{
				IdentityPath: "/etc/openassetwatch/agent/identity.json",
				ConfigPath:   "/etc/openassetwatch/agent/config.json",
				StateDir:     "/var/lib/openassetwatch/agent",
				LogDir:       "/var/log/openassetwatch/agent",
				StatusPath:   "/var/log/openassetwatch/agent/status.json",
			},
		},
		{
			name: "darwin",
			goos: "darwin",
			want: AgentPaths{
				IdentityPath: "/Library/Application Support/OpenAssetWatch/Agent/identity/identity.json",
				ConfigPath:   "/Library/Application Support/OpenAssetWatch/Agent/config/config.json",
				StateDir:     "/Library/Application Support/OpenAssetWatch/Agent/state",
				LogDir:       "/Library/Logs/OpenAssetWatch/Agent",
				StatusPath:   "/Library/Application Support/OpenAssetWatch/Agent/state/status.json",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := AgentPathsForOS(test.goos, func(key string) string { return test.env[key] })
			if got != test.want {
				t.Fatalf("AgentPathsForOS(%q) = %+v, want %+v", test.goos, got, test.want)
			}
		})
	}
}
