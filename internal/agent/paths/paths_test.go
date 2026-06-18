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

	if runtime.GOOS == "windows" {
		if !strings.HasSuffix(got, filepath.Join("OpenAssetWatch", "agent", "identity.json")) {
			t.Fatalf("windows identity path = %q", got)
		}
		return
	}

	want := filepath.Join(string(filepath.Separator), "etc", "openassetwatch", "agent", "identity.json")
	if got != want {
		t.Fatalf("identity path = %q, want %q", got, want)
	}
}

func TestDefaultLogAndStatusPathsResolveForOS(t *testing.T) {
	logDir := DefaultLogDir()
	statusPath := DefaultStatusPath()
	if logDir == "" {
		t.Fatal("default log path is empty")
	}
	if statusPath == "" {
		t.Fatal("default status path is empty")
	}

	if runtime.GOOS == "windows" {
		if !strings.HasSuffix(logDir, filepath.Join("OpenAssetWatch", "agent", "logs")) {
			t.Fatalf("windows log path = %q", logDir)
		}
		if !strings.HasSuffix(statusPath, filepath.Join("OpenAssetWatch", "agent", "logs", "status.json")) {
			t.Fatalf("windows status path = %q", statusPath)
		}
		return
	}

	wantLogDir := filepath.Join(string(filepath.Separator), "var", "log", "openassetwatch", "agent")
	if logDir != wantLogDir {
		t.Fatalf("log path = %q, want %q", logDir, wantLogDir)
	}
	wantStatusPath := filepath.Join(wantLogDir, "status.json")
	if statusPath != wantStatusPath {
		t.Fatalf("status path = %q, want %q", statusPath, wantStatusPath)
	}
}

func TestDefaultAgentPathsIncludeOnlyPaths(t *testing.T) {
	paths := DefaultAgentPaths()
	if paths.IdentityPath == "" || paths.ConfigPath == "" || paths.LogDir == "" || paths.StatusPath == "" {
		t.Fatalf("default paths must be populated: %+v", paths)
	}
	combined := strings.ToLower(paths.IdentityPath + paths.ConfigPath + paths.LogDir + paths.StatusPath)
	for _, forbidden := range []string{"token", "secret", "password", "enrollment"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("default paths include forbidden term %q: %+v", forbidden, paths)
		}
	}
}
