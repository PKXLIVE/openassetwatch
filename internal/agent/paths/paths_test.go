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

func TestDefaultAgentPathsIncludeOnlyPaths(t *testing.T) {
	paths := DefaultAgentPaths()
	if paths.IdentityPath == "" || paths.ConfigPath == "" {
		t.Fatalf("default paths must be populated: %+v", paths)
	}
	combined := strings.ToLower(paths.IdentityPath + paths.ConfigPath)
	for _, forbidden := range []string{"token", "secret", "password", "enrollment"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("default paths include forbidden term %q: %+v", forbidden, paths)
		}
	}
}
