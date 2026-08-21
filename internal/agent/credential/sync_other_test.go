//go:build !windows

package credential

import (
	"errors"
	"os"
	"strings"
	"testing"
)

type recordingDirectorySyncHandle struct {
	syncErr  error
	closeErr error
	calls    []string
}

func (handle *recordingDirectorySyncHandle) Sync() error {
	handle.calls = append(handle.calls, "sync")
	return handle.syncErr
}

func (handle *recordingDirectorySyncHandle) Close() error {
	handle.calls = append(handle.calls, "close")
	return handle.closeErr
}

func TestSyncRootDirectoryAfterRename(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	file, err := root.OpenFile("credential.tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("credential record")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := root.Rename("credential.tmp", "credential.json"); err != nil {
		t.Fatal(err)
	}
	if err := syncRootDirectory(root); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Lstat("credential.json"); err != nil {
		t.Fatalf("renamed credential is unavailable after directory sync: %v", err)
	}
}

func TestSyncAndCloseRootDirectoryPreservesErrors(t *testing.T) {
	credentialMarker := testAgentCredential("a")
	syncErr := errors.New(credentialMarker + "-sync-detail")
	closeErr := errors.New(credentialMarker + "-close-detail")

	tests := []struct {
		name      string
		syncErr   error
		closeErr  error
		wantError string
		wantSync  bool
		wantClose bool
	}{
		{name: "success"},
		{name: "sync", syncErr: syncErr, wantError: "sync agent credential directory", wantSync: true},
		{name: "close", closeErr: closeErr, wantError: "close agent credential directory", wantClose: true},
		{
			name:      "sync and close",
			syncErr:   syncErr,
			closeErr:  closeErr,
			wantError: "sync agent credential directory\nclose agent credential directory",
			wantSync:  true,
			wantClose: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handle := &recordingDirectorySyncHandle{syncErr: test.syncErr, closeErr: test.closeErr}
			err := syncAndCloseRootDirectory(handle)
			if got := strings.Join(handle.calls, ","); got != "sync,close" {
				t.Fatalf("call order = %q, want sync,close", got)
			}
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || err.Error() != test.wantError {
				t.Fatalf("error = %v, want %q", err, test.wantError)
			}
			if errors.Is(err, syncErr) != test.wantSync {
				t.Fatalf("sync error preservation = %v, want %v", errors.Is(err, syncErr), test.wantSync)
			}
			if errors.Is(err, closeErr) != test.wantClose {
				t.Fatalf("close error preservation = %v, want %v", errors.Is(err, closeErr), test.wantClose)
			}
			if strings.Contains(err.Error(), credentialMarker) {
				t.Fatalf("error exposed credential material: %q", err)
			}
		})
	}
}
