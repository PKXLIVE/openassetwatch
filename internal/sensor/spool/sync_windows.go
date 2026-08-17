//go:build windows

package spool

import "os"

// Windows does not support FlushFileBuffers on a directory handle opened by
// os.Root. Individual spool files are flushed before the atomic rename; the
// rename itself remains same-directory and atomic.
func syncDirectoryFile(*os.File) error {
	return nil
}
