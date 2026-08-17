//go:build windows

package credential

import "os"

// Windows does not support fsync on an open directory through os.Root. The
// credential file itself is flushed before the same-directory atomic rename.
func syncRootDirectory(*os.Root) error { return nil }
