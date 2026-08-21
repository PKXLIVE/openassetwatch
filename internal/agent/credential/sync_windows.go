//go:build windows

package credential

import "os"

// Windows directory handles do not expose a portable fsync operation.
func syncRootDirectory(*os.Root) error { return nil }
