//go:build windows

package identity

import "os"

// Windows does not expose portable directory fsync semantics through os.File.
// The identity file itself is flushed before close and is published with
// exclusive creation inside an already-open rooted directory.
func syncRootDirectory(*os.Root) error { return nil }
