//go:build !linux && !darwin

package safefile

import "os"

func ValidateOwnerAndMode(os.FileInfo, bool) error { return nil }
func ValidateParentOwnerAndMode(os.FileInfo) error { return nil }

// A link count is not portable on all supported platforms. Returning zero
// makes callers skip POSIX-only hard-link assertions instead of claiming a
// guarantee that the platform implementation does not provide.
func LinkCount(os.FileInfo) uint64 { return 0 }
