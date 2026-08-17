//go:build windows

package status

import "os"

func syncDirectoryFile(*os.File) error { return nil }
