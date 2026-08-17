//go:build !windows

package status

import "os"

func syncDirectoryFile(file *os.File) error { return file.Sync() }
