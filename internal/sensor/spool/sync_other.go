//go:build !windows

package spool

import "os"

func syncDirectoryFile(directory *os.File) error {
	return directory.Sync()
}
