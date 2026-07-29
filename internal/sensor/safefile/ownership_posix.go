//go:build linux || darwin

package safefile

import (
	"errors"
	"os"
	"syscall"
)

func ValidateOwnerAndMode(info os.FileInfo, directory bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("private sensor path has wrong ownership")
	}
	if directory {
		if info.Mode().Perm()&0o077 != 0 {
			return errors.New("private sensor directory must not grant group or other permissions")
		}
		return nil
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("private sensor file must not grant group or other permissions")
	}
	return nil
}

func ValidateParentOwnerAndMode(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("private parent ownership cannot be verified")
	}
	uid := uint32(os.Geteuid())
	if stat.Uid != uid && stat.Uid != 0 {
		return errors.New("private parent directory has wrong ownership")
	}
	perm := info.Mode().Perm()
	// A sticky /tmp-style parent is safe for a private child. Any other
	// group/other-writable parent permits path replacement by another user.
	if perm&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return errors.New("private parent directory is group-writable")
	}
	return nil
}

func LinkCount(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 0
}
