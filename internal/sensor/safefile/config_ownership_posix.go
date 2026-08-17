//go:build linux || darwin

package safefile

import (
	"errors"
	"os"
	"syscall"
)

func ValidateConfigDirectory(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("sensor config directory ownership cannot be verified")
	}
	if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		return errors.New("sensor config directory must be owned by root or the current user")
	}
	if info.Mode().Perm()&0o027 != 0 {
		return errors.New("sensor config directory must not be writable by group or accessible by other users")
	}
	if stat.Uid == 0 && os.Geteuid() != 0 {
		if info.Mode().Perm()&0o050 != 0o050 || !currentProcessGroup(uint32(stat.Gid)) {
			return errors.New("root-owned sensor config directory must be readable by the sensor service group")
		}
	}
	return nil
}

func ValidateConfigFile(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("sensor config ownership cannot be verified")
	}
	if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		return errors.New("sensor config must be owned by root or the current user")
	}
	permissions := info.Mode().Perm()
	if permissions&0o137 != 0 {
		return errors.New("sensor config must not be executable, group-writable, or accessible by other users")
	}
	if stat.Nlink != 1 {
		return errors.New("sensor config must have exactly one hard link")
	}
	if stat.Uid == 0 && os.Geteuid() != 0 {
		if permissions&0o040 == 0 || !currentProcessGroup(uint32(stat.Gid)) {
			return errors.New("root-owned sensor config must be readable by the sensor service group")
		}
	}
	return nil
}

func ValidateConfigAncestor(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("sensor config ancestor ownership cannot be verified")
	}
	if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		return errors.New("sensor config ancestor has unsafe ownership")
	}
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return errors.New("sensor config ancestor is group-writable")
	}
	return nil
}

func currentProcessGroup(group uint32) bool {
	if group == uint32(os.Getegid()) {
		return true
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, value := range groups {
		if group == uint32(value) {
			return true
		}
	}
	return false
}
