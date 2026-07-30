//go:build linux

package interfaceinfo

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	linuxInterfacePromiscuous = 0x100
	maxInterfaceFlags         = 64
)

func platformPromiscuous(name string) (bool, bool) {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", name, "flags"))
	if err != nil || len(data) == 0 || len(data) > maxInterfaceFlags {
		return false, false
	}
	flags, err := parseLinuxInterfaceFlags(string(data))
	if err != nil {
		return false, false
	}
	return flags&linuxInterfacePromiscuous != 0, true
}

func parseLinuxInterfaceFlags(value string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(value), 0, 32)
}
