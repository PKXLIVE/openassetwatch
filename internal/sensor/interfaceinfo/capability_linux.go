//go:build linux

package interfaceinfo

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

const (
	capNetAdmin = 12
	capNetRaw   = 13
	maxStatus   = 64 << 10
)

func EffectiveCapabilities() CapabilityState {
	state := CapabilityState{
		Platform: runtime.GOOS, InspectionSource: "/proc/self/status",
		Supported: true, Required: []string{"CAP_NET_RAW"},
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil || len(data) > maxStatus {
		state.InspectionSource = "unavailable"
		return state
	}
	effective, ok := parseEffectiveCapabilities(string(data))
	if !ok {
		state.InspectionSource = "unavailable"
		return state
	}
	state.NetRawEffective = effective&(uint64(1)<<capNetRaw) != 0
	state.NetAdminEffective = effective&(uint64(1)<<capNetAdmin) != 0
	state.Sufficient = state.NetRawEffective
	return state
}

func parseEffectiveCapabilities(value string) (uint64, bool) {
	for _, line := range strings.Split(value, "\n") {
		key, encoded, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(key) != "CapEff" {
			continue
		}
		parsed, err := strconv.ParseUint(strings.TrimSpace(encoded), 16, 64)
		return parsed, err == nil
	}
	return 0, false
}
