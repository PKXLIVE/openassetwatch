//go:build !linux

package interfaceinfo

import "runtime"

func EffectiveCapabilities() CapabilityState {
	return CapabilityState{
		Platform: runtime.GOOS, InspectionSource: "unsupported",
		Supported: false, Required: []string{"CAP_NET_RAW"},
	}
}
