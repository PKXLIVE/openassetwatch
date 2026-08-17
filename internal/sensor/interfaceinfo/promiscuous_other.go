//go:build !linux

package interfaceinfo

func platformPromiscuous(_ string) (bool, bool) {
	return false, false
}
