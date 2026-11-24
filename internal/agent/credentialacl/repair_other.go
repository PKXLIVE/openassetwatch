//go:build !windows

package credentialacl

import "errors"

func RepairDefault() error {
	return errors.New("credential ACL repair is supported only on Windows")
}
