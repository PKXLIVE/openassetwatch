//go:build !linux && !darwin

package safefile

import "os"

func ValidateConfigDirectory(os.FileInfo) error { return nil }
func ValidateConfigFile(os.FileInfo) error      { return nil }
func ValidateConfigAncestor(os.FileInfo) error  { return nil }
