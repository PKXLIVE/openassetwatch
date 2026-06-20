//go:build !windows

package supervisor

import "os"

func replaceFile(source string, target string) error {
	return os.Rename(source, target)
}
