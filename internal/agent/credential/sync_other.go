//go:build !windows

package credential

import "os"

func syncRootDirectory(root *os.Root) error {
	return root.Sync()
}
