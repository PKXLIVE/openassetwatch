//go:build !windows

package credential

import (
	"errors"
	"os"
)

type directorySyncHandle interface {
	Sync() error
	Close() error
}

type credentialDurabilityError struct {
	message string
	cause   error
}

func (err *credentialDurabilityError) Error() string { return err.message }

func (err *credentialDurabilityError) Unwrap() error { return err.cause }

func syncRootDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return &credentialDurabilityError{
			message: "open agent credential directory for sync",
			cause:   err,
		}
	}
	return syncAndCloseRootDirectory(directory)
}

func syncAndCloseRootDirectory(directory directorySyncHandle) error {
	syncErr := directory.Sync()
	closeErr := directory.Close()

	var failures []error
	if syncErr != nil {
		failures = append(failures, &credentialDurabilityError{
			message: "sync agent credential directory",
			cause:   syncErr,
		})
	}
	if closeErr != nil {
		failures = append(failures, &credentialDurabilityError{
			message: "close agent credential directory",
			cause:   closeErr,
		})
	}
	return errors.Join(failures...)
}
