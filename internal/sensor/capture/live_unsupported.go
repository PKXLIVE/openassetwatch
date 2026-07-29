//go:build !linux

package capture

func NewLive(string) (Source, error) { return nil, ErrUnsupported }
