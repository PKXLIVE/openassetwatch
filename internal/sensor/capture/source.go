package capture

import (
	"context"
	"errors"
	"time"
)

const MaxFrameBytes = 65535

var ErrUnsupported = errors.New("live packet capture is not supported on this platform")

type Packet struct {
	Data       []byte
	ObservedAt time.Time
}

type Source interface {
	Next(context.Context) (Packet, error)
	Close() error
	Name() string
}
