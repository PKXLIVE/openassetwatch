package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	// These limits intentionally keep replay input small enough for a local
	// demonstration.  Raw frames are copied only for the lifetime of the
	// source and are never persisted by this package.
	MaxSyntheticFrames     = 5_000
	MaxSyntheticFrameBytes = MaxFrameBytes
	MaxSyntheticTotalBytes = 16 << 20
	MaxSyntheticReplaySpan = 24 * time.Hour
)

type Synthetic struct {
	mu      sync.Mutex
	packets []Packet
	index   int
	closed  bool
	initErr error
}

func NewSynthetic(packets []Packet) *Synthetic {
	source, err := NewSyntheticWithLimits(packets, MaxSyntheticFrames, MaxSyntheticFrameBytes, MaxSyntheticTotalBytes, MaxSyntheticReplaySpan)
	if err != nil {
		return &Synthetic{initErr: err}
	}
	return source
}

// NewSyntheticWithLimits creates a defensive, bounded replay source. A zero
// limit uses the corresponding package default. The input slice and each
// packet's payload are copied, so callers may safely reuse or mutate them.
func NewSyntheticWithLimits(packets []Packet, maxFrames, maxFrameBytes, maxTotalBytes int, maxSpan time.Duration) (*Synthetic, error) {
	if maxFrames <= 0 {
		maxFrames = MaxSyntheticFrames
	}
	if maxFrames > MaxSyntheticFrames {
		return nil, fmt.Errorf("synthetic replay frame limit cannot exceed %d", MaxSyntheticFrames)
	}
	if maxFrameBytes <= 0 {
		maxFrameBytes = MaxSyntheticFrameBytes
	}
	if maxFrameBytes > MaxSyntheticFrameBytes {
		return nil, fmt.Errorf("synthetic frame limit cannot exceed %d bytes", MaxSyntheticFrameBytes)
	}
	if maxTotalBytes <= 0 {
		maxTotalBytes = MaxSyntheticTotalBytes
	}
	if maxTotalBytes > MaxSyntheticTotalBytes {
		return nil, fmt.Errorf("synthetic replay byte limit cannot exceed %d", MaxSyntheticTotalBytes)
	}
	if maxSpan <= 0 {
		maxSpan = MaxSyntheticReplaySpan
	}
	if maxSpan > MaxSyntheticReplaySpan {
		return nil, fmt.Errorf("synthetic replay span cannot exceed %s", MaxSyntheticReplaySpan)
	}
	if len(packets) > maxFrames {
		return nil, fmt.Errorf("synthetic replay exceeds %d frames", maxFrames)
	}
	copyPackets := make([]Packet, 0, len(packets))
	var total int
	var first, last time.Time
	for _, packet := range packets {
		if len(packet.Data) == 0 || len(packet.Data) > maxFrameBytes {
			return nil, fmt.Errorf("synthetic frame must contain 1 to %d bytes", maxFrameBytes)
		}
		if total > maxTotalBytes-len(packet.Data) {
			return nil, fmt.Errorf("synthetic replay exceeds %d bytes", maxTotalBytes)
		}
		total += len(packet.Data)
		if !packet.ObservedAt.IsZero() {
			if first.IsZero() || packet.ObservedAt.Before(first) {
				first = packet.ObservedAt
			}
			if last.IsZero() || packet.ObservedAt.After(last) {
				last = packet.ObservedAt
			}
		}
		data := append([]byte(nil), packet.Data...)
		copyPackets = append(copyPackets, Packet{Data: data, ObservedAt: packet.ObservedAt})
	}
	if !first.IsZero() && !last.IsZero() && last.Sub(first) > maxSpan {
		return nil, fmt.Errorf("synthetic replay span exceeds %s", maxSpan)
	}
	return &Synthetic{packets: copyPackets}, nil
}

func (s *Synthetic) Next(ctx context.Context) (Packet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Packet{}, err
	}
	if s.initErr != nil {
		return Packet{}, s.initErr
	}
	if s.closed {
		return Packet{}, errors.New("capture source is closed")
	}
	if s.index >= len(s.packets) {
		return Packet{}, io.EOF
	}
	packet := s.packets[s.index]
	s.packets[s.index] = Packet{}
	s.index++
	packet.Data = append([]byte(nil), packet.Data...)
	return packet, nil
}

func (s *Synthetic) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.packets = nil
	return nil
}

func (s *Synthetic) Name() string { return "synthetic-replay" }
