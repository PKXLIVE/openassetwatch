package capture

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestSyntheticDefensivelyCopiesAndReleasesFrames(t *testing.T) {
	observedAt := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	input := []Packet{{Data: []byte{1, 2, 3}, ObservedAt: observedAt}}
	source, err := NewSyntheticWithLimits(input, 1, 16, 16, time.Second)
	if err != nil {
		t.Fatalf("NewSyntheticWithLimits() error = %v", err)
	}
	input[0].Data[0] = 9
	packet, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if packet.Data[0] != 1 {
		t.Fatalf("source retained caller mutation: %v", packet.Data)
	}
	if source.packets[0].Data != nil {
		t.Fatal("source retained raw frame bytes after delivery")
	}
	packet.Data[0] = 7
	if _, err := source.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("Next() after replay = %v, want EOF", err)
	}
	if err := source.Close(); err != nil || source.packets != nil {
		t.Fatalf("Close() = %v, packets retained=%t", err, source.packets != nil)
	}
}

func TestSyntheticEnforcesAllReplayBounds(t *testing.T) {
	base := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		packets              []Packet
		frames, frame, total int
		span                 time.Duration
	}{
		"frame count": {
			packets: []Packet{{Data: []byte{1}}, {Data: []byte{2}}},
			frames:  1, frame: 8, total: 8, span: time.Second,
		},
		"individual frame": {
			packets: []Packet{{Data: []byte{1, 2, 3}}},
			frames:  1, frame: 2, total: 8, span: time.Second,
		},
		"total bytes": {
			packets: []Packet{{Data: []byte{1, 2}}, {Data: []byte{3, 4}}},
			frames:  2, frame: 2, total: 3, span: time.Second,
		},
		"replay span": {
			packets: []Packet{
				{Data: []byte{1}, ObservedAt: base},
				{Data: []byte{2}, ObservedAt: base.Add(2 * time.Second)},
			},
			frames: 2, frame: 8, total: 8, span: time.Second,
		},
		"empty frame": {
			packets: []Packet{{Data: nil}},
			frames:  1, frame: 8, total: 8, span: time.Second,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSyntheticWithLimits(test.packets, test.frames, test.frame, test.total, test.span); err == nil {
				t.Fatal("NewSyntheticWithLimits() unexpectedly succeeded")
			}
		})
	}
}

func TestSyntheticRejectsLimitsAboveAbsoluteMaximums(t *testing.T) {
	packet := []Packet{{Data: []byte{1}}}
	if _, err := NewSyntheticWithLimits(packet, MaxSyntheticFrames+1, 1, 1, time.Second); err == nil {
		t.Fatal("accepted frame limit above absolute maximum")
	}
	if _, err := NewSyntheticWithLimits(packet, 1, MaxSyntheticFrameBytes+1, 1, time.Second); err == nil {
		t.Fatal("accepted frame size above absolute maximum")
	}
	if _, err := NewSyntheticWithLimits(packet, 1, 1, MaxSyntheticTotalBytes+1, time.Second); err == nil {
		t.Fatal("accepted byte limit above absolute maximum")
	}
	if _, err := NewSyntheticWithLimits(packet, 1, 1, 1, MaxSyntheticReplaySpan+time.Second); err == nil {
		t.Fatal("accepted replay span above absolute maximum")
	}
}

func TestSyntheticHonorsCancelledContext(t *testing.T) {
	source := NewSynthetic([]Packet{{Data: []byte{1}}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Next() = %v, want context cancellation", err)
	}
}
