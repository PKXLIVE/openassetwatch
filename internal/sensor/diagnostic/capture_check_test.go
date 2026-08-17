package diagnostic

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/openassetwatch/openassetwatch/internal/sensor/capture"
	"github.com/openassetwatch/openassetwatch/internal/sensor/interfaceinfo"
	"github.com/openassetwatch/openassetwatch/internal/sensor/replay"
)

type waitingSource struct{}

func (waitingSource) Next(ctx context.Context) (capture.Packet, error) {
	<-ctx.Done()
	return capture.Packet{}, ctx.Err()
}
func (waitingSource) Close() error { return nil }
func (waitingSource) Name() string { return "test-waiting-source" }

func TestReplayCaptureCheckIsAggregateOnly(t *testing.T) {
	source := replay.NewSource(replay.DemoObservedAt)
	defer source.Close()
	summary, err := Run(
		context.Background(), source, "synthetic-test", time.Second,
		interfaceinfo.CapabilityState{Platform: "test", Required: []string{"CAP_NET_RAW"}, Sufficient: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if summary.FramesObserved != 6 || summary.FramesDecoded != 6 || summary.MalformedFrames != 0 {
		t.Fatalf("capture summary = %+v", summary)
	}
	if summary.CandidateDeviceCount != 1 || len(summary.VLANIDsObserved) != 1 || summary.VLANIDsObserved[0] != 100 {
		t.Fatalf("bounded device/VLAN summary = %+v", summary)
	}
	for _, protocol := range []string{"arp", "dhcpv4", "dns", "mdns", "ssdp", "nbns", "vlan"} {
		if summary.ProtocolCounts[protocol] == 0 {
			t.Errorf("protocol %q was not counted", protocol)
		}
	}
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"raw_packet", "packet_bytes", "payload", "printer.example", "authorization", "credential"} {
		if strings.Contains(strings.ToLower(string(data)), forbidden) {
			t.Fatalf("capture summary exposed forbidden value %q", forbidden)
		}
	}
}

func TestCaptureCheckCountsMalformedAndUnsupportedFrames(t *testing.T) {
	source, err := capture.NewSyntheticWithLimits(
		[]capture.Packet{
			{Data: []byte{1, 2, 3}, ObservedAt: time.Now()},
			{Data: make([]byte, 14), ObservedAt: time.Now()},
		},
		2,
		capture.MaxFrameBytes,
		2*capture.MaxFrameBytes,
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	summary, err := Run(context.Background(), source, "synthetic-test", time.Second, interfaceinfo.CapabilityState{})
	if err != nil {
		t.Fatal(err)
	}
	if summary.FramesObserved != 2 || summary.MalformedFrames != 1 || summary.RejectedFrames != 2 {
		t.Fatalf("capture summary = %+v", summary)
	}
}

func TestCaptureCheckDurationIsRequiredAndBounded(t *testing.T) {
	for _, duration := range []time.Duration{0, time.Millisecond, MaxDuration + time.Second} {
		if _, err := Run(context.Background(), waitingSource{}, "test", duration, interfaceinfo.CapabilityState{}); err == nil {
			t.Fatalf("Run() accepted duration %s", duration)
		}
	}
	started := time.Now()
	summary, err := Run(context.Background(), waitingSource{}, "test", time.Second, interfaceinfo.CapabilityState{})
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 900*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("bounded capture duration = %s", elapsed)
	}
	if summary.CaptureDurationMillis < 900 || summary.CaptureDurationMillis > 2000 {
		t.Fatalf("reported capture duration = %dms", summary.CaptureDurationMillis)
	}
}
