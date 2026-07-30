// Package diagnostic provides bounded, aggregate-only passive capture checks.
package diagnostic

import (
	"context"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/openassetwatch/openassetwatch/internal/sensor/capture"
	"github.com/openassetwatch/openassetwatch/internal/sensor/decode"
	"github.com/openassetwatch/openassetwatch/internal/sensor/interfaceinfo"
)

const (
	MinDuration         = time.Second
	MaxDuration         = 5 * time.Minute
	MaxCandidateDevices = 10_000
)

type Summary struct {
	Interface               string                        `json:"interface"`
	CaptureSource           string                        `json:"capture_source"`
	RequestedDuration       string                        `json:"requested_duration"`
	CaptureDurationMillis   int64                         `json:"capture_duration_ms"`
	FramesObserved          uint64                        `json:"frames_observed"`
	FramesDecoded           uint64                        `json:"frames_decoded"`
	MalformedFrames         uint64                        `json:"malformed_frames"`
	RejectedFrames          uint64                        `json:"rejected_frames"`
	ProtocolCounts          map[string]uint64             `json:"protocol_counts"`
	VLANIDsObserved         []int                         `json:"vlan_ids_observed"`
	CandidateDeviceCount    int                           `json:"candidate_device_count"`
	CandidateDeviceOverflow bool                          `json:"candidate_device_overflow"`
	Capabilities            interfaceinfo.CapabilityState `json:"capabilities"`
}

func Run(
	parent context.Context,
	source capture.Source,
	interfaceName string,
	duration time.Duration,
	capabilities interfaceinfo.CapabilityState,
) (Summary, error) {
	if source == nil {
		return Summary{}, errors.New("capture source is required")
	}
	if duration < MinDuration || duration > MaxDuration {
		return Summary{}, errors.New("capture-check duration must be between 1s and 5m")
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, duration)
	defer cancel()
	summary := Summary{
		Interface: interfaceName, CaptureSource: source.Name(),
		RequestedDuration: duration.String(), ProtocolCounts: make(map[string]uint64),
		Capabilities: capabilities, VLANIDsObserved: []int{},
	}
	devices := make(map[string]struct{})
	vlans := make(map[int]struct{})
	for {
		packet, err := source.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.DeadlineExceeded) ||
				(errors.Is(err, context.Canceled) && ctx.Err() != nil) {
				break
			}
			return summary, err
		}
		summary.FramesObserved++
		evidence, decodeErr := decode.Frame(packet.Data, packet.ObservedAt)
		clear(packet.Data)
		packet.Data = nil
		if decodeErr != nil {
			summary.MalformedFrames++
			summary.RejectedFrames++
			continue
		}
		if len(evidence) == 0 {
			summary.RejectedFrames++
			continue
		}
		summary.FramesDecoded++
		frameProtocols := make(map[string]struct{}, 8)
		frameHasVLAN := false
		for _, item := range evidence {
			if supportedProtocol(item.Protocol) {
				frameProtocols[item.Protocol] = struct{}{}
			}
			if item.VLANID != nil && *item.VLANID >= 0 && *item.VLANID <= 4094 {
				vlans[*item.VLANID] = struct{}{}
				frameHasVLAN = true
			}
			if item.MAC != "" {
				if len(devices) < MaxCandidateDevices {
					devices[item.MAC] = struct{}{}
				} else if _, exists := devices[item.MAC]; !exists {
					summary.CandidateDeviceOverflow = true
				}
			}
		}
		if frameHasVLAN {
			frameProtocols["vlan"] = struct{}{}
		}
		for protocol := range frameProtocols {
			summary.ProtocolCounts[protocol]++
		}
	}
	summary.CandidateDeviceCount = len(devices)
	for vlan := range vlans {
		summary.VLANIDsObserved = append(summary.VLANIDsObserved, vlan)
	}
	sort.Ints(summary.VLANIDsObserved)
	summary.CaptureDurationMillis = time.Since(started).Milliseconds()
	return summary, nil
}

func supportedProtocol(value string) bool {
	switch value {
	case "arp", "dhcpv4", "dns", "mdns", "ssdp", "nbns":
		return true
	default:
		return false
	}
}
