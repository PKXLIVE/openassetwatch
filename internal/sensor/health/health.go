package health

import (
	"strings"
	"sync"
	"time"
)

type Snapshot struct {
	Running               bool      `json:"running"`
	CaptureSource         string    `json:"capture_source"`
	CaptureMode           string    `json:"capture_mode,omitempty"`
	CaptureInterface      string    `json:"capture_interface,omitempty"`
	PacketsObserved       uint64    `json:"packets_observed"`
	PacketsDecoded        uint64    `json:"packets_decoded"`
	MalformedFrames       uint64    `json:"malformed_frames"`
	ObservationsGenerated uint64    `json:"observations_generated"`
	BatchesSent           uint64    `json:"batches_sent"`
	BatchesQueued         int       `json:"batches_queued"`
	LastSuccessfulUpload  time.Time `json:"last_successful_upload,omitempty"`
	LastCaptureError      string    `json:"last_capture_error,omitempty"`
	LastHubError          string    `json:"last_hub_error,omitempty"`
	QueueUtilization      float64   `json:"queue_utilization"`
	QueueWarning          string    `json:"queue_warning,omitempty"`
	QueueOverflow         bool      `json:"queue_overflow"`
	Version               string    `json:"version"`
	SiteID                string    `json:"site_id"`
	SensorID              string    `json:"sensor_id"`
}

type Tracker struct {
	mu    sync.Mutex
	state Snapshot
}

func New(version, siteID, sensorID, source string) *Tracker {
	return NewWithDetails(version, siteID, sensorID, "", "", source)
}

func NewWithDetails(version, siteID, sensorID, mode, interfaceName, source string) *Tracker {
	return &Tracker{state: Snapshot{
		Running:          true,
		Version:          version,
		SiteID:           siteID,
		SensorID:         sensorID,
		CaptureMode:      clean(mode),
		CaptureInterface: clean(interfaceName),
		CaptureSource:    clean(source),
	}}
}

func (t *Tracker) Stop() { t.update(func(state *Snapshot) { state.Running = false }) }
func (t *Tracker) Packet(decoded bool) {
	t.PacketResult(decoded, !decoded)
}

func (t *Tracker) PacketResult(decoded, malformed bool) {
	t.update(func(state *Snapshot) {
		state.PacketsObserved++
		if decoded {
			state.PacketsDecoded++
		}
		if malformed {
			state.MalformedFrames++
		}
	})
}
func (t *Tracker) Observations(count int) {
	t.update(func(state *Snapshot) { state.ObservationsGenerated += uint64(max(count, 0)) })
}
func (t *Tracker) Sent(at time.Time) {
	t.update(func(state *Snapshot) {
		state.BatchesSent++
		state.LastSuccessfulUpload = at.UTC()
		state.LastHubError = ""
	})
}
func (t *Tracker) CaptureError(message string) {
	t.update(func(state *Snapshot) { state.LastCaptureError = clean(message) })
}
func (t *Tracker) HubError(message string) {
	t.update(func(state *Snapshot) { state.LastHubError = clean(message) })
}
func (t *Tracker) Queue(items int, utilization float64, warning string) {
	t.QueueState(items, utilization, warning, false)
}

func (t *Tracker) QueueState(items int, utilization float64, warning string, overflow bool) {
	t.update(func(state *Snapshot) {
		state.BatchesQueued = items
		state.QueueUtilization = utilization
		state.QueueWarning = clean(warning)
		state.QueueOverflow = overflow
	})
}
func (t *Tracker) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

func (t *Tracker) update(fn func(*Snapshot)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fn(&t.state)
}

func clean(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}
