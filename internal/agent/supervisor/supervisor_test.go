package supervisor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNextDelayUsesSuccessInterval(t *testing.T) {
	options := Options{
		SuccessInterval: time.Hour,
		RetryBase:       5 * time.Minute,
		MaxRetryDelay:   time.Hour,
		Jitter:          0,
	}
	if got := NextDelay(true, 0, options); got != time.Hour {
		t.Fatalf("success delay = %s, want 1h", got)
	}
}

func TestNextDelayUsesBoundedExponentialBackoff(t *testing.T) {
	options := Options{
		SuccessInterval: time.Hour,
		RetryBase:       5 * time.Minute,
		MaxRetryDelay:   time.Hour,
		Jitter:          0,
	}
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{failures: 1, want: 5 * time.Minute},
		{failures: 2, want: 10 * time.Minute},
		{failures: 3, want: 20 * time.Minute},
		{failures: 99, want: time.Hour},
	}
	for _, tt := range tests {
		if got := NextDelay(false, tt.failures, options); got != tt.want {
			t.Fatalf("failure delay for %d failures = %s, want %s", tt.failures, got, tt.want)
		}
	}
}

func TestNextDelayAddsBoundedJitter(t *testing.T) {
	options := Options{
		SuccessInterval: time.Hour,
		RetryBase:       5 * time.Minute,
		MaxRetryDelay:   time.Hour,
		Jitter:          30 * time.Second,
		RandomInt63n: func(n int64) int64 {
			if n != int64(30*time.Second)+1 {
				t.Fatalf("jitter bound = %d", n)
			}
			return int64(7 * time.Second)
		},
	}
	if got := NextDelay(false, 1, options); got != 5*time.Minute+7*time.Second {
		t.Fatalf("delay with jitter = %s", got)
	}
}

func TestWriteStatusAtomicRedactsSensitiveTerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "status.json")
	err := WriteStatusAtomic(path, Status{
		ServiceState:  StateRunning,
		Health:        HealthDegraded,
		ErrorCategory: "token",
		ErrorMessage:  "password token secret credential api_key private_key",
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(data))
	for _, forbidden := range []string{"password", "token", "secret", "credential", "api_key", "private_key"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("status contains forbidden term %q: %s", forbidden, string(data))
		}
	}
	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatalf("status JSON malformed: %v", err)
	}
	if status.ErrorMessage == "" || !strings.Contains(status.ErrorMessage, "[redacted]") {
		t.Fatalf("error message not redacted: %+v", status)
	}
}

func TestWriteStatusAtomicReplacesExistingStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "status.json")
	if err := WriteStatusAtomic(path, Status{ServiceState: StateRunning, Health: HealthDegraded, ErrorMessage: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteStatusAtomic(path, Status{ServiceState: StateRunning, Health: HealthHealthy, ErrorMessage: "second"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "first") {
		t.Fatalf("status replacement retained old content: %s", string(data))
	}
	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	if status.Health != HealthHealthy || status.ErrorMessage != "second" {
		t.Fatalf("status = %+v, want replacement content", status)
	}
}

func TestSupervisorRunsFirstCycleImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	cycle := func(context.Context) CycleResult {
		started <- struct{}{}
		<-release
		return CycleResult{OK: true}
	}
	options := Options{
		StatusPath:      filepath.Join(t.TempDir(), "status.json"),
		InitialDelay:    0,
		SuccessInterval: time.Hour,
		NewTimer: func(time.Duration) Timer {
			return manualTimer{ch: make(chan time.Time)}
		},
	}
	done := make(chan error, 1)
	go func() {
		done <- New(options, cycle, nil).Run(ctx)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("initial cycle did not start promptly")
	}
	cancel()
	close(release)
	<-done
}

func TestSupervisorCancelBeforeDelayedCycleStopsWithoutCycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	timers := newTimerRecorder()
	cycles := 0
	done := make(chan error, 1)
	go func() {
		done <- New(Options{
			StatusPath:      filepath.Join(t.TempDir(), "status.json"),
			InitialDelay:    time.Hour,
			NewTimer:        timers.NewTimer,
			ShutdownTimeout: time.Second,
		}, func(context.Context) CycleResult {
			cycles++
			return CycleResult{OK: true}
		}, nil).Run(ctx)
	}()
	if got := timers.waitForDelay(t, 0); got != time.Hour {
		t.Fatalf("initial timer delay = %s, want 1h", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if cycles != 0 {
		t.Fatalf("cycles = %d, want 0", cycles)
	}
}

func TestSupervisorShutdownTimeoutBoundsActiveCycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	timers := newTimerRecorder()
	started := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- New(Options{
			StatusPath:       filepath.Join(t.TempDir(), "status.json"),
			InitialDelay:     0,
			ShutdownTimeout:  30 * time.Second,
			NewTimer:         timers.NewTimer,
			SuccessInterval:  time.Hour,
			ServiceStartTime: time.Unix(0, 0).UTC(),
		}, func(ctx context.Context) CycleResult {
			started <- struct{}{}
			<-ctx.Done()
			select {}
		}, nil).Run(ctx)
	}()
	<-started
	cancel()
	if got := timers.waitForDelay(t, 0); got != 30*time.Second {
		t.Fatalf("shutdown timer delay = %s, want 30s", got)
	}
	timers.fire(0)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorRetryResetAfterSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timers := newTimerRecorder()
	results := []CycleResult{{OK: false, ErrorCategory: "missing_config", ErrorMessage: "missing config"}, {OK: true}}
	done := make(chan error, 1)
	go func() {
		done <- New(Options{
			StatusPath:      filepath.Join(t.TempDir(), "status.json"),
			InitialDelay:    0,
			SuccessInterval: time.Hour,
			RetryBase:       5 * time.Minute,
			MaxRetryDelay:   time.Hour,
			Jitter:          0,
			NewTimer:        timers.NewTimer,
		}, func(context.Context) CycleResult {
			result := results[0]
			results = results[1:]
			return result
		}, nil).Run(ctx)
	}()
	if got := timers.waitForDelay(t, 0); got != 5*time.Minute {
		t.Fatalf("retry timer delay = %s, want 5m", got)
	}
	timers.fire(0)
	if got := timers.waitForDelay(t, 1); got != time.Hour {
		t.Fatalf("success timer delay = %s, want 1h", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorWritesDegradedMissingConfigStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	statusPath := filepath.Join(t.TempDir(), "status.json")
	timers := newTimerRecorder()
	done := make(chan error, 1)
	go func() {
		done <- New(Options{
			StatusPath:    statusPath,
			InitialDelay:  0,
			RetryBase:     5 * time.Minute,
			MaxRetryDelay: time.Hour,
			Jitter:        0,
			NewTimer:      timers.NewTimer,
		}, func(context.Context) CycleResult {
			return CycleResult{OK: false, ErrorCategory: "missing_config", ErrorMessage: "missing config"}
		}, nil).Run(ctx)
	}()
	_ = timers.waitForDelay(t, 0)
	var status Status
	data, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	if status.Health != HealthDegraded || status.ConsecutiveFailureCount != 1 || status.ErrorCategory != "missing_config" {
		t.Fatalf("status = %+v, want degraded missing config", status)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorCancelsActiveCycleContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	timers := newTimerRecorder()
	started := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- New(Options{
			StatusPath:      filepath.Join(t.TempDir(), "status.json"),
			InitialDelay:    0,
			ShutdownTimeout: time.Minute,
			NewTimer:        timers.NewTimer,
		}, func(ctx context.Context) CycleResult {
			started <- struct{}{}
			<-ctx.Done()
			cancelled <- struct{}{}
			return CycleResult{OK: false, ErrorCategory: "cancelled", ErrorMessage: ctx.Err().Error()}
		}, nil).Run(ctx)
	}()
	<-started
	cancel()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("cycle context was not cancelled")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorDoesNotRunOverlappingCycles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var concurrent int
	var maxConcurrent int
	cycle := func(context.Context) CycleResult {
		concurrent++
		if concurrent > maxConcurrent {
			maxConcurrent = concurrent
		}
		started <- struct{}{}
		<-release
		concurrent--
		return CycleResult{OK: true}
	}
	options := Options{
		StatusPath:      filepath.Join(t.TempDir(), "status.json"),
		InitialDelay:    0,
		SuccessInterval: time.Hour,
		RetryBase:       time.Minute,
		MaxRetryDelay:   time.Hour,
		Jitter:          0,
		NewTimer: func(time.Duration) Timer {
			return manualTimer{ch: make(chan time.Time)}
		},
	}
	done := make(chan error, 1)
	go func() {
		done <- New(options, cycle, nil).Run(ctx)
	}()
	<-started
	cancel()
	close(release)
	<-done
	if maxConcurrent != 1 {
		t.Fatalf("max concurrent cycles = %d, want 1", maxConcurrent)
	}
}

type manualTimer struct {
	ch chan time.Time
}

func (timer manualTimer) C() <-chan time.Time {
	return timer.ch
}

func (timer manualTimer) Stop() bool {
	return true
}

type timerRecorder struct {
	mu     sync.Mutex
	timers []recordedTimer
	ready  chan struct{}
}

type recordedTimer struct {
	delay time.Duration
	ch    chan time.Time
}

func newTimerRecorder() *timerRecorder {
	return &timerRecorder{ready: make(chan struct{}, 32)}
}

func (recorder *timerRecorder) NewTimer(delay time.Duration) Timer {
	timer := recordedTimer{delay: delay, ch: make(chan time.Time, 1)}
	recorder.mu.Lock()
	recorder.timers = append(recorder.timers, timer)
	recorder.mu.Unlock()
	recorder.ready <- struct{}{}
	return manualTimer{ch: timer.ch}
}

func (recorder *timerRecorder) waitForDelay(t *testing.T, index int) time.Duration {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		recorder.mu.Lock()
		if len(recorder.timers) > index {
			delay := recorder.timers[index].delay
			recorder.mu.Unlock()
			return delay
		}
		recorder.mu.Unlock()
		select {
		case <-recorder.ready:
		case <-deadline:
			t.Fatalf("timer %d was not created", index)
		}
	}
}

func (recorder *timerRecorder) fire(index int) {
	recorder.mu.Lock()
	timer := recorder.timers[index]
	recorder.mu.Unlock()
	timer.ch <- time.Now()
}
