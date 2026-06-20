package supervisor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
