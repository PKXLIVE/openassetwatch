package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/openassetwatch/openassetwatch/pkg/version"
)

const (
	HealthHealthy  = "healthy"
	HealthDegraded = "degraded"
	HealthStopping = "stopping"

	StateStarting = "starting"
	StateRunning  = "running"
	StateStopping = "stopping"
	StateStopped  = "stopped"
)

var sensitivePattern = regexp.MustCompile(`(?i)(authorization|credential|password|token|api[_-]?key|apikey|secret|private[_-]?key)`)

type CycleFunc func(context.Context) CycleResult

type CycleResult struct {
	OK                bool
	ErrorCategory     string
	ErrorMessage      string
	LastInventoryPath string
}

type Logger interface {
	Info(string)
	Warn(string)
	Error(string)
}

type Options struct {
	ConfigPath       string
	IdentityPath     string
	OutputDir        string
	StatusPath       string
	InitialDelay     time.Duration
	SuccessInterval  time.Duration
	RetryBase        time.Duration
	MaxRetryDelay    time.Duration
	Jitter           time.Duration
	ShutdownTimeout  time.Duration
	Now              func() time.Time
	NewTimer         func(time.Duration) Timer
	RandomInt63n     func(int64) int64
	ProcessID        int
	AgentVersion     string
	ServiceName      string
	ServiceStartTime time.Time
}

type Timer interface {
	C() <-chan time.Time
	Stop() bool
}

type realTimer struct {
	timer *time.Timer
}

func (timer realTimer) C() <-chan time.Time {
	return timer.timer.C
}

func (timer realTimer) Stop() bool {
	return timer.timer.Stop()
}

type Status struct {
	SchemaVersion           int    `json:"schema_version"`
	AgentVersion            string `json:"agent_version"`
	ServiceName             string `json:"service_name,omitempty"`
	ServiceState            string `json:"service_state"`
	Health                  string `json:"health"`
	ProcessID               int    `json:"process_id,omitempty"`
	ConfigPath              string `json:"config_path,omitempty"`
	IdentityPath            string `json:"identity_path,omitempty"`
	OutputDir               string `json:"output_dir,omitempty"`
	LastAttemptAt           string `json:"last_attempt_at,omitempty"`
	LastSuccessfulAt        string `json:"last_successful_at,omitempty"`
	NextScheduledAttemptAt  string `json:"next_scheduled_attempt_at,omitempty"`
	ConsecutiveFailureCount int    `json:"consecutive_failure_count"`
	ErrorCategory           string `json:"error_category,omitempty"`
	ErrorMessage            string `json:"error_message,omitempty"`
	LastInventoryPath       string `json:"last_inventory_path,omitempty"`
	UpdatedAt               string `json:"updated_at"`
	StartedAt               string `json:"started_at,omitempty"`
}

type Supervisor struct {
	options Options
	cycle   CycleFunc
	logger  Logger
}

func New(options Options, cycle CycleFunc, logger Logger) *Supervisor {
	options = normalizeOptions(options)
	return &Supervisor{options: options, cycle: cycle, logger: logger}
}

func normalizeOptions(options Options) Options {
	if options.InitialDelay < 0 {
		options.InitialDelay = 0
	}
	if options.SuccessInterval <= 0 {
		options.SuccessInterval = time.Hour
	}
	if options.RetryBase <= 0 {
		options.RetryBase = 5 * time.Minute
	}
	if options.MaxRetryDelay <= 0 {
		options.MaxRetryDelay = time.Hour
	}
	if options.MaxRetryDelay < options.RetryBase {
		options.MaxRetryDelay = options.RetryBase
	}
	if options.Jitter < 0 {
		options.Jitter = 0
	}
	if options.ShutdownTimeout <= 0 {
		options.ShutdownTimeout = 30 * time.Second
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewTimer == nil {
		options.NewTimer = func(delay time.Duration) Timer {
			return realTimer{timer: time.NewTimer(delay)}
		}
	}
	if options.RandomInt63n == nil {
		source := rand.New(rand.NewSource(time.Now().UnixNano()))
		options.RandomInt63n = source.Int63n
	}
	if options.ProcessID == 0 {
		options.ProcessID = os.Getpid()
	}
	if strings.TrimSpace(options.AgentVersion) == "" {
		options.AgentVersion = version.String()
	}
	if options.ServiceStartTime.IsZero() {
		options.ServiceStartTime = options.Now().UTC()
	}
	return options
}

func (supervisor *Supervisor) Run(ctx context.Context) error {
	if supervisor.cycle == nil {
		return errors.New("supervisor cycle function is required")
	}

	supervisor.logInfo("service supervisor starting")
	delay := supervisor.options.InitialDelay
	consecutiveFailures := 0
	var lastAttempt time.Time
	var lastSuccess time.Time
	var lastInventoryPath string
	var lastErrorCategory string
	var lastErrorMessage string

	_ = supervisor.writeStatus(Status{
		ServiceState: StateRunning,
		Health:       HealthDegraded,
		UpdatedAt:    formatTime(supervisor.options.Now().UTC()),
		StartedAt:    formatTime(supervisor.options.ServiceStartTime.UTC()),
	})

	for {
		if delay > 0 {
			next := supervisor.options.Now().UTC().Add(delay)
			_ = supervisor.writeStatus(Status{
				ServiceState:            StateRunning,
				Health:                  healthForFailures(consecutiveFailures),
				LastAttemptAt:           formatTime(lastAttempt),
				LastSuccessfulAt:        formatTime(lastSuccess),
				NextScheduledAttemptAt:  formatTime(next),
				ConsecutiveFailureCount: consecutiveFailures,
				ErrorCategory:           lastErrorCategory,
				ErrorMessage:            lastErrorMessage,
				LastInventoryPath:       lastInventoryPath,
				UpdatedAt:               formatTime(supervisor.options.Now().UTC()),
				StartedAt:               formatTime(supervisor.options.ServiceStartTime.UTC()),
			})
			if err := supervisor.wait(ctx, delay); err != nil {
				return supervisor.stop(ctx, consecutiveFailures, lastAttempt, lastSuccess, lastInventoryPath, "", "")
			}
		}

		lastAttempt = supervisor.options.Now().UTC()
		result, stopped := supervisor.runCycle(ctx, consecutiveFailures, lastAttempt, lastSuccess, lastInventoryPath)
		if stopped {
			return supervisor.stop(ctx, consecutiveFailures, lastAttempt, lastSuccess, lastInventoryPath, "", "")
		}

		errorCategory := ""
		errorMessage := ""
		if result.OK {
			consecutiveFailures = 0
			lastErrorCategory = ""
			lastErrorMessage = ""
			lastSuccess = supervisor.options.Now().UTC()
			if strings.TrimSpace(result.LastInventoryPath) != "" {
				lastInventoryPath = strings.TrimSpace(result.LastInventoryPath)
			}
			supervisor.logInfo("agent cycle completed successfully")
		} else {
			consecutiveFailures++
			errorCategory = sanitize(result.ErrorCategory)
			errorMessage = sanitize(result.ErrorMessage)
			lastErrorCategory = errorCategory
			lastErrorMessage = errorMessage
			supervisor.logWarn("agent cycle degraded: " + errorCategory)
		}

		delay = NextDelay(result.OK, consecutiveFailures, supervisor.options)
		next := supervisor.options.Now().UTC().Add(delay)
		_ = supervisor.writeStatus(Status{
			ServiceState:            StateRunning,
			Health:                  healthForFailures(consecutiveFailures),
			LastAttemptAt:           formatTime(lastAttempt),
			LastSuccessfulAt:        formatTime(lastSuccess),
			NextScheduledAttemptAt:  formatTime(next),
			ConsecutiveFailureCount: consecutiveFailures,
			ErrorCategory:           errorCategory,
			ErrorMessage:            errorMessage,
			LastInventoryPath:       lastInventoryPath,
			UpdatedAt:               formatTime(supervisor.options.Now().UTC()),
			StartedAt:               formatTime(supervisor.options.ServiceStartTime.UTC()),
		})
	}
}

func (supervisor *Supervisor) wait(ctx context.Context, delay time.Duration) error {
	timer := supervisor.options.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C():
		return nil
	}
}

func (supervisor *Supervisor) runCycle(ctx context.Context, consecutiveFailures int, lastAttempt time.Time, lastSuccess time.Time, lastInventoryPath string) (CycleResult, bool) {
	cycleCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan CycleResult, 1)
	go func() {
		done <- supervisor.cycle(cycleCtx)
	}()

	select {
	case result := <-done:
		return result, false
	case <-ctx.Done():
		cancel()
		_ = supervisor.writeStatus(Status{
			ServiceState:            StateStopping,
			Health:                  HealthStopping,
			LastAttemptAt:           formatTime(lastAttempt),
			LastSuccessfulAt:        formatTime(lastSuccess),
			ConsecutiveFailureCount: consecutiveFailures,
			LastInventoryPath:       lastInventoryPath,
			UpdatedAt:               formatTime(supervisor.options.Now().UTC()),
			StartedAt:               formatTime(supervisor.options.ServiceStartTime.UTC()),
		})
		timer := supervisor.options.NewTimer(supervisor.options.ShutdownTimeout)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C():
			supervisor.logWarn("agent cycle did not stop before shutdown timeout")
		}
		return CycleResult{}, true
	}
}

func (supervisor *Supervisor) stop(_ context.Context, consecutiveFailures int, lastAttempt time.Time, lastSuccess time.Time, lastInventoryPath string, category string, message string) error {
	supervisor.logInfo("service supervisor stopped")
	return supervisor.writeStatus(Status{
		ServiceState:            StateStopped,
		Health:                  HealthStopping,
		LastAttemptAt:           formatTime(lastAttempt),
		LastSuccessfulAt:        formatTime(lastSuccess),
		ConsecutiveFailureCount: consecutiveFailures,
		ErrorCategory:           sanitize(category),
		ErrorMessage:            sanitize(message),
		LastInventoryPath:       lastInventoryPath,
		UpdatedAt:               formatTime(supervisor.options.Now().UTC()),
		StartedAt:               formatTime(supervisor.options.ServiceStartTime.UTC()),
	})
}

func (supervisor *Supervisor) writeStatus(status Status) error {
	status.SchemaVersion = 1
	status.AgentVersion = supervisor.options.AgentVersion
	status.ServiceName = supervisor.options.ServiceName
	status.ProcessID = supervisor.options.ProcessID
	status.ConfigPath = supervisor.options.ConfigPath
	status.IdentityPath = supervisor.options.IdentityPath
	status.OutputDir = supervisor.options.OutputDir
	if strings.TrimSpace(status.UpdatedAt) == "" {
		status.UpdatedAt = formatTime(supervisor.options.Now().UTC())
	}
	if strings.TrimSpace(status.StartedAt) == "" {
		status.StartedAt = formatTime(supervisor.options.ServiceStartTime.UTC())
	}
	if strings.TrimSpace(supervisor.options.StatusPath) == "" {
		return nil
	}
	return WriteStatusAtomic(supervisor.options.StatusPath, status)
}

func (supervisor *Supervisor) logInfo(message string) {
	if supervisor.logger != nil {
		supervisor.logger.Info(message)
	}
}

func (supervisor *Supervisor) logWarn(message string) {
	if supervisor.logger != nil {
		supervisor.logger.Warn(message)
	}
}

func NextDelay(success bool, consecutiveFailures int, options Options) time.Duration {
	options = normalizeOptions(options)
	if success || consecutiveFailures <= 0 {
		return options.SuccessInterval + jitter(options)
	}
	exponent := consecutiveFailures - 1
	if exponent > 30 {
		exponent = 30
	}
	delay := time.Duration(float64(options.RetryBase) * math.Pow(2, float64(exponent)))
	if delay <= 0 || delay > options.MaxRetryDelay {
		delay = options.MaxRetryDelay
	}
	return delay + jitter(options)
}

func WriteStatusAtomic(path string, status Status) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	status.ErrorCategory = sanitize(status.ErrorCategory)
	status.ErrorMessage = sanitize(status.ErrorMessage)
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := replaceFile(tempPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func jitter(options Options) time.Duration {
	if options.Jitter <= 0 {
		return 0
	}
	n := options.Jitter.Nanoseconds()
	if n <= 0 {
		return 0
	}
	return time.Duration(options.RandomInt63n(n + 1))
}

func healthForFailures(consecutiveFailures int) string {
	if consecutiveFailures > 0 {
		return HealthDegraded
	}
	return HealthHealthy
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func sanitize(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return sensitivePattern.ReplaceAllString(value, "[redacted]")
}
