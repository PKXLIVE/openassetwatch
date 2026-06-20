//go:build darwin

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	agentsupervisor "github.com/openassetwatch/openassetwatch/internal/agent/supervisor"
)

const (
	darwinLogFile       = "oaw-agent.log"
	darwinLogMaxBytes   = int64(1024 * 1024)
	darwinLogMaxBackups = 3
)

func runServiceRuntime(options agentsupervisor.Options, cycle agentsupervisor.CycleFunc, _ io.Writer, stderr io.Writer) int {
	logger := newDarwinServiceLogger(defaultAgentPaths().LogDir, stderr)
	defer logger.Close()

	ctx, stop := signalContext()
	defer stop()

	serviceSupervisor := agentsupervisor.New(options, cycle, logger)
	if err := serviceSupervisor.Run(ctx); err != nil {
		logger.Error(err.Error())
		return 1
	}
	return 0
}

type darwinServiceLogger struct {
	mu       sync.Mutex
	path     string
	fallback io.Writer
}

func newDarwinServiceLogger(logDir string, fallback io.Writer) *darwinServiceLogger {
	return &darwinServiceLogger{
		path:     filepath.Join(strings.TrimSpace(logDir), darwinLogFile),
		fallback: fallback,
	}
}

func (logger *darwinServiceLogger) Close() {}

func (logger *darwinServiceLogger) Info(message string) {
	logger.write("info", message)
}

func (logger *darwinServiceLogger) Warn(message string) {
	logger.write("warn", message)
}

func (logger *darwinServiceLogger) Error(message string) {
	logger.write("error", message)
}

func (logger *darwinServiceLogger) write(level string, message string) {
	if logger == nil {
		return
	}
	line := fmt.Sprintf("%s %s %s\n", time.Now().UTC().Format(time.RFC3339), level, sanitizeLogMessage(message))

	logger.mu.Lock()
	defer logger.mu.Unlock()

	if strings.TrimSpace(logger.path) == "" {
		_, _ = io.WriteString(logger.fallback, line)
		return
	}
	if err := os.MkdirAll(filepath.Dir(logger.path), 0o750); err != nil {
		_, _ = io.WriteString(logger.fallback, line)
		return
	}
	if err := logger.rotateIfNeeded(int64(len(line))); err != nil {
		_, _ = io.WriteString(logger.fallback, line)
		return
	}
	file, err := os.OpenFile(logger.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		_, _ = io.WriteString(logger.fallback, line)
		return
	}
	defer file.Close()
	_, _ = file.WriteString(line)
}

func (logger *darwinServiceLogger) rotateIfNeeded(nextBytes int64) error {
	info, err := os.Stat(logger.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Size()+nextBytes <= darwinLogMaxBytes {
		return nil
	}

	for index := darwinLogMaxBackups - 1; index >= 1; index-- {
		from := fmt.Sprintf("%s.%d", logger.path, index)
		to := fmt.Sprintf("%s.%d", logger.path, index+1)
		if _, err := os.Stat(from); err == nil {
			_ = os.Rename(from, to)
		}
	}
	return os.Rename(logger.path, logger.path+".1")
}

func sanitizeLogMessage(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return ""
	}
	return sensitiveLogPattern.ReplaceAllString(message, "[redacted]")
}
