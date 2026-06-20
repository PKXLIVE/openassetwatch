package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	agentsupervisor "github.com/openassetwatch/openassetwatch/internal/agent/supervisor"
)

type stderrServiceLogger struct {
	writer io.Writer
}

var runServiceRuntimeForCommand = runServiceRuntime

var sensitiveLogPattern = regexp.MustCompile(`(?i)(authorization|credential|password|token|api[_-]?key|apikey|secret|private[_-]?key)(\s*[:=]\s*[^,\s;]+)?|request body|response body`)

func (logger stderrServiceLogger) Info(message string) {
	fmt.Fprintf(logger.writer, "info: %s\n", message)
}

func (logger stderrServiceLogger) Warn(message string) {
	fmt.Fprintf(logger.writer, "warn: %s\n", message)
}

func (logger stderrServiceLogger) Error(message string) {
	fmt.Fprintf(logger.writer, "error: %s\n", message)
}

func runForegroundServiceRuntime(options agentsupervisor.Options, cycle agentsupervisor.CycleFunc, stderr io.Writer) int {
	ctx, stop := signalContext()
	defer stop()

	logger := stderrServiceLogger{writer: stderr}
	serviceSupervisor := agentsupervisor.New(options, cycle, logger)
	if err := serviceSupervisor.Run(ctx); err != nil {
		logger.Error(err.Error())
		return 1
	}
	return 0
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
