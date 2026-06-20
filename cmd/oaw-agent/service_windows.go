//go:build windows

package main

import (
	"context"
	"io"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	agentsupervisor "github.com/openassetwatch/openassetwatch/internal/agent/supervisor"
)

func runServiceRuntime(options agentsupervisor.Options, cycle agentsupervisor.CycleFunc, _ io.Writer, stderr io.Writer) int {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return runForegroundServiceRuntime(options, cycle, stderr)
	}

	logger := newWindowsEventLogger(options.ServiceName, stderr)
	defer logger.Close()

	if err := svc.Run(options.ServiceName, &windowsAgentService{
		options: options,
		cycle:   cycle,
		logger:  logger,
	}); err != nil {
		logger.Error("windows service runtime failed: " + err.Error())
		return 1
	}
	return 0
}

type windowsAgentService struct {
	options agentsupervisor.Options
	cycle   agentsupervisor.CycleFunc
	logger  *windowsEventLogger
}

func (service *windowsAgentService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	changes <- svc.Status{State: svc.StartPending}

	go func() {
		supervisor := agentsupervisor.New(service.options, service.cycle, service.logger)
		done <- supervisor.Run(ctx)
	}()

	running := svc.Status{State: svc.Running, Accepts: accepted}
	changes <- running
	service.logger.Info("OpenAssetWatch Agent service running")

	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- running
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				service.logger.Info("OpenAssetWatch Agent service stopping")
				cancel()
				err := <-done
				if err != nil {
					service.logger.Error("OpenAssetWatch Agent service stopped with error: " + err.Error())
					changes <- svc.Status{State: svc.Stopped, Win32ExitCode: 1}
					return false, 1
				}
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			default:
				service.logger.Warn("unsupported Windows service control request ignored")
			}
		case err := <-done:
			if err != nil {
				service.logger.Error("OpenAssetWatch Agent service exited with fatal error: " + err.Error())
				changes <- svc.Status{State: svc.Stopped, Win32ExitCode: 1}
				return false, 1
			}
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}

type windowsEventLogger struct {
	source   string
	eventLog *eventlog.Log
	fallback io.Writer
}

func newWindowsEventLogger(source string, fallback io.Writer) *windowsEventLogger {
	logger := &windowsEventLogger{source: source, fallback: fallback}
	if log, err := eventlog.Open(source); err == nil {
		logger.eventLog = log
	}
	return logger
}

func (logger *windowsEventLogger) Close() {
	if logger != nil && logger.eventLog != nil {
		_ = logger.eventLog.Close()
	}
}

func (logger *windowsEventLogger) Info(message string) {
	if logger != nil && logger.eventLog != nil {
		_ = logger.eventLog.Info(1, message)
		return
	}
	stderrServiceLogger{writer: logger.fallback}.Info(message)
}

func (logger *windowsEventLogger) Warn(message string) {
	if logger != nil && logger.eventLog != nil {
		_ = logger.eventLog.Warning(2, message)
		return
	}
	stderrServiceLogger{writer: logger.fallback}.Warn(message)
}

func (logger *windowsEventLogger) Error(message string) {
	if logger != nil && logger.eventLog != nil {
		_ = logger.eventLog.Error(3, message)
		return
	}
	stderrServiceLogger{writer: logger.fallback}.Error(message)
}
