//go:build !windows && !darwin

package main

import (
	"io"

	agentsupervisor "github.com/openassetwatch/openassetwatch/internal/agent/supervisor"
)

func runServiceRuntime(options agentsupervisor.Options, cycle agentsupervisor.CycleFunc, _ io.Writer, stderr io.Writer) int {
	return runForegroundServiceRuntime(options, cycle, stderr)
}
