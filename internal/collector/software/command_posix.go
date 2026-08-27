//go:build linux || darwin

package software

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
)

var errOutputLimit = errors.New("native package command output limit exceeded")

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (value *limitedBuffer) Write(data []byte) (int, error) {
	remaining := value.limit - value.buffer.Len()
	if remaining <= 0 {
		return 0, errOutputLimit
	}
	if len(data) > remaining {
		_, _ = value.buffer.Write(data[:remaining])
		return remaining, errOutputLimit
	}
	return value.buffer.Write(data)
}

func (value *limitedBuffer) Bytes() []byte { return value.buffer.Bytes() }

func fixedExecutable(candidates ...string) string {
	for _, candidate := range candidates {
		info, err := os.Lstat(candidate)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&0o022 != 0 {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Nlink != 1 {
			continue
		}
		return candidate
	}
	return ""
}

func runFixedCommand(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	stdout := &limitedBuffer{limit: MaxCommandOutput}
	stderr := &limitedBuffer{limit: MaxDiagnosticBytes}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = []string{"LC_ALL=C", "LANG=C"}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return stdout.Bytes(), context.DeadlineExceeded
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return stdout.Bytes(), errors.New("native package command failed")
		}
		if errors.Is(err, io.ErrShortWrite) || errors.Is(err, errOutputLimit) {
			return stdout.Bytes(), errOutputLimit
		}
		return stdout.Bytes(), errors.New("native package command unavailable")
	}
	return stdout.Bytes(), nil
}
