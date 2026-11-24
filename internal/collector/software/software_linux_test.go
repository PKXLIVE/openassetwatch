//go:build linux

package software

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLinuxNativeParsersAreBoundedAndDeterministic(t *testing.T) {
	observedAt := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	dpkg, malformed := parseDpkgOutput([]byte("libfictional:amd64\t1:2.3-1\tamd64\nbad-row\n"), "linux-dpkg", observedAt)
	if len(dpkg) != 1 || malformed != 1 || dpkg[0].Name != "libfictional" || dpkg[0].Version != "1:2.3-1" {
		t.Fatalf("dpkg = %+v malformed=%d", dpkg, malformed)
	}
	rpm, malformed := parseRPMOutput([]byte("fictional\t0:4.5-2\tx86_64\n"), "linux-rpm", observedAt)
	if len(rpm) != 1 || malformed != 0 || rpm[0].Version != "4.5-2" {
		t.Fatalf("rpm = %+v malformed=%d", rpm, malformed)
	}
}

func TestLimitedBufferStopsAtReviewedOutputLimit(t *testing.T) {
	buffer := &limitedBuffer{limit: 4}
	written, err := buffer.Write([]byte("123456"))
	if written != 4 || !errors.Is(err, errOutputLimit) || string(buffer.Bytes()) != "1234" {
		t.Fatalf("written=%d err=%v bytes=%q", written, err, buffer.Bytes())
	}
	if _, err := buffer.Write([]byte("7")); !errors.Is(err, errOutputLimit) {
		t.Fatalf("second write err=%v, want output limit", err)
	}
}

func TestLinuxParserRejectsOversizedLine(t *testing.T) {
	components, malformed := parseDpkgOutput(
		[]byte(strings.Repeat("x", 5000)+"\t1\tamd64\n"),
		"linux-dpkg",
		time.Now().UTC(),
	)
	if len(components) != 0 || malformed == 0 {
		t.Fatalf("components=%d malformed=%d", len(components), malformed)
	}
}

func TestLinuxSourceClassifiesTimeoutWithoutDiagnostics(t *testing.T) {
	observedAt := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	result := collectLinuxSources(
		context.Background(),
		observedAt,
		[]linuxSource{{
			id: "linux-dpkg", ecosystem: "deb", executable: "/usr/bin/dpkg-query",
			arguments: []string{"-W"}, parser: parseDpkgOutput,
		}},
		func(context.Context, string, ...string) ([]byte, error) {
			return []byte("private command diagnostics"), context.DeadlineExceeded
		},
	)
	if len(result.components) != 0 || len(result.sources) != 1 {
		t.Fatalf("result = %+v", result)
	}
	source := result.sources[0]
	if source.Status != "failed" || source.ErrorCode != "command-timeout" || len(source.Limitations) != 0 {
		t.Fatalf("source = %+v", source)
	}
}

func TestRunFixedCommandHonorsContextDeadline(t *testing.T) {
	executable := fixedExecutable("/usr/bin/sleep", "/bin/sleep")
	if executable == "" {
		t.Skip("reviewed sleep binary is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := runFixedCommand(ctx, executable, "1")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
}

func TestLinuxSourceClassifiesBoundedOutputAsPartial(t *testing.T) {
	observedAt := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	result := collectLinuxSources(
		context.Background(),
		observedAt,
		[]linuxSource{{
			id: "linux-dpkg", ecosystem: "deb", executable: "/usr/bin/dpkg-query",
			arguments: []string{"-W"}, parser: parseDpkgOutput,
		}},
		func(context.Context, string, ...string) ([]byte, error) {
			return []byte("fictional\t1.0\tamd64\n"), errOutputLimit
		},
	)
	if len(result.components) != 1 || len(result.sources) != 1 {
		t.Fatalf("result = %+v", result)
	}
	source := result.sources[0]
	if source.Status != "partial" || !source.Truncated || source.ErrorCode != "output-limit" {
		t.Fatalf("source = %+v", source)
	}
}
