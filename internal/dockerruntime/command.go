package dockerruntime

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
)

const (
	commandStdoutLimit = 64 << 10
	commandStderrLimit = 32 << 10
)

var minimalEnvironment = []string{
	"HOME=/nonexistent",
	"LANG=C",
	"LC_ALL=C",
	"PATH=/usr/bin:/bin",
}

func (r *Runtime) command(ctx context.Context, arguments ...string) *exec.Cmd {
	all := make([]string, 0, len(arguments)+2)
	all = append(all, "--host", r.endpoint)
	all = append(all, arguments...)
	command := exec.CommandContext(ctx, r.cli, all...)
	command.Env = append([]string(nil), minimalEnvironment...)
	return command
}

func (r *Runtime) run(ctx context.Context, operation string, arguments ...string) ([]byte, error) {
	output, _, err := r.runObserved(ctx, operation, arguments...)
	return output, err
}

// runObserved reports whether the CLI process was actually started. This is
// security-significant only for Docker create: a local exec/start failure is
// certain not to have reached the daemon, while any failure after Start leaves
// the daemon-side result uncertain. Callers must retain boot-scoped durable
// intent authority and must not dispatch a replacement Create.
func (r *Runtime) runObserved(ctx context.Context, operation string, arguments ...string) ([]byte, bool, error) {
	command := r.command(ctx, arguments...)
	stdout := newBoundedBuffer(commandStdoutLimit)
	stderr := newBoundedBuffer(commandStderrLimit)
	command.Stdout = stdout
	command.Stderr = stderr

	err := command.Run()
	started := command.Process != nil
	if ctxErr := ctx.Err(); err != nil && ctxErr != nil {
		return nil, started, &CommandError{
			Operation: operation,
			ExitCode:  commandExitCode(err),
			Kind:      ErrCommandFailed,
			Cause:     ctxErr,
		}
	}
	if stdout.exceeded || stderr.exceeded {
		return nil, started, &CommandError{
			Operation: operation,
			ExitCode:  commandExitCode(err),
			Kind:      ErrOutputLimit,
		}
	}
	if err != nil {
		return nil, started, &CommandError{
			Operation: operation,
			ExitCode:  commandExitCode(err),
			Kind:      ErrCommandFailed,
		}
	}
	return append([]byte(nil), stdout.Bytes()...), started, nil
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	return &boundedBuffer{limit: limit}
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	written := len(value)
	remaining := b.limit - b.buffer.Len()
	if remaining < len(value) {
		b.exceeded = true
		if remaining < 0 {
			remaining = 0
		}
		value = value[:remaining]
	}
	_, _ = b.buffer.Write(value)
	return written, nil
}

func (b *boundedBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}
