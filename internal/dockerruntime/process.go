package dockerruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"sync"
)

// Process exposes only the three HRP/1 pipes and a sanitized, idempotent Wait.
// Callers must close Stdin after the single start frame.
type Process struct {
	Stdin  io.WriteCloser
	Stdout io.ReadCloser
	Stderr io.ReadCloser

	command    *exec.Cmd
	ctx        context.Context
	input      *boundedWriteCloser
	stdout     *boundedStream
	stderr     *boundedStream
	stdoutDone <-chan struct{}
	stderrDone <-chan struct{}
	waitOnce   sync.Once
	waitErr    error
}

func (r *Runtime) AttachStart(ctx context.Context, ref ContainerRef) (*Process, error) {
	record, spec, err := r.inspectManaged(ctx, ref)
	if err != nil {
		return nil, err
	}
	if record.State != StateCreated {
		return nil, ErrInvalidState
	}
	if err := validateSpecStorage(spec); err != nil {
		return nil, err
	}

	command := r.command(ctx, "container", "start", "--attach", "--interactive", string(ref))
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, commandFailure("attach-start", err, ctx)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, commandFailure("attach-start", err, ctx)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, commandFailure("attach-start", err, ctx)
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, commandFailure("attach-start", err, ctx)
	}

	input := &boundedWriteCloser{writer: stdin, limit: spec.stdinLimit}
	var terminateOnce sync.Once
	terminateAttach := func() {
		terminateOnce.Do(func() {
			// A limit violation ends the fixed attach CLI immediately. The
			// container remains owned by sandboxd and is removed by its normal
			// verified cleanup path.
			if command.Process != nil {
				_ = command.Process.Kill()
			}
		})
	}
	stdoutStream, stdoutDone := startBoundedStream(stdout, spec.stdoutLimit, terminateAttach)
	stderrStream, stderrDone := startBoundedStream(stderr, spec.stderrLimit, terminateAttach)
	return &Process{
		Stdin:      input,
		Stdout:     stdoutStream,
		Stderr:     stderrStream,
		command:    command,
		ctx:        ctx,
		input:      input,
		stdout:     stdoutStream,
		stderr:     stderrStream,
		stdoutDone: stdoutDone,
		stderrDone: stderrDone,
	}, nil
}

// Wait waits exactly once. It never returns exec.ExitError or child stderr.
func (p *Process) Wait() error {
	if p == nil || p.command == nil || p.stdoutDone == nil || p.stderrDone == nil {
		return ErrInvalidArgument
	}
	p.waitOnce.Do(func() {
		// StdoutPipe/StderrPipe require reads to finish before Wait closes the
		// descriptors. The bounded pumps drain concurrently and never wait for
		// the public readers, so joining them here is bounded by child lifetime.
		<-p.stdoutDone
		<-p.stderrDone
		waitErr := p.command.Wait()
		if waitErr != nil && p.ctx != nil && p.ctx.Err() != nil {
			p.waitErr = commandFailure("attach-start", waitErr, p.ctx)
			return
		}
		if p.input.limitExceeded() || p.stdout.limitExceeded() || p.stderr.limitExceeded() {
			p.waitErr = &CommandError{
				Operation: "attach-start",
				ExitCode:  commandExitCode(waitErr),
				Kind:      ErrOutputLimit,
			}
			return
		}
		if waitErr != nil {
			p.waitErr = commandFailure("attach-start", waitErr, p.ctx)
			return
		}
		if p.stdout.failed() || p.stderr.failed() {
			p.waitErr = &CommandError{
				Operation: "attach-start",
				ExitCode:  commandExitCode(waitErr),
				Kind:      ErrCommandFailed,
			}
			return
		}
	})
	return p.waitErr
}

func commandFailure(operation string, err error, ctx context.Context) error {
	commandError := &CommandError{
		Operation: operation,
		ExitCode:  commandExitCode(err),
		Kind:      ErrCommandFailed,
	}
	if err != nil && ctx != nil && ctx.Err() != nil {
		commandError.Cause = ctx.Err()
	}
	return commandError
}

type boundedWriteCloser struct {
	mu       sync.Mutex
	writer   io.WriteCloser
	limit    int64
	written  int64
	exceeded bool
}

func (w *boundedWriteCloser) Write(value []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(value) == 0 {
		return 0, nil
	}
	remaining := w.limit - w.written
	if remaining <= 0 {
		w.exceeded = true
		return 0, ErrOutputLimit
	}
	toWrite := len(value)
	if int64(toWrite) > remaining {
		toWrite = int(remaining)
		w.exceeded = true
	}
	written, err := w.writer.Write(value[:toWrite])
	w.written += int64(written)
	if err != nil {
		return written, ErrCommandFailed
	}
	if written != toWrite {
		return written, io.ErrShortWrite
	}
	if toWrite != len(value) {
		return written, ErrOutputLimit
	}
	return written, nil
}

func (w *boundedWriteCloser) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.writer.Close(); err != nil {
		return ErrCommandFailed
	}
	return nil
}

func (w *boundedWriteCloser) limitExceeded() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.exceeded
}

// boundedStream eagerly copies the child into a total-byte-bounded in-memory
// stream. The pump closes its source as soon as one byte exceeds the limit;
// it must never keep draining an unbounded hostile stream.
type boundedStream struct {
	mu             sync.Mutex
	ready          *sync.Cond
	buffer         bytes.Buffer
	limit          int64
	received       int64
	done           bool
	closed         bool
	exceeded       bool
	terminalError  error
	errorDelivered bool
}

func newBoundedStream(limit int64) *boundedStream {
	stream := &boundedStream{limit: limit}
	stream.ready = sync.NewCond(&stream.mu)
	return stream
}

func startBoundedStream(source io.ReadCloser, limit int64, onLimit func()) (*boundedStream, <-chan struct{}) {
	stream := newBoundedStream(limit)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer source.Close()
		buffer := make([]byte, 32<<10)
		for {
			count, err := source.Read(buffer)
			if count > 0 && stream.feed(buffer[:count]) {
				if onLimit != nil {
					onLimit()
				}
				return
			}
			if err != nil {
				stream.finish(err)
				return
			}
		}
	}()
	return stream, done
}

// feed returns true once the source has exceeded its byte authority. It also
// publishes the terminal error before returning so a public reader never has
// to wait for source EOF (or even for source.Close) to observe the violation.
func (s *boundedStream) feed(value []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	remaining := s.limit - s.received
	accepted := len(value)
	if remaining < int64(accepted) {
		accepted = int(max(remaining, 0))
		s.exceeded = true
		s.done = true
		s.terminalError = ErrOutputLimit
	}
	s.received += int64(accepted)
	if !s.closed && accepted > 0 {
		_, _ = s.buffer.Write(value[:accepted])
	}
	s.ready.Broadcast()
	return s.exceeded
}

func (s *boundedStream) finish(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	if s.exceeded {
		s.terminalError = ErrOutputLimit
	} else if err != nil && !errors.Is(err, io.EOF) {
		s.terminalError = ErrCommandFailed
	}
	s.ready.Broadcast()
}

func (s *boundedStream) Read(value []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.buffer.Len() == 0 && !s.done && !s.closed {
		s.ready.Wait()
	}
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	if s.buffer.Len() > 0 {
		return s.buffer.Read(value)
	}
	if s.terminalError != nil && !s.errorDelivered {
		s.errorDelivered = true
		return 0, s.terminalError
	}
	return 0, io.EOF
}

func (s *boundedStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.buffer.Reset()
	s.ready.Broadcast()
	return nil
}

func (s *boundedStream) limitExceeded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exceeded
}

func (s *boundedStream) failed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminalError != nil && !errors.Is(s.terminalError, ErrOutputLimit)
}
