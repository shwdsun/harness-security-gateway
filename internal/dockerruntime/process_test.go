package dockerruntime

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAttachStartExposesOnlyBoundedPipes(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateCreated)},
		helperStep{ReadStdin: true, Stdout: "runner-protocol-output\n", Stderr: "bounded diagnostic\n"},
	)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	process, err := runtime.AttachStart(context.Background(), ContainerRef(testContainerID))
	if err != nil {
		t.Fatal(err)
	}
	startFrame := "{\"protocol\":\"hrp/1\"}\n"
	if _, err := io.WriteString(process.Stdin, startFrame); err != nil {
		t.Fatal(err)
	}
	if err := process.Stdin.Close(); err != nil {
		t.Fatal(err)
	}
	stdout, stdoutErr := io.ReadAll(process.Stdout)
	stderr, stderrErr := io.ReadAll(process.Stderr)
	if stdoutErr != nil || stderrErr != nil {
		t.Fatalf("read errors: stdout=%v stderr=%v", stdoutErr, stderrErr)
	}
	if string(stdout) != "runner-protocol-output\n" || string(stderr) != "bounded diagnostic\n" {
		t.Fatalf("unexpected streams stdout=%q stderr=%q", stdout, stderr)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatalf("second Wait was not idempotent: %v", err)
	}

	calls := fixture.calls(t)
	if len(calls) != 3 {
		t.Fatalf("got %d calls, want 3", len(calls))
	}
	requireArguments(t, calls[0], []string{
		"--host", fixture.config.Runtime.Endpoint,
		"info", "--format", rootlessInfoFormat,
	})
	requireArguments(t, calls[1], []string{
		"--host", fixture.config.Runtime.Endpoint,
		"container", "inspect", "--format", inspectFormat, testContainerID,
	})
	requireArguments(t, calls[2], []string{
		"--host", fixture.config.Runtime.Endpoint,
		"container", "start", "--attach", "--interactive", testContainerID,
	})
	if calls[2].Stdin != startFrame {
		t.Fatalf("unexpected stdin %q", calls[2].Stdin)
	}
}

func TestAttachStartRequiresCreatedManagedContainer(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateRunning)},
	)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runtime.AttachStart(context.Background(), ContainerRef(testContainerID))
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("got %v", err)
	}
	if calls := fixture.calls(t); len(calls) != 2 {
		t.Fatalf("unexpected calls: %#v", calls)
	}
}

func TestAttachStartEnforcesAggregateOutputLimit(t *testing.T) {
	fixture := newFixture(t)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	spec := runtime.targets[targetKey{id: fixture.manifest.ID, revision: fixture.manifest.Revision}]
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateCreated)},
		helperStep{ReadStdin: true, Stdout: strings.Repeat("x", int(spec.stdoutLimit)+1)},
	)
	process, err := runtime.AttachStart(context.Background(), ContainerRef(testContainerID))
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Stdin.Close(); err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(process.Stdout)
	if !errors.Is(readErr, ErrOutputLimit) {
		t.Fatalf("read error = %v", readErr)
	}
	if int64(len(data)) != spec.stdoutLimit {
		t.Fatalf("read %d bytes, want %d", len(data), spec.stdoutLimit)
	}
	_, _ = io.ReadAll(process.Stderr)
	if err := process.Wait(); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("Wait error = %v", err)
	}
}

func TestAttachStartEnforcesStderrLimit(t *testing.T) {
	fixture := newFixture(t)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	spec := runtime.targets[targetKey{id: fixture.manifest.ID, revision: fixture.manifest.Revision}]
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateCreated)},
		helperStep{ReadStdin: true, Stderr: strings.Repeat("d", int(spec.stderrLimit)+1)},
	)
	process, err := runtime.AttachStart(context.Background(), ContainerRef(testContainerID))
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Stdin.Close(); err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(process.Stdout)
	data, readErr := io.ReadAll(process.Stderr)
	if !errors.Is(readErr, ErrOutputLimit) || int64(len(data)) != spec.stderrLimit {
		t.Fatalf("stderr = (%d bytes, %v), limit %d", len(data), readErr, spec.stderrLimit)
	}
	if err := process.Wait(); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("Wait error = %v", err)
	}
}

func TestAttachStartEnforcesInputLimit(t *testing.T) {
	fixture := newFixture(t)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	spec := runtime.targets[targetKey{id: fixture.manifest.ID, revision: fixture.manifest.Revision}]
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateCreated)},
		helperStep{ReadStdin: true},
	)
	process, err := runtime.AttachStart(context.Background(), ContainerRef(testContainerID))
	if err != nil {
		t.Fatal(err)
	}
	written, writeErr := process.Stdin.Write([]byte(strings.Repeat("x", int(spec.stdinLimit)+1)))
	if !errors.Is(writeErr, ErrOutputLimit) || int64(written) != spec.stdinLimit {
		t.Fatalf("write = (%d, %v), limit %d", written, writeErr, spec.stdinLimit)
	}
	if err := process.Stdin.Close(); err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(process.Stdout)
	_, _ = io.ReadAll(process.Stderr)
	if err := process.Wait(); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("Wait error = %v", err)
	}
}

func TestAttachWaitDoesNotLeakChildStderr(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateCreated)},
		helperStep{ReadStdin: true, Stderr: "provider-token=secret", ExitCode: 42},
	)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	process, err := runtime.AttachStart(context.Background(), ContainerRef(testContainerID))
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Stdin.Close(); err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(process.Stdout)
	_, _ = io.ReadAll(process.Stderr)
	err = process.Wait()
	if !errors.Is(err, ErrCommandFailed) {
		t.Fatalf("got %v", err)
	}
	var commandError *CommandError
	if !errors.As(err, &commandError) || commandError.ExitCode != 42 {
		t.Fatalf("unexpected typed error: %#v", err)
	}
	if strings.Contains(err.Error(), "provider-token") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("stderr leaked through Wait: %v", err)
	}
}

func TestBoundedStreamStopsInfiniteSourceAtFirstExcessByte(t *testing.T) {
	source := newInfiniteReadCloser()
	const limit = int64(32 << 10)
	var terminated atomic.Int32
	stream, done := startBoundedStream(source, limit, func() {
		terminated.Add(1)
	})

	type readResult struct {
		data []byte
		err  error
	}
	result := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(stream)
		result <- readResult{data: data, err: err}
	}()

	select {
	case got := <-result:
		if int64(len(got.data)) != limit || !errors.Is(got.err, ErrOutputLimit) {
			t.Fatalf("ReadAll() = (%d bytes, %v), want (%d, ErrOutputLimit)", len(got.data), got.err, limit)
		}
	case <-time.After(time.Second):
		_ = source.Close()
		t.Fatal("reader waited for EOF from an infinite over-limit source")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		_ = source.Close()
		t.Fatal("bounded pump did not terminate its infinite source")
	}
	if got := source.reads.Load(); got != 2 {
		t.Fatalf("source reads = %d, want exactly two (limit plus first excess chunk)", got)
	}
	if got := terminated.Load(); got != 1 {
		t.Fatalf("limit callback calls = %d, want 1", got)
	}
	select {
	case <-source.closed:
	default:
		t.Fatal("source was not closed after exceeding the limit")
	}
}

type infiniteReadCloser struct {
	closed chan struct{}
	once   sync.Once
	reads  atomic.Int64
}

func newInfiniteReadCloser() *infiniteReadCloser {
	return &infiniteReadCloser{closed: make(chan struct{})}
}

func (r *infiniteReadCloser) Read(value []byte) (int, error) {
	select {
	case <-r.closed:
		return 0, io.EOF
	default:
	}
	for index := range value {
		value[index] = 'x'
	}
	r.reads.Add(1)
	return len(value), nil
}

func (r *infiniteReadCloser) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}
