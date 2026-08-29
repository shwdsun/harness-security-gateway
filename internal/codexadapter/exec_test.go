package codexadapter

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestExecLauncherStopsRealProcessOnDiagnosticOverflow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout := &boundedDiscard{limit: 1024, cancel: cancel}
	process, err := (ExecLauncher{}).Start(ctx, helperInvocation(t, "flood", stdout))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	select {
	case <-done:
		if !stdout.Exceeded() {
			t.Fatal("process stopped before exercising diagnostic limit")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("process remained alive after diagnostic overflow cancelled its context")
	}
}

func TestExecLauncherEscalatesFromTermToKill(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := &readyWriter{ready: make(chan struct{})}
	process, err := (ExecLauncher{}).Start(ctx, helperInvocation(t, "ignore-term", ready))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	select {
	case <-ready.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("helper did not become ready")
	}

	started := time.Now()
	cancel()
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	select {
	case waitErr := <-done:
		if waitErr == nil {
			t.Fatal("TERM-resistant helper exited successfully, want forced termination")
		}
		if elapsed := time.Since(started); elapsed < childStopGrace {
			t.Fatalf("helper stopped after %s, before KILL grace %s", elapsed, childStopGrace)
		}
	case <-time.After(childStopGrace + 3*time.Second):
		t.Fatal("TERM-resistant helper remained alive after KILL grace")
	}
}

func TestExecLauncherHelper(t *testing.T) {
	if os.Getenv("HGW_CODEX_EXEC_HELPER") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	switch mode {
	case "flood":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), 1<<20))
		for {
			time.Sleep(time.Hour)
		}
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
		_, _ = io.WriteString(os.Stdout, "ready\n")
		for {
			time.Sleep(time.Hour)
		}
	default:
		os.Exit(64)
	}
}

func helperInvocation(t *testing.T, mode string, stdout io.Writer) Invocation {
	t.Helper()
	return Invocation{
		Path:   os.Args[0],
		Args:   []string{"-test.run=^TestExecLauncherHelper$", "--", mode},
		Env:    []string{"HGW_CODEX_EXEC_HELPER=1"},
		Dir:    t.TempDir(),
		Stdin:  strings.NewReader(""),
		Stdout: stdout,
		Stderr: io.Discard,
	}
}

type readyWriter struct {
	ready chan struct{}
	once  sync.Once
}

func (w *readyWriter) Write(value []byte) (int, error) {
	if bytes.Contains(value, []byte("ready\n")) {
		w.once.Do(func() { close(w.ready) })
	}
	return len(value), nil
}
