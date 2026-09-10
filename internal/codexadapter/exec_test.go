package codexadapter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
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

func TestExecLauncherBoundsInheritedPipeAfterLeaderExit(t *testing.T) {
	// A private stdin pipe releases the detached helper during cleanup. This
	// test never finds or signals an unowned PID, and needs no network/namespace.
	releaseRead, releaseWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseRead.Close()
	defer releaseWrite.Close()
	ready := &readyWriter{ready: make(chan struct{})}
	invocation := helperInvocation(t, "orphan-pipe", ready)
	invocation.Stdin = releaseRead
	process, err := (ExecLauncher{}).Start(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if err := releaseRead.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	t.Cleanup(func() {
		_ = releaseWrite.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("launcher did not finish after the test released the orphan")
		}
	})
	select {
	case <-ready.ready:
	case <-time.After(3 * time.Second):
		t.Fatal("detached pipe holder did not start")
	}
	select {
	case err := <-done:
		// Retain the result for cleanup's join even when this assertion fails.
		done <- err
		if !errors.Is(err, exec.ErrWaitDelay) {
			t.Fatalf("Wait error = %v, want inherited-pipe timeout", err)
		}
	case <-time.After(childStopGrace + 2*time.Second):
		t.Fatal("leader exit left Wait blocked on the detached child's output pipe")
	}
}

func TestExecLauncherKeepsEmptyEnvironmentEmpty(t *testing.T) {
	t.Setenv("HGW_EXEC_PARENT_CANARY", "must-not-be-inherited")
	for _, tc := range []struct {
		name string
		env  []string
	}{{"nil", nil}, {"empty", []string{}}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var stdout bytes.Buffer
			process, err := (ExecLauncher{}).Start(ctx, Invocation{
				Path: os.Args[0], Args: []string{"-test.run=^TestExecLauncherEmptyEnvHelper$", "--", "hgw-empty-env-probe"},
				Env: tc.env, Dir: t.TempDir(), Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: io.Discard,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := process.Wait(); err != nil || stdout.String() != "empty\n" {
				t.Fatalf("empty invocation environment inherited the parent canary: output=%q err=%v", stdout.String(), err)
			}
		})
	}
}

func TestExecLauncherEmptyEnvHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--" || os.Args[len(os.Args)-1] != "hgw-empty-env-probe" {
		return
	}
	// Inspect only this synthetic key, never dump inherited environment values.
	if _, present := os.LookupEnv("HGW_EXEC_PARENT_CANARY"); present {
		_, _ = io.WriteString(os.Stdout, "inherited\n")
		os.Exit(66)
	}
	_, _ = io.WriteString(os.Stdout, "empty\n")
	os.Exit(0)
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
	case "orphan-pipe":
		child := exec.Command(os.Args[0], "-test.run=^TestExecLauncherHelper$", "--", "hold-pipe")
		child.Env = []string{"HGW_CODEX_EXEC_HELPER=1"}
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := child.Start(); err != nil {
			os.Exit(65)
		}
		os.Exit(0)
	case "hold-pipe":
		_, _ = io.WriteString(os.Stdout, "ready\n")
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
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
