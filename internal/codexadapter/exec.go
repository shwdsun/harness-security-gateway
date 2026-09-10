package codexadapter

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

const childStopGrace = 2 * time.Second

// ExecLauncher starts Codex without a shell and places it in a separate process
// group. Context cancellation first sends TERM and then KILL to that original
// group. Detached descendants and leader-exits-first races remain the outer
// sandboxd container teardown's responsibility and are a release-test gate.
type ExecLauncher struct{}

func (ExecLauncher) Start(ctx context.Context, invocation Invocation) (Process, error) {
	if ctx == nil {
		return nil, errors.New("codex adapter: nil launch context")
	}
	command := exec.Command(invocation.Path, invocation.Args...)
	// An empty invocation must remain empty: nil would inherit the parent.
	command.Env = append([]string{}, invocation.Env...)
	command.Dir = invocation.Dir
	command.Stdin = invocation.Stdin
	command.Stdout = invocation.Stdout
	command.Stderr = invocation.Stderr
	// A descendant may retain the diagnostic pipes after the leader exits.
	// Bound that drain and return an error; closing a pipe is not evidence of
	// descendant quiescence, which remains the outer runtime's responsibility.
	command.WaitDelay = childStopGrace
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, err
	}

	process := &execProcess{
		command: command,
		done:    make(chan struct{}),
	}
	go process.reap()
	go process.stopOnContext(ctx)
	return process, nil
}

type execProcess struct {
	command *exec.Cmd
	done    chan struct{}
	mu      sync.Mutex
	err     error
}

func (p *execProcess) reap() {
	err := p.command.Wait()
	p.mu.Lock()
	p.err = err
	p.mu.Unlock()
	close(p.done)
}

func (p *execProcess) Wait() error {
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *execProcess) stopOnContext(ctx context.Context) {
	select {
	case <-p.done:
		return
	case <-ctx.Done():
	}

	pid := p.command.Process.Pid
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	timer := time.NewTimer(childStopGrace)
	defer timer.Stop()
	select {
	case <-p.done:
		return
	case <-timer.C:
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
}

var _ Launcher = ExecLauncher{}
var _ Process = (*execProcess)(nil)
