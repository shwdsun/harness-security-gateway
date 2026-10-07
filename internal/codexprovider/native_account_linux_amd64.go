//go:build linux && amd64

package codexprovider

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
	"golang.org/x/sys/unix"
)

// One invocation, owned by a registered Run resource BEFORE start. There is no
// public arbitrary-command constructor. The isolated V4 candidate uses the
// verified native_launcher FD contract. Its activation gates remain open.
// The no-new-TGID restriction is a prerequisite for the writer-join proof.
type nativeAccountProcess struct {
	cmd                     *exec.Cmd
	stdin, stdout, stderr   *os.File
	waitEnd, outEnd, errEnd chan struct{}
	messages                chan nativeAccountEnvelope
	pidfd                   int
	waitErr                 error // Read only after waitEnd.
	outputOK, errorsOK      bool  // Read only after the respective reader end.
	stopMu                  sync.Mutex
	forced                  bool
	released                bool
}

type nativeAccountEnvelope struct {
	ID          *int            `json:"id"`
	Result      json.RawMessage `json:"result"`
	Error       json.RawMessage `json:"error"`
	Method      string          `json:"method"`
	Params      json.RawMessage `json:"params"`
	EmittedAtMS *int64          `json:"emittedAtMs"`
}

func decodeNativeAccountEnvelope(data []byte, m *nativeAccountEnvelope) bool {
	var fields map[string]json.RawMessage
	if strictjson.Decode(data, maxOwnerAuthBytes, 12, &fields) != nil || fields == nil {
		return false
	}
	for key := range fields {
		switch key {
		case "id", "result", "error", "method", "params", "emittedAtMs":
		default:
			return false // encoding/json struct matching alone folds case.
		}
	}
	if json.Unmarshal(data, m) != nil {
		return false
	}
	if _, present := fields["emittedAtMs"]; present && (m.EmittedAtMS == nil || *m.EmittedAtMS < 0) {
		return false
	}
	if m.ID == nil {
		return m.Method != "" && len(m.Result) == 0 && len(m.Error) == 0
	}
	return m.Method == "" && len(m.Params) == 0 && m.EmittedAtMS == nil
}

// start leaves every started process and reader on p, including the unlikely
// unavailable-pidfd case. Only failures before cmd.Start succeeds return with no
// waitEnd. The consumer never interprets an error as proof of no resources.
func (p *nativeAccountProcess) start() error {
	if p.cmd == nil || p.waitEnd != nil {
		return ErrOwnerAuth
	}
	in, input, err := os.Pipe()
	if err != nil {
		return ErrOwnerAuth
	}
	defer in.Close()
	out, output, err := os.Pipe()
	if err != nil {
		input.Close()
		return ErrOwnerAuth
	}
	defer output.Close()
	errors, errorOutput, err := os.Pipe()
	if err != nil {
		input.Close()
		out.Close()
		return ErrOwnerAuth
	}
	defer errorOutput.Close()
	p.cmd.Stdin, p.cmd.Stdout, p.cmd.Stderr = in, output, errorOutput
	p.pidfd = -1
	p.cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &p.pidfd}
	if p.cmd.Start() != nil {
		input.Close()
		out.Close()
		errors.Close()
		return ErrOwnerAuth
	}
	p.stdin, p.stdout, p.stderr = input, out, errors
	p.waitEnd, p.outEnd, p.errEnd = make(chan struct{}), make(chan struct{}), make(chan struct{})
	p.messages = make(chan nativeAccountEnvelope, 16)
	go func() { p.waitErr = p.cmd.Wait(); close(p.waitEnd) }()
	go p.readOutput()
	go func() {
		defer close(p.errEnd)
		defer p.stderr.Close()
		// Drain a bounded diagnostic stream without retaining or exporting it.
		n, err := io.Copy(io.Discard, io.LimitReader(p.stderr, 1<<20+1))
		p.errorsOK = err == nil && n <= 1<<20
	}()
	if p.pidfd < 0 {
		return ErrOwnerAuth
	}
	return nil
}

func (p *nativeAccountProcess) readOutput() {
	defer close(p.outEnd)
	defer close(p.messages)
	defer p.stdout.Close()
	scan := bufio.NewScanner(p.stdout)
	scan.Buffer(make([]byte, 4096), maxOwnerAuthBytes)
	total := 0
	for scan.Scan() {
		total += len(scan.Bytes()) + 1
		var m nativeAccountEnvelope
		if total > 1<<20 || !decodeNativeAccountEnvelope(scan.Bytes(), &m) {
			return
		}
		if m.ID == nil {
			// Native 0.151.0 emits optional emittedAtMs on notifications.
			// Neither the timestamp nor the payload carries authority; discard.
			continue
		}
		select {
		case p.messages <- m:
		default:
			return
		}
	}
	p.outputOK = scan.Err() == nil
}

func (p *nativeAccountProcess) write(ctx context.Context, value any) error {
	if p.stdin == nil || ctx.Err() != nil {
		return ErrOwnerAuth
	}
	data, err := json.Marshal(value)
	if err != nil || len(data) > 2048 {
		return ErrOwnerAuth
	}
	data = append(data, '\n')
	if p.stdin.SetWriteDeadline(deadline(ctx, 50*time.Second)) != nil {
		return ErrOwnerAuth
	}
	n, err := p.stdin.Write(data)
	if err != nil || n != len(data) {
		return ErrOwnerAuth
	}
	return nil
}

func (p *nativeAccountProcess) exchange(ctx context.Context, id int, method string, params any) (json.RawMessage, error) {
	if p.write(ctx, map[string]any{"id": id, "method": method, "params": params}) != nil {
		return nil, ErrOwnerAuth
	}
	select {
	case m, ok := <-p.messages:
		if !ok || m.ID == nil || *m.ID != id || (len(m.Error) != 0 && !bytes.Equal(m.Error, []byte("null"))) || len(m.Result) == 0 {
			return nil, ErrOwnerAuth
		}
		return m.Result, nil
	case <-ctx.Done():
		return nil, ErrOwnerAuth
	}
}

func (p *nativeAccountProcess) account(ctx context.Context, relay *ownerRefresh, force bool) error {
	if _, err := p.exchange(ctx, 1, "initialize", map[string]any{"clientInfo": map[string]string{"name": "hsg_owner_auth", "version": "0.1.0"}}); err != nil {
		return err
	}
	if p.write(ctx, map[string]any{"method": "initialized", "params": map[string]any{}}) != nil {
		return ErrOwnerAuth
	}
	// Stale initialize may already have performed the one allowed refresh.
	result, err := p.exchange(ctx, 2, "account/read", map[string]bool{"refreshToken": force && !relay.attempted()})
	if err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	var account map[string]json.RawMessage
	var kind string
	if strictjson.Decode(result, maxOwnerAuthBytes, 8, &fields) != nil ||
		json.Unmarshal(fields["account"], &account) != nil ||
		json.Unmarshal(account["type"], &kind) != nil || kind != "chatgpt" {
		return ErrOwnerAuth
	}
	// This is RPC readiness only. The caller separately verifies candidate
	// identity and captured refresh tokens after all writers have stopped.
	return nil
}

func awaitNative(ctx context.Context, done <-chan struct{}, limit time.Duration) bool {
	return awaitNativeContexts(ctx, ctx, done, limit)
}

func awaitNativeContexts(live, cleanup context.Context, done <-chan struct{}, limit time.Duration) bool {
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-done:
		return true
	default:
	}
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	case <-live.Done():
		return false
	case <-cleanup.Done():
		return false
	}
}

// stop is retryable cleanup, not a replay of native work. A timeout retains the
// process handle and join channels. pidfds target the original task even if Wait
// races signaling; no group/numeric-PID signal can reach another Run or attach.
func (p *nativeAccountProcess) stop(ctx context.Context) error {
	return p.stopWithGrace(ctx, ctx, 5*time.Second)
}

const nativeFinishGrace = 8 * time.Second

// finish is only for successful account RPCs. Native's normal EOF shutdown can
// approach five seconds. Allow fixed margin while cancellation immediately ends
// the normal wait; independent cleanup still joins any required escalation.
func (p *nativeAccountProcess) finish(live, cleanup context.Context) error {
	return p.stopWithGrace(live, cleanup, nativeFinishGrace)
}

func (p *nativeAccountProcess) stopWithGrace(live, cleanup context.Context, grace time.Duration) error {
	p.stopMu.Lock()
	defer p.stopMu.Unlock()
	if p.waitEnd == nil || p.released {
		return nil
	}
	_ = p.stdin.Close()
	if !awaitNativeContexts(live, cleanup, p.waitEnd, grace) {
		p.forced = true
		p.signal(unix.SIGTERM)
		if !awaitNative(cleanup, p.waitEnd, 3*time.Second) {
			p.signal(unix.SIGKILL)
			if !awaitNative(cleanup, p.waitEnd, 2*time.Second) {
				return ErrCleanup
			}
		}
	}
	// Wait returning an OS error is not itself proof of termination. Preserve
	// the original pidfd and cleanup obligation when no terminal state exists;
	// replacement recovery must establish absence through the startup gate.
	if p.cmd.ProcessState == nil {
		p.forced = true
		p.signal(unix.SIGKILL)
		return ErrCleanup
	}
	status, ok := p.cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || (!status.Exited() && !status.Signaled()) {
		return ErrCleanup
	}
	if !awaitNative(cleanup, p.outEnd, time.Second) || !awaitNative(cleanup, p.errEnd, time.Second) {
		return ErrCleanup
	}
	if p.pidfd >= 0 {
		_ = unix.Close(p.pidfd)
		p.pidfd = -1
	}
	p.released = true
	return nil
}

func (p *nativeAccountProcess) signal(signal unix.Signal) {
	if p.pidfd >= 0 {
		_ = unix.PidfdSendSignal(p.pidfd, signal, nil, 0)
	} else {
		// Fallback only for a kernel without the required pidfd feature. Go's
		// Process synchronizes signaling with Wait; this invocation is rejected
		// regardless, and its cleanup obligation is retained until joined.
		_ = p.cmd.Process.Signal(syscall.Signal(signal))
	}
}

func (p *nativeAccountProcess) cleanExit() bool {
	p.stopMu.Lock()
	defer p.stopMu.Unlock()
	return p.released && !p.forced && p.waitErr == nil && p.outputOK && p.errorsOK && len(p.messages) == 0
}
