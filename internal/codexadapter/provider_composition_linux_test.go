//go:build linux && codexintegration

package codexadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/responsesgate"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
	"golang.org/x/sys/unix"
)

// Run-scoped in-memory HTTP transport: exercise the actual Gate server and
// response controller without creating another IP or Unix frontend.
type providerPipeListener struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
	ready       chan struct{}
	readyOnce   sync.Once
}

func (l *providerPipeListener) Accept() (net.Conn, error) {
	l.readyOnce.Do(func() { close(l.ready) })
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *providerPipeListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (l *providerPipeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (l *providerPipeListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.connections <- server:
		return client, nil
	case <-ctx.Done():
	case <-l.done:
	}
	_ = client.Close()
	_ = server.Close()
	return nil, net.ErrClosed
}

type providerCompositionOps struct {
	ctx      context.Context
	gate     *responsesgate.Gate
	client   *http.Client
	nonce    string
	mu       sync.Mutex
	counts   map[string]int
	statuses []int
	close    func()
}

func newProviderCompositionOps(t *testing.T, ctx context.Context, nonce string, responder responsesgate.Responder) *providerCompositionOps {
	t.Helper()
	gate, err := responsesgate.NewSynthetic(ctx, "hsg-synthetic.invalid", responder)
	if err != nil {
		t.Fatal(err)
	}
	listener := &providerPipeListener{connections: make(chan net.Conn), done: make(chan struct{}), ready: make(chan struct{})}
	transport := &http.Transport{DialContext: listener.dial, DisableKeepAlives: true}
	ops := &providerCompositionOps{ctx: ctx, gate: gate, nonce: nonce, counts: make(map[string]int),
		client: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("no redirects") }}}
	done := make(chan error, 1)
	go func() { done <- gate.Serve(listener) }()
	// Wait for Serve to own its listener before a rejection-only case can
	// stop it. A never-started server is not a successful cleanup witness.
	select {
	case <-listener.ready:
	case err := <-done:
		gate.Stop()
		t.Fatalf("consumer did not start: %v", err)
	}
	var closed sync.Once
	ops.close = func() {
		closed.Do(func() {
			gate.Stop()
			transport.CloseIdleConnections()
			if err := <-done; err != nil {
				t.Errorf("consumer cleanup failed: %v", err)
			}
		})
	}
	t.Cleanup(ops.close)
	if gate.Open() != nil {
		t.Fatal("cannot open synthetic consumer")
	}
	return ops
}

func (o *providerCompositionOps) respond(w http.ResponseWriter, r *http.Request, body []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	status := http.StatusBadRequest
	defer func() {
		if len(o.statuses) < 16 {
			o.statuses = append(o.statuses, status)
		}
	}()
	deny := func() { http.Error(w, "fixed synthetic operation rejected", status) }
	o.counts["attempts"]++
	if o.ctx.Err() != nil || o.counts["attempts"] > 8 || r.Proto != "HTTP/1.1" ||
		r.URL.IsAbs() || r.URL.RawPath != "" || r.URL.ForceQuery || r.URL.Fragment != "" ||
		len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || len(body) > responsesgate.MaxBodyBytes {
		deny()
		return
	}
	// Frozen metadata names; values never become transport or authority.
	allowed := map[string]bool{}
	for _, name := range strings.Fields("Accept Authorization Chatgpt-Account-Id Content-Length Content-Type Originator Session-Id Thread-Id User-Agent X-Client-Request-Id X-Codex-Turn-Metadata X-Codex-Window-Id X-Openai-Internal-Codex-Responses-Lite Cache-Control") {
		allowed[name] = true
	}
	headerBytes := 0
	for name, values := range r.Header {
		if !allowed[name] || len(values) != 1 {
			deny()
			return
		}
		headerBytes += len(name) + len(values[0]) + 4
	}
	if headerBytes > responsesgate.MaxHeaderBytes || r.ContentLength != int64(len(body)) {
		deny()
		return
	}
	auth := r.Header.Get("Authorization") == "Bearer "+o.nonce+"-refreshed" && r.Header.Get("ChatGPT-Account-ID") == "hsg-synthetic-account"
	switch {
	case r.Host == "auth.openai.com" && r.Method == "POST" && r.URL.Path == "/oauth/token" && r.URL.RawQuery == "":
		var fields map[string]string
		if r.Header.Get("Content-Type") != "application/json" || strictjson.Decode(body, 8192, 4, &fields) != nil || len(fields) != 3 ||
			fields["grant_type"] != "refresh_token" || fields["refresh_token"] != o.nonce+"-refresh" ||
			fields["client_id"] != "app_EMoamEEZ73f0CkXaXp7hrann" || o.counts["refresh"] != 0 || r.Header.Get("Authorization") != "" {
			deny()
			return
		}
		o.counts["refresh"]++
		status = http.StatusOK
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": o.nonce + "-refreshed", "id_token": providerSyntheticJWT(), "refresh_token": o.nonce + "-refresh-after", "expires_in": 3600, "token_type": "Bearer"})
	case auth && r.Host == "chatgpt.com" && r.Method == "GET" && r.URL.Path == "/backend-api/codex/models" && r.URL.RawQuery == "client_version=0.151.0" && len(body) == 0:
		if o.counts["catalog"] >= 2 {
			deny()
			return
		}
		o.counts["catalog"]++
		status = http.StatusOK
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"models":[]}`)
	case r.Host == "chatgpt.com" && r.Method == "GET" && r.URL.Path == "/backend-api/wham/settings/user" && r.URL.RawQuery == "":
		o.counts["settings_rejected"]++
		status = http.StatusNotFound
		deny()
	case auth && r.Host == "chatgpt.com" && r.Method == "POST" && r.URL.Path == "/backend-api/codex/responses" && r.URL.RawQuery == "" && r.Header.Get("Content-Type") == "application/json":
		// Exact source operation was checked above. The inner operation and
		// headers are constructed by this trusted fixture, never forwarded.
		request, err := http.NewRequestWithContext(o.ctx, "POST", "http://hsg-synthetic.invalid/v1/responses", bytes.NewReader(body))
		if err != nil {
			deny()
			return
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", o.gate.SyntheticAuthorization())
		response, err := o.client.Do(request)
		if err != nil {
			deny()
			return
		}
		defer response.Body.Close()
		payload, err := io.ReadAll(io.LimitReader(response.Body, responsesgate.MaxBodyBytes+1))
		if err != nil || len(payload) > responsesgate.MaxBodyBytes {
			deny()
			return
		}
		status = response.StatusCode
		if status != http.StatusOK {
			deny()
			return
		}
		o.counts["inference"]++
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write(payload)
	default:
		deny()
	}
}

func providerUnixCanary(t *testing.T, address, nonce string) {
	t.Helper()
	listener, err := net.Listen("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(conn, nonce)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
}

func providerWritePlan(t *testing.T, workspace string, plan providerProbePlan) {
	t.Helper()
	encoded, _ := json.Marshal(plan)
	if err := os.WriteFile(filepath.Join(workspace, "provider-probe-plan.json"), encoded, 0o444); err != nil {
		t.Fatal(err)
	}
}

// Differential boundary check: accepted operation reaches the real consumer;
// changes to transport authority/framing or JSON authorization do not dispatch.
func TestProviderCompositionOperationBoundary(t *testing.T) {
	validBody := `{"model":"gpt-5.6-sol","reasoning":{"effort":"medium"},"stream":true}`
	for _, name := range []string{"valid", "wrong-authority", "suffix-alias", "query", "upgrade", "compression", "duplicate-auth", "duplicate-model", "wrong-effort", "closed"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			dispatches := 0
			ops := newProviderCompositionOps(t, ctx, "unit", func(_ context.Context, request responsesgate.Request) (responsesgate.Response, error) {
				dispatches++
				if len(request.Header) != 2 || request.Header.Get("Content-Type") != "application/json" {
					return responsesgate.Response{}, errors.New("header projection")
				}
				return responsesgate.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: synthetic\n\n"))}, nil
			})
			body := validBody
			if name == "duplicate-model" {
				body = strings.Replace(body, `"model":`, `"model":"other","model":`, 1)
			}
			if name == "wrong-effort" {
				body = strings.Replace(body, "medium", "high", 1)
			}
			r := httptest.NewRequest("POST", "/backend-api/codex/responses", strings.NewReader(body))
			r.Host = "chatgpt.com"
			r.Header.Set("Authorization", "Bearer unit-refreshed")
			r.Header.Set("ChatGPT-Account-ID", "hsg-synthetic-account")
			r.Header.Set("Content-Type", "application/json")
			switch name {
			case "wrong-authority":
				r.Host = "auth.openai.com"
			case "suffix-alias":
				r.URL.Path = "/other/responses"
			case "query":
				r.URL.RawQuery = "redirect=elsewhere"
			case "upgrade":
				r.Header.Set("Upgrade", "websocket")
			case "compression":
				r.Header.Set("Content-Encoding", "zstd")
			case "duplicate-auth":
				r.Header.Add("Authorization", "Bearer unit-refreshed")
			case "closed":
				ops.gate.Stop()
			}
			response := httptest.NewRecorder()
			ops.respond(response, r, []byte(body))
			want := 0
			if name == "valid" {
				want = 1
			}
			if dispatches != want || (response.Code == http.StatusOK) != (want == 1) {
				t.Fatalf("dispatches=%d status=%d", dispatches, response.Code)
			}
		})
	}
}

func TestCodexProviderComposition(t *testing.T) {
	if os.Getenv("HSG_CODEX_PROVIDER_COMPOSITION") != "1" {
		t.Skip("opt-in offline native provider/tool composition")
	}
	requireProviderInventoryNamespace(t)
	root := t.TempDir()
	config := MessagingToolsConfig(codexprofile.ModelNameV1)
	config.Workspace, config.CodexHome, config.OutputDirectory = filepath.Join(root, "workspace"), filepath.Join(root, "home"), filepath.Join(root, "output")
	for _, path := range []string{config.Workspace, config.CodexHome, filepath.Join(root, "tmp"), filepath.Join(root, "control")} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	seed := newProviderProbeSeed(t)
	defer runtime.KeepAlive(seed)
	nonce := seed.plan.Nonce
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	var mu sync.Mutex
	dispatches, outputVerified := 0, false
	var report providerProbeReport
	var fixtureError string
	var nativePID atomic.Int64
	var observer *providerObserver
	ops := newProviderCompositionOps(t, ctx, nonce, func(_ context.Context, request responsesgate.Request) (responsesgate.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		dispatches++
		recorder := httptest.NewRecorder()
		var input struct {
			Input []struct {
				Type   string
				CallID string `json:"call_id"`
				Output json.RawMessage
				Tools  []struct {
					Name  string
					Tools []struct{ Type, Name, Description string }
				}
			}
		}
		if json.Unmarshal(request.Body, &input) != nil {
			return responsesgate.Response{}, errors.New("fixture projection")
		}
		if dispatches == 1 {
			// Snapshot the native client's live sockets, plus the TLS peer's
			// accepted sockets, before issuing the fixed tool call. Stdio pipes
			// required by Code Mode are deliberately not classified as provider FDs.
			pid := int(nativePID.Load())
			entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
			if pid <= 1 || err != nil {
				return responsesgate.Response{}, errors.New("native descriptor inventory unavailable")
			}
			identities := make(map[string]bool)
			for _, identity := range seed.plan.ProtectedFDs {
				identities[identity] = true
			}
			clientSockets := 0
			for _, entry := range entries {
				var stat unix.Stat_t
				if unix.Stat(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()), &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFSOCK {
					identities[fmt.Sprintf("%d:%d:%d", stat.Dev, stat.Ino, stat.Mode&unix.S_IFMT)] = true
					clientSockets++
				}
			}
			observer.mu.Lock()
			for conn := range observer.connections {
				if raw, err := conn.(syscall.Conn).SyscallConn(); err == nil {
					_ = raw.Control(func(fd uintptr) {
						if identity, err := providerFDIdentity(int(fd)); err == nil {
							identities[identity] = true
						}
					})
				}
			}
			observer.mu.Unlock()
			if clientSockets == 0 || len(identities) < 4 {
				return responsesgate.Response{}, errors.New("live provider descriptors missing")
			}
			seed.plan.ProtectedFDs = nil
			for identity := range identities {
				seed.plan.ProtectedFDs = append(seed.plan.ProtectedFDs, identity)
			}
			encoded, _ := json.Marshal(seed.plan)
			if os.WriteFile(filepath.Join(config.Workspace, "provider-probe-plan.json"), encoded, 0o444) != nil {
				return responsesgate.Response{}, errors.New("native probe plan write")
			}
			execCount := 0
			for _, item := range input.Input {
				if item.Type == "additional_tools" {
					for _, ns := range item.Tools {
						for _, tool := range ns.Tools {
							if ns.Name == "functions" && tool.Name == "exec" && tool.Type == "custom" && strings.Contains(tool.Description, "exec_command") {
								execCount++
							}
						}
					}
				}
			}
			if execCount != 1 {
				fixtureError = "native exec definition unavailable"
				return responsesgate.Response{}, errors.New(fixtureError)
			}
			self, err := os.Executable()
			if err != nil {
				return responsesgate.Response{}, err
			}
			args, _ := json.Marshal(map[string]any{"cmd": "exec " + toolsCanaryShellCommand(self, "-test.run=^TestProviderProbeProcess$", "--", "hsg-provider-probe", config.Workspace), "workdir": config.Workspace, "yield_time_ms": 10000, "max_output_tokens": 2000})
			code := fmt.Sprintf(`text({command_marker:%q,result:await tools.exec_command(%s)});`, nonce, args)
			writeIntegrationResponse(recorder, nonce, map[string]any{"type": "custom_tool_call", "id": "ct_" + nonce, "call_id": "call_" + nonce, "name": "exec", "namespace": "functions", "input": code, "status": "completed"})
		} else {
			data, err := os.ReadFile(filepath.Join(config.Workspace, "provider-probe-report.json"))
			if err != nil || len(data) > 8192 || json.Unmarshal(data, &report) != nil || report.Nonce != nonce {
				fixtureError = "native probe report missing"
				return responsesgate.Response{}, errors.New(fixtureError)
			}
			for _, item := range input.Input {
				if item.Type == "custom_tool_call_output" && item.CallID == "call_"+nonce && verifyToolsExecOutput(item.Output, nonce, 0, string(data)) {
					outputVerified = true
				}
			}
			if !outputVerified {
				fixtureError = "native output does not match independent report"
				return responsesgate.Response{}, errors.New(fixtureError)
			}
			writeIntegrationResponse(recorder, nonce, map[string]any{"type": "message", "id": "msg_" + nonce, "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": "HSG_PROVIDER_COMPOSED", "annotations": []any{}}}})
		}
		return responsesgate.Response{StatusCode: recorder.Code, Header: recorder.Header(), Body: io.NopCloser(bytes.NewReader(recorder.Body.Bytes()))}, nil
	})
	observer = newProviderObserverWithResponder(t, nonce, ops.respond)
	defer func() {
		observer.close()
		mu.Lock()
		defer mu.Unlock()
		ops.mu.Lock()
		defer ops.mu.Unlock()
		encoded, _ := json.Marshal(map[string]any{"utc": time.Now().UTC().Format(time.RFC3339Nano), "counts": ops.counts, "statuses": ops.statuses, "dispatches": dispatches, "tool_output_verified": outputVerified, "tool": report, "fixture_error": fixtureError, "passed": !t.Failed()})
		t.Logf("HSG_PROVIDER_COMPOSITION %s", encoded)
	}()
	seed.plan.TCP = observer.server.Listener.Addr().String()
	seed.plan.Pathname = filepath.Join(config.Workspace, "canary.sock")
	seed.plan.Abstract = "@hsg-canary-" + nonce
	providerUnixCanary(t, seed.plan.Pathname, nonce)
	providerUnixCanary(t, seed.plan.Abstract, nonce)
	raw, err := observer.server.Listener.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Control(func(fd uintptr) {
		identity, err := providerFDIdentity(int(fd))
		if err == nil {
			seed.plan.ProtectedFDs = append(seed.plan.ProtectedFDs, identity)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if len(seed.plan.ProtectedFDs) != 2 {
		t.Fatal("provider frontend descriptor identity unavailable")
	}
	// Positive controls use the same addresses and helper outside the native
	// tool sandbox, intentionally inheriting only the synthetic memfd.
	controlDir := filepath.Join(root, "control")
	providerWritePlan(t, controlDir, seed.plan)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	control := exec.CommandContext(ctx, self, "-test.run=^TestProviderProbeProcess$", "--", "hsg-provider-probe", controlDir)
	control.Env = []string{"HOME=/nonexistent", "PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	control.ExtraFiles = []*os.File{seed.file}
	controlOutput, err := control.Output()
	if err != nil {
		t.Fatal("local positive-control helper failed")
	}
	var positive providerProbeReport
	data, err := os.ReadFile(filepath.Join(controlDir, "provider-probe-report.json"))
	if err != nil || json.Unmarshal(data, &positive) != nil || !bytes.Contains(controlOutput, data) || positive.Inherited != 1 || !positive.Results["tcp"].Access || !positive.Results["pathname"].Access || !positive.Results["abstract"].Access {
		t.Fatal("socket/inheritance positive control failed")
	}
	t.Logf("HSG_PROVIDER_LOCAL_CONTROL %s", data)
	caPath := filepath.Join(root, "observer-ca.pem")
	if os.WriteFile(caPath, observer.ca, 0o600) != nil {
		t.Fatal("fixture CA write")
	}
	auth, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "OPENAI_API_KEY": nil, "last_refresh": "2000-01-01T00:00:00Z", "tokens": map[string]any{"id_token": providerSyntheticJWT(), "access_token": nonce, "refresh_token": nonce + "-refresh", "account_id": "hsg-synthetic-account"}})
	if os.WriteFile(filepath.Join(config.CodexHome, "auth.json"), auth, 0o600) != nil {
		t.Fatal("synthetic auth write")
	}
	launcher := launcherFunc(func(ctx context.Context, inv Invocation) (Process, error) {
		inv.Args = append(inv.Args[:len(inv.Args)-1], "--skip-git-repo-check",
			"--config", `model_provider="hsg-subscription-https"`,
			"--config", `model_providers.hsg-subscription-https={name="HSG subscription HTTPS",base_url="https://chatgpt.com/backend-api/codex",wire_api="responses",requires_openai_auth=true,supports_websockets=false}`,
			"--config", `features.enable_request_compression=false`, "-")
		inv.Env = append(inv.Env, "HTTPS_PROXY="+observer.server.URL, "HTTP_PROXY="+observer.server.URL, "CODEX_CA_CERTIFICATE="+caPath, "TMPDIR="+filepath.Join(root, "tmp"))
		process, err := (ExecLauncher{}).Start(ctx, inv)
		if err == nil {
			nativePID.Store(int64(process.(*execProcess).command.Process.Pid))
		}
		return process, err
	})
	start := testStart()
	start.Input.Text = "Execute the fixed synthetic provider-boundary probe once and return its completion marker."
	frames, _, err := execute(t, ctx, start, config, launcher)
	if err != nil || len(frames) != 3 {
		t.Fatal("native run did not complete HRP")
	}
	completed, ok := frames[2].(*runnerwire.RunCompleted)
	if !ok || completed.Output.Text != "HSG_PROVIDER_COMPOSED" {
		t.Fatalf("native completion missing: %T", frames[2])
	}
	observer.close()
	mu.Lock()
	if dispatches != 2 || !outputVerified {
		t.Error("strict consumer/native tool composition incomplete")
	}
	if report.Inherited != 0 || report.ProtectedCount != len(seed.plan.ProtectedFDs) || report.ProtectedCount < 4 || report.Results["tcp"].Access || report.Results["tcp"].Errno != int(syscall.EPERM) {
		t.Error("native tool reached or could not test provider ingress")
	}
	if report.OwnerMatched || report.AncestorProcView {
		checks := []string{"proc_fd", "proc_mem"}
		if report.OwnerMatched {
			checks = append(checks, "process_vm", "pidfd_getfd", "ptrace_seize")
		}
		for _, name := range checks {
			outcome, exists := report.Results[name]
			if !exists || outcome.Access || (outcome.Errno != int(syscall.EPERM) && outcome.Errno != int(syscall.EACCES)) {
				t.Errorf("parent access not denied: %s", name)
			}
		}
	} else {
		t.Error("owned parent visibility/control is unresolved")
	}
	mu.Unlock()
	ops.mu.Lock()
	if ops.counts["refresh"] != 1 || ops.counts["inference"] != 2 {
		t.Error("refresh/inference count mismatch")
	}
	for _, status := range ops.statuses {
		if status != http.StatusOK && status != http.StatusNotFound {
			t.Error("unexpected operation rejection")
		}
	}
	ops.mu.Unlock()
	data, err = os.ReadFile(filepath.Join(config.CodexHome, "auth.json"))
	var saved struct {
		Tokens struct {
			AccessToken string `json:"access_token"`
		} `json:"tokens"`
	}
	if err != nil || json.Unmarshal(data, &saved) != nil || saved.Tokens.AccessToken != nonce+"-refreshed" {
		t.Error("synthetic refreshed token not persisted")
	}
	ops.gate.Stop()
	assertIntegrationQuiescence(t)
}
