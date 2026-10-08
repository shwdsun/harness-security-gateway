//go:build linux && codexintegration

package codexadapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"golang.org/x/sys/unix"
)

// This opt-in test keeps the actual adapter + exec launcher in the path. Its
// synthetic provider is reachable only inside a disposable network namespace;
// there is no host interface, credential, public provider or Docker operation.
func TestCodexExecIntegration(t *testing.T) {
	binary, err := exec.LookPath("codex")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	_, hashErr := io.Copy(digest, f)
	closeErr := f.Close()
	if hashErr != nil || closeErr != nil || hex.EncodeToString(digest.Sum(nil)) != codexprofile.CLIBinarySHA256V1 {
		t.Fatal("pinned CLI artifact mismatch or read error")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	// Keep the owned test executable reachable after /tmp is replaced by a
	// private scratch mount (the native sandbox has a fixed /tmp registry).
	selfSource, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer selfSource.Close()
	self = filepath.Join(root, "integration.test")
	selfCopy, err := os.OpenFile(self, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(selfCopy, selfSource)
	if err := selfCopy.Close(); err != nil || copyErr != nil {
		t.Fatal("copy owned test executable:", copyErr, err)
	}
	networkNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// bwrap configures its private loopback before dropping setup privileges.
	// Only the fixture root is writable; no host interface or mount is changed.
	cmd := exec.CommandContext(ctx, "/usr/bin/bwrap",
		"--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc",
		"--as-pid-1", "--die-with-parent", "--new-session",
		"--ro-bind", "/", "/", "--tmpfs", "/tmp", "--bind", root, root,
		"--proc", "/proc", "--dev", "/dev", "--chdir", root, "--",
		self, "-test.v", "-test.run=^TestCodexExecIntegrationNamespace$", "--", root, binary, networkNS)
	cmd.Env = []string{"HSG_EXEC_INTEGRATION_CHILD=1", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "TMPDIR=" + root}
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput()
	t.Logf("namespace result:\n%s", out)
	if err != nil {
		t.Fatalf("isolated exec integration failed (startup failure is not an isolation verdict): %v", err)
	}
}

func TestCodexExecIntegrationNamespace(t *testing.T) {
	if os.Getenv("HSG_EXEC_INTEGRATION_CHILD") != "1" {
		return
	}
	if len(os.Args) < 4 || os.Args[len(os.Args)-4] != "--" || os.Getpid() != 1 {
		t.Fatal("refuse to run without a fresh PID namespace")
	}
	root, binary := os.Args[len(os.Args)-3], os.Args[len(os.Args)-2]
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || current == os.Args[len(os.Args)-1] {
		t.Fatal("refuse to modify a shared network namespace:", err)
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagUp == 0 {
		t.Fatal("namespace must contain only loopback:", interfaces, err)
	}
	t.Log("disposable PID/network namespaces established; loopback only")

	for _, mode := range []string{"catalog-baseline", "cancel-control", "tool-deny", "tool-allow-control", "cancel"} {
		if !t.Run(mode, func(t *testing.T) { runCodexIntegration(t, root, binary, mode) }) {
			// PID-1 exit contains failed-fixture descendants. This safety net is
			// never counted as evidence that ExecLauncher cleaned them up.
			t.FailNow()
		}
	}
}

// This deliberately synthetic catalog is a lab delta. With no catalog override,
// the pinned candidate currently exposes no tools when its Code Mode host is
// disabled. A direct-mode fixture does not resolve that production readiness gap.
const integrationCatalog = `{"models":[{"slug":"gpt-5.6-sol","display_name":"HSG synthetic","description":"local fixture only","supported_reasoning_levels":[{"effort":"medium","description":"fixture"}],"shell_type":"unified_exec","visibility":"none","supported_in_api":true,"priority":0,"support_verbosity":false,"truncation_policy":{"mode":"bytes","limit":10000},"experimental_supported_tools":[],"tool_mode":"direct","model_messages":{"instructions_template":"Local deterministic fixture."}}]}`

type integrationProbe struct {
	Nonce   string `json:"nonce"`
	Outcome string `json:"outcome"`
	Errno   int    `json:"errno"`
}

func runCodexIntegration(t *testing.T, parent, binary, mode string) {
	root := filepath.Join(parent, mode)
	usesTool := mode != "catalog-baseline" && mode != "cancel-control"
	isCancellation := mode == "cancel" || mode == "cancel-control"
	config := MessagingConfig(codexprofile.ModelNameV1)
	config.Binary, config.Workspace = binary, filepath.Join(root, "workspace")
	config.CodexHome, config.OutputDirectory = filepath.Join(root, "codex-home"), filepath.Join(root, "output")
	for _, dir := range []string{root, config.Workspace, config.CodexHome, filepath.Join(root, "tmp")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	catalog := filepath.Join(root, "synthetic-models.json")
	if err := os.WriteFile(catalog, []byte(integrationCatalog), 0o600); err != nil {
		t.Fatal(err)
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	answer, prompt := "HSG_COMPLETED_"+nonce, "synthetic user input "+nonce
	witness := filepath.Join(config.Workspace, "probe.json")
	lock, err := os.OpenFile(filepath.Join(config.Workspace, "probe.lock"), os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var fixtureErr error
	requests, canaryHits, verifiedOutput := 0, 0, false
	controlWaiting := make(chan struct{})
	controlDisconnected := false
	var trace []string
	server := httptest.NewUnstartedServer(nil)
	server.Config.ReadHeaderTimeout = 2 * time.Second
	server.Config.ReadTimeout = 5 * time.Second
	server.Config.WriteTimeout = 5 * time.Second
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fail := func(message string) {
			fixtureErr = errors.New(message)
			http.Error(w, message, http.StatusBadRequest)
		}
		if r.Method == "GET" && r.URL.Path == "/canary/"+nonce && r.URL.RawQuery == "" {
			canaryHits++
			_, _ = io.WriteString(w, nonce)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/v1/responses" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+nonce {
			fail("unexpected fixture route or synthetic authentication")
			return
		}
		requests++
		if requests > 2 {
			fail("fixture inference limit exceeded")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
		var request struct {
			Model     string
			Reasoning struct{ Effort string }
			Tools     []struct{ Type, Name string }
			Input     []struct {
				Type, Role string
				CallID     string `json:"call_id"`
				Output     json.RawMessage
				Content    []struct{ Type, Text string }
			}
		}
		if err != nil || len(body) > 2<<20 || json.Unmarshal(body, &request) != nil {
			fail("invalid or oversized synthetic request")
			return
		}
		if request.Model != codexprofile.ModelNameV1 || request.Reasoning.Effort != codexprofile.ModelReasoningEffortV1 {
			fail("model or reasoning drift")
			return
		}
		developerCount, userCount := 0, 0
		for _, item := range request.Input {
			for _, part := range item.Content {
				if item.Role == "developer" {
					developerCount += strings.Count(part.Text, codexprofile.MessagingInstructionTextV1)
				}
				if item.Role == "user" && part.Text == prompt {
					userCount++
				}
			}
		}
		if developerCount != 1 || userCount != 1 {
			fail(fmt.Sprintf("instruction role/count drift: developer=%d user=%d", developerCount, userCount))
			return
		}
		trace = append(trace, fmt.Sprintf("request=%d model/effort/roles/auth=matched tools=%d", requests, len(request.Tools)))
		if mode == "cancel-control" {
			if requests != 1 {
				fail("cancel control requested another inference")
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			close(controlWaiting)
			select {
			case <-r.Context().Done():
				controlDisconnected = true
			case <-time.After(5 * time.Second):
				fixtureErr = errors.New("cancelled native client retained its provider connection")
			}
			return
		} else if mode == "catalog-baseline" {
			if len(request.Tools) != 0 || requests != 1 {
				fail("pinned no-catalog baseline changed; re-audit tool compatibility")
				return
			}
		} else if requests == 1 {
			found := 0
			for _, tool := range request.Tools {
				if tool.Type == "function" && tool.Name == "exec_command" {
					found++
				}
			}
			if found != 1 {
				fail("expected exactly one native exec_command tool")
				return
			}
			// Only this fixed owned helper command is supplied by the simulator.
			parts := []string{self, "-test.run=^TestCodexExecIntegrationTool$", "--", "hsg-exec-probe", mode, config.Workspace, nonce, server.URL}
			for i := range parts {
				parts[i] = "'" + strings.ReplaceAll(parts[i], "'", "'\"'\"'") + "'"
			}
			args, _ := json.Marshal(map[string]any{"cmd": "exec " + strings.Join(parts, " "), "yield_time_ms": 10000, "max_output_tokens": 1000})
			writeIntegrationResponse(w, nonce, map[string]any{"type": "function_call", "id": "fc_" + nonce, "call_id": "call_" + nonce, "name": "exec_command", "arguments": string(args), "status": "completed"})
			return
		} else {
			if mode == "cancel" {
				fail("cancel fixture unexpectedly requested another inference")
				return
			}
			want := integrationProbe{Nonce: nonce, Outcome: "denied", Errno: int(syscall.EPERM)}
			if mode == "tool-allow-control" {
				want.Outcome, want.Errno = "reachable", 0
			}
			encoded, _ := json.Marshal(want)
			var outputEvidence []string
			for _, item := range request.Input {
				var output string
				if item.Type == "function_call_output" {
					outputEvidence = append(outputEvidence, fmt.Sprintf("call_id=%s output=%s", item.CallID, item.Output[:min(len(item.Output), 4096)]))
				}
				if item.Type == "function_call_output" && item.CallID == "call_"+nonce && json.Unmarshal(item.Output, &output) == nil && strings.Contains(output, string(encoded)) {
					verifiedOutput = true
				}
			}
			if !verifiedOutput {
				fail(fmt.Sprintf("missing nonce-bound native tool output: %v", outputEvidence))
				return
			}
		}
		writeIntegrationResponse(w, nonce, map[string]any{"id": "msg_" + nonce, "type": "message", "status": "completed", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": answer, "annotations": []any{}}}})
	})
	server.Start()
	defer server.Close()

	var diagnostics integrationDiagnostics
	var launched *execProcess
	launcher := launcherFunc(func(ctx context.Context, invocation Invocation) (Process, error) {
		if len(invocation.Args) == 0 || invocation.Args[len(invocation.Args)-1] != "-" {
			return nil, errors.New("adapter stdin argument drift")
		}
		// Preserve every production argument except the counted positive-control
		// network bit. All additions here are explicit lab deltas, never HRP input.
		args := append([]string(nil), invocation.Args[:len(invocation.Args)-1]...)
		networkBits := 0
		for i, arg := range args {
			if arg == "sandbox_workspace_write.network_access=false" && i > 0 && args[i-1] == "--config" {
				networkBits++
				if mode == "tool-allow-control" {
					args[i] = "sandbox_workspace_write.network_access=true"
				}
			}
		}
		if networkBits != 1 {
			return nil, errors.New("expected exactly one sealed network deny argument")
		}
		args = append(args, "--skip-git-repo-check", "--config", `model_provider="hsg-local"`, "--config",
			`model_providers.hsg-local={name="HSG synthetic",base_url="`+server.URL+`/v1",wire_api="responses",requires_openai_auth=false,env_key="HSG_SYNTHETIC_PROVIDER_KEY",supports_websockets=false,request_max_retries=0,stream_max_retries=0,stream_idle_timeout_ms=5000}`)
		if usesTool {
			args = append(args, "--config", fmt.Sprintf("model_catalog_json=%q", catalog))
		}
		invocation.Args = append(args, "-")
		invocation.Env = append(invocation.Env, "TMPDIR="+filepath.Join(root, "tmp"), "HSG_SYNTHETIC_PROVIDER_KEY="+nonce)
		invocation.Stdout = io.MultiWriter(invocation.Stdout, &diagnostics)
		invocation.Stderr = io.MultiWriter(invocation.Stderr, &diagnostics)
		process, err := (ExecLauncher{}).Start(ctx, invocation)
		if err == nil {
			launched = process.(*execProcess)
		}
		return process, err
	})
	start := testStart()
	start.Input.Text = prompt
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cancelObserved := make(chan error, 1)
	var cancelledAt time.Time // read only after receiving cancelObserved
	if isCancellation {
		go func() {
			if mode == "cancel-control" {
				select {
				case <-ctx.Done():
					cancelObserved <- errors.New("deadline before native provider request")
				case <-controlWaiting:
					cancelledAt = time.Now()
					cancelObserved <- nil
					cancel()
				}
				return
			}
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					cancelObserved <- errors.New("deadline before owned lock was held")
					return
				case <-ticker.C:
					body, err := os.ReadFile(witness)
					var probe integrationProbe
					if err != nil || json.Unmarshal(body, &probe) != nil || probe.Nonce != nonce || probe.Outcome != "held" {
						continue
					}
					err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
					if !errors.Is(err, syscall.EWOULDBLOCK) {
						if err == nil {
							_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
						}
						cancelObserved <- fmt.Errorf("helper did not hold lock: %v", err)
						cancel()
						return
					}
					cancelledAt = time.Now()
					cancelObserved <- nil
					cancel()
					return
				}
			}
		}()
	}
	frames, _, runErr := execute(t, ctx, start, config, launcher)
	cancel()
	if isCancellation {
		if err := <-cancelObserved; err != nil {
			t.Error(err)
		} else if elapsed := time.Since(cancelledAt); elapsed > childStopGrace+3*time.Second {
			t.Errorf("native cancellation took %s", elapsed)
		}
	}
	t.Logf("native diagnostics:\n%s", diagnostics.String())
	if runErr != nil || len(frames) != 3 || launched == nil || launched.command.ProcessState == nil {
		t.Fatalf("adapter result: frames=%d err=%v leader reaped=%t", len(frames), runErr, launched != nil && launched.command.ProcessState != nil)
	}
	if isCancellation {
		if cancelled, ok := frames[2].(*runnerwire.RunCancelled); !ok || cancelled.Seq != 2 {
			t.Fatalf("cancel did not produce the sole terminal seq 2: %#v", frames[2])
		}
	} else if completed, ok := frames[2].(*runnerwire.RunCompleted); !ok || strings.TrimSpace(completed.Output.Text) != answer {
		t.Fatalf("synthetic exec did not complete: %#v", frames[2])
	}
	if mode == "catalog-baseline" && !strings.Contains(diagnostics.String(), "Code Mode is unavailable") {
		t.Fatal("pinned no-catalog diagnostic changed; re-audit tool compatibility")
	}
	// Establish quiescence before the outer PID namespace is destroyed. This
	// does not substitute for the still-unimplemented exact-image release gate.
	assertIntegrationQuiescence(t)
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("owned helper lock survived adapter termination:", err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if usesTool {
		body, err := os.ReadFile(witness)
		var probe integrationProbe
		want := "denied"
		if mode == "cancel" {
			want = "held"
		} else if mode == "tool-allow-control" {
			want = "reachable"
		}
		if err != nil || json.Unmarshal(body, &probe) != nil || probe.Nonce != nonce || probe.Outcome != want {
			t.Fatalf("owned helper execution witness mismatch: %s (%v)", body, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(config.CodexHome, "auth.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("synthetic execution unexpectedly created auth state:", err)
	}
	mu.Lock()
	defer mu.Unlock()
	wantRequests, wantHits := 2, 0
	if mode == "catalog-baseline" || isCancellation {
		wantRequests = 1
	}
	if mode == "tool-allow-control" {
		wantHits = 1
	}
	if fixtureErr != nil || requests != wantRequests || canaryHits != wantHits {
		t.Fatalf("fixture: inference=%d canary=%d err=%v", requests, canaryHits, fixtureErr)
	}
	if mode == "cancel-control" && !controlDisconnected {
		t.Fatal("native provider connection survived cancellation")
	}
	t.Logf("%s: inference=%d canary=%d tool-output=%t provider-disconnected=%t; leader reaped, namespace descendants gone, owned lock available before namespace teardown; %v", mode, requests, canaryHits, verifiedOutput, controlDisconnected, trace)
}

func writeIntegrationResponse(w http.ResponseWriter, nonce string, item map[string]any) {
	w.Header().Set("Content-Type", "text/event-stream")
	for _, event := range []map[string]any{
		{"type": "response.output_item.done", "output_index": 0, "sequence_number": 0, "item": item},
		{"type": "response.completed", "sequence_number": 1, "response": map[string]any{"id": "resp_" + nonce, "status": "completed", "output": []any{item}}},
	} {
		encoded, _ := json.Marshal(event)
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event["type"], encoded)
	}
}

// The only model-generated command in the fixture executes this owned helper.
// Its network attempt targets the same listener as successful control traffic.
func TestCodexExecIntegrationTool(t *testing.T) {
	if len(os.Args) < 7 || os.Args[len(os.Args)-6] != "--" || os.Args[len(os.Args)-5] != "hsg-exec-probe" {
		return
	}
	mode, workspace, nonce, endpoint := os.Args[len(os.Args)-4], os.Args[len(os.Args)-3], os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	parsed, err := url.Parse(endpoint)
	nonceBytes, nonceErr := hex.DecodeString(nonce)
	if (mode != "cancel" && mode != "tool-deny" && mode != "tool-allow-control") || !filepath.IsAbs(workspace) || nonceErr != nil || len(nonceBytes) != 16 || err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.Path != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		t.Fatal("invalid owned helper operands")
	}
	if _, present := os.LookupEnv("HSG_SYNTHETIC_PROVIDER_KEY"); present {
		t.Fatal("synthetic provider environment leaked into native tool")
	}
	probe := integrationProbe{Nonce: nonce}
	if mode == "cancel" {
		lock, err := os.OpenFile(filepath.Join(workspace, "probe.lock"), os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		probe.Outcome = "held"
		encoded, _ := json.Marshal(probe)
		if err := os.WriteFile(filepath.Join(workspace, "probe.json"), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		fmt.Println(string(encoded))
		for {
			time.Sleep(time.Hour)
		}
	}
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("no redirects") }}
	response, err := client.Get(endpoint + "/canary/" + nonce)
	if err != nil {
		if !errors.Is(err, syscall.EPERM) {
			t.Fatal("network probe failed without kernel EPERM:", err)
		}
		probe.Outcome, probe.Errno = "denied", int(syscall.EPERM)
	} else {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 128))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || string(body) != nonce {
			t.Fatal("network positive control did not reach the exact fixture")
		}
		probe.Outcome = "reachable"
	}
	encoded, _ := json.Marshal(probe)
	if err := os.WriteFile(filepath.Join(workspace, "probe.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(encoded))
}

func assertIntegrationQuiescence(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(childStopGrace + 3*time.Second)
	var remaining []string
	for time.Now().Before(deadline) {
		// Run has already reaped its leader. PID 1 may now reap adopted fixture
		// orphans without racing any other exec.Cmd in this sequential test.
		for {
			pid, err := unix.Wait4(-1, nil, unix.WNOHANG, nil)
			if err != nil || pid == 0 {
				break
			}
		}
		entries, err := os.ReadDir("/proc")
		if err != nil {
			t.Fatal(err)
		}
		remaining = nil
		for _, entry := range entries {
			if pid, err := strconv.Atoi(entry.Name()); err == nil && pid != 1 {
				remaining = append(remaining, entry.Name())
			}
		}
		if len(remaining) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("namespace descendants remain before safety teardown: %v", remaining)
}

type integrationDiagnostics struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (d *integrationDiagnostics) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := len(p)
	if remaining := (64 << 10) - d.buf.Len(); remaining > 0 {
		d.buf.Write(p[:min(len(p), remaining)])
	}
	return n, nil
}

func (d *integrationDiagnostics) String() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.buf.String()
}
