//go:build linux && codexintegration

package codexadapter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/responsesgate"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"golang.org/x/sys/unix"
)

// TestCodexToolsConfiguration requires the documented externally owned offline
// namespace. No model service or real auth is used. The synthetic responder
// executes only the fixed canaries below and never a model-generated script.
func TestCodexToolsConfiguration(t *testing.T) {
	if os.Getenv("HSG_CODEX_TOOLS_CANARY") != "1" {
		t.Skip("opt-in offline native tool-package canary")
	}
	interfaces, err := net.Interfaces()
	if err != nil || os.Getpid() != 1 || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagUp == 0 {
		t.Fatal("requires owned PID-1 namespace with only active loopback")
	}
	binary, err := exec.LookPath("codex")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyToolsPackage(binary); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"host", "agent-capacity", "file-write", "command-exec", "network-allow-control", "network-deny", "command-cancel"} {
		if !t.Run(mode, func(t *testing.T) { toolsConfigurationCase(t, binary, mode) }) {
			t.FailNow()
		}
		assertIntegrationQuiescence(t)
	}
}

func toolsConfigurationCase(t *testing.T, binary, mode string) {
	toolsConfigurationConsumerCase(t, binary, mode, false)
}

// The composed case substitutes the implemented consumer for the old permissive
// HTTP fixture, retaining its independent native-command result checks.
func toolsConfigurationConsumerCase(t *testing.T, binary, mode string, boundedConsumer bool) {
	toolsConfigurationConsumerIO(t, binary, mode, boundedConsumer, nil)
}

func toolsConfigurationConsumerIO(t *testing.T, binary, mode string, boundedConsumer bool, external *controllerRunnerIO) {
	toolsConfigurationProviderIO(t, binary, mode, boundedConsumer, external, false)
}

func toolsConfigurationProviderIO(t *testing.T, binary, mode string, boundedConsumer bool, external *controllerRunnerIO, subscription bool) {
	if subscription && (!boundedConsumer || external == nil || (mode != "command-exec" && mode != "command-cancel")) {
		t.Fatal("unsupported fixed HTTPS fixture")
	}
	root := t.TempDir()
	c := MessagingToolsConfig(codexprofile.ModelNameV1)
	c.Binary, c.Workspace = binary, filepath.Join(root, "workspace")
	c.CodexHome, c.OutputDirectory = filepath.Join(root, "home"), filepath.Join(root, "output")
	if boundedConsumer {
		// The outer fixture independently verifies this mounted synthetic object
		// before permitting its immutable bootstrap to execute this test.
		c.CodexHome = "/tmp/hgw-codex-home"
	}
	if external != nil {
		c.Workspace = "/workspace"
	}
	for _, dir := range []string{c.Workspace, filepath.Join(root, "tmp")} {
		if err := os.Mkdir(dir, 0o700); err != nil && !(external != nil && dir == c.Workspace && errors.Is(err, os.ErrExist)) {
			t.Fatal(err)
		}
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	deadlineCase := mode == "command-deadline"
	cancellation := mode == "command-cancel" || deadlineCase
	wantRequests := 2
	var lock *os.File
	witness := filepath.Join(c.Workspace, "probe.json")
	if cancellation {
		wantRequests = 1
		if deadlineCase {
			wantRequests = 2 // The async tool's continuation waits for the real Run deadline.
		}
		var err error
		lock, err = os.OpenFile(filepath.Join(c.Workspace, "probe.lock"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
	}
	marker, answer := "HOST_OK_"+nonce, "HSG_DONE_"+nonce
	commandMarker, stderrMarker := "COMMAND_OK_"+nonce, "COMMAND_STDERR_"+nonce
	commandProof, _ := json.Marshal(toolsCommandProof{Nonce: nonce, Directory: c.Workspace, UID: os.Geteuid(), NoNewPrivs: "1", CapEff: "0000000000000000"})
	networkControl := mode == "network-allow-control"
	networkCase := networkControl || mode == "network-deny"
	networkMarker := "NETWORK_OK_" + nonce
	networkWant := integrationProbe{Nonce: nonce, Outcome: "denied", Errno: int(syscall.EPERM)}
	if networkControl {
		networkWant.Outcome, networkWant.Errno = "reachable", 0
	}
	networkProof, _ := json.Marshal(networkWant)
	socketWant := make([]networkProbeResult, 0, len(networkSocketCases))
	for _, socket := range networkSocketCases {
		socketWant = append(socketWant, networkProbeResult{Name: socket.name, Errno: networkWant.Errno})
	}
	socketProof, _ := json.Marshal(socketWant)
	var mu sync.Mutex
	requests, verified := 0, false
	probeHits := 0
	var fixtureErr string
	fixtureAuthorization := "Bearer " + nonce
	budget := 25 * time.Second
	if cancellation && external != nil {
		budget = 75 * time.Second // Outer controller cancellation must win first.
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	server := httptest.NewUnstartedServer(nil)
	server.Config.ReadHeaderTimeout, server.Config.ReadTimeout, server.Config.WriteTimeout = 2*time.Second, 5*time.Second, 5*time.Second
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fail := func(reason string) { fixtureErr = reason; http.Error(w, reason, http.StatusBadRequest) }
		// The client and native tool target the same live listener. This route
		// stays reachable in the simulator even for the network-deny case.
		if networkCase && r.Method == "GET" && r.URL.Path == "/canary/"+nonce && r.URL.RawQuery == "" && r.Header.Get("Authorization") == "" {
			probeHits++
			_, _ = io.WriteString(w, nonce)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/v1/responses" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != fixtureAuthorization {
			fail("unexpected synthetic request")
			return
		}
		requests++
		if requests > wantRequests {
			fail("unexpected extra inference, including possible child agent")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
		var req struct {
			Model     string
			Reasoning struct{ Effort string }
			Tools     []json.RawMessage
			Input     []struct {
				Type   string
				CallID string `json:"call_id"`
				Output json.RawMessage
				Tools  []struct {
					Type, Name string
					Tools      []struct{ Type, Name, Description string }
				}
			}
		}
		if err != nil || len(body) > 2<<20 || json.Unmarshal(body, &req) != nil || req.Model != c.Model || req.Reasoning.Effort != c.ReasoningEffort {
			fail("request shape or model drift")
			return
		}
		if requests == 1 {
			// Responses Lite puts definitions in input.additional_tools. An empty
			// top-level tools array alone says nothing about tool availability.
			execCount, spawnCount := 0, 0
			for _, item := range req.Input {
				if item.Type != "additional_tools" {
					continue
				}
				for _, namespace := range item.Tools {
					for _, tool := range namespace.Tools {
						if namespace.Name == "functions" && tool.Name == "exec" && tool.Type == "custom" && strings.Contains(tool.Description, "exec_command") {
							execCount++
						}
						if namespace.Name == "collaboration" && tool.Name == "spawn_agent" && tool.Type == "function" {
							spawnCount++
						}
					}
				}
			}
			if execCount != 1 || spawnCount != 1 {
				fail("native namespaced tool definitions drifted")
				return
			}
			if mode != "agent-capacity" {
				patch, _ := json.Marshal("*** Begin Patch\n*** Add File: native-marker.txt\n+" + nonce + "\n*** End Patch")
				code := fmt.Sprintf(`text({marker:%q,names:ALL_TOOLS.map(t=>t.name),process:typeof process,require:typeof require,fetch:typeof fetch});`, marker)
				if mode == "file-write" {
					code += fmt.Sprintf(` text(await tools.apply_patch(%s));`, patch)
				}
				if mode == "command-exec" {
					self, err := os.Executable()
					if err != nil {
						fail("owned command helper unavailable")
						return
					}
					parts := []string{self, "-test.run=^TestCodexToolsCommandProbe$", "--", "hsg-v3-command-probe", c.Workspace, nonce}
					args, _ := json.Marshal(map[string]any{"cmd": "exec " + toolsCanaryShellCommand(parts...), "workdir": c.Workspace, "yield_time_ms": 10000, "max_output_tokens": 1000})
					code += fmt.Sprintf(` text({command_marker:%q,result:await tools.exec_command(%s)});`, commandMarker, args)
				}
				if cancellation {
					self, err := os.Executable()
					if err != nil {
						fail("owned cancellation helper unavailable")
						return
					}
					// The existing fixed helper holds a parent-created lock until
					// killed. Use the real V3 Code Mode host and bundled catalog.
					command := toolsCanaryShellCommand(self, "-test.run=^TestCodexExecIntegrationTool$", "--", "hsg-exec-probe", "cancel", c.Workspace, nonce, server.URL)
					args, _ := json.Marshal(map[string]any{"cmd": "exec " + command, "workdir": c.Workspace, "yield_time_ms": 10000, "max_output_tokens": 1000})
					code += fmt.Sprintf(` text(await tools.exec_command(%s));`, args)
				}
				if networkCase {
					self, err := os.Executable()
					if err != nil {
						fail("owned network helpers unavailable")
						return
					}
					probeMode := "tool-deny"
					if networkControl {
						probeMode = "tool-allow-control"
					}
					// Reuse the fixed probes, without the older direct-mode fixture
					// or its synthetic model catalog. Both run in this native tool.
					httpProbe := toolsCanaryShellCommand(self, "-test.run=^TestCodexExecIntegrationTool$", "--", "hsg-exec-probe", probeMode, c.Workspace, nonce, server.URL)
					sockets := toolsCanaryShellCommand(self, "-test.run=^TestCodexNetworkProbeProcess$", "--", "hsg-network-probe")
					args, _ := json.Marshal(map[string]any{"cmd": httpProbe + " && exec " + sockets, "workdir": c.Workspace, "yield_time_ms": 10000, "max_output_tokens": 1000})
					code += fmt.Sprintf(` text({command_marker:%q,result:await tools.exec_command(%s)});`, networkMarker, args)
				}
				writeIntegrationResponse(w, nonce, map[string]any{"type": "custom_tool_call", "id": "ct_" + nonce, "call_id": "call_" + nonce, "name": "exec", "namespace": "functions", "input": code, "status": "completed"})
			} else {
				args, _ := json.Marshal(map[string]string{"task_name": "capacity_probe", "message": "Synthetic capacity rejection probe; no work is authorized."})
				writeIntegrationResponse(w, nonce, map[string]any{"type": "function_call", "id": "fc_" + nonce, "call_id": "call_" + nonce, "name": "spawn_agent", "namespace": "collaboration", "arguments": string(args), "status": "completed"})
			}
			return
		}
		for _, item := range req.Input {
			if item.CallID != "call_"+nonce {
				continue
			}
			output := string(item.Output)
			if mode != "agent-capacity" && item.Type == "custom_tool_call_output" && strings.Contains(output, marker) && strings.Contains(output, `\"process\":\"undefined\"`) && strings.Contains(output, `\"require\":\"undefined\"`) && strings.Contains(output, `\"fetch\":\"undefined\"`) {
				verified = true
				if mode == "command-exec" {
					verified = verifyToolsCommandOutput(item.Output, commandMarker, string(commandProof), stderrMarker)
				}
				if networkCase {
					verified = verifyToolsExecOutput(item.Output, networkMarker, 0, string(networkProof), string(socketProof))
				}
			}
			if mode == "agent-capacity" && item.Type == "function_call_output" && strings.Contains(strings.ToLower(output), "limit") && !strings.Contains(output, "agent_id") {
				verified = true
				t.Logf("capacity rejection: %s", output)
			}
			if !verified && (item.Type == "custom_tool_call_output" || item.Type == "function_call_output") {
				fixtureErr = "unverified native output: " + output
			}
		}
		if !verified {
			fail("expected tool result missing: " + fixtureErr)
			return
		}
		writeIntegrationResponse(w, nonce, map[string]any{"type": "message", "id": "msg_" + nonce, "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": answer, "annotations": []any{}}}})
	})
	var consumer *responsesgate.Gate
	var provider *providerObserver
	var providerCA string
	if boundedConsumer {
		// Reuse only the trusted deterministic responder and native result
		// assertions. The real Gate owns HTTP parsing, admission and teardown.
		var err error
		responder := func(callCtx context.Context, request responsesgate.Request) (responsesgate.Response, error) {
			recorder := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(request.Body))).WithContext(callCtx)
			r.Header = request.Header
			server.Config.Handler.ServeHTTP(recorder, r)
			response := recorder.Result()
			if deadlineCase && response.StatusCode == http.StatusOK && requests == 2 && verified {
				_ = response.Body.Close()
				if err := awaitToolsHeldLock(callCtx, lock, witness, nonce); err != nil {
					return responsesgate.Response{}, err
				}
				// Fixed synthetic continuation; no new tool action or completed
				// model answer. Heartbeats respect the unchanged Gate idle limit.
				proof, _ := json.Marshal(map[string]any{"Nonce": nonce, "Requests": requests, "UTC": time.Now().UTC().Format(time.RFC3339Nano)})
				if err := os.WriteFile(filepath.Join(c.Workspace, "deadline-provider-wait.json"), proof, 0o600); err != nil {
					return responsesgate.Response{}, err
				}
				return responsesgate.Response{StatusCode: http.StatusOK, Header: response.Header, Body: newDeadlineHeartbeatBody(callCtx)}, nil
			}
			return responsesgate.Response{StatusCode: response.StatusCode, Header: response.Header, Body: response.Body}, nil
		}
		if subscription {
			_ = server.Listener.Close() // No unused second frontend survives launch.
			var cleanup func()
			consumer, provider, providerCA, cleanup = newProviderControllerConsumer(t, ctx, c.CodexHome, c.Workspace, nonce, responder)
			defer cleanup()
			fixtureAuthorization = consumer.SyntheticAuthorization()
			server.URL = provider.server.URL // Only a checked operand for the fixed held-tool helper.
		} else {
			consumer, err = responsesgate.NewSynthetic(ctx, server.Listener.Addr().String(), responder)
			if err != nil {
				_ = server.Listener.Close()
				t.Fatal(err)
			}
			fixtureAuthorization = consumer.SyntheticAuthorization()
			server.URL = "http://" + server.Listener.Addr().String()
			served := make(chan error, 1)
			go func() { served <- consumer.Serve(server.Listener) }()
			defer func() {
				consumer.Stop()
				select {
				case err := <-served:
					if err != nil {
						t.Error("synthetic consumer cleanup:", err)
					}
				case <-time.After(3 * time.Second):
					t.Error("synthetic consumer did not finish cleanup")
				}
			}()
		}
	} else {
		server.Start()
		defer server.Close()
	}
	var diagnostics integrationDiagnostics
	var launched *execProcess
	launcher := launcherFunc(func(ctx context.Context, inv Invocation) (Process, error) {
		args := append([]string(nil), inv.Args[:len(inv.Args)-1]...)
		if networkCase {
			// The positive control changes exactly this one production argument.
			// The VM and outer namespace remain offline in both cases.
			networkBits := 0
			for i, arg := range args {
				if arg == "sandbox_workspace_write.network_access=false" && i > 0 && args[i-1] == "--config" {
					networkBits++
					if networkControl {
						args[i] = "sandbox_workspace_write.network_access=true"
					}
				}
			}
			if networkBits != 1 {
				return nil, fmt.Errorf("expected exactly one sealed network deny argument, got %d", networkBits)
			}
		}
		if subscription {
			inv.Args = append(args, "--skip-git-repo-check", "--config", `model_provider="hsg-subscription-https"`,
				"--config", `model_providers.hsg-subscription-https={name="HSG subscription HTTPS",base_url="https://chatgpt.com/backend-api/codex",wire_api="responses",requires_openai_auth=true,supports_websockets=false}`,
				"--config", `features.enable_request_compression=false`, "-")
			inv.Env = append(inv.Env, "HTTPS_PROXY="+provider.server.URL, "HTTP_PROXY="+provider.server.URL, "CODEX_CA_CERTIFICATE="+providerCA, "TMPDIR="+filepath.Join(root, "tmp"))
		} else {
			inv.Args = append(args, "--skip-git-repo-check", "--config", `model_provider="hsg-local"`, "--config", `model_providers.hsg-local={name="HSG synthetic",base_url="`+server.URL+`/v1",wire_api="responses",requires_openai_auth=false,env_key="HSG_SYNTHETIC_PROVIDER_KEY",supports_websockets=false,request_max_retries=0,stream_max_retries=0,stream_idle_timeout_ms=5000}`, "-")
			inv.Env = append(inv.Env, "HSG_SYNTHETIC_PROVIDER_KEY="+strings.TrimPrefix(fixtureAuthorization, "Bearer "), "TMPDIR="+filepath.Join(root, "tmp"))
		}
		inv.Stdout = io.MultiWriter(inv.Stdout, &diagnostics)
		inv.Stderr = io.MultiWriter(inv.Stderr, &diagnostics)
		if consumer != nil && !subscription {
			if err := consumer.Open(); err != nil {
				return nil, err
			}
		}
		process, err := (ExecLauncher{}).Start(ctx, inv)
		if err == nil {
			launched = process.(*execProcess)
		}
		return process, err
	})
	start := testStart()
	start.Input.Text = "Fixed native configuration canary " + nonce
	type observation struct {
		at  time.Time
		err error
	}
	observed := make(chan observation, 1)
	if cancellation && external == nil {
		go func() {
			err := awaitToolsHeldLock(ctx, lock, witness, nonce)
			observed <- observation{at: time.Now(), err: err}
			cancel()
		}()
	}
	var frames []runnerwire.RunnerFrame
	var err error
	if external == nil {
		frames, _, err = execute(t, ctx, start, c, launcher)
	} else {
		err = Run(ctx, external.input, external, c, launcher)
		frames = external.frames
	}
	cancel()
	if cancellation && external != nil {
		t.Fatal("external cancellation fixture returned before outer teardown")
	}
	var cancelledAt time.Time
	if cancellation {
		proof := <-observed
		if proof.err != nil {
			t.Fatalf("cancellation lacked a live held-lock witness: %v diagnostics=%s", proof.err, diagnostics.String())
		}
		cancelledAt = proof.at
	}
	mu.Lock()
	defer mu.Unlock()
	if err != nil || fixtureErr != "" || requests != wantRequests || (!cancellation && !verified) {
		t.Fatalf("native canary: err=%v requests=%d verified=%v fixture=%s diagnostics=%s", err, requests, verified, fixtureErr, diagnostics.String())
	}
	if len(frames) != 3 {
		t.Fatalf("frames=%d", len(frames))
	}
	ready, ok := frames[0].(*runnerwire.RunnerReady)
	if !ok || ready.Adapter.Version != codexprofile.AdapterVersionV3 {
		t.Fatal("V3 readiness identity mismatch")
	}
	if cancellation {
		if terminal, ok := frames[2].(*runnerwire.RunCancelled); !ok || terminal.Seq != 2 {
			t.Fatalf("expected sole cancelled terminal seq 2: %#v diagnostics=%s", frames[2], diagnostics.String())
		}
		if launched == nil || launched.command.ProcessState == nil {
			t.Fatal("native leader was not reaped")
		}
		// Observe descendants and the same lock before t.TempDir cleanup and
		// before the outer namespace's safety teardown can hide a survivor.
		assertIntegrationQuiescence(t)
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			t.Fatal("owned tool lock survived cancellation:", err)
		}
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
			t.Fatal(err)
		}
		elapsed := time.Since(cancelledAt)
		if elapsed > childStopGrace+3*time.Second {
			t.Fatalf("cancellation and cleanup took %s", elapsed)
		}
		body, readErr := os.ReadFile(witness)
		var proof integrationProbe
		if readErr != nil || json.Unmarshal(body, &proof) != nil || proof != (integrationProbe{Nonce: nonce, Outcome: "held"}) {
			t.Fatalf("held-lock receipt changed: %v", readErr)
		}
		if _, err := os.Lstat(filepath.Join(c.CodexHome, "auth.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("synthetic cancellation unexpectedly created auth state:", err)
		}
		t.Logf("command-cancel: requests=1, nonce and held lock witnessed before cancel; sole V3 cancelled seq=2, leader reaped, descendants gone and same lock available before namespace teardown; cleanup_ms=%d", elapsed.Milliseconds())
		return
	}
	completed, ok := frames[2].(*runnerwire.RunCompleted)
	if !ok || completed.Output.Text != answer {
		t.Fatalf("terminal=%#v diagnostics=%s", frames[2], diagnostics.String())
	}
	if mode == "file-write" {
		data, err := os.ReadFile(filepath.Join(c.Workspace, "native-marker.txt"))
		if err != nil || string(data) != nonce+"\n" {
			t.Fatalf("native patch did not write exact owned marker: %v diagnostics=%s", err, diagnostics.String())
		}
	}
	if mode == "command-exec" {
		data, err := os.ReadFile(filepath.Join(c.Workspace, "native-command-proof.json"))
		if err != nil || string(data) != string(commandProof) {
			t.Fatalf("native command did not leave exact owned receipt: %v diagnostics=%s", err, diagnostics.String())
		}
		t.Logf("command-exec: exit=17, stdout and stderr, owned receipt, UID=%d, CWD, NNP=1 and CapEff=0 verified", os.Geteuid())
	}
	if networkCase {
		wantHits := 0
		if networkControl {
			wantHits = 1
		}
		data, err := os.ReadFile(filepath.Join(c.Workspace, "probe.json"))
		if err != nil || string(data) != string(networkProof) || probeHits != wantHits {
			t.Fatalf("network receipt or listener count mismatch: err=%v probe_hits=%d want=%d diagnostics=%s", err, probeHits, wantHits, diagnostics.String())
		}
		t.Logf("%s: requests=2 probe_hits=%d outcome=%s errno=%d, owned receipt and four socket results verified", mode, probeHits, networkWant.Outcome, networkWant.Errno)
	}
	t.Logf("%s: exact native result, two synthetic requests, V3 completion", mode)
}

// A file alone cannot prove a tool is still running. Require both the exact
// receipt and an independently contended lock on the parent's original inode.
func awaitToolsHeldLock(ctx context.Context, lock *os.File, witness, nonce string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("cancelled before owned lock was witnessed: %w", ctx.Err())
		case <-ticker.C:
			body, err := os.ReadFile(witness)
			var proof integrationProbe
			if err != nil || json.Unmarshal(body, &proof) != nil || proof != (integrationProbe{Nonce: nonce, Outcome: "held"}) {
				continue
			}
			err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
			if errors.Is(err, syscall.EWOULDBLOCK) {
				return ctx.Err()
			}
			if err == nil {
				err = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
			}
			return fmt.Errorf("receipt exists but helper did not hold the original lock: %v", err)
		}
	}
}

func TestToolsHeldLockEvidence(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		proof                       integrationProbe
		hold, absent, cancelled, ok bool
	}{
		{"live-helper", integrationProbe{Nonce: "owned", Outcome: "held"}, true, false, false, true},
		{"receipt-without-lock", integrationProbe{Nonce: "owned", Outcome: "held"}, false, false, false, false},
		{"wrong-nonce", integrationProbe{Nonce: "other", Outcome: "held"}, true, false, false, false},
		{"wrong-outcome", integrationProbe{Nonce: "owned", Outcome: "reachable"}, true, false, false, false},
		{"nonzero-errno", integrationProbe{Nonce: "owned", Outcome: "held", Errno: 1}, true, false, false, false},
		{"no-receipt", integrationProbe{}, true, true, false, false},
		{"already-cancelled", integrationProbe{Nonce: "owned", Outcome: "held"}, true, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			lock, err := os.OpenFile(filepath.Join(root, "probe.lock"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			owner, err := os.OpenFile(lock.Name(), os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			if tc.hold {
				if err := unix.Flock(int(owner.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			}
			witness := filepath.Join(root, "probe.json")
			if !tc.absent {
				body, _ := json.Marshal(tc.proof)
				if err := os.WriteFile(witness, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			if err := awaitToolsHeldLock(ctx, lock, witness, "owned"); (err == nil) != tc.ok {
				t.Fatalf("witness error=%v want success=%v", err, tc.ok)
			}
		})
	}
}

func toolsCanaryShellCommand(parts ...string) string {
	quoted := make([]string, len(parts))
	for i, part := range parts {
		quoted[i] = "'" + strings.ReplaceAll(part, "'", "'\"'\"'") + "'"
	}
	return strings.Join(quoted, " ")
}

type toolsCommandProof struct {
	Nonce      string `json:"nonce"`
	Directory  string `json:"directory"`
	UID        int    `json:"uid"`
	NoNewPrivs string `json:"no_new_privs"`
	CapEff     string `json:"cap_eff"`
}

func verifyToolsCommandOutput(raw json.RawMessage, marker, stdout, stderr string) bool {
	return verifyToolsExecOutput(raw, marker, 17, stdout, stderr)
}

func verifyToolsExecOutput(raw json.RawMessage, marker string, exitCode int, expectedLines ...string) bool {
	var chunks []struct{ Type, Text string }
	if len(expectedLines) == 0 || json.Unmarshal(raw, &chunks) != nil {
		return false
	}
	matches := 0
	for _, chunk := range chunks {
		var report struct {
			Marker string `json:"command_marker"`
			Result struct {
				ExitCode  *int `json:"exit_code"`
				SessionID *int `json:"session_id"`
				Output    string
			}
		}
		if chunk.Type != "input_text" || json.Unmarshal([]byte(chunk.Text), &report) != nil || report.Marker != marker {
			continue
		}
		if report.Result.ExitCode == nil || *report.Result.ExitCode != exitCode || report.Result.SessionID != nil {
			return false
		}
		lines := strings.Split(report.Result.Output, "\n")
		for _, expected := range expectedLines {
			count := 0
			for _, line := range lines {
				if line == expected {
					count++
				}
			}
			if count != 1 {
				return false
			}
		}
		matches++
	}
	return matches == 1
}

func TestToolsCommandOutputEvidence(t *testing.T) {
	valid := `{"command_marker":"command-nonce","result":{"exit_code":17,"output":"stdout-proof\nstderr-proof\n"}}`
	for _, tc := range []struct {
		name, report string
		copies       int
		want         bool
	}{
		{"complete", valid, 1, true},
		{"missing-exit", strings.Replace(valid, `"exit_code":17,`, "", 1), 1, false},
		{"wrong-exit", strings.Replace(valid, `"exit_code":17`, `"exit_code":0`, 1), 1, false},
		{"still-running", strings.Replace(valid, `"exit_code":17`, `"session_id":7,"exit_code":17`, 1), 1, false},
		{"wrong-nonce", strings.Replace(valid, "command-nonce", "other-nonce", 1), 1, false},
		{"missing-stdout", strings.Replace(valid, `stdout-proof\n`, "", 1), 1, false},
		{"missing-stderr", strings.Replace(valid, `stderr-proof\n`, "", 1), 1, false},
		{"duplicate-report", valid, 2, false},
		{"plain-marker-is-not-evidence", "command-nonce stdout-proof stderr-proof", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chunks := []map[string]string{{"type": "input_text", "text": "Script completed"}}
			for i := 0; i < tc.copies; i++ {
				chunks = append(chunks, map[string]string{"type": "input_text", "text": tc.report})
			}
			raw, _ := json.Marshal(chunks)
			if got := verifyToolsCommandOutput(raw, "command-nonce", "stdout-proof", "stderr-proof"); got != tc.want {
				t.Fatalf("accepted=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestToolsNetworkOutputEvidence(t *testing.T) {
	valid := `{"command_marker":"network-nonce","result":{"exit_code":0,"output":"http-proof\nsocket-proof\n"}}`
	for _, tc := range []struct {
		name, report string
		want         bool
	}{
		{"zero-exit", valid, true},
		{"missing-exit-is-not-zero", strings.Replace(valid, `"exit_code":0,`, "", 1), false},
		{"both-probes-required", strings.Replace(valid, `socket-proof\n`, "", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal([]map[string]string{{"type": "input_text", "text": tc.report}})
			if got := verifyToolsExecOutput(raw, "network-nonce", 0, "http-proof", "socket-proof"); got != tc.want {
				t.Fatalf("accepted=%v want=%v", got, tc.want)
			}
		})
	}
}

// Executed only by the fixed synthetic exec_command call, inside the native
// sandbox. Its deliberate nonzero exit must be returned as tool data while the
// surrounding V3 Run still completes. The parent independently reads its file.
func TestCodexToolsCommandProbe(t *testing.T) {
	if len(os.Args) < 5 || os.Args[len(os.Args)-4] != "--" || os.Args[len(os.Args)-3] != "hsg-v3-command-probe" {
		return
	}
	workspace, nonce := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	nonceBytes, err := hex.DecodeString(nonce)
	if err != nil || len(nonceBytes) != 16 || !filepath.IsAbs(workspace) || os.Geteuid() == 0 {
		t.Fatal("invalid owned command probe operands or identity")
	}
	directory, err := os.Getwd()
	if err != nil || directory != workspace {
		t.Fatal("native command working directory mismatch")
	}
	if _, present := os.LookupEnv("HSG_SYNTHETIC_PROVIDER_KEY"); present {
		t.Fatal("synthetic provider environment leaked into command")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			fields[parts[0]] = parts[1]
		}
	}
	if fields["NoNewPrivs:"] != "1" || fields["CapEff:"] != "0000000000000000" {
		t.Fatal("native command privilege boundary mismatch")
	}
	proof, _ := json.Marshal(toolsCommandProof{Nonce: nonce, Directory: directory, UID: os.Geteuid(), NoNewPrivs: fields["NoNewPrivs:"], CapEff: fields["CapEff:"]})
	file, err := os.OpenFile(filepath.Join(workspace, "native-command-proof.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(proof); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(proof))
	fmt.Fprintln(os.Stderr, "COMMAND_STDERR_"+nonce)
	os.Exit(17)
}
