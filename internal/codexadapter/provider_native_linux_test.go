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
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/providerfixture"
	"github.com/shwdsun/harness-security-gateway/internal/providerrelay"
	"github.com/shwdsun/harness-security-gateway/internal/responsesgate"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
	"golang.org/x/sys/unix"
)

const nativeProviderWorkspace = "/tmp/hsg-native-workspace"
const nativeProviderSocket = "/run/hsg-provider.sock"
const nativeProviderMarker = "HSG_NATIVE_CHANNEL_DONE"

type nativeProviderIdentity struct {
	PID      int
	Dev, Ino uint64
	UID, GID uint32
}

// These files coordinate only the fixed offline experiment. They are not
// runtime authorization, enrollment or terminal-publication witnesses.
func nativeProviderWrite(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".native-witness-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("fixture witness write failed")
	}
	return os.Rename(file.Name(), path)
}

func nativeProviderRead(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (32<<10)+1))
	if err != nil {
		return err
	}
	return strictjson.Decode(data, 32<<10, 16, value)
}

func nativeProviderWait(ctx context.Context, path string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func nativeProviderProbeValid(plan providerProbePlan, report providerProbeReport) bool {
	if len(plan.Nonce) != 32 || report.Nonce != plan.Nonce || report.Inherited != 0 ||
		report.ProtectedCount != len(plan.ProtectedFDs) || report.ProtectedCount < 4 ||
		(!report.OwnerMatched && !report.AncestorProcView) || !report.PIDView.OwnerStartMatches {
		return false
	}
	for _, name := range []string{"tcp", "pathname", "proc_fd", "proc_mem"} {
		outcome, exists := report.Results[name]
		if !exists || outcome.Access || (outcome.Errno != int(unix.EPERM) && outcome.Errno != int(unix.EACCES)) {
			return false
		}
		if (name == "tcp" || name == "pathname") && outcome.Errno != int(unix.EPERM) {
			return false
		}
	}
	return true
}

func TestProviderNativeOwner(t *testing.T) {
	root := os.Getenv("HSG_PROVIDER_NATIVE_OWNER_ROOT")
	if root == "" {
		t.Skip("opt-in owned host endpoint for offline native acceptance")
	}
	info, err := os.Lstat(root)
	if err != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || !info.IsDir() || info.Mode().Perm() != 0o700 || os.Geteuid() != 1000 {
		t.Fatal("requires a fresh private ordinary-user fixture root")
	}
	var fixture struct{ Case string }
	if nativeProviderRead(filepath.Join(root, "fixture.json"), &fixture) != nil || (fixture.Case != "complete" && fixture.Case != "owner-loss") {
		t.Fatal("invalid fixed fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	workspace := filepath.Join(root, "workspace")
	dispatches, verified := 0, false // Read only after Gate shutdown joins callbacks.
	var plan providerProbePlan
	var report providerProbeReport
	ops := newProviderCompositionOps(t, ctx, providerfixture.Nonce, func(callCtx context.Context, request responsesgate.Request) (responsesgate.Response, error) {
		dispatches++
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
			return responsesgate.Response{}, errors.New("fixture input projection")
		}
		recorder := httptest.NewRecorder()
		switch dispatches {
		case 1:
			if nativeProviderWrite(filepath.Join(workspace, "snapshot-request.json"), true) != nil ||
				nativeProviderWait(callCtx, filepath.Join(workspace, "provider-probe-plan.json")) != nil ||
				nativeProviderRead(filepath.Join(workspace, "provider-probe-plan.json"), &plan) != nil || len(plan.Nonce) != 32 || len(plan.ProtectedFDs) < 4 {
				return responsesgate.Response{}, errors.New("live descriptor snapshot missing")
			}
			execCount := 0
			for _, item := range input.Input {
				if item.Type == "additional_tools" {
					for _, ns := range item.Tools {
						for _, tool := range ns.Tools {
							if ns.Name == "functions" && tool.Type == "custom" && tool.Name == "exec" && strings.Contains(tool.Description, "exec_command") {
								execCount++
							}
						}
					}
				}
			}
			if execCount != 1 {
				return responsesgate.Response{}, errors.New("fixed native exec definition absent")
			}
			args, _ := json.Marshal(map[string]any{"cmd": "exec " + toolsCanaryShellCommand("/native.test", "-test.run=^TestProviderProbeProcess$", "--", "hsg-provider-probe", nativeProviderWorkspace), "workdir": nativeProviderWorkspace, "yield_time_ms": 10000, "max_output_tokens": 2000})
			code := fmt.Sprintf(`text({command_marker:%q,result:await tools.exec_command(%s)});`, plan.Nonce, args)
			writeIntegrationResponse(recorder, plan.Nonce, map[string]any{"type": "custom_tool_call", "id": "ct_" + plan.Nonce, "call_id": "call_" + plan.Nonce, "name": "exec", "namespace": "functions", "input": code, "status": "completed"})
		case 2:
			data, err := os.ReadFile(filepath.Join(workspace, "provider-probe-report.json"))
			if err != nil || len(data) > 8192 || json.Unmarshal(data, &report) != nil || !nativeProviderProbeValid(plan, report) {
				return responsesgate.Response{}, errors.New("native boundary report invalid")
			}
			for _, item := range input.Input {
				if item.Type == "custom_tool_call_output" && item.CallID == "call_"+plan.Nonce && verifyToolsExecOutput(item.Output, plan.Nonce, 0, string(data)) {
					verified = true
				}
			}
			if !verified {
				return responsesgate.Response{}, errors.New("native output differs from independent report")
			}
			if fixture.Case == "owner-loss" {
				if nativeProviderWrite(filepath.Join(root, "owner-active.json"), map[string]any{"PID": os.Getpid(), "Nonce": plan.Nonce, "ToolVerified": true, "Dispatch": dispatches}) != nil {
					return responsesgate.Response{}, errors.New("active witness failed")
				}
				<-callCtx.Done()
				return responsesgate.Response{}, callCtx.Err()
			}
			writeIntegrationResponse(recorder, plan.Nonce, map[string]any{"type": "message", "id": "msg_" + plan.Nonce, "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": nativeProviderMarker, "annotations": []any{}}}})
		default:
			return responsesgate.Response{}, errors.New("unexpected fixture dispatch")
		}
		return responsesgate.Response{StatusCode: recorder.Code, Header: recorder.Header(), Body: io.NopCloser(bytes.NewReader(recorder.Body.Bytes()))}, nil
	})
	observer := newProviderObserverOnListener(t, providerfixture.Nonce, ops.respond, relayOwnerListener(t, root))
	defer observer.close()
	var stat unix.Stat_t
	if unix.Stat(filepath.Join(root, "owner.sock"), &stat) != nil || stat.Mode&0o777 != 0o600 || stat.Uid != 1000 || stat.Gid != 1000 {
		t.Fatal("owner socket identity invalid")
	}
	if os.WriteFile(filepath.Join(root, "ca.pem"), observer.ca, 0o600) != nil || nativeProviderWrite(filepath.Join(root, "identity.json"), nativeProviderIdentity{os.Getpid(), uint64(stat.Dev), stat.Ino, stat.Uid, stat.Gid}) != nil {
		t.Fatal("public trust/identity witness failed")
	}
	// Only the exact spawning driver holds stdin. EOF requests joined shutdown.
	done := make(chan struct{})
	go func() { var one [1]byte; _, _ = os.Stdin.Read(one[:]); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Error("owner shutdown control expired")
	}
	observer.close()
	ops.close()
	observer.mu.Lock()
	defer observer.mu.Unlock()
	ops.mu.Lock()
	defer ops.mu.Unlock()
	if fixture.Case != "complete" || dispatches != 2 || !verified || ops.counts["refresh"] != 1 || ops.counts["inference"] != 2 {
		t.Error("native channel completion incomplete")
	}
	for _, status := range ops.statuses {
		if status != 200 && status != 404 {
			t.Error("unexpected synthetic operation rejection")
		}
	}
	if nativeProviderWrite(filepath.Join(root, "owner-result.json"), map[string]any{"Passed": !t.Failed(), "ClosedJoined": true, "Counts": ops.counts, "Statuses": ops.statuses, "Dispatches": dispatches, "ToolVerified": verified, "TLSStages": observer.stages, "Connects": len(observer.connects)}) != nil {
		t.Error("owner result write failed")
	}
}

func TestProviderNativeClient(t *testing.T) {
	mode := os.Getenv("HSG_PROVIDER_NATIVE_CLIENT")
	if mode == "" {
		t.Skip("opt-in fixed native container")
	}
	if mode != "complete" && mode != "owner-loss" {
		t.Fatal("invalid native mode")
	}
	result := map[string]any{"Mode": mode}
	defer func() {
		result["Passed"] = !t.Failed()
		if nativeProviderWrite(filepath.Join(nativeProviderWorkspace, "client-result.json"), result) != nil {
			t.Error("client result write failed")
		}
	}()
	controllerRunnerNamespace(t)
	var identity nativeProviderIdentity
	var stat unix.Stat_t
	if nativeProviderRead("/hsg-provider-identity.json", &identity) != nil || unix.Stat(nativeProviderSocket, &stat) != nil ||
		identity.PID < 2 || uint64(stat.Dev) != identity.Dev || stat.Ino != identity.Ino || stat.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		stat.Mode&0o777 != 0o600 || stat.Uid != 1000 || stat.Gid != 1000 || identity.UID != 1000 || identity.GID != 1000 {
		t.Fatal("mounted socket identity/UID mismatch")
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal("mount view unavailable")
	}
	matched := 0
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 6 && fields[4] == nativeProviderSocket {
			matched++
			if !strings.Contains(","+fields[5]+",", ",ro,") {
				t.Fatal("socket bind is writable")
			}
		}
	}
	if matched != 1 {
		t.Fatal("exact socket mount missing")
	}
	result["ReadOnlySocketIdentity"] = identity
	conn, err := net.DialTimeout("unix", nativeProviderSocket, time.Second)
	if err != nil {
		t.Fatalf("direct Unix positive control: %v", err)
	}
	raw, rawErr := conn.(*net.UnixConn).SyscallConn()
	var peer *unix.Ucred
	var peerErr error
	if rawErr == nil {
		rawErr = raw.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	}
	_ = conn.Close()
	if rawErr != nil || peerErr != nil || peer == nil || peer.Uid != 1000 || peer.Gid != 1000 {
		t.Fatal("mapped owner peer identity mismatch")
	}
	result["DirectUnixPeer"] = peer // Host PID may be zero in the child namespace.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	relay, err := providerrelay.Start(ctx, nativeProviderSocket, localidentity.UID(1000))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		closeErr := relay.Close()
		result["RelayJoined"] = true
		if closeErr != nil {
			result["RelayError"] = closeErr.Error()
		}
	}()
	seed := newProviderProbeSeed(t)
	defer runtime.KeepAlive(seed)
	seed.plan.TCP, seed.plan.Pathname = relay.Address(), nativeProviderSocket
	controlDir := t.TempDir()
	controlPlan := seed.plan
	controlPlan.Pathname = "" // Real TLS ingress does not implement nonce echoes.
	providerWritePlan(t, controlDir, controlPlan)
	control := exec.CommandContext(ctx, "/native.test", "-test.run=^TestProviderProbeProcess$", "--", "hsg-provider-probe", controlDir)
	control.Env = []string{"HOME=/nonexistent", "PATH=/usr/bin:/bin", "LANG=C.UTF-8", "GOMAXPROCS=2"}
	control.ExtraFiles = []*os.File{seed.file}
	controlOutput, err := control.Output()
	var positive providerProbeReport
	data, readErr := os.ReadFile(filepath.Join(controlDir, "provider-probe-report.json"))
	if err != nil || readErr != nil || json.Unmarshal(data, &positive) != nil || !bytes.Contains(controlOutput, data) || positive.Inherited != 1 || !positive.Results["tcp"].Access || !positive.Results["proc_fd"].Access {
		t.Fatal("local TCP/descriptor positive control failed")
	}
	result["PositiveControl"] = positive
	config := MessagingToolsConfig(codexprofile.ModelNameV1)
	config.Workspace, config.CodexHome, config.OutputDirectory = nativeProviderWorkspace, "/tmp/hgw-codex-home", filepath.Join(t.TempDir(), "output")
	// Docker creates the single-file bind's parent in disposable tmpfs. Match
	// the existing bootstrap's private-home setup, without touching auth.json
	// or the host directory. The adapter must create its own output directory.
	home, err := os.Lstat(config.CodexHome)
	if err != nil || !home.IsDir() || home.Mode()&os.ModeSymlink != 0 || !ownedByEffectiveUser(home) {
		t.Fatal("disposable home identity invalid")
	}
	result["HomeModeBefore"] = fmt.Sprintf("%04o", home.Mode().Perm())
	if os.Chmod(config.CodexHome, 0o700) != nil {
		t.Fatal("private disposable home setup failed")
	}
	authPath := filepath.Join(config.CodexHome, "auth.json")
	before, err := os.Stat(authPath)
	data, readErr = os.ReadFile(authPath)
	if err != nil || readErr != nil || before.Mode().Perm() != 0o600 || !providerfixture.AuthMatches(data, false) {
		t.Fatal("mounted fake auth invalid")
	}
	var nativePID atomic.Int64
	snapshotCtx, stopSnapshot := context.WithCancel(ctx)
	snapshot := make(chan error, 1)
	snapshotDone := make(chan struct{})
	go func() {
		defer close(snapshotDone)
		if err := nativeProviderWait(snapshotCtx, filepath.Join(nativeProviderWorkspace, "snapshot-request.json")); err != nil {
			snapshot <- err
			return
		}
		identities := map[string]bool{seed.plan.ProtectedFDs[0]: true}
		clientSockets := 0
		for _, pid := range []int{os.Getpid(), int(nativePID.Load())} {
			if pid < 1 {
				snapshot <- errors.New("native PID missing")
				return
			}
			entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
			if err != nil {
				snapshot <- err
				return
			}
			for _, entry := range entries {
				var metadata unix.Stat_t
				if unix.Stat(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()), &metadata) == nil && metadata.Mode&unix.S_IFMT == unix.S_IFSOCK {
					identities[fmt.Sprintf("%d:%d:%d", metadata.Dev, metadata.Ino, metadata.Mode&unix.S_IFMT)] = true
					if pid != os.Getpid() {
						clientSockets++
					}
				}
			}
		}
		if clientSockets < 1 || len(identities) < 4 {
			snapshot <- errors.New("live provider sockets absent")
			return
		}
		seed.plan.ProtectedFDs = nil
		for identity := range identities {
			seed.plan.ProtectedFDs = append(seed.plan.ProtectedFDs, identity)
		}
		sort.Strings(seed.plan.ProtectedFDs)
		snapshot <- nativeProviderWrite(filepath.Join(nativeProviderWorkspace, "provider-probe-plan.json"), seed.plan)
	}()
	defer func() { stopSnapshot(); <-snapshotDone }()
	tmp := t.TempDir()
	var diagnostics integrationDiagnostics
	defer func() {
		// Closed synthetic fixture only; retain bounded private diagnostics on
		// failure, never add native transcripts to normal runtime logging.
		if t.Failed() {
			if os.WriteFile(filepath.Join(nativeProviderWorkspace, "native-diagnostics.txt"), []byte(diagnostics.String()), 0o600) != nil {
				t.Error("cannot retain bounded native diagnostics")
			}
		}
	}()
	launcher := launcherFunc(func(ctx context.Context, inv Invocation) (Process, error) {
		inv.Stdout = io.MultiWriter(inv.Stdout, &diagnostics)
		inv.Stderr = io.MultiWriter(inv.Stderr, &diagnostics)
		inv.Args = append(inv.Args[:len(inv.Args)-1], "--skip-git-repo-check", "--config", `model_provider="hsg-subscription-https"`,
			"--config", `model_providers.hsg-subscription-https={name="HSG subscription HTTPS",base_url="https://chatgpt.com/backend-api/codex",wire_api="responses",requires_openai_auth=true,supports_websockets=false}`,
			"--config", `features.enable_request_compression=false`, "-")
		inv.Env = append(inv.Env, "HTTPS_PROXY=http://"+relay.Address(), "HTTP_PROXY=http://"+relay.Address(), "CODEX_CA_CERTIFICATE=/hsg-provider-ca.pem", "TMPDIR="+tmp)
		process, err := (ExecLauncher{}).Start(ctx, inv)
		if err == nil {
			nativePID.Store(int64(process.(*execProcess).command.Process.Pid))
		}
		return process, err
	})
	start := testStart()
	start.Input.Text = "Execute the fixed synthetic provider-boundary probe once and return its completion marker."
	frames, _, err := execute(t, ctx, start, config, launcher)
	stopSnapshot()
	if snapshotErr := <-snapshot; snapshotErr != nil {
		t.Errorf("snapshot: %v", snapshotErr)
	}
	if err != nil || len(frames) != 3 || ctx.Err() != nil {
		t.Fatal("native HRP did not terminate before its deadline")
	}
	result["Terminal"] = fmt.Sprintf("%T", frames[2])
	result["NativePID"] = nativePID.Load()
	if failed, ok := frames[2].(*runnerwire.RunFailed); ok {
		result["Failure"] = failed.Error
	}
	if mode == "complete" {
		completed, ok := frames[2].(*runnerwire.RunCompleted)
		if !ok || completed.Output.Text != nativeProviderMarker {
			t.Fatal("native completion missing")
		}
	} else {
		failed, ok := frames[2].(*runnerwire.RunFailed)
		if !ok || failed.Error.Code != runnerwire.ErrorCodeHarnessError {
			t.Fatal("owner loss did not become a harness failure")
		}
	}
	var report providerProbeReport
	if nativeProviderRead(filepath.Join(nativeProviderWorkspace, "provider-probe-report.json"), &report) != nil || !nativeProviderProbeValid(seed.plan, report) {
		t.Fatal("native tool boundary incomplete")
	}
	result["Tool"] = report
	after, err := os.Stat(authPath)
	data, readErr = os.ReadFile(authPath)
	if err != nil || readErr != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0o600 || !providerfixture.AuthMatches(data, true) {
		t.Fatal("fake refresh did not preserve mounted object")
	}
	result["RefreshedSameFile"] = true
	err = relay.Close()
	result["RelayJoined"] = true
	if err != nil {
		result["RelayError"] = err.Error()
	}
	if (mode == "complete" && err != nil) || (mode == "owner-loss" && !errors.Is(err, providerrelay.ErrEndpoint)) {
		t.Errorf("relay outcome: %v", err)
	}
	assertIntegrationQuiescence(t)
}
