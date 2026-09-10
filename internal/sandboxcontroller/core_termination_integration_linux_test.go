//go:build linux && amd64 && codexintegration

package sandboxcontroller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentdispatch"
	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/agentservice"
	"github.com/shwdsun/harness-security-gateway/internal/connectorhttp"
	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
	"golang.org/x/sys/unix"
)

type nativeTerminationResult struct {
	coreNativeResult
	Deadline, WitnessAt, TERMAt, QuiescentAt          string
	Stops, Kills, ExitCode, InitPID, DescendantPID    int
	DetachedDescendant, TERMObserved, ProcessesExited bool
	BeforeRemoval, Final                              nativeRecoverySnapshot
}

type nativeTerminationRuntime struct {
	*coreNativeRuntime
	stops, kills atomic.Int32
}

func (r *nativeTerminationRuntime) Stop(ctx context.Context, ref string) error {
	r.stops.Add(1)
	r.record("real-docker-stop-dispatched")
	err := r.DockerRuntime.Stop(ctx, ref)
	if err == nil {
		r.record("real-docker-stop-returned")
	}
	return err
}

func (r *nativeTerminationRuntime) Kill(ctx context.Context, ref string) error {
	r.kills.Add(1)
	r.record("real-docker-kill-dispatched")
	return r.DockerRuntime.Kill(ctx, ref)
}

// Real native deadline and a separately pinned adversarial HRP descendant
// exercise one existing cleanup/publication boundary. No production override.
func TestCoreSyntheticV3Termination(t *testing.T) {
	if os.Getenv("HSG_CORE_NATIVE_TERMINATION") != "1" {
		t.Skip("requires a fresh frozen offline termination fixture")
	}
	path := os.Getenv("HSG_CORE_NATIVE_FIXTURE")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || os.Geteuid() != 1000 {
		t.Fatal("invalid owned fixture identity")
	}
	data, err := os.ReadFile(path)
	var config coreNativeConfig
	if err != nil || strictjson.Decode(data, 64<<10, 12, &config) != nil || (config.Case != "native-deadline" && config.Case != "resistant-descendant") {
		t.Fatal("invalid fixed termination case")
	}
	root := filepath.Dir(path)
	for _, owned := range []string{config.Runtime.WorkspaceRoot, config.Runtime.Credential.Root} {
		if !strings.HasPrefix(owned, root+"/") {
			t.Fatal("fixture write escaped owned root")
		}
	}
	result := nativeTerminationResult{coreNativeResult: coreNativeResult{RunID: config.RunID, Case: config.Case}}
	defer func() {
		result.Passed = !t.Failed()
		writeNativeRecoveryRecord(t, filepath.Join(root, "result.json"), result)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 160*time.Second)
	defer cancel()
	for _, name := range []string{"core", "sandbox", "connector", "other-connector"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	settings := coreNativeSettings(root, config.Runtime.Manifest)
	settings.RunTimeoutSeconds = 70
	policy, err := agentpolicy.Compile(settings)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := policy.Endpoint("synthetic")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := endpoint.SessionScope("operator", "private")
	if err != nil {
		t.Fatal(err)
	}
	result.ScopeDigest, err = sessionauth.Digest(scope)
	if err != nil {
		t.Fatal(err)
	}
	core, err := corestore.Open(ctx, settings.Database, corestore.Options{Admission: coreNativeAdmission(settings.Ingress)})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	var observed *nativeTerminationRuntime
	c, db, witness, pin, source := newCoreNativeController(t, ctx, root, config, scope, func(w *coreNativeRuntime) Runtime {
		observed = &nativeTerminationRuntime{coreNativeRuntime: w}
		w.blockRemoval.Store(true)
		return observed
	})
	defer db.Close()
	result.SyntheticPin, result.SourceDigest = pin, source
	writeNativeRecoveryRecord(t, filepath.Join(root, "fixture-ready.json"), map[string]string{"SyntheticPin": pin, "SourceDigest": source})
	defer func() {
		witness.blockRemoval.Store(false)
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if err := c.Close(cleanup); err != nil {
			t.Error("controller cleanup:", err)
		}
		witness.mu.Lock()
		defer witness.mu.Unlock()
		result.ContainerRef, result.Events = witness.ref, append([]string(nil), witness.events...)
		result.Creates, result.Attaches = witness.creates, witness.attaches
		result.RemovedWhileHeld, result.ReleasedBeforePublication = witness.removed, witness.released
		result.RemovalFailures = int(witness.removalFailures.Load())
		result.Stops, result.Kills = int(observed.stops.Load()), int(observed.kills.Load())
	}()
	readback := openNativeRecoveryReadback(t, filepath.Join(root, "sandbox", "state.sqlite3"))
	defer readback.Close()
	handler, err := executionhttp.NewHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	stopExecution := serveCoreNativeHTTP(t, settings.SandboxSocket, handler)
	defer stopExecution()
	execution, err := executionhttp.NewClient(settings.SandboxSocket, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := agentdispatch.New(core, execution, 60*time.Second, 70*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	service, err := agentservice.NewWithRunIDSource(endpoint, 30*time.Second, core, func() (string, error) { return config.RunID, nil })
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := connectorhttp.NewHandler(service)
	if err != nil {
		t.Fatal(err)
	}
	stopIngress := serveCoreNativeHTTP(t, settings.Connectors[0].Socket, ingress)
	defer stopIngress()
	connector, err := connectorhttp.NewClient(settings.Connectors[0].Socket, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	event := connectorwire.InboundEventV1{EventID: "termination-event", ActorRef: "operator", ConversationRef: "private", MessageRef: "termination-message",
		OccurredAtUnixMS: time.Now().UnixMilli(), Content: connectorwire.InboundContentV1{Type: connectorwire.ContentTypeText, Text: "fixed offline termination witness"}}
	receipt, err := connector.Ingest(ctx, event)
	if err != nil || receipt.RunID != config.RunID || receipt.Disposition != connectorwire.InboundAccepted {
		t.Fatal("Core admission:", err)
	}
	if _, claimed, err := engine.DispatchOne(ctx); err != nil || !claimed {
		t.Fatal("Core dispatch:", err)
	}
	awaitCoreNative(t, ctx, func() bool {
		advanced, err := engine.Advance(ctx, config.RunID)
		if err != nil || advanced.Finished {
			t.Fatal("work ended before live witness:", err, advanced)
		}
		return advanced.CoreState == corestore.RunRunning
	}, "Run never reached Running")
	run, err := db.GetRun(ctx, config.RunID)
	if err != nil || run.RuntimeRef == nil || run.TerminalPending {
		t.Fatal("missing live runtime:", err)
	}
	ref := *run.RuntimeRef
	result.ContainerRef, result.Deadline = ref, run.Deadline.UTC().Format(time.RFC3339Nano)
	workspace := filepath.Join(config.Runtime.WorkspaceRoot, config.Runtime.WorkspaceDirectory)
	var pidfds []int
	defer func() {
		for _, fd := range pidfds {
			_ = unix.Close(fd)
		}
	}()
	if config.Case == "native-deadline" {
		awaitCoreNative(t, ctx, func() bool { result.ToolNonce = coreNativeHeldToolNonce(workspace); return result.ToolNonce != "" }, "native tool did not hold a witnessed lock")
		var continuation struct {
			Nonce, UTC string
			Requests   int
		}
		awaitNativeRecoveryRecord(t, ctx, filepath.Join(workspace, "deadline-provider-wait.json"), &continuation)
		if continuation.Nonce != result.ToolNonce || continuation.Requests != 2 || coreNativeHeldToolNonce(workspace) != result.ToolNonce {
			t.Fatal("missing live tool during the fixed synthetic continuation")
		}
	} else {
		var proof struct {
			Nonce                           string
			PID, PPID, PGID, SID, LeaderPID int
		}
		awaitNativeRecoveryRecord(t, ctx, filepath.Join(workspace, "resistant-ready.json"), &proof)
		if !coreNativeNonce(proof.Nonce) || proof.PID != proof.PGID || proof.PID != proof.SID || proof.PID == proof.LeaderPID {
			t.Fatal("invalid detached descendant receipt")
		}
		result.ToolNonce = proof.Nonce
		result.InitPID, result.DescendantPID, pidfds = observeNativeDetachedDescendant(t, ctx, ref, proof.PID, proof.LeaderPID)
		result.DetachedDescendant = true
		if err := nativeCredentialLock(filepath.Join(workspace, "descendant.lock"), true); err != nil {
			t.Fatal("descendant not holding its lock:", err)
		}
	}
	if !time.Now().Before(run.Deadline.Add(-2*time.Second)) || nativeRecoveryContainerState(t, ctx, ref) != "running" || nativeCredentialLock(witness.auth, true) != nil {
		t.Fatal("live witness was too late or lacked runtime/source")
	}
	result.WitnessAt = time.Now().UTC().Format(time.RFC3339Nano)
	witness.record("independent-live-work-and-source-witness")
	requireCoreNativeNoDelivery(t, ctx, connector)
	if config.Case == "resistant-descendant" {
		file, err := os.OpenFile(filepath.Join(workspace, "release-terminal"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		awaitCoreNative(t, ctx, func() bool {
			if coreNativeHeldToolNonce(workspace) != result.ToolNonce {
				t.Fatal("native tool stopped before its real deadline")
			}
			return !time.Now().Before(run.Deadline.Add(-time.Second))
		}, "native work did not reach the frozen deadline boundary")
		witness.record("native-tool-lock-held-within-one-second-of-deadline")
	}
	awaitCoreNative(t, ctx, func() bool { return witness.removalFailures.Load() > 0 }, "outer cleanup did not reach withheld removal")
	result.BeforeRemoval = readNativeRecoverySnapshot(t, ctx, readback, config.RunID)
	before := result.BeforeRemoval
	if !before.Staged || !before.Occupied || !before.WriterLocked || before.OutputVisible || before.RuntimeRef != ref || nativeCredentialLock(witness.auth, true) != nil {
		t.Fatal("failed removal released staged ownership:", before)
	}
	inspection, err := witness.DockerRuntime.Inspect(ctx, ref)
	if err != nil || inspection.State != dockerruntime.StateExited {
		t.Fatal("outer termination not independently observed:", err, inspection)
	}
	result.ExitCode = inspection.ExitCode
	lockName := "probe.lock"
	if config.Case == "resistant-descendant" {
		lockName = "descendant.lock"
		var term struct {
			Nonce, UTC string
			PID        int
		}
		readNativeRecoveryRecord(t, filepath.Join(workspace, "term-observed.json"), &term)
		if term.Nonce != result.ToolNonce || term.PID != 1 || inspection.ExitCode != 137 || observed.stops.Load() != 1 {
			t.Fatal("TERM-resistant outer stop not established", term, inspection)
		}
		termTime, err := time.Parse(time.RFC3339Nano, term.UTC)
		if err != nil || termTime.Before(mustNativeTime(t, result.WitnessAt)) || time.Since(termTime) < 4*time.Second {
			t.Fatal("missing real stop-grace interval:", err)
		}
		result.TERMAt, result.TERMObserved = term.UTC, true
		for _, fd := range pidfds {
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if n, err := unix.Poll(poll, 1000); err != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
				t.Fatal("exact runtime process still alive:", err)
			}
		}
		result.ProcessesExited = true
	} else if time.Now().Before(run.Deadline) {
		t.Fatal("native deadline case ended before frozen deadline")
	}
	if err := nativeCredentialLock(filepath.Join(workspace, lockName), false); err != nil {
		t.Fatal("work lock survived outer termination:", err)
	}
	result.QuiescentAt = time.Now().UTC().Format(time.RFC3339Nano)
	advanced, err := engine.Advance(ctx, config.RunID)
	if err != nil || advanced.Finished || advanced.CoreState != corestore.RunRunning {
		t.Fatal("Core released result before removal:", err, advanced)
	}
	requireCoreNativeNoDelivery(t, ctx, connector)
	result.NoPrematureDelivery = true
	witness.record("runtime-exited-work-lock-free-source-held-core-no-delivery")
	witness.blockRemoval.Store(false)
	c.signalReconcile()
	awaitCoreNative(t, ctx, func() bool {
		advanced, err = engine.Advance(ctx, config.RunID)
		if err != nil {
			t.Fatal(err)
		}
		return advanced.Finished
	}, "Core did not receive post-cleanup terminal")
	run, err = db.GetRun(ctx, config.RunID)
	if err != nil {
		t.Fatal(err)
	}
	result.Final = readNativeRecoverySnapshot(t, ctx, readback, config.RunID)
	if result.Final.Occupied || result.Final.WriterLocked || result.Final.Staged || result.Final.RuntimeRef != "" || c.hasRetainedCredentials() || nativeCredentialLock(witness.auth, false) != nil {
		t.Fatal("terminal retained cleanup authority")
	}
	result.CoreState, result.SandboxState = string(advanced.CoreState), string(run.State)
	wantOutput := "fixed resistant-runner result"
	if config.Case == "native-deadline" {
		wantOutput = "Run failed: deadline exceeded."
		if advanced.CoreState != corestore.RunFailed || run.Failure == nil || run.Failure.Code != executionwire.FailureDeadlineExceeded || run.Output != nil {
			t.Fatal("wrong frozen-deadline result", run.Failure)
		}
	} else if advanced.CoreState != corestore.RunCompleted || run.Output == nil || run.Output.Text != wantOutput {
		t.Fatal("lost original staged completion")
	}
	requireNativeRecoveryAbsent(t, ctx, ref, config.RunID)
	claim, err := connector.Claim(ctx, connectorwire.DeliveryClaimV1{Limit: 2})
	if err != nil || len(claim.Deliveries) != 1 {
		t.Fatal("unique scoped delivery:", err)
	}
	delivery := claim.Deliveries[0]
	if delivery.ConversationRef != event.ConversationRef || delivery.ReplyToRef != event.MessageRef || delivery.Content.Text != wantOutput {
		t.Fatal("wrong delivery scope or result")
	}
	result.Output, result.DeliveryID = delivery.Content.Text, delivery.DeliveryID
	completion := connectorwire.DeliveryCompleteV1{DeliveryID: delivery.DeliveryID, LeaseToken: delivery.LeaseToken, Outcome: connectorwire.DeliveryDelivered, ProviderMessageRef: "fixed-termination-delivery"}
	if err := connector.Complete(ctx, completion); err != nil {
		t.Fatal(err)
	}
	if err := connector.Complete(ctx, completion); err != nil {
		t.Fatal(err)
	}
	requireCoreNativeReplay(t, ctx, connector, event, config.RunID)
	if _, err := engine.Advance(ctx, config.RunID); err != nil {
		t.Fatal(err)
	}
	requireCoreNativeNoDelivery(t, ctx, connector)
	witness.mu.Lock()
	countsOK := witness.creates == 1 && witness.attaches == 1 && witness.removed && witness.released
	witness.mu.Unlock()
	if !countsOK {
		t.Fatal("missing exact cleanup or duplicate execution")
	}
	if data, err := os.ReadFile(witness.auth); err != nil || string(data) != "{}\n" {
		t.Fatal("synthetic source changed")
	}
	t.Logf("case=%s: witnessed work -> outer termination -> retained terminal/occupancy on failed removal -> exact cleanup -> one Core delivery", config.Case)
}

func mustNativeTime(t *testing.T, value string) time.Time {
	t.Helper()
	stamp, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return stamp
}

// Inspect only processes from the exact container's read-only Docker top view.
// PID namespace IDs are checked against procfs before retaining stable pidfds.
func observeNativeDetachedDescendant(t *testing.T, ctx context.Context, ref string, childNS, leaderNS int) (int, int, []int) {
	t.Helper()
	var init int
	if _, err := fmt.Sscan(string(nativeRecoveryDockerRead(t, ctx, "container", "inspect", "--format", "{{.State.Pid}}", ref)), &init); err != nil || init <= 1 {
		t.Fatal("missing exact init PID:", err)
	}
	rows := strings.Split(strings.TrimSpace(string(nativeRecoveryDockerRead(t, ctx, "container", "top", ref, "-eo", "pid,ppid,pgid,sid,stat"))), "\n")
	if len(rows) != 3 {
		t.Fatal("unexpected resistant fixture process inventory")
	}
	child, initSeen := 0, false
	for _, line := range rows[1:] {
		fields := strings.Fields(line)
		if len(fields) != 5 {
			t.Fatal("invalid process record")
		}
		values := make([]int, 4)
		for i := range values {
			value, err := strconv.Atoi(fields[i])
			if err != nil || value < 0 {
				t.Fatal("invalid process identity")
			}
			values[i] = value
		}
		pid, ppid, pgid, sid := values[0], values[1], values[2], values[3]
		if strings.ContainsAny(fields[4], "ZX") {
			t.Fatal("descendant witness is already dead")
		}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			t.Fatal(err)
		}
		nsPID := 0
		for _, entry := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(entry, "NSpid:") {
				fields := strings.Fields(entry)
				nsPID, _ = strconv.Atoi(fields[len(fields)-1])
			}
		}
		if nsPID == leaderNS {
			t.Fatal("original leader remains")
		}
		if pid == init && nsPID == 1 {
			initSeen = true
			continue
		}
		if ppid != init || pid != pgid || pid != sid || nsPID != childNS {
			t.Fatal("child did not escape leader session and reparent to init")
		}
		child = pid
	}
	if !initSeen || child == 0 {
		t.Fatal("missing exact detached descendant")
	}
	var fds []int
	for _, pid := range []int{init, child} {
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			for _, held := range fds {
				_ = unix.Close(held)
			}
			t.Fatal(err)
		}
		fds = append(fds, fd)
	}
	return init, child, fds
}
