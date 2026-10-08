//go:build formalpilot

package sandboxcontroller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// The baseline checks observable safety, independently of the symbolic model.
// One known-boot, unbound Create has already returned an uncertain result.
// A synthetic handler may complete later; recovery and SQLite are real code.
var recoveryPilotActions = []string{
	"reconcile", "late", "restart", "reboot", "remove_fail", "clear_fail",
	"publish_fail", "lookup_late", "clear_lost", "publish_lost", "stage_fail", "stage_lost",
	"remove_lost",
}

type recoveryPilotState struct {
	Pending bool `json:"pending"`
	Fence   bool `json:"fence"`
	Done    bool `json:"done"`
	Staged  bool `json:"staged"`
	Handler bool `json:"handler"`
	Object  bool `json:"object"`
	Same    bool `json:"same"`
}

type recoveryPilotTrace struct {
	Name    string               `json:"name"`
	Actions []string             `json:"actions"`
	States  []recoveryPilotState `json:"states"`
}

var errRecoveryPilot = errors.New("injected recovery pilot failure")

type recoveryPilotStore struct {
	*sandboxstore.Store
	fault string
}

func (s *recoveryPilotStore) StageTerminal(ctx context.Context, event executionwire.RunEvent, mapping *sandboxstore.SessionMapping) (sandboxstore.Run, error) {
	if s.fault == "stage_fail" {
		return sandboxstore.Run{}, errRecoveryPilot
	}
	run, err := s.Store.StageTerminal(ctx, event, mapping)
	if err == nil && s.fault == "stage_lost" {
		return sandboxstore.Run{}, errRecoveryPilot
	}
	return run, err
}

func (s *recoveryPilotStore) ClearRuntimeIntent(ctx context.Context, id string) (sandboxstore.Run, error) {
	if s.fault == "clear_fail" {
		return sandboxstore.Run{}, errRecoveryPilot
	}
	run, err := s.Store.ClearRuntimeIntent(ctx, id)
	if err == nil && s.fault == "clear_lost" {
		return sandboxstore.Run{}, errRecoveryPilot
	}
	return run, err
}

func (s *recoveryPilotStore) ConfirmRuntimeStopped(ctx context.Context, id string) (sandboxstore.Run, error) {
	if s.fault == "publish_fail" {
		return sandboxstore.Run{}, errRecoveryPilot
	}
	run, err := s.Store.ConfirmRuntimeStopped(ctx, id)
	if err == nil && s.fault == "publish_lost" {
		return sandboxstore.Run{}, errRecoveryPilot
	}
	return run, err
}

type recoveryPilot struct {
	store   *recoveryPilotStore
	control *Controller
	runtime *fakeRuntime
	dbPath  string
	id      string
	handler bool
}

func newRecoveryPilot(t *testing.T) *recoveryPilot {
	t.Helper()
	manifest := controllerManifest("target-pilot", "target-pilot-r1", "workspace-pilot",
		targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly)
	deps := newTestDependencies(t, manifest)
	request := controllerRequest("run_pilot", manifest, "synthetic input")
	request.Deadline = time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	if _, _, err := registerTestStart(deps, context.Background(), request, manifest.Revision, manifest.WorkspaceRef, true); err != nil {
		t.Fatal(err)
	}
	if _, created, err := deps.store.BeginRuntimeIntent(context.Background(), request.RunID, testBootID); err != nil || !created {
		t.Fatalf("prepare committed intent: created=%t err=%v", created, err)
	}
	p := &recoveryPilot{store: &recoveryPilotStore{Store: deps.store}, runtime: newFakeRuntime(), dbPath: deps.dbPath, id: request.RunID}
	p.control = &Controller{registry: deps.registry, store: p.store, runtime: p.runtime,
		bootID: testBootID, clock: time.Now, cleanupTimeout: time.Second}
	// This call establishes the external precondition. The experiment starts
	// after dispatch, and does not claim to verify the initial dispatch path.
	p.runtime.createFn = func(context.Context, string, targetmanifest.Definition) (string, error) {
		p.handler = true
		return "", dockerruntime.ErrCreateUncertain
	}
	definition, err := targetmanifest.FromV1(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.runtime.Create(context.Background(), request.RunID, definition); !errors.Is(err, dockerruntime.ErrCreateUncertain) {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.store.Close() })
	return p
}

func (p *recoveryPilot) late() {
	if p.handler {
		p.handler = false
		p.runtime.installIntent(p.id, dockerruntime.StateCreated)
	}
}

func (p *recoveryPilot) step(t *testing.T, action string) {
	t.Helper()
	p.store.fault = action
	p.runtime.removeErr = nil
	p.runtime.removeResponseLost = action == "remove_lost"
	p.runtime.lookupFn = nil
	switch action {
	case "late":
		p.late()
		return
	case "reboot":
		// Simulated host assumption; objects persist, old handlers do not.
		p.handler = false
		p.control.bootID = otherBootID
		return
	case "restart":
		// A clean DB close/reopen at a call boundary, not SIGKILL/power-loss.
		if err := p.store.Close(); err != nil {
			t.Fatal(err)
		}
		store, err := sandboxstore.Open(context.Background(), p.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		p.store.Store = store
		return
	case "remove_fail":
		p.runtime.removeErr = errRecoveryPilot
	case "lookup_late":
		p.runtime.lookupFn = func(context.Context, string, targetmanifest.Definition) (string, bool, error) {
			p.runtime.mu.Lock()
			ref := p.runtime.intents[p.id]
			p.runtime.mu.Unlock()
			// Return the observation made before the delayed handler finished.
			if ref == "" {
				p.late()
			}
			return ref, ref != "", nil
		}
	case "reconcile", "clear_fail", "publish_fail", "clear_lost", "publish_lost", "stage_fail", "stage_lost", "remove_lost":
	default:
		t.Fatalf("unknown pilot action %q", action)
	}
	run, err := p.store.GetRun(context.Background(), p.id)
	if err != nil {
		t.Fatal(err)
	}
	err = p.control.reconcileRun(context.Background(), run)
	if err != nil && !errors.Is(err, ErrRuntimeIntentUnresolved) && !errors.Is(err, errRecoveryPilot) {
		t.Fatalf("unexpected reconciliation error: %v", err)
	}
}

func (p *recoveryPilot) observe(t *testing.T) recoveryPilotState {
	t.Helper()
	run, err := p.store.GetRun(context.Background(), p.id)
	if err != nil {
		t.Fatal(err)
	}
	p.runtime.mu.Lock()
	object := len(p.runtime.states) != 0
	p.runtime.mu.Unlock()
	s := recoveryPilotState{run.RuntimeIntentPending, run.WorkspaceLockHeld, terminalState(run.State),
		run.TerminalPending, p.handler, object, p.control.bootID == testBootID}
	if ((s.Handler || s.Object) && (!s.Fence || s.Done)) ||
		(!s.Pending && (s.Handler || s.Object)) || s.Done == s.Fence {
		t.Fatalf("recovery safety violated: %+v", s)
	}
	if count := runtimeCreateCount(p.runtime, p.id); count != 1 {
		t.Fatalf("recovery dispatched Create: calls=%d", count)
	}
	if s.Done && run.LastEventSeq != 1 {
		t.Fatalf("completion publication count: sequence=%d", run.LastEventSeq)
	}
	return s
}

func replayRecoveryPilot(t *testing.T, actions []string, states []recoveryPilotState) {
	t.Helper()
	p := newRecoveryPilot(t)
	if states != nil && len(states) != len(actions)+1 {
		t.Fatal("model trace must include the initial state and every resulting state")
	}
	check := func(index int) {
		t.Helper()
		got := p.observe(t)
		if states != nil && got != states[index] {
			t.Fatalf("model/implementation mismatch after %v: got %+v want %+v", actions[:index], got, states[index])
		}
	}
	check(0)
	for i, action := range actions {
		p.step(t, action)
		check(i + 1)
	}
	// An independent progress oracle under explicit healthy-runtime/DB
	// assumptions prevents a permanently stuck implementation from passing.
	for _, action := range []string{"reboot", "reconcile", "restart"} {
		p.step(t, action)
		p.observe(t)
	}
	if !p.observe(t).Done {
		t.Fatal("healthy recovery after a changed boot failed to publish")
	}
}

func TestRecoveryPilotProperties(t *testing.T) {
	for seed := uint64(0); seed < 64; seed++ {
		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, 20260908))
			actions := make([]string, 16)
			for i := range actions {
				actions[i] = recoveryPilotActions[rng.IntN(len(recoveryPilotActions))]
			}
			t.Logf("actions=%v", actions)
			replayRecoveryPilot(t, actions, nil)
		})
	}
}

func TestRecoveryPilotModelTraces(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "formal", "recovery", "traces.json"))
	if err != nil {
		t.Fatal(err)
	}
	var traces []recoveryPilotTrace
	if err := json.Unmarshal(data, &traces); err != nil || len(traces) == 0 {
		t.Fatalf("load model traces: count=%d err=%v", len(traces), err)
	}
	for _, trace := range traces {
		t.Run(trace.Name, func(t *testing.T) { replayRecoveryPilot(t, trace.Actions, trace.States) })
	}
}
