package sandboxcontroller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

var errPredispatchRead = errors.New("injected pre-dispatch read failure")

// Synchronous execute/reconcile calls make this a fault schedule, not a race
// against a sub-second wall-clock budget. Real SQLite retains durable state.
type predispatchReadStore struct {
	*sandboxstore.Store
	failAfterBegin bool
	readsBlocked   bool
	beginLost      bool
	clearFailures  int
	clearLost      bool
	mutateRead     func(*sandboxstore.Run)
}

func (s *predispatchReadStore) BeginRuntimeIntent(ctx context.Context, id, boot string) (sandboxstore.Run, bool, error) {
	run, created, err := s.Store.BeginRuntimeIntent(ctx, id, boot)
	if err == nil && created && s.failAfterBegin {
		s.readsBlocked = true
	}
	if err == nil && s.beginLost {
		s.beginLost = false
		return sandboxstore.Run{}, false, errPredispatchRead
	}
	return run, created, err
}
func (s *predispatchReadStore) GetRun(ctx context.Context, id string) (sandboxstore.Run, error) {
	if s.readsBlocked {
		return sandboxstore.Run{}, errPredispatchRead
	}
	run, err := s.Store.GetRun(ctx, id)
	if err == nil && s.mutateRead != nil {
		s.mutateRead(&run)
	}
	return run, err
}
func (s *predispatchReadStore) ClearRuntimeIntent(ctx context.Context, id string) (sandboxstore.Run, error) {
	if s.clearFailures > 0 {
		s.clearFailures--
		return sandboxstore.Run{}, errPredispatchRead
	}
	run, err := s.Store.ClearRuntimeIntent(ctx, id)
	if err == nil && s.clearLost {
		s.clearLost = false
		s.readsBlocked = true
		return sandboxstore.Run{}, errPredispatchRead
	}
	return run, err
}

func faultController(deps testDependencies, store Store, runtime *fakeRuntime) *Controller {
	return &Controller{registry: deps.registry, store: store, runtime: runtime,
		rootCtx: context.Background(), clock: time.Now, bootID: testBootID,
		cleanupTimeout: 5 * time.Second, desired: make(map[string]terminalSpec),
		certainNoRuntime: make(map[string]bool)}
}

func TestPredispatchReadFailureRecoversWithoutRuntimeAuthority(t *testing.T) {
	manifest := controllerManifest("target-pre-read", "target-pre-read-r1", "workspace-pre-read", targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly)
	deps := newTestDependencies(t, manifest)
	req := controllerRequest("run_pre_read", manifest, "synthetic task")
	if _, _, err := registerTestStart(deps, context.Background(), req, manifest.Revision, manifest.WorkspaceRef, true); err != nil {
		t.Fatal(err)
	}
	store := &predispatchReadStore{Store: deps.store, failAfterBegin: true}
	runtime := newFakeRuntime()
	c := faultController(deps, store, runtime)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.execute(ctx, cancel, req)
	run, err := deps.store.GetRun(context.Background(), req.RunID)
	if err != nil || !run.RuntimeIntentPending || !run.WorkspaceLockHeld || terminalState(run.State) {
		t.Fatalf("failed read released authority: %#v, %v", run, err)
	}
	if len(runtime.callSnapshot()) != 0 {
		t.Fatalf("runtime reached before proof recovered: %v", runtime.callSnapshot())
	}
	// Keep the store unavailable through another reconciliation before recovery.
	if err := c.reconcile(context.Background()); err == nil {
		t.Fatal("blocked reads unexpectedly reconciled")
	}
	store.readsBlocked = false
	if err := c.reconcile(context.Background()); err != nil {
		t.Fatalf("healthy proof did not recover: %v; calls=%v", err, runtime.callSnapshot())
	}
	run, err = deps.store.GetRun(context.Background(), req.RunID)
	if err != nil || !terminalState(run.State) || run.RuntimeIntentPending || run.RuntimeRef != nil || run.WorkspaceLockHeld || run.LastEventSeq != 1 {
		t.Fatalf("final state %#v, %v; calls=%v", run, err, runtime.callSnapshot())
	}
	if calls := runtime.callSnapshot(); containsCall(calls, "create:") || containsCall(calls, "lookup:") {
		t.Fatalf("pre-dispatch recovery borrowed runtime authority: %v", calls)
	}
	t.Logf("final=%s pending=%t fence=%t calls=%v", run.State, run.RuntimeIntentPending, run.WorkspaceLockHeld, runtime.callSnapshot())
}

type clearOnceStore struct {
	*sandboxstore.Store
	fail bool
}

func (s *clearOnceStore) ClearRuntimeIntent(ctx context.Context, id string) (sandboxstore.Run, error) {
	if s.fail {
		s.fail = false
		return sandboxstore.Run{}, errors.New("injected clear failure after removal")
	}
	return s.Store.ClearRuntimeIntent(ctx, id)
}

// This is the documented post-dispatch availability boundary, not the
// pre-dispatch bug: a lost removal proof cannot be recreated from absence.
func TestRemovedUncertainIntentRetainsFenceUntilChangedBoot(t *testing.T) {
	manifest := controllerManifest("target-cleared-proof", "target-cleared-proof-r1", "workspace-cleared-proof", targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly)
	deps := newTestDependencies(t, manifest)
	req := controllerRequest("run_cleared_proof", manifest, "synthetic task")
	ctx := context.Background()
	if _, _, err := registerTestStart(deps, ctx, req, manifest.Revision, manifest.WorkspaceRef, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := deps.store.BeginRuntimeIntent(ctx, req.RunID, testBootID); err != nil {
		t.Fatal(err)
	}
	runtime := newFakeRuntime()
	runtime.createFn = func(_ context.Context, id string, _ targetmanifest.Definition) (string, error) {
		runtime.installIntent(id, dockerruntime.StateCreated)
		return "", dockerruntime.ErrCreateUncertain
	}
	def, err := targetmanifest.FromV1(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Create(ctx, req.RunID, def); !errors.Is(err, dockerruntime.ErrCreateUncertain) {
		t.Fatal(err)
	}
	store := &clearOnceStore{Store: deps.store, fail: true}
	c := faultController(deps, store, runtime)
	if err := c.reconcile(ctx); err == nil {
		t.Fatal("injected clear failure was ignored")
	}
	if err := c.reconcile(ctx); !errors.Is(err, ErrRuntimeIntentUnresolved) {
		t.Fatalf("same-boot absence discharged intent: %v", err)
	}
	run, err := deps.store.GetRun(ctx, req.RunID)
	if err != nil || !run.RuntimeIntentPending || !run.TerminalPending || !run.WorkspaceLockHeld || terminalState(run.State) {
		t.Fatalf("unsafe state %#v, %v", run, err)
	}
	t.Logf("same boot: pending=%t fence=%t calls=%v", run.RuntimeIntentPending, run.WorkspaceLockHeld, runtime.callSnapshot())
	c.bootID = otherBootID // Simulated epoch assumption; no host reboot.
	if err := c.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	run, err = deps.store.GetRun(ctx, req.RunID)
	if err != nil || run.State != executionwire.RunStateInterrupted || run.RuntimeIntentPending || run.WorkspaceLockHeld || run.LastEventSeq != 1 {
		t.Fatalf("changed-boot recovery %#v, %v", run, err)
	}
	creates := 0
	for _, call := range runtime.callSnapshot() {
		if call == "create:"+req.RunID {
			creates++
		}
	}
	if creates != 1 {
		t.Fatalf("speculative Create count=%d", creates)
	}
}

func TestPredispatchFailureSchedules(t *testing.T) {
	for _, mode := range []string{"begin_response_lost", "clear_retry_exhausted", "clear_response_lost", "cancel_after_read_failure"} {
		t.Run(mode, func(t *testing.T) {
			manifest := controllerManifest("target-pre-schedule", "target-pre-schedule-r1", "workspace-pre-schedule", targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly)
			deps := newTestDependencies(t, manifest)
			req := controllerRequest("run_pre_schedule", manifest, "synthetic task")
			ctx := context.Background()
			if _, _, err := registerTestStart(deps, ctx, req, manifest.Revision, manifest.WorkspaceRef, true); err != nil {
				t.Fatal(err)
			}
			store := &predispatchReadStore{Store: deps.store, failAfterBegin: true, beginLost: mode == "begin_response_lost"}
			runtime := newFakeRuntime()
			c := faultController(deps, store, runtime)
			execCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			c.execute(execCtx, cancel, req)
			store.readsBlocked = false
			switch mode {
			case "clear_retry_exhausted":
				store.clearFailures = 4
			case "clear_response_lost":
				store.clearLost = true
			case "cancel_after_read_failure":
				if _, err := deps.store.MarkCancelling(ctx, req.RunID); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "clear_retry_exhausted" || mode == "clear_response_lost" {
				if err := c.reconcile(ctx); err == nil {
					t.Fatal("injected clear failure ignored")
				}
				run, err := deps.store.GetRun(ctx, req.RunID)
				if err != nil || !run.WorkspaceLockHeld || terminalState(run.State) {
					t.Fatalf("failure exposed terminal: %#v %v", run, err)
				}
				store.readsBlocked = false
			}
			if err := c.reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			run, err := deps.store.GetRun(ctx, req.RunID)
			if err != nil || !terminalState(run.State) || run.RuntimeIntentPending || run.WorkspaceLockHeld || run.LastEventSeq != 1 {
				t.Fatalf("failed recovery %#v %v", run, err)
			}
			if mode == "cancel_after_read_failure" && run.State != executionwire.RunStateCancelled {
				t.Fatalf("lost cancellation: %#v", run)
			}
			if calls := runtime.callSnapshot(); containsCall(calls, "create:") || containsCall(calls, "lookup:") {
				t.Fatalf("runtime reached: %v", calls)
			}
			if err := c.reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			again, err := deps.store.GetRun(ctx, req.RunID)
			if err != nil || again.LastEventSeq != 1 {
				t.Fatal("duplicate publication")
			}
		})
	}
}

func TestPredispatchProofRejectsConflictsAndDoesNotSurviveRestart(t *testing.T) {
	for _, mode := range []string{"identity", "bound_ref", "other_boot", "legacy_boot", "restart"} {
		t.Run(mode, func(t *testing.T) {
			manifest := controllerManifest("target-pre-guard", "target-pre-guard-r1", "workspace-pre-guard", targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly)
			deps := newTestDependencies(t, manifest)
			ctx := context.Background()
			req := controllerRequest("run_pre_guard", manifest, "synthetic task")
			if _, _, err := registerTestStart(deps, ctx, req, manifest.Revision, manifest.WorkspaceRef, true); err != nil {
				t.Fatal(err)
			}
			store := &predispatchReadStore{Store: deps.store, failAfterBegin: true}
			runtime := newFakeRuntime()
			c := faultController(deps, store, runtime)
			execCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			c.execute(execCtx, cancel, req)
			store.readsBlocked = false
			store.mutateRead = func(run *sandboxstore.Run) {
				switch mode {
				case "identity":
					run.Fingerprint = "conflicting-identity"
				case "bound_ref":
					ref := fakeContainerRef(req.RunID)
					run.RuntimeRef = &ref
				case "other_boot":
					boot := otherBootID
					run.RuntimeIntentBootID = &boot
				case "legacy_boot":
					run.RuntimeIntentBootID = nil
				}
			}
			if mode == "restart" {
				c = faultController(deps, store, runtime)
			}
			if err := c.reconcile(ctx); err == nil {
				t.Fatal("invalid/missing proof released authority")
			}
			run, err := deps.store.GetRun(ctx, req.RunID)
			if err != nil || !run.RuntimeIntentPending || !run.WorkspaceLockHeld || terminalState(run.State) {
				t.Fatalf("proof bypass %#v %v", run, err)
			}
			calls := runtime.callSnapshot()
			if containsCall(calls, "create:") || (mode != "restart" && containsCall(calls, "lookup:")) {
				t.Fatalf("invalid proof reached runtime: %v", calls)
			}
		})
	}
}

func TestPredispatchReofferCannotDispatchAfterLostClear(t *testing.T) {
	manifest := controllerManifest("target-pre-reoffer", "target-pre-reoffer-r1", "workspace-pre-reoffer", targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly)
	deps := newTestDependencies(t, manifest)
	ctx := context.Background()
	req := controllerRequest("run_pre_reoffer", manifest, "synthetic task")
	if _, _, err := registerTestStart(deps, ctx, req, manifest.Revision, manifest.WorkspaceRef, true); err != nil {
		t.Fatal(err)
	}
	store := &predispatchReadStore{Store: deps.store, failAfterBegin: true}
	runtime := newFakeRuntime()
	c := faultController(deps, store, runtime)
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	c.execute(execCtx, cancel, req)
	store.readsBlocked = false
	store.clearLost = true
	if err := c.reconcile(ctx); err == nil {
		t.Fatal("lost clear response ignored")
	}
	run, err := deps.store.GetRun(ctx, req.RunID)
	if err != nil || run.State != executionwire.RunStateAccepted || run.RuntimeIntentPending || !run.WorkspaceLockHeld {
		t.Fatalf("wrong reoffer window: %#v %v", run, err)
	}
	store.readsBlocked = false
	store.failAfterBegin = false
	// The same accepted fingerprint can reach the worker again. Existing terminal
	// intent must win even though the database no longer has a Create intent.
	c.execute(execCtx, cancel, req)
	run, err = deps.store.GetRun(ctx, req.RunID)
	if err != nil || run.State != executionwire.RunStateInterrupted || run.WorkspaceLockHeld || run.RuntimeIntentPending || run.LastEventSeq != 1 {
		t.Fatalf("reoffer did not finish old decision: %#v %v", run, err)
	}
	if calls := runtime.callSnapshot(); containsCall(calls, "create:") || containsCall(calls, "lookup:") {
		t.Fatalf("stale proof crossed new dispatch: %v", calls)
	}
}
