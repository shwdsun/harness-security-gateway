package sandboxcontroller

import (
	"context"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

type certainFailureStore struct {
	*predispatchReadStore
	stageFailure, confirmFailure bool
	stale                        []sandboxstore.Run
}

func (s *certainFailureStore) StageTerminal(ctx context.Context, event executionwire.RunEvent, mapping *sandboxstore.SessionMapping) (sandboxstore.Run, error) {
	if s.stageFailure {
		s.stageFailure = false
		return sandboxstore.Run{}, errPredispatchRead
	}
	return s.Store.StageTerminal(ctx, event, mapping)
}

func (s *certainFailureStore) ConfirmRuntimeStopped(ctx context.Context, id string) (sandboxstore.Run, error) {
	if s.confirmFailure {
		s.confirmFailure = false
		return sandboxstore.Run{}, errPredispatchRead
	}
	return s.Store.ConfirmRuntimeStopped(ctx, id)
}

func (s *certainFailureStore) ListUnreconciled(ctx context.Context) ([]sandboxstore.Run, error) {
	if s.stale != nil {
		runs := s.stale
		s.stale = nil
		return runs, nil
	}
	return s.Store.ListUnreconciled(ctx)
}

func TestCertainCreateProofSurvivesPersistenceFailures(t *testing.T) {
	for _, mode := range []string{"read", "clear_retry_exhausted", "clear_response_lost", "stage", "confirm", "reoffer"} {
		t.Run(mode, func(t *testing.T) {
			manifest := controllerManifest("target-certain-fault", "target-certain-fault-r1", "workspace-certain-fault", targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly)
			deps := newTestDependencies(t, manifest)
			req := controllerRequest("run_certain_fault", manifest, "synthetic task")
			ctx := context.Background()
			if _, _, err := registerTestStart(deps, ctx, req, manifest.Revision, manifest.WorkspaceRef, true); err != nil {
				t.Fatal(err)
			}
			store := &certainFailureStore{predispatchReadStore: &predispatchReadStore{Store: deps.store}}
			runtime := newFakeRuntime()
			runtime.createFn = func(context.Context, string, targetmanifest.Definition) (string, error) {
				switch mode {
				case "read":
					store.readsBlocked = true
				case "clear_retry_exhausted":
					store.clearFailures = 4
				case "clear_response_lost", "reoffer":
					store.clearLost = true
				case "stage":
					store.stageFailure = true
				case "confirm":
					store.confirmFailure = true
				}
				// The Runtime method was called, but certifies that no external
				// Create was dispatched. This is not ErrCreateUncertain.
				return "", dockerruntime.ErrInvalidArgument
			}
			c := faultController(deps, store, runtime)
			execCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			c.execute(execCtx, cancel, req)
			run, err := deps.store.GetRun(ctx, req.RunID)
			if err != nil || terminalState(run.State) || !run.WorkspaceLockHeld {
				t.Fatalf("failure released unfinished work: %#v %v", run, err)
			}
			store.readsBlocked = false
			if mode == "reoffer" {
				c.execute(execCtx, cancel, req)
			} else if err := c.reconcile(ctx); err != nil {
				t.Fatalf("certain failure did not recover: %v; calls=%v", err, runtime.callSnapshot())
			}
			run, err = deps.store.GetRun(ctx, req.RunID)
			if err != nil || run.State != executionwire.RunStateFailed || run.Failure == nil || run.Failure.Code != executionwire.FailureInternal ||
				run.RuntimeIntentPending || run.RuntimeRef != nil || run.WorkspaceLockHeld || run.TerminalPending || run.LastEventSeq != 1 {
				t.Fatalf("certain failure changed outcome or kept authority: %#v %v", run, err)
			}
			calls := runtime.callSnapshot()
			if len(calls) != 1 || calls[0] != "create:"+req.RunID {
				t.Fatalf("certain failure reached runtime again: %v", calls)
			}
			if err := c.reconcile(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOnlineReconciliationRefreshesClaimedSnapshot(t *testing.T) {
	manifest := controllerManifest("target-old-snapshot", "target-old-snapshot-r1", "workspace-old-snapshot", targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly)
	deps := newTestDependencies(t, manifest)
	ctx := context.Background()
	req := controllerRequest("run_old_snapshot", manifest, "synthetic task")
	if _, _, err := registerTestStart(deps, ctx, req, manifest.Revision, manifest.WorkspaceRef, true); err != nil {
		t.Fatal(err)
	}
	store := &certainFailureStore{predispatchReadStore: &predispatchReadStore{Store: deps.store}}
	runtime := newFakeRuntime()
	runtime.createFn = func(context.Context, string, targetmanifest.Definition) (string, error) {
		pending, err := deps.store.GetRun(ctx, req.RunID)
		if err != nil || !pending.RuntimeIntentPending {
			t.Fatalf("missing actual pending snapshot: %#v %v", pending, err)
		}
		store.stale = []sandboxstore.Run{pending}
		return "", dockerruntime.ErrInvalidArgument
	}
	c := faultController(deps, store, runtime)
	c.offered = make(map[string]*offeredRun)
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	c.execute(execCtx, cancel, req)
	before, err := deps.store.GetRun(ctx, req.RunID)
	if err != nil || before.State != executionwire.RunStateFailed || before.WorkspaceLockHeld || before.RuntimeIntentPending || before.TerminalPending {
		t.Fatalf("worker did not finish before reconciliation claim: %#v %v", before, err)
	}
	// Model List finishing before the worker, and claim acquiring ownership
	// after the worker. The cached row really existed; no sleep/race is needed.
	c.reconcileOnline()
	after, err := deps.store.GetRun(ctx, req.RunID)
	if err != nil || after.State != before.State || after.LastEventSeq != before.LastEventSeq || after.WorkspaceLockHeld || after.TerminalPending {
		t.Fatalf("stale reconciliation changed published outcome: %#v %v", after, err)
	}
	if calls := runtime.callSnapshot(); len(calls) != 1 || calls[0] != "create:"+req.RunID {
		t.Fatalf("stale snapshot reached runtime after clean completion: %v", calls)
	}
	if len(c.offered) != 0 {
		t.Fatal("reconciliation retained its claim")
	}
}
