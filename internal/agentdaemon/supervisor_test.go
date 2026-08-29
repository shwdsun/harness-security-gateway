package agentdaemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentdispatch"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
)

type fakeEngine struct {
	mu sync.Mutex

	dispatch  func(context.Context) (agentdispatch.Result, bool, error)
	advance   func(context.Context, string) (agentdispatch.Result, error)
	reconcile func(context.Context, int) ([]agentdispatch.ReconcileItem, error)

	dispatchCalls  int
	advanceCalls   []string
	reconcileCalls int
}

func (e *fakeEngine) DispatchOne(ctx context.Context) (agentdispatch.Result, bool, error) {
	e.mu.Lock()
	e.dispatchCalls++
	fn := e.dispatch
	e.mu.Unlock()
	if fn == nil {
		return agentdispatch.Result{}, false, nil
	}
	return fn(ctx)
}

func (e *fakeEngine) Advance(ctx context.Context, runID string) (agentdispatch.Result, error) {
	e.mu.Lock()
	e.advanceCalls = append(e.advanceCalls, runID)
	fn := e.advance
	e.mu.Unlock()
	if fn == nil {
		return agentdispatch.Result{RunID: runID, CoreState: corestore.RunDispatching}, nil
	}
	return fn(ctx, runID)
}

func (e *fakeEngine) Reconcile(ctx context.Context, limit int) ([]agentdispatch.ReconcileItem, error) {
	e.mu.Lock()
	e.reconcileCalls++
	fn := e.reconcile
	e.mu.Unlock()
	if fn == nil {
		return nil, nil
	}
	return fn(ctx, limit)
}

func TestRunAdvancesAcceptedDispatchBeforeClaimingAnother(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := &fakeEngine{}
	engine.dispatch = func(context.Context) (agentdispatch.Result, bool, error) {
		return agentdispatch.Result{RunID: "run_active", CoreState: corestore.RunDispatching, SandboxState: executionwire.RunStateAccepted}, true, nil
	}
	engine.advance = func(context.Context, string) (agentdispatch.Result, error) {
		cancel()
		return agentdispatch.Result{RunID: "run_active", CoreState: corestore.RunRunning, SandboxState: executionwire.RunStateRunning}, nil
	}

	if err := Run(ctx, engine, time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.dispatchCalls != 1 {
		t.Fatalf("DispatchOne calls = %d, want 1", engine.dispatchCalls)
	}
	if len(engine.advanceCalls) != 1 || engine.advanceCalls[0] != "run_active" {
		t.Fatalf("Advance calls = %#v", engine.advanceCalls)
	}
}

func TestRunReconcilesDurableRunningBeforeNewDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := &fakeEngine{}
	engine.reconcile = func(context.Context, int) ([]agentdispatch.ReconcileItem, error) {
		cancel()
		return []agentdispatch.ReconcileItem{{Result: agentdispatch.Result{
			RunID: "run_existing", CoreState: corestore.RunRunning,
			SandboxState: executionwire.RunStateRunning,
		}}}, nil
	}
	if err := Run(ctx, engine, time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.dispatchCalls != 0 {
		t.Fatalf("DispatchOne ran %d times while a durable Run existed", engine.dispatchCalls)
	}
}

func TestRunFailsClosedWhenRunningListIsUnavailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := &fakeEngine{}
	reconcileCall := 0
	engine.reconcile = func(context.Context, int) ([]agentdispatch.ReconcileItem, error) {
		reconcileCall++
		if reconcileCall == 1 {
			return nil, &agentdispatch.Error{Code: agentdispatch.ErrorStoreUnavailable, Cause: errors.New("private database detail")}
		}
		cancel()
		return []agentdispatch.ReconcileItem{{Result: agentdispatch.Result{
			RunID: "run_unknown", CoreState: corestore.RunRunning,
		}}}, nil
	}
	var reports []agentdispatch.ErrorCode
	if err := Run(ctx, engine, time.Millisecond, func(code agentdispatch.ErrorCode) {
		reports = append(reports, code)
	}); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.dispatchCalls != 0 {
		t.Fatalf("DispatchOne ran %d times while running state was unknown", engine.dispatchCalls)
	}
	if len(reports) != 1 || reports[0] != agentdispatch.ErrorStoreUnavailable {
		t.Fatalf("reports = %#v", reports)
	}
}

func TestRunForgetsLostLeaseAndReportsOnlyClosedCode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	private := errors.New("SECRET prompt /private/socket")
	engine := &fakeEngine{}
	dispatchNumber := 0
	engine.dispatch = func(context.Context) (agentdispatch.Result, bool, error) {
		dispatchNumber++
		if dispatchNumber == 1 {
			return agentdispatch.Result{RunID: "run_old", CoreState: corestore.RunDispatching}, true, nil
		}
		cancel()
		return agentdispatch.Result{}, false, nil
	}
	engine.advance = func(context.Context, string) (agentdispatch.Result, error) {
		return agentdispatch.Result{RunID: "run_old", CoreState: corestore.RunDispatching}, &agentdispatch.Error{
			Code: agentdispatch.ErrorDispatchLost, Cause: private,
		}
	}
	var reports []agentdispatch.ErrorCode
	if err := Run(ctx, engine, time.Millisecond, func(code agentdispatch.ErrorCode) {
		reports = append(reports, code)
	}); err != nil {
		t.Fatal(err)
	}
	if dispatchNumber != 2 {
		t.Fatalf("dispatch attempts = %d, want 2", dispatchNumber)
	}
	if len(reports) != 1 || reports[0] != agentdispatch.ErrorDispatchLost {
		t.Fatalf("closed reports = %#v", reports)
	}
}

func TestRunValidatesInputsAndStopsCleanly(t *testing.T) {
	if err := Run(nil, &fakeEngine{}, time.Millisecond, nil); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := Run(context.Background(), nil, time.Millisecond, nil); err == nil {
		t.Fatal("nil engine accepted")
	}
	if err := Run(context.Background(), &fakeEngine{}, 0, nil); err == nil {
		t.Fatal("zero interval accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, &fakeEngine{}, time.Millisecond, nil); err != nil {
		t.Fatalf("cancelled Run error = %v", err)
	}
}

func TestInnerRequestDeadlineDoesNotStopDaemon(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := &fakeEngine{}
	engine.dispatch = func(context.Context) (agentdispatch.Result, bool, error) {
		engine.mu.Lock()
		calls := engine.dispatchCalls
		engine.mu.Unlock()
		if calls >= 2 {
			cancel()
		}
		return agentdispatch.Result{}, false, &agentdispatch.Error{
			Code: agentdispatch.ErrorContextDone, Cause: context.DeadlineExceeded,
		}
	}
	if err := Run(ctx, engine, time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.dispatchCalls < 2 {
		t.Fatalf("daemon stopped after %d inner timeout(s)", engine.dispatchCalls)
	}
}
