package sandboxcontroller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/runnerbridge"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func TestStartupReconciliationStateMatrixAndIntentLookup(t *testing.T) {
	tests := []struct {
		name         string
		initial      executionwire.RunState
		withRef      bool
		withIntent   bool
		pending      bool
		expired      bool
		writable     bool
		wantState    executionwire.RunState
		wantRetained bool
		wantLookup   bool
	}{
		{"terminal with ref", executionwire.RunStateFailed, true, true, true, false, true, executionwire.RunStateFailed, false, false},
		{"accepted with ref", executionwire.RunStateAccepted, true, true, true, false, false, executionwire.RunStateInterrupted, false, false},
		{"running with ref", executionwire.RunStateRunning, true, true, true, false, false, executionwire.RunStateInterrupted, false, false},
		{"cancelling with ref", executionwire.RunStateCancelling, true, true, true, false, true, executionwire.RunStateCancelled, false, false},
		{"running pending no ref", executionwire.RunStateRunning, false, true, true, false, false, executionwire.RunStateInterrupted, false, true},
		{"legacy running no ref", executionwire.RunStateRunning, false, true, false, false, false, executionwire.RunStateInterrupted, false, true},
		{"cancelling pending no ref", executionwire.RunStateCancelling, false, true, true, false, true, executionwire.RunStateInterrupted, false, true},
		{"expired accepted pending no ref", executionwire.RunStateAccepted, false, true, true, true, true, executionwire.RunStateInterrupted, false, true},
		{"unexpired accepted no intent awaits reoffer", executionwire.RunStateAccepted, false, false, false, false, false, executionwire.RunStateAccepted, true, false},
		{"unexpired accepted pending is interrupted", executionwire.RunStateAccepted, false, true, true, false, false, executionwire.RunStateInterrupted, false, true},
		{"interrupted writer pending no ref", executionwire.RunStateInterrupted, false, true, true, false, true, executionwire.RunStateInterrupted, false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mode := targetmanifest.WorkspaceReadOnly
			if test.writable {
				mode = targetmanifest.WorkspaceReadWrite
			}
			manifest := controllerManifest(
				"target-startup", "target-startup-r1", "workspace-startup", mode, targetmanifest.SessionNewOnly,
			)
			dependencies := newTestDependencies(t, manifest)
			request := controllerRequest("run_startup", manifest, "not persisted")
			if test.expired {
				request.Deadline = time.Now().UTC().Add(-time.Second)
			}
			run, _, err := registerTestStart(dependencies,
				context.Background(), request, manifest.Revision, manifest.WorkspaceRef,
				manifest.WorkspaceMode == targetmanifest.WorkspaceReadWrite,
			)
			if err != nil {
				t.Fatal(err)
			}

			runtime := newFakeRuntime()
			var ref string
			if test.withIntent {
				ref = runtime.installIntent(request.RunID, dockerruntimeStateForStartup(test.initial))
			}
			if test.pending {
				if _, _, err := dependencies.store.BeginRuntimeIntent(context.Background(), request.RunID, testBootID); err != nil {
					t.Fatalf("BeginRuntimeIntent() error = %v", err)
				}
			}
			if test.withRef {
				if ref == "" {
					ref = runtime.installIntent(request.RunID, dockerruntimeStateForStartup(test.initial))
				}
				if _, err := dependencies.store.SetRuntimeRef(context.Background(), request.RunID, ref); err != nil {
					t.Fatal(err)
				}
			}
			switch test.initial {
			case executionwire.RunStateRunning:
				_, err = dependencies.store.AppendEvent(context.Background(), startedEmission(request.RunID).Event, nil)
			case executionwire.RunStateCancelling:
				run, err = dependencies.store.MarkCancelling(context.Background(), request.RunID)
			case executionwire.RunStateFailed:
				_, err = dependencies.store.AppendEvent(context.Background(), executionwire.RunEvent{
					RunID: request.RunID,
					Seq:   1,
					Type:  executionwire.RunEventFailed,
					Failure: &executionwire.RunFailure{
						Code: executionwire.FailureInternal, Message: "stored terminal",
					},
				}, nil)
			case executionwire.RunStateInterrupted:
				_, err = dependencies.store.AppendEvent(context.Background(), executionwire.RunEvent{
					RunID: request.RunID,
					Seq:   1,
					Type:  executionwire.RunEventInterrupted,
					Failure: &executionwire.RunFailure{
						Code: executionwire.FailureRuntimeInterrupted, Message: messageInterrupted,
					},
				}, nil)
			}
			if err != nil {
				t.Fatalf("prepare state %s: %v", test.initial, err)
			}
			_ = run

			controller, err := New(
				context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
				WithCleanupTimeout(500*time.Millisecond),
				WithReconcileInterval(10*time.Millisecond),
				WithBootIDSource(fixedBootID(testBootID)),
			)
			if err != nil {
				t.Fatalf("New() reconciliation error = %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			defer func() {
				if err := controller.Close(ctx); err != nil {
					t.Errorf("Close() error = %v", err)
				}
			}()

			got, err := dependencies.store.GetRun(context.Background(), request.RunID)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != test.wantState {
				t.Fatalf("state = %s, want %s; run=%#v", got.State, test.wantState, got)
			}
			if test.wantRetained {
				if got.RuntimeRef != nil || (test.writable && !got.WorkspaceLockHeld) {
					t.Fatalf("accepted reoffer authority = %#v", got)
				}
			} else if got.RuntimeRef != nil || got.WorkspaceLockHeld {
				t.Fatalf("reconciled authority retained = %#v", got)
			}
			calls := runtime.callSnapshot()
			if containsCall(calls, "lookup:"+request.RunID) != test.wantLookup {
				t.Fatalf("intent lookup calls = %v, wantLookup=%v", calls, test.wantLookup)
			}
			if containsCall(calls, "create:"+request.RunID) {
				t.Fatalf("startup reconciliation dispatched Create: %v", calls)
			}
			if test.wantLookup && callIndex(calls, "lookup:"+request.RunID) > callIndex(calls, "list-managed") {
				t.Fatalf("managed sweep ran before DB intent reconciliation: %v", calls)
			}
			if test.withRef {
				removeIndex, listIndex := callIndex(calls, "remove:"+ref), callIndex(calls, "list-managed")
				if removeIndex < 0 || listIndex < 0 || removeIndex > listIndex {
					t.Fatalf("managed sweep ran before durable ref reconciliation: %v", calls)
				}
			}
		})
	}
}

func TestStartupManagedSweepCleansContainerMissingFromDatabase(t *testing.T) {
	manifest := controllerManifest(
		"target-managed-sweep", "target-managed-sweep-r1", "workspace-managed-sweep",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	ref := runtime.installIntent("run_missing_database_row", dockerruntime.StateRunning)
	controller, err := New(
		context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
		WithCleanupTimeout(500*time.Millisecond), WithReconcileInterval(10*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	defer func() {
		if err := controller.Close(ctx); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()
	if _, err := runtime.Inspect(context.Background(), ref); !errors.Is(err, dockerruntime.ErrNotFound) {
		t.Fatalf("managed orphan remained after startup sweep: %v", err)
	}
	calls := runtime.callSnapshot()
	if len(calls) == 0 || calls[0] != "list-managed" || !containsCall(calls, "remove:"+ref) {
		t.Fatalf("managed sweep calls = %v", calls)
	}
}

func TestStartupManagedEnumerationFailureIsFailClosed(t *testing.T) {
	manifest := controllerManifest(
		"target-managed-fail", "target-managed-fail-r1", "workspace-managed-fail",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	runtime.managedFn = func(context.Context) ([]string, error) {
		return nil, dockerruntime.ErrForeignContainer
	}
	if _, err := New(
		context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
	); !errors.Is(err, dockerruntime.ErrForeignContainer) {
		t.Fatalf("New() enumeration error = %v", err)
	}

	runtime = newFakeRuntime()
	ref := runtime.installIntent("run_managed_cleanup_failure", dockerruntime.StateCreated)
	runtime.removeErr = errors.New("private remove failure")
	if _, err := New(
		context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
		WithCleanupTimeout(100*time.Millisecond),
	); !errors.Is(err, ErrCleanup) {
		t.Fatalf("New() managed cleanup error = %v", err)
	}
	if _, err := runtime.Inspect(context.Background(), ref); err != nil {
		t.Fatalf("failed managed cleanup lost runtime authority: %v", err)
	}
}

func TestNewValidatesBootIDBeforeRuntimeReconciliation(t *testing.T) {
	manifest := controllerManifest(
		"target-boot-source", "target-boot-source-r1", "workspace-boot-source",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	for _, test := range []struct {
		name   string
		source BootIDSource
	}{
		{
			name:   "unavailable",
			source: func() (string, error) { return "", errors.New("private procfs diagnostic") },
		},
		{name: "noncanonical", source: fixedBootID("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := newFakeRuntime()
			_, err := New(
				context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
				WithBootIDSource(test.source),
			)
			if err == nil || strings.Contains(err.Error(), "private procfs diagnostic") {
				t.Fatalf("New() boot source error = %v", err)
			}
			if calls := runtime.callSnapshot(); len(calls) != 0 {
				t.Fatalf("invalid boot ID reached runtime reconciliation: %v", calls)
			}
		})
	}
}

func TestLegacyNoPendingOrphanCleansAndFinalizesInOnePass(t *testing.T) {
	manifest := controllerManifest(
		"target-legacy-orphan", "target-legacy-orphan-r1", "workspace-legacy-orphan",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	request := controllerRequest("run_legacy_orphan", manifest, "legacy")
	run, _, err := registerTestStart(dependencies,
		context.Background(), request, manifest.Revision, manifest.WorkspaceRef, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	run, err = dependencies.store.AppendEvent(context.Background(), startedEmission(request.RunID).Event, nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime := newFakeRuntime()
	runtime.installIntent(request.RunID, dockerruntime.StateRunning)
	controller := &Controller{
		registry:       dependencies.registry,
		store:          dependencies.store,
		runtime:        runtime,
		clock:          func() time.Time { return time.Now().UTC() },
		cleanupTimeout: 500 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := controller.reconcileRun(ctx, run); err != nil {
		t.Fatalf("reconcileRun() error = %v", err)
	}
	stored, err := dependencies.store.GetRun(context.Background(), request.RunID)
	if err != nil || stored.State != executionwire.RunStateInterrupted || stored.RuntimeRef != nil {
		t.Fatalf("legacy reconciliation = %#v, %v", stored, err)
	}
	calls := runtime.callSnapshot()
	if !containsCall(calls, "lookup:"+request.RunID) || containsCall(calls, "create:"+request.RunID) {
		t.Fatalf("legacy reconciliation authority calls = %v", calls)
	}
}

func TestLegacyPendingWithoutBootNeverClearsAutomatically(t *testing.T) {
	for _, found := range []bool{false, true} {
		name := "absent"
		if found {
			name = "found"
		}
		t.Run(name, func(t *testing.T) {
			manifest := controllerManifest(
				"target-legacy-pending-"+name, "target-legacy-pending-r1", "workspace-legacy-pending-"+name,
				targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
			)
			dependencies := newTestDependencies(t, manifest)
			request := controllerRequest("run_legacy_pending_"+name, manifest, "legacy pending")
			if _, _, err := registerTestStart(dependencies,
				context.Background(), request, manifest.Revision, manifest.WorkspaceRef, true,
			); err != nil {
				t.Fatal(err)
			}
			if _, _, err := dependencies.store.BeginRuntimeIntent(
				context.Background(), request.RunID, testBootID,
			); err != nil {
				t.Fatal(err)
			}
			store := &legacyIntentStore{Store: dependencies.store}
			runtime := newFakeRuntime()
			var ref string
			if found {
				ref = runtime.installIntent(request.RunID, dockerruntime.StateCreated)
			}
			if _, err := New(
				context.Background(), dependencies.durable, dependencies.registry, store, runtime,
				WithCleanupTimeout(200*time.Millisecond), WithBootIDSource(fixedBootID(otherBootID)),
			); !errors.Is(err, ErrRuntimeIntentUnresolved) {
				t.Fatalf("New() legacy pending error = %v", err)
			}
			if store.clearCalls.Load() != 0 {
				t.Fatalf("legacy pending intent was cleared %d times", store.clearCalls.Load())
			}
			run, err := store.GetRun(context.Background(), request.RunID)
			if err != nil || !run.RuntimeIntentPending || run.RuntimeIntentBootID != nil ||
				!run.WorkspaceLockHeld || run.State != executionwire.RunStateInterrupted {
				t.Fatalf("legacy pending authority = %#v, %v", run, err)
			}
			calls := runtime.callSnapshot()
			if !containsCall(calls, "lookup:"+request.RunID) ||
				containsCall(calls, "create:"+request.RunID) || containsCall(calls, "list-managed") {
				t.Fatalf("legacy pending recovery calls = %v", calls)
			}
			if found {
				if _, err := runtime.Inspect(context.Background(), ref); !errors.Is(err, dockerruntime.ErrNotFound) {
					t.Fatalf("visible legacy runtime was not cleaned: %v", err)
				}
			}
		})
	}
}

func TestCleanupFailureRetainsAuthorityAndFailsClosedOnRestart(t *testing.T) {
	manifest := controllerManifest(
		"target-cleanup-fail", "target-cleanup-fail-r1", "workspace-cleanup-fail",
		targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	runtime.stopLeavesRunning = true
	runtime.killErr = errors.New("private daemon kill failure")
	controller, err := New(
		context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
		WithBridge(completeBridge),
		WithCleanupTimeout(200*time.Millisecond),
		WithReconcileInterval(10*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	request := controllerRequest("run_cleanup_failure", manifest, "cleanup")
	if _, err := controller.StartRun(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	run := awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
		return run.State == executionwire.RunStateCompleted && run.RuntimeRef != nil && run.WorkspaceLockHeld
	})
	if run.RuntimeRef == nil {
		t.Fatal("cleanup failure cleared the runtime ref")
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := controller.Close(closeCtx); !errors.Is(err, ErrCleanup) {
		t.Fatalf("Close() cleanup error = %v", err)
	}
	if _, err := New(
		context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
		WithCleanupTimeout(100*time.Millisecond),
	); !errors.Is(err, ErrCleanup) {
		t.Fatalf("restart reconciliation error = %v", err)
	}
	run, err = dependencies.store.GetRun(context.Background(), request.RunID)
	if err != nil || run.RuntimeRef == nil || !run.WorkspaceLockHeld {
		t.Fatalf("failed restart released authority: run=%#v error=%v", run, err)
	}
}

func TestCleanupFailureClosesGlobalExecutionGate(t *testing.T) {
	manifest := controllerManifest(
		"target-cleanup-gate", "target-cleanup-gate-r1", "workspace-cleanup-gate",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	runtime.removeErr = errors.New("private daemon failure")
	controller, err := New(
		context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
		WithBridge(completeBridge),
		// Leave enough control-plane time for race-instrumented SQLite to
		// persist and re-read the runtime intent. The injected Remove failure,
		// rather than an artificial pre-Create timeout, is the subject here.
		WithCleanupTimeout(time.Second),
		WithReconcileInterval(10*time.Millisecond),
		WithBootIDSource(fixedBootID(testBootID)),
	)
	if err != nil {
		t.Fatal(err)
	}

	first := controllerRequest("run_cleanup_gate_first", manifest, "first")
	second := controllerRequest("run_cleanup_gate_second", manifest, "second")
	second.SessionScopeDigest = strings.Repeat("b", 64)
	if _, err := controller.StartRun(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.StartRun(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	firstRun := awaitRun(t, dependencies.store, first.RunID, func(run sandboxstore.Run) bool {
		return run.State == executionwire.RunStateCompleted && run.RuntimeRef != nil
	})
	if firstRun.RuntimeRef == nil {
		t.Fatal("cleanup failure did not retain the first runtime reference")
	}

	// Give both the worker and online reconciler several scheduling windows.
	// The second read-only Run shares writable harness state with the first, so
	// it must remain accepted until the first runtime is proven stopped.
	time.Sleep(250 * time.Millisecond)
	secondRun, err := dependencies.store.GetRun(context.Background(), second.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if secondRun.State != executionwire.RunStateAccepted || secondRun.RuntimeRef != nil || secondRun.RuntimeIntentPending {
		t.Fatalf("second Run crossed the execution gate: %#v", secondRun)
	}
	calls := runtime.callSnapshot()
	if !containsCall(calls, "create:"+first.RunID) ||
		containsCall(calls, "create:"+second.RunID) ||
		containsCall(calls, "attach:"+fakeContainerRef(second.RunID)) {
		t.Fatalf("cleanup failure allowed a later runtime: %v", calls)
	}

	controller.BeginClose()
	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := controller.Close(closeCtx); !errors.Is(err, ErrCleanup) {
		t.Fatalf("Close() error = %v, want ErrCleanup", err)
	}
}

func TestOnlineReconciliationRetriesTransientPersistenceFailures(t *testing.T) {
	manifest := controllerManifest(
		"target-online-retry", "target-online-retry-r1", "workspace-online-retry",
		targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	store := &transientStore{Store: dependencies.store}
	store.confirmFailures.Store(1)
	bridgeReturned := make(chan struct{})
	bridge := func(
		ctx context.Context,
		request executionwire.StartRunRequest,
		manifest targetmanifest.Manifest,
		token *string,
		output io.Reader,
		input io.Writer,
		sink runnerbridge.Sink,
	) error {
		if request.RunID == "run_get_retry" {
			if err := sink(ctx, startedEmission(request.RunID)); err != nil {
				return err
			}
			store.failNextGet.Store(1)
			close(bridgeReturned)
			return &runnerbridge.BridgeError{Class: runnerbridge.ErrorProtocolViolation}
		}
		return completeBridge(ctx, request, manifest, token, output, input, sink)
	}
	controller, err := New(
		context.Background(), dependencies.durable, dependencies.registry, store, runtime,
		WithBridge(bridge), WithCleanupTimeout(500*time.Millisecond), WithReconcileInterval(10*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := controller.Close(ctx); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	request := controllerRequest("run_confirm_retry", manifest, "retry")
	if _, err := controller.StartRun(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
		return run.State == executionwire.RunStateCompleted && run.RuntimeRef == nil && !run.WorkspaceLockHeld
	})
	if store.confirmCalls.Load() < 2 {
		t.Fatalf("ConfirmRuntimeStopped calls = %d, want retry", store.confirmCalls.Load())
	}

	request = controllerRequest("run_get_retry", manifest, "retry get")
	if _, err := controller.StartRun(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	<-bridgeReturned
	run := awaitTerminal(t, dependencies.store, request.RunID)
	if run.State != executionwire.RunStateInterrupted || run.Failure == nil ||
		run.Failure.Code != executionwire.FailureRuntimeInterrupted {
		t.Fatalf("uncertain transient state was not reconciled safely: %#v", run)
	}
}

func TestCreateIntentCertainAndUncertainFailureBoundaries(t *testing.T) {
	t.Run("certain preflight clears intent without a mutating probe", func(t *testing.T) {
		manifest := controllerManifest(
			"target-certain-create", "target-certain-create-r1", "workspace-certain-create",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		runtime := newFakeRuntime()
		var creates atomic.Int32
		runtime.createFn = func(context.Context, string, targetmanifest.Manifest) (string, error) {
			creates.Add(1)
			return "", dockerruntime.ErrInvalidArgument
		}
		controller := newTestController(t, dependencies, runtime, completeBridge)
		request := controllerRequest("run_certain_create", manifest, "preflight")
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		run := awaitTerminal(t, dependencies.store, request.RunID)
		if run.State != executionwire.RunStateFailed || run.RuntimeIntentPending ||
			run.Failure == nil || run.Failure.Code != executionwire.FailureInternal {
			t.Fatalf("certain Create failure = %#v", run)
		}
		if creates.Load() != 1 || containsCall(runtime.callSnapshot(), "lookup:"+request.RunID) {
			t.Fatalf("certain Create used a mutating/lookup probe: calls=%v", runtime.callSnapshot())
		}
	})

	t.Run("uncertain dispatched create is fenced before terminal", func(t *testing.T) {
		manifest := controllerManifest(
			"target-uncertain-create", "target-uncertain-create-r1", "workspace-uncertain-create",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		runtime := newFakeRuntime()
		var creates atomic.Int32
		runtime.createFn = func(_ context.Context, runID string, _ targetmanifest.Manifest) (string, error) {
			creates.Add(1)
			runtime.installIntent(runID, dockerruntime.StateCreated)
			return "", fmt.Errorf("%w: sanitized", dockerruntime.ErrCreateUncertain)
		}
		controller := newTestController(t, dependencies, runtime, completeBridge)
		request := controllerRequest("run_uncertain_create", manifest, "uncertain")
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		run := awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return terminalState(run.State) && !run.RuntimeIntentPending && run.RuntimeRef == nil && !run.WorkspaceLockHeld
		})
		if run.State != executionwire.RunStateInterrupted || creates.Load() != 1 ||
			!containsCall(runtime.callSnapshot(), "lookup:"+request.RunID) {
			t.Fatalf("uncertain Create recovery = %#v, creates=%d", run, creates.Load())
		}
	})

	t.Run("same boot absence stays pending and a changed boot fences it", func(t *testing.T) {
		manifest := controllerManifest(
			"target-create-epoch", "target-create-epoch-r1", "workspace-create-epoch",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		runtime := newFakeRuntime()
		var creates atomic.Int32
		runtime.createFn = func(context.Context, string, targetmanifest.Manifest) (string, error) {
			creates.Add(1)
			return "", dockerruntime.ErrCreateUncertain
		}
		controller, err := New(
			context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
			WithBridge(completeBridge), WithCleanupTimeout(200*time.Millisecond),
			WithReconcileInterval(10*time.Millisecond), WithBootIDSource(fixedBootID(testBootID)),
		)
		if err != nil {
			t.Fatal(err)
		}
		request := controllerRequest("run_create_epoch", manifest, "uncertain")
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		run := awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return run.State == executionwire.RunStateInterrupted && run.RuntimeIntentPending
		})
		time.Sleep(40 * time.Millisecond)
		run, err = dependencies.store.GetRun(context.Background(), request.RunID)
		if err != nil || run.State != executionwire.RunStateInterrupted || !run.RuntimeIntentPending ||
			run.RuntimeIntentBootID == nil || *run.RuntimeIntentBootID != testBootID || !run.WorkspaceLockHeld {
			t.Fatalf("same-boot unresolved intent = %#v, %v", run, err)
		}
		if got := creates.Load(); got != 1 {
			t.Fatalf("same-boot recovery dispatched Create %d times", got)
		}
		controller.BeginClose()
		closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
		defer closeCancel()
		if err := controller.Close(closeCtx); !errors.Is(err, ErrRuntimeIntentUnresolved) {
			t.Fatalf("same-boot Close() error = %v", err)
		}
		beforeRestart := len(runtime.callSnapshot())
		if _, err := New(
			context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
			WithCleanupTimeout(200*time.Millisecond), WithBootIDSource(fixedBootID(testBootID)),
		); !errors.Is(err, ErrRuntimeIntentUnresolved) {
			t.Fatalf("same-boot New() error = %v", err)
		}
		restartCalls := runtime.callSnapshot()[beforeRestart:]
		if !containsCall(restartCalls, "lookup:"+request.RunID) ||
			containsCall(restartCalls, "create:"+request.RunID) ||
			containsCall(restartCalls, "list-managed") {
			t.Fatalf("same-boot startup crossed authority boundary: %v", restartCalls)
		}

		restarted, err := New(
			context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
			WithCleanupTimeout(200*time.Millisecond), WithReconcileInterval(10*time.Millisecond),
			WithBootIDSource(fixedBootID(otherBootID)),
		)
		if err != nil {
			t.Fatalf("changed-boot New() error = %v", err)
		}
		restartCtx, restartCancel := context.WithTimeout(context.Background(), time.Second)
		defer restartCancel()
		defer func() {
			if err := restarted.Close(restartCtx); err != nil {
				t.Errorf("changed-boot Close() error = %v", err)
			}
		}()
		run, err = dependencies.store.GetRun(context.Background(), request.RunID)
		if err != nil || run.State != executionwire.RunStateInterrupted || run.RuntimeIntentPending ||
			run.RuntimeIntentBootID != nil || run.WorkspaceLockHeld {
			t.Fatalf("changed-boot recovery = %#v, %v", run, err)
		}
		if creates.Load() != 1 {
			t.Fatalf("changed-boot recovery dispatched another Create: %d", creates.Load())
		}
	})

	t.Run("read-only uncertain intent is terminal but remains unreconciled", func(t *testing.T) {
		manifest := controllerManifest(
			"target-create-ro", "target-create-ro-r1", "workspace-create-ro",
			targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		runtime := newFakeRuntime()
		var creates atomic.Int32
		runtime.createFn = func(context.Context, string, targetmanifest.Manifest) (string, error) {
			creates.Add(1)
			return "", dockerruntime.ErrCreateUncertain
		}
		controller, err := New(
			context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
			WithCleanupTimeout(200*time.Millisecond), WithReconcileInterval(10*time.Millisecond),
			WithBootIDSource(fixedBootID(testBootID)),
		)
		if err != nil {
			t.Fatal(err)
		}
		request := controllerRequest("run_create_ro", manifest, "uncertain read only")
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		run := awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return run.State == executionwire.RunStateInterrupted && run.RuntimeIntentPending
		})
		if run.WorkspaceLockHeld {
			t.Fatalf("read-only intent unexpectedly holds writer lock: %#v", run)
		}
		runs, err := dependencies.store.ListUnreconciled(context.Background())
		if err != nil || len(runs) != 1 || runs[0].RunID != request.RunID {
			t.Fatalf("terminal read-only pending inventory = %#v, %v", runs, err)
		}
		controller.BeginClose()
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := controller.Close(closeCtx); !errors.Is(err, ErrRuntimeIntentUnresolved) {
			t.Fatalf("Close() read-only pending error = %v", err)
		}
		if creates.Load() != 1 {
			t.Fatalf("read-only recovery dispatched Create %d times", creates.Load())
		}
	})

	t.Run("re-offered existing intent never dispatches create", func(t *testing.T) {
		manifest := controllerManifest(
			"target-existing-intent", "target-existing-intent-r1", "workspace-existing-intent",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		runtime := newFakeRuntime()
		var creates atomic.Int32
		runtime.createFn = func(context.Context, string, targetmanifest.Manifest) (string, error) {
			creates.Add(1)
			return fakeContainerRef("should_not_create"), nil
		}
		controller, err := New(
			context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
			WithCleanupTimeout(200*time.Millisecond), WithReconcileInterval(30*time.Second),
			WithBootIDSource(fixedBootID(testBootID)),
		)
		if err != nil {
			t.Fatal(err)
		}
		request := controllerRequest("run_existing_intent", manifest, "reoffer")
		if _, _, err := registerTestStart(dependencies,
			context.Background(), request, manifest.Revision, manifest.WorkspaceRef, true,
		); err != nil {
			t.Fatal(err)
		}
		if _, _, err := dependencies.store.BeginRuntimeIntent(
			context.Background(), request.RunID, testBootID,
		); err != nil {
			t.Fatal(err)
		}
		if err := controller.Offer(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		run := awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return run.State == executionwire.RunStateInterrupted && run.RuntimeIntentPending
		})
		if run.RuntimeIntentBootID == nil || *run.RuntimeIntentBootID != testBootID ||
			creates.Load() != 0 || !containsCall(runtime.callSnapshot(), "lookup:"+request.RunID) {
			t.Fatalf("existing intent recovery = %#v calls=%v", run, runtime.callSnapshot())
		}
		controller.BeginClose()
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := controller.Close(closeCtx); !errors.Is(err, ErrRuntimeIntentUnresolved) {
			t.Fatalf("Close() existing intent error = %v", err)
		}
	})

	for _, recoveryFailure := range []string{"lookup", "cleanup"} {
		t.Run("transient "+recoveryFailure+" failure keeps terminal authority", func(t *testing.T) {
			manifest := controllerManifest(
				"target-intent-"+recoveryFailure, "target-intent-r1", "workspace-intent-"+recoveryFailure,
				targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
			)
			dependencies := newTestDependencies(t, manifest)
			runtime := newFakeRuntime()
			var creates atomic.Int32
			runtime.createFn = func(_ context.Context, runID string, _ targetmanifest.Manifest) (string, error) {
				creates.Add(1)
				if recoveryFailure == "cleanup" {
					runtime.installIntent(runID, dockerruntime.StateCreated)
				}
				return "", dockerruntime.ErrCreateUncertain
			}
			if recoveryFailure == "lookup" {
				runtime.lookupFn = func(context.Context, string, targetmanifest.Manifest) (string, bool, error) {
					return "", false, errors.New("private lookup failure")
				}
			} else {
				runtime.removeErr = errors.New("private remove failure")
			}
			controller, err := New(
				context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
				// The test must reach Runtime.Create before exercising uncertain
				// recovery. Race instrumentation can make the Begin plus fresh-read
				// proof exceed sub-second synthetic budgets.
				WithCleanupTimeout(5*time.Second), WithReconcileInterval(10*time.Millisecond),
				WithBootIDSource(fixedBootID(testBootID)),
			)
			if err != nil {
				t.Fatal(err)
			}
			request := controllerRequest("run_intent_"+recoveryFailure, manifest, "transient")
			if _, err := controller.StartRun(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			run := awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
				return run.State == executionwire.RunStateInterrupted && run.RuntimeIntentPending
			})
			if !run.WorkspaceLockHeld || run.RuntimeIntentBootID == nil ||
				*run.RuntimeIntentBootID != testBootID || creates.Load() != 1 {
				t.Fatalf("failed recovery authority = %#v creates=%d", run, creates.Load())
			}
			controller.BeginClose()
			closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := controller.Close(closeCtx); err == nil {
				t.Fatal("Close() unexpectedly released transiently failed intent")
			}
			run, err = dependencies.store.GetRun(context.Background(), request.RunID)
			if err != nil || !run.RuntimeIntentPending || !run.WorkspaceLockHeld ||
				run.State != executionwire.RunStateInterrupted {
				t.Fatalf("Close released failed recovery authority: %#v, %v", run, err)
			}
			if creates.Load() != 1 {
				t.Fatalf("failed recovery retried Create %d times", creates.Load())
			}
		})
	}
}

func TestUncertainCreateAlwaysUsesInterruptedTerminalClass(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		manifest := controllerManifest(
			"target-uncertain-cancel", "target-uncertain-cancel-r1", "workspace-uncertain-cancel",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		runtime := newFakeRuntime()
		createStarted := make(chan struct{})
		runtime.createFn = func(ctx context.Context, _ string, _ targetmanifest.Manifest) (string, error) {
			close(createStarted)
			<-ctx.Done()
			return "", fmt.Errorf("%w: private cancellation detail", dockerruntime.ErrCreateUncertain)
		}
		controller, err := New(
			context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
			WithCleanupTimeout(200*time.Millisecond), WithReconcileInterval(10*time.Millisecond),
			WithBootIDSource(fixedBootID(testBootID)),
		)
		if err != nil {
			t.Fatal(err)
		}
		request := controllerRequest("run_uncertain_cancel", manifest, "cancel")
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		select {
		case <-createStarted:
		case <-time.After(time.Second):
			t.Fatal("Create did not start")
		}
		if _, err := controller.CancelRun(
			context.Background(), executionwire.CancelRunRequest{RunID: request.RunID},
		); err != nil {
			t.Fatal(err)
		}
		run := awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return run.State == executionwire.RunStateInterrupted && run.RuntimeIntentPending
		})
		if run.Failure == nil || run.Failure.Code != executionwire.FailureRuntimeInterrupted ||
			run.Failure.Message != messageInterrupted || !run.WorkspaceLockHeld {
			t.Fatalf("uncertain cancellation = %#v", run)
		}
		controller.BeginClose()
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := controller.Close(closeCtx); !errors.Is(err, ErrRuntimeIntentUnresolved) {
			t.Fatalf("Close() uncertain cancellation error = %v", err)
		}
	})

	t.Run("deadline", func(t *testing.T) {
		manifest := controllerManifest(
			"target-uncertain-deadline", "target-uncertain-deadline-r1", "workspace-uncertain-deadline",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		runtime := newFakeRuntime()
		createStarted := make(chan struct{})
		runtime.createFn = func(ctx context.Context, _ string, _ targetmanifest.Manifest) (string, error) {
			close(createStarted)
			<-ctx.Done()
			return "", fmt.Errorf("%w: private deadline detail", dockerruntime.ErrCreateUncertain)
		}
		controller, err := New(
			context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
			WithCleanupTimeout(200*time.Millisecond), WithReconcileInterval(10*time.Millisecond),
			WithBootIDSource(fixedBootID(testBootID)),
		)
		if err != nil {
			t.Fatal(err)
		}
		request := controllerRequest("run_uncertain_deadline", manifest, "deadline")
		request.Deadline = time.Now().UTC().Add(time.Second)
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		select {
		case <-createStarted:
		case <-time.After(time.Second):
			t.Fatal("Create did not start before the request deadline")
		}
		run := awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return run.State == executionwire.RunStateInterrupted && run.RuntimeIntentPending
		})
		if run.Failure == nil || run.Failure.Code != executionwire.FailureRuntimeInterrupted ||
			run.Failure.Message != messageInterrupted || !run.WorkspaceLockHeld {
			t.Fatalf("uncertain deadline = %#v", run)
		}
		controller.BeginClose()
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := controller.Close(closeCtx); !errors.Is(err, ErrRuntimeIntentUnresolved) {
			t.Fatalf("Close() uncertain deadline error = %v", err)
		}
	})
}

func TestPredispatchIntentControlPlaneProofsNeverCallCreateOrLookup(t *testing.T) {
	t.Run("cancellation while Begin is blocked", func(t *testing.T) {
		manifest := controllerManifest(
			"target-begin-cancel", "target-begin-cancel-r1", "workspace-begin-cancel",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		gatedStore := &beginGateStore{
			Store:   dependencies.store,
			started: make(chan struct{}),
			release: make(chan struct{}),
		}
		runtime := newFakeRuntime()
		controller, err := New(
			context.Background(), dependencies.durable, dependencies.registry, gatedStore, runtime,
			// Race instrumentation can pause this goroutine long enough to expire a
			// sub-second control proof after Begin returns. Keep the test focused on
			// cancellation interleaving, not scheduler wall time.
			WithCleanupTimeout(5*time.Second), WithReconcileInterval(10*time.Millisecond),
			WithBootIDSource(fixedBootID(testBootID)),
		)
		if err != nil {
			t.Fatal(err)
		}
		request := controllerRequest("run_begin_cancel", manifest, "cancel before dispatch")
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		select {
		case <-gatedStore.started:
		case <-time.After(time.Second):
			t.Fatal("BeginRuntimeIntent did not start")
		}
		if _, err := controller.CancelRun(
			context.Background(), executionwire.CancelRunRequest{RunID: request.RunID},
		); err != nil {
			t.Fatal(err)
		}
		close(gatedStore.release)
		run := awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return run.State == executionwire.RunStateCancelled && !run.RuntimeIntentPending && !run.WorkspaceLockHeld
		})
		if run.Failure != nil || gatedStore.contextCancelled.Load() {
			t.Fatalf("pre-dispatch cancellation = %#v contextCancelled=%v", run, gatedStore.contextCancelled.Load())
		}
		calls := runtime.callSnapshot()
		if containsCall(calls, "create:"+request.RunID) || containsCall(calls, "lookup:"+request.RunID) {
			t.Fatalf("pre-dispatch proof touched runtime: %v", calls)
		}
		controller.BeginClose()
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := controller.Close(closeCtx); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Begin commits then loses response", func(t *testing.T) {
		manifest := controllerManifest(
			"target-begin-ambiguous", "target-begin-ambiguous-r1", "workspace-begin-ambiguous",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		transient := &transientStore{Store: dependencies.store}
		transient.beginFailures.Store(1)
		transient.beginCommitThenFail.Store(true)
		transient.appendFailures.Store(1)
		runtime := newFakeRuntime()
		controller, err := New(
			context.Background(), dependencies.durable, dependencies.registry, transient, runtime,
			WithCleanupTimeout(500*time.Millisecond), WithReconcileInterval(10*time.Millisecond),
			WithBootIDSource(fixedBootID(testBootID)),
		)
		if err != nil {
			t.Fatal(err)
		}
		request := controllerRequest("run_begin_ambiguous", manifest, "ambiguous Begin")
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		run := awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return run.State == executionwire.RunStateFailed && !run.RuntimeIntentPending && !run.WorkspaceLockHeld
		})
		if run.Failure == nil || run.Failure.Code != executionwire.FailureInternal {
			t.Fatalf("ambiguous Begin result = %#v", run)
		}
		calls := runtime.callSnapshot()
		if containsCall(calls, "create:"+request.RunID) || containsCall(calls, "lookup:"+request.RunID) {
			t.Fatalf("ambiguous Begin proof touched runtime: %v", calls)
		}
		controller.BeginClose()
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := controller.Close(closeCtx); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Clear retries share one proof path", func(t *testing.T) {
		manifest := controllerManifest(
			"target-clear-retry", "target-clear-retry-r1", "workspace-clear-retry",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		transient := &transientStore{Store: dependencies.store}
		transient.beginFailures.Store(1)
		transient.beginCommitThenFail.Store(true)
		transient.clearFailures.Store(3)
		runtime := newFakeRuntime()
		controller, err := New(
			context.Background(), dependencies.durable, dependencies.registry, transient, runtime,
			// Keep the proof bounded while allowing four deliberate store attempts
			// to complete under the race detector.
			WithCleanupTimeout(5*time.Second), WithReconcileInterval(10*time.Millisecond),
			WithBootIDSource(fixedBootID(testBootID)),
		)
		if err != nil {
			t.Fatal(err)
		}
		request := controllerRequest("run_clear_retry", manifest, "retry clear")
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return terminalState(run.State) && !run.RuntimeIntentPending && !run.WorkspaceLockHeld
		})
		if transient.clearCalls.Load() != 4 {
			t.Fatalf("ClearRuntimeIntent calls = %d, want 4", transient.clearCalls.Load())
		}
		calls := runtime.callSnapshot()
		if containsCall(calls, "create:"+request.RunID) || containsCall(calls, "lookup:"+request.RunID) {
			t.Fatalf("clear retry proof touched runtime: %v", calls)
		}
		controller.BeginClose()
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := controller.Close(closeCtx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCertainNoRuntimeMemoFreshReadFallsBackToRuntimeCleanup(t *testing.T) {
	manifest := controllerManifest(
		"target-certain-memo", "target-certain-memo-r1", "workspace-certain-memo",
		targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	controller, err := New(
		context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
		WithCleanupTimeout(500*time.Millisecond), WithReconcileInterval(30*time.Second),
		WithBootIDSource(fixedBootID(testBootID)),
	)
	if err != nil {
		t.Fatal(err)
	}
	request := controllerRequest("run_certain_memo_stale", manifest, "stale proof")
	if _, err := dependencies.durable.StartRun(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	stale, err := dependencies.store.GetRun(context.Background(), request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := dependencies.store.BeginRuntimeIntent(context.Background(), request.RunID, testBootID); err != nil {
		t.Fatal(err)
	}
	ref := runtime.installIntent(request.RunID, dockerruntime.StateRunning)
	if _, err := dependencies.store.SetRuntimeRef(context.Background(), request.RunID, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := dependencies.store.AppendEvent(context.Background(), startedEmission(request.RunID).Event, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := controller.reconcileDesired(ctx, stale, terminalCancelled, true); err != nil {
		t.Fatal(err)
	}
	run, err := dependencies.store.GetRun(context.Background(), request.RunID)
	if err != nil || run.State != executionwire.RunStateCancelled || run.RuntimeRef != nil ||
		run.RuntimeIntentPending || run.WorkspaceLockHeld {
		t.Fatalf("stale certain memo result = %#v, err=%v", run, err)
	}
	calls := runtime.callSnapshot()
	if !containsCall(calls, "remove:"+ref) || containsCall(calls, "create:"+request.RunID) {
		t.Fatalf("stale certain memo cleanup calls = %v", calls)
	}
	controller.BeginClose()
	closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
	defer closeCancel()
	if err := controller.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
}

func TestDesiredTerminalRetriesAfterCertainCreateAndAppendFailure(t *testing.T) {
	manifest := controllerManifest(
		"target-desired-retry", "target-desired-retry-r1", "workspace-desired-retry",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	store := &transientStore{Store: dependencies.store}
	store.appendFailures.Store(1)
	runtime := newFakeRuntime()
	runtime.createFn = func(context.Context, string, targetmanifest.Manifest) (string, error) {
		return "", dockerruntime.ErrInvalidArgument
	}
	controller, err := New(
		context.Background(), dependencies.durable, dependencies.registry, store, runtime,
		WithBridge(completeBridge), WithCleanupTimeout(500*time.Millisecond), WithReconcileInterval(10*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := controller.Close(ctx); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	request := controllerRequest("run_desired_retry", manifest, "retry terminal")
	if _, err := controller.StartRun(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	run := awaitTerminal(t, dependencies.store, request.RunID)
	if run.State != executionwire.RunStateFailed || run.Failure == nil ||
		run.Failure.Code != executionwire.FailureInternal || run.RuntimeIntentPending {
		t.Fatalf("desired terminal retry = %#v", run)
	}
	if store.appendCalls.Load() < 2 {
		t.Fatalf("AppendEvent calls = %d, want online retry", store.appendCalls.Load())
	}
}

func TestSetRuntimeRefFailureCannotStrandPendingAuthority(t *testing.T) {
	for _, afterCommit := range []bool{false, true} {
		name := "before_commit"
		if afterCommit {
			name = "response_loss_after_commit"
		}
		t.Run(name, func(t *testing.T) {
			manifest := controllerManifest(
				"target-set-ref-"+name, "target-set-ref-r1", "workspace-set-ref-"+name,
				targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
			)
			dependencies := newTestDependencies(t, manifest)
			store := &transientStore{Store: dependencies.store}
			store.setFailures.Store(1)
			store.setCommitThenFail.Store(afterCommit)
			runtime := newFakeRuntime()
			controller, err := New(
				context.Background(), dependencies.durable, dependencies.registry, store, runtime,
				WithBridge(completeBridge), WithCleanupTimeout(500*time.Millisecond), WithReconcileInterval(10*time.Millisecond),
			)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := controller.Close(ctx); err != nil {
					t.Errorf("Close() error = %v", err)
				}
			})
			request := controllerRequest("run_set_ref_"+name, manifest, "set ref")
			if _, err := controller.StartRun(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			run := awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
				return terminalState(run.State) && !run.RuntimeIntentPending && run.RuntimeRef == nil && !run.WorkspaceLockHeld
			})
			if run.State != executionwire.RunStateFailed {
				t.Fatalf("SetRuntimeRef failure run = %#v", run)
			}
			createCalls := 0
			for _, call := range runtime.callSnapshot() {
				if call == "create:"+request.RunID {
					createCalls++
				}
			}
			wantCreates := 1
			if createCalls != wantCreates {
				t.Fatalf("Create calls = %d, want %d; calls=%v", createCalls, wantCreates, runtime.callSnapshot())
			}
		})
	}
}

func TestStartNeverReturnsAcceptedAfterConcurrentCancel(t *testing.T) {
	manifest := controllerManifest(
		"target-monotonic", "target-monotonic-r1", "workspace-monotonic",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	gated := &gatedStartService{
		DurableService: dependencies.durable,
		persisted:      make(chan struct{}),
		release:        make(chan struct{}),
	}
	controller, err := New(
		context.Background(), gated, dependencies.registry, dependencies.store, runtime,
		WithBridge(completeBridge), WithCleanupTimeout(500*time.Millisecond), WithReconcileInterval(10*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = controller.Close(ctx)
	})
	request := controllerRequest("run_monotonic", manifest, "race")
	type result struct {
		status executionwire.RunStatus
		err    error
	}
	resultChannel := make(chan result, 1)
	go func() {
		status, err := controller.StartRun(context.Background(), request)
		resultChannel <- result{status: status, err: err}
	}()
	select {
	case <-gated.persisted:
	case <-time.After(time.Second):
		t.Fatal("StartRun did not persist before gate")
	}
	if _, err := controller.CancelRun(context.Background(), executionwire.CancelRunRequest{RunID: request.RunID}); err != nil {
		t.Fatal(err)
	}
	close(gated.release)
	resultValue := <-resultChannel
	if resultValue.err != nil {
		var serviceErr *executionhttp.ServiceError
		if errors.As(resultValue.err, &serviceErr) {
			t.Fatalf("racing StartRun() error = %v, cause = %v", resultValue.err, serviceErr.Cause)
		}
		t.Fatalf("racing StartRun() error = %v", resultValue.err)
	}
	if resultValue.status.State == executionwire.RunStateAccepted {
		t.Fatalf("StartRun returned stale accepted after cancellation: %#v", resultValue.status)
	}
}

func TestBeginCloseFencesDurableStartAndCloseWaitsForEnteredStart(t *testing.T) {
	manifest := controllerManifest(
		"target-close-gate", "target-close-gate-r1", "workspace-close-gate",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	gated := &gatedStartService{
		DurableService: dependencies.durable,
		persisted:      make(chan struct{}),
		release:        make(chan struct{}),
	}
	controller, err := New(
		context.Background(), gated, dependencies.registry, dependencies.store, runtime,
		WithBridge(completeBridge), WithCleanupTimeout(500*time.Millisecond), WithReconcileInterval(10*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	first := controllerRequest("run_close_gate_entered", manifest, "entered")
	startResult := make(chan error, 1)
	go func() {
		_, err := controller.StartRun(context.Background(), first)
		startResult <- err
	}()
	select {
	case <-gated.persisted:
	case <-time.After(time.Second):
		t.Fatal("entered Start did not reach durable registration")
	}

	controller.BeginClose()
	late := controllerRequest("run_close_gate_late", manifest, "late")
	if _, err := controller.StartRun(context.Background(), late); serviceErrorCode(err) != executionhttp.ErrorUnavailable {
		t.Fatalf("late StartRun() error = %v", err)
	}
	if _, err := dependencies.store.GetRun(context.Background(), late.RunID); !errors.Is(err, sandboxstore.ErrNotFound) {
		t.Fatalf("late StartRun reached durable store: %v", err)
	}

	closeResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		closeResult <- controller.Close(ctx)
	}()
	select {
	case err := <-closeResult:
		t.Fatalf("Close returned before entered Start drained: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(gated.release)
	if err := <-startResult; serviceErrorCode(err) != executionhttp.ErrorUnavailable {
		t.Fatalf("entered Start after gate error = %v", err)
	}
	if err := <-closeResult; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if run, err := dependencies.store.GetRun(context.Background(), first.RunID); err != nil || run.State != executionwire.RunStateAccepted {
		t.Fatalf("entered durable run after final reconciliation = %#v, %v", run, err)
	}
}

func TestCancellationWinsOldReconcileSnapshot(t *testing.T) {
	manifest := controllerManifest(
		"target-reconcile-cancel", "target-reconcile-cancel-r1", "workspace-reconcile-cancel",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	lookupStarted := make(chan struct{})
	releaseLookup := make(chan struct{})
	var once sync.Once
	runtime.lookupFn = func(context.Context, string, targetmanifest.Manifest) (string, bool, error) {
		once.Do(func() { close(lookupStarted) })
		<-releaseLookup
		return "", false, nil
	}
	controller := newTestController(t, dependencies, runtime, completeBridge)
	request := controllerRequest("run_reconcile_cancel", manifest, "expired")
	request.Deadline = time.Now().UTC().Add(-time.Second)
	if _, _, err := registerTestStart(dependencies,
		context.Background(), request, manifest.Revision, manifest.WorkspaceRef, false,
	); err != nil {
		t.Fatal(err)
	}
	controller.signalReconcile()
	select {
	case <-lookupStarted:
	case <-time.After(time.Second):
		t.Fatal("online reconciliation did not start lookup")
	}
	if _, err := controller.CancelRun(context.Background(), executionwire.CancelRunRequest{RunID: request.RunID}); err != nil {
		t.Fatal(err)
	}
	close(releaseLookup)
	run := awaitTerminal(t, dependencies.store, request.RunID)
	if run.State != executionwire.RunStateCancelled {
		t.Fatalf("old deadline snapshot overrode cancellation: %#v", run)
	}
}

func TestCloseDeadlineBoundsFinalReconciliation(t *testing.T) {
	manifest := controllerManifest(
		"target-close-deadline", "target-close-deadline-r1", "workspace-close-deadline",
		targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	runtime.lookupFn = func(ctx context.Context, _ string, _ targetmanifest.Manifest) (string, bool, error) {
		<-ctx.Done()
		return "", false, ctx.Err()
	}
	controller, err := New(
		context.Background(), dependencies.durable, dependencies.registry, dependencies.store, runtime,
		WithCleanupTimeout(500*time.Millisecond), WithReconcileInterval(30*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	request := controllerRequest("run_close_deadline", manifest, "expired")
	request.Deadline = time.Now().UTC().Add(-time.Second)
	if _, _, err := registerTestStart(dependencies,
		context.Background(), request, manifest.Revision, manifest.WorkspaceRef, true,
	); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = controller.Close(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("Close ignored its total deadline: %v", elapsed)
	}
	run, getErr := dependencies.store.GetRun(context.Background(), request.RunID)
	if getErr != nil || run.State != executionwire.RunStateAccepted || !run.WorkspaceLockHeld {
		t.Fatalf("timed-out close released authority: run=%#v error=%v", run, getErr)
	}
}

func TestProductionBridgeClosesRunnerInputAfterStartFrame(t *testing.T) {
	manifest := controllerManifest(
		"target-real-bridge", "target-real-bridge-r1", "workspace-real-bridge",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	process := newFakeProcess()
	request := controllerRequest("run_real_bridge", manifest, "inspect")
	var output bytes.Buffer
	encoder := runnerwire.NewEncoder(&output)
	frames := []runnerwire.Frame{
		&runnerwire.RunnerReady{
			Protocol: runnerwire.ProtocolV1,
			Type:     runnerwire.TypeRunnerReady,
			Adapter: runnerwire.Adapter{
				Family: manifest.Runner.Family, Version: manifest.Runner.AdapterVersion,
			},
			Features: append([]runnerwire.Feature(nil), manifest.Runner.RequiredFeatures...),
		},
		&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: request.RunID, Seq: 1},
		&runnerwire.RunCompleted{
			Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunCompleted, RunID: request.RunID, Seq: 2,
			Output: runnerwire.TextContent{MediaType: runnerwire.MediaTypeTextPlain, Text: "done"},
		},
	}
	for _, frame := range frames {
		if err := encoder.Encode(frame); err != nil {
			t.Fatal(err)
		}
	}
	process.output = io.NopCloser(bytes.NewReader(output.Bytes()))
	runtime.process = func() *fakeProcess { return process }
	controller := newTestController(t, dependencies, runtime, nil)
	if _, err := controller.StartRun(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	awaitTerminal(t, dependencies.store, request.RunID)
	input, closed := process.input.snapshot()
	if !closed || !bytes.HasSuffix(input, []byte("\n")) {
		t.Fatalf("run.start input = %q, closed=%v", input, closed)
	}
	decoder := runnerwire.NewDecoder(bytes.NewReader(input))
	frame, err := decoder.DecodeControllerFrame()
	if err != nil {
		t.Fatalf("decode run.start: %v", err)
	}
	start, ok := frame.(*runnerwire.RunStart)
	if !ok || start.RunID != request.RunID || start.Input.Text != request.Input.Text {
		t.Fatalf("run.start = %#v", frame)
	}
}

type transientStore struct {
	*sandboxstore.Store
	failNextGet         atomic.Int32
	beginFailures       atomic.Int32
	beginCommitThenFail atomic.Bool
	clearFailures       atomic.Int32
	clearCalls          atomic.Int32
	confirmFailures     atomic.Int32
	confirmCalls        atomic.Int32
	appendFailures      atomic.Int32
	appendCalls         atomic.Int32
	setFailures         atomic.Int32
	setCommitThenFail   atomic.Bool
}

type beginGateStore struct {
	*sandboxstore.Store
	started          chan struct{}
	release          chan struct{}
	once             sync.Once
	contextCancelled atomic.Bool
}

func (s *beginGateStore) BeginRuntimeIntent(
	ctx context.Context,
	runID string,
	bootID string,
) (sandboxstore.Run, bool, error) {
	s.once.Do(func() { close(s.started) })
	<-s.release
	if ctx.Err() != nil {
		s.contextCancelled.Store(true)
	}
	return s.Store.BeginRuntimeIntent(ctx, runID, bootID)
}

func (s *transientStore) BeginRuntimeIntent(
	ctx context.Context,
	runID string,
	bootID string,
) (sandboxstore.Run, bool, error) {
	if s.beginFailures.Load() > 0 && s.beginFailures.Add(-1) >= 0 {
		if s.beginCommitThenFail.Load() {
			if _, _, err := s.Store.BeginRuntimeIntent(ctx, runID, bootID); err != nil {
				return sandboxstore.Run{}, false, err
			}
		}
		return sandboxstore.Run{}, false, errors.New("private BeginRuntimeIntent response failure")
	}
	return s.Store.BeginRuntimeIntent(ctx, runID, bootID)
}

func (s *transientStore) ClearRuntimeIntent(ctx context.Context, runID string) (sandboxstore.Run, error) {
	s.clearCalls.Add(1)
	if s.clearFailures.Load() > 0 && s.clearFailures.Add(-1) >= 0 {
		return sandboxstore.Run{}, errors.New("private ClearRuntimeIntent response failure")
	}
	return s.Store.ClearRuntimeIntent(ctx, runID)
}

// legacyIntentStore presents a migrated v2 pending row whose original boot is
// unknowable. The underlying v3 row remains valid SQLite state while the
// controller-facing snapshot exercises the stricter legacy recovery rule.
type legacyIntentStore struct {
	*sandboxstore.Store
	clearCalls atomic.Int32
}

func maskLegacyIntentBoot(run sandboxstore.Run) sandboxstore.Run {
	if run.RuntimeIntentPending {
		run.RuntimeIntentBootID = nil
	}
	return run
}

func (s *legacyIntentStore) GetRun(ctx context.Context, runID string) (sandboxstore.Run, error) {
	run, err := s.Store.GetRun(ctx, runID)
	return maskLegacyIntentBoot(run), err
}

func (s *legacyIntentStore) ListUnreconciled(ctx context.Context) ([]sandboxstore.Run, error) {
	runs, err := s.Store.ListUnreconciled(ctx)
	for index := range runs {
		runs[index] = maskLegacyIntentBoot(runs[index])
	}
	return runs, err
}

func (s *legacyIntentStore) AppendEvent(
	ctx context.Context,
	event executionwire.RunEvent,
	mapping *sandboxstore.SessionMapping,
) (sandboxstore.Run, error) {
	run, err := s.Store.AppendEvent(ctx, event, mapping)
	return maskLegacyIntentBoot(run), err
}

func (s *legacyIntentStore) ClearRuntimeIntent(ctx context.Context, runID string) (sandboxstore.Run, error) {
	s.clearCalls.Add(1)
	return s.Store.ClearRuntimeIntent(ctx, runID)
}

func (s *transientStore) GetRun(ctx context.Context, runID string) (sandboxstore.Run, error) {
	if s.failNextGet.CompareAndSwap(1, 0) {
		return sandboxstore.Run{}, errors.New("private transient GetRun failure")
	}
	return s.Store.GetRun(ctx, runID)
}

func (s *transientStore) ConfirmRuntimeStopped(ctx context.Context, runID string) (sandboxstore.Run, error) {
	s.confirmCalls.Add(1)
	if s.confirmFailures.CompareAndSwap(1, 0) {
		return sandboxstore.Run{}, errors.New("private transient Confirm failure")
	}
	return s.Store.ConfirmRuntimeStopped(ctx, runID)
}

func (s *transientStore) AppendEvent(
	ctx context.Context,
	event executionwire.RunEvent,
	mapping *sandboxstore.SessionMapping,
) (sandboxstore.Run, error) {
	s.appendCalls.Add(1)
	if s.appendFailures.CompareAndSwap(1, 0) {
		return sandboxstore.Run{}, errors.New("private transient AppendEvent failure")
	}
	return s.Store.AppendEvent(ctx, event, mapping)
}

func (s *transientStore) SetRuntimeRef(
	ctx context.Context,
	runID string,
	runtimeRef string,
) (sandboxstore.Run, error) {
	if s.setFailures.CompareAndSwap(1, 0) {
		if s.setCommitThenFail.Load() {
			if _, err := s.Store.SetRuntimeRef(ctx, runID, runtimeRef); err != nil {
				return sandboxstore.Run{}, err
			}
		}
		return sandboxstore.Run{}, errors.New("private SetRuntimeRef response failure")
	}
	return s.Store.SetRuntimeRef(ctx, runID, runtimeRef)
}

type gatedStartService struct {
	DurableService
	persisted chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (s *gatedStartService) StartRun(
	ctx context.Context,
	request executionwire.StartRunRequest,
) (executionwire.RunStatus, error) {
	status, err := s.DurableService.StartRun(ctx, request)
	s.once.Do(func() { close(s.persisted) })
	select {
	case <-s.release:
		return status, err
	case <-ctx.Done():
		return executionwire.RunStatus{}, ctx.Err()
	}
}

func dockerruntimeStateForStartup(state executionwire.RunState) dockerruntime.ContainerState {
	if state == executionwire.RunStateAccepted {
		return dockerruntime.StateCreated
	}
	return dockerruntime.StateRunning
}

var _ Store = (*transientStore)(nil)
var _ Store = (*legacyIntentStore)(nil)
var _ Store = (*beginGateStore)(nil)
var _ DurableService = (*gatedStartService)(nil)
