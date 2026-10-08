package sandboxcontroller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
)

type credentialRecoveryFixture struct {
	dependencies testDependencies
	freeRegistry *targetregistry.Registry
	request      executionwire.StartRunRequest
	freeRequest  executionwire.StartRunRequest
	workspace    string
}

// The service remains credential-free. Injecting a separate bound target into
// the real store and controller registry exercises recovery without pretending
// that production enrollment, credential reopening or mounts are implemented.
func newCredentialRecoveryFixture(t *testing.T) *credentialRecoveryFixture {
	t.Helper()
	ctx := context.Background()
	free := controllerManifest("free-target", "free-r1", "free-workspace",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly)
	bound := controllerManifest("bound-target", "bound-r1", "bound-workspace",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly)
	deps := newTestDependencies(t, free)
	f := &credentialRecoveryFixture{dependencies: deps, freeRegistry: deps.registry,
		request:     controllerRequest("old-credential-run", bound, "synthetic input"),
		freeRequest: controllerRequest("free-run", free, "synthetic input"), workspace: bound.WorkspaceRef}
	registry, err := targetregistry.New([]targetmanifest.Manifest{free, bound})
	if err != nil {
		t.Fatal(err)
	}
	f.dependencies.registry = registry
	gen := sandboxstore.CredentialGeneration{SlotRef: "synthetic", Generation: 1,
		SourceDigest: strings.Repeat("b", 64), WorkspaceRef: bound.WorkspaceRef,
		AuthProfileRef: "synthetic.auth", ScopeDigest: f.request.SessionScopeDigest}
	if err := deps.store.RegisterCredentialGeneration(ctx, gen); err != nil {
		t.Fatal(err)
	}
	if err := deps.store.RegisterTargetAuthorities(ctx, []sandboxstore.TargetAuthority{{
		TargetID: bound.ID, TargetRevision: bound.Revision, RevisionPin: strings.Repeat("c", 64),
		RunnerStateKind: targetmanifest.RunnerStatePersistent, RunnerStateRef: bound.StateRef,
		RunnerStatePathDigest: strings.Repeat("d", 64), StatePathAbsent: true,
		Credential: &sandboxstore.CredentialRef{SlotRef: gen.SlotRef, Generation: gen.Generation},
	}}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *credentialRecoveryFixture) admit(t *testing.T) {
	t.Helper()
	if _, _, err := f.dependencies.store.RegisterStart(context.Background(), f.request,
		f.request.ExpectedRevision, f.workspace, false,
		sandboxstore.SessionPolicy{Mode: targetmanifest.SessionNewOnly}); err != nil {
		t.Fatal(err)
	}
}

func (f *credentialRecoveryFixture) reopen(t *testing.T) {
	t.Helper()
	if err := f.dependencies.store.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := sandboxstore.Open(context.Background(), f.dependencies.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	durable, err := sandboxservice.New(context.Background(), f.freeRegistry, s, controllerStateOwnership)
	if err != nil {
		t.Fatal(err)
	}
	f.dependencies.store, f.dependencies.durable = s, durable
}

func (f *credentialRecoveryFixture) start(t *testing.T, s Store, runtime Runtime) (*Controller, error) {
	t.Helper()
	c, err := New(context.Background(), f.dependencies.durable, f.dependencies.registry, s, runtime,
		WithBootIDSource(fixedBootID(testBootID)), WithCleanupTimeout(time.Second),
		WithReconcileInterval(30*time.Second),
		WithClock(func() time.Time { return f.request.Deadline.Add(-5 * time.Second) }))
	if err == nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := c.Close(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	return c, err
}

func TestCredentialStartupRetiresBeforeCleanupAndRejectsOldReoffer(t *testing.T) {
	ctx := context.Background()
	f := newCredentialRecoveryFixture(t)
	f.admit(t)
	if _, _, err := registerTestStart(f.dependencies, ctx, f.freeRequest,
		f.freeRequest.ExpectedRevision, "free-workspace", false); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	s := f.dependencies.store
	runtime := newFakeRuntime()
	lookup := false
	runtime.lookupFn = func(ctx context.Context, runID string, _ targetmanifest.Definition) (string, bool, error) {
		lookup = true
		// This runs while occupancy is still retained. BeginRuntimeIntent must
		// reject revoked authority, even before considering the staged outcome.
		if _, _, err := s.BeginRuntimeIntent(ctx, runID, testBootID); !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
			t.Fatalf("runtime recovery preceded credential retirement: %v", err)
		}
		return "", false, nil
	}
	c, err := f.start(t, s, runtime)
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.GetRun(ctx, f.request.RunID)
	if err != nil || !lookup || run.State != executionwire.RunStateInterrupted ||
		run.CredentialLeaseHeld || run.TerminalPending || run.RuntimeIntentPending || run.RuntimeRef != nil ||
		run.Failure == nil || run.Failure.Code != executionwire.FailureRuntimeInterrupted {
		t.Fatalf("old accepted credential Run recovered incorrectly: %#v %v", run, err)
	}
	if err := c.Offer(ctx, f.request); !errors.Is(err, ErrNotAccepted) {
		t.Fatalf("retired Run reoffered: %v", err)
	}
	freeRun, err := s.GetRun(ctx, f.freeRequest.RunID)
	if err != nil || freeRun.State != executionwire.RunStateAccepted || freeRun.TerminalPending {
		t.Fatalf("credential-free reoffer path changed: %#v %v", freeRun, err)
	}
	if runtimeCreateCount(runtime, f.request.RunID) != 0 {
		t.Fatal("startup recovery issued Create")
	}
}

type retirementFaultStore struct {
	*sandboxstore.Store
	committed bool
	fault     error
}

func (s *retirementFaultStore) RetireOccupiedCredentialGenerations(ctx context.Context) error {
	if s.committed {
		if err := s.Store.RetireOccupiedCredentialGenerations(ctx); err != nil {
			return err
		}
	}
	return s.fault
}

func TestCredentialStartupRetirementErrorStopsBeforeRuntimeAndCanRetry(t *testing.T) {
	for _, committed := range []bool{false, true} {
		name := "before-commit"
		if committed {
			name = "committed-response-lost"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			f := newCredentialRecoveryFixture(t)
			f.admit(t)
			runtime := newFakeRuntime()
			fault := errors.New("synthetic retirement transport failure")
			wrapped := &retirementFaultStore{Store: f.dependencies.store, committed: committed, fault: fault}
			if c, err := f.start(t, wrapped, runtime); c != nil || !errors.Is(err, fault) {
				t.Fatalf("retirement error did not prevent startup: %v %v", c, err)
			}
			if calls := runtime.callSnapshot(); len(calls) != 0 {
				t.Fatalf("runtime called after retirement error: %v", calls)
			}
			f.reopen(t)
			run, err := f.dependencies.store.GetRun(ctx, f.request.RunID)
			if err != nil || run.State != executionwire.RunStateAccepted || !run.CredentialLeaseHeld || run.TerminalPending {
				t.Fatalf("failed startup lost retained authority: %#v %v", run, err)
			}
			if committed {
				if _, _, err := f.dependencies.store.BeginRuntimeIntent(ctx, run.RunID, testBootID); !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
					t.Fatalf("lost response undid committed retirement: %v", err)
				}
			}
			if _, err := f.start(t, f.dependencies.store, runtime); err != nil {
				t.Fatal(err)
			}
			run, err = f.dependencies.store.GetRun(ctx, run.RunID)
			if err != nil || run.State != executionwire.RunStateInterrupted || run.CredentialLeaseHeld ||
				runtimeCreateCount(runtime, run.RunID) != 0 {
				t.Fatalf("retirement retry: %#v %v", run, err)
			}
		})
	}
}

func TestCredentialStartupRetainsUncertainIntentUntilLateRuntimeCleanup(t *testing.T) {
	ctx := context.Background()
	f := newCredentialRecoveryFixture(t)
	f.admit(t)
	if _, _, err := f.dependencies.store.BeginRuntimeIntent(ctx, f.request.RunID, testBootID); err != nil {
		t.Fatal(err)
	}
	runtime := newFakeRuntime()
	if c, err := f.start(t, f.dependencies.store, runtime); c != nil || !errors.Is(err, ErrRuntimeIntentUnresolved) {
		t.Fatalf("same-boot absence allowed startup: %v %v", c, err)
	}
	f.reopen(t)
	s := f.dependencies.store
	run, err := s.GetRun(ctx, f.request.RunID)
	if err != nil || !run.CredentialLeaseHeld || !run.RuntimeIntentPending || !run.TerminalPending || run.Failure != nil {
		t.Fatalf("uncertain authority was lost or published: %#v %v", run, err)
	}
	if _, _, err := s.BeginRuntimeIntent(ctx, run.RunID, testBootID); !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
		t.Fatalf("uncertain Run still had fresh credential authority: %v", err)
	}
	ref := runtime.installIntent(run.RunID, dockerruntime.StateRunning)
	if _, err := f.start(t, s, runtime); err != nil {
		t.Fatal(err)
	}
	run, err = s.GetRun(ctx, run.RunID)
	if err != nil || run.State != executionwire.RunStateInterrupted || run.CredentialLeaseHeld ||
		run.RuntimeIntentPending || run.TerminalPending || runtimeCreateCount(runtime, run.RunID) != 0 {
		t.Fatalf("late runtime recovery: %#v %v", run, err)
	}
	if _, err := runtime.Inspect(ctx, ref); !errors.Is(err, dockerruntime.ErrNotFound) {
		t.Fatalf("late runtime survived cleanup: %v", err)
	}
}

func TestCredentialStartupPreservesStagedResultAcrossFailedCleanup(t *testing.T) {
	ctx := context.Background()
	f := newCredentialRecoveryFixture(t)
	f.admit(t)
	s := f.dependencies.store
	if _, _, err := s.BeginRuntimeIntent(ctx, f.request.RunID, testBootID); err != nil {
		t.Fatal(err)
	}
	runtime := newFakeRuntime()
	ref := runtime.installIntent(f.request.RunID, dockerruntime.StateRunning)
	if _, err := s.SetRuntimeRef(ctx, f.request.RunID, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendEvent(ctx, startedEmission(f.request.RunID).Event, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StageTerminal(ctx, completedEmission(f.request.RunID, 2, "retained result", nil).Event, nil); err != nil {
		t.Fatal(err)
	}
	runtime.removeErr = errors.New("synthetic remove failure")
	if c, err := f.start(t, s, runtime); c != nil || err == nil {
		t.Fatalf("failed cleanup allowed startup: %v %v", c, err)
	}
	f.reopen(t)
	s = f.dependencies.store
	run, err := s.GetRun(ctx, f.request.RunID)
	if err != nil || !run.CredentialLeaseHeld || !run.TerminalPending || run.Output != nil ||
		run.RuntimeRef == nil || *run.RuntimeRef != ref {
		t.Fatalf("failed cleanup discarded authority or exposed result: %#v %v", run, err)
	}
	if _, _, err := s.BeginRuntimeIntent(ctx, run.RunID, testBootID); !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
		t.Fatalf("failed cleanup undid retirement: %v", err)
	}
	runtime.removeErr = nil // No controller workers started on the failed attempt.
	if _, err := f.start(t, s, runtime); err != nil {
		t.Fatal(err)
	}
	run, err = s.GetRun(ctx, run.RunID)
	if err != nil || run.State != executionwire.RunStateCompleted || run.Output == nil || run.Output.Text != "retained result" ||
		run.CredentialLeaseHeld || run.TerminalPending || run.RuntimeRef != nil || runtimeCreateCount(runtime, run.RunID) != 0 {
		t.Fatalf("cleanup retry replaced staged outcome: %#v %v", run, err)
	}
}

func TestCredentialStartupLeavesIdleGenerationAndCurrentProcessAcceptanceUsable(t *testing.T) {
	ctx := context.Background()
	f := newCredentialRecoveryFixture(t)
	runtime := newFakeRuntime()
	c, err := f.start(t, f.dependencies.store, runtime)
	if err != nil {
		t.Fatal(err)
	}
	f.admit(t) // Idle at startup; this acceptance belongs to the current process.
	if err := c.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	run, err := f.dependencies.store.GetRun(ctx, f.request.RunID)
	if err != nil || run.State != executionwire.RunStateAccepted || run.TerminalPending || !run.CredentialLeaseHeld {
		t.Fatalf("ordinary reconciliation terminalized fresh acceptance: %#v %v", run, err)
	}
	if _, created, err := f.dependencies.store.BeginRuntimeIntent(ctx, run.RunID, testBootID); err != nil || !created {
		t.Fatalf("ordinary reconciliation retired a current generation: created=%v %v", created, err)
	}
	// No external Create was dispatched. Clear this synthetic intent so the
	// registered controller cleanup can run its ordinary reconciliation again.
	if _, err := f.dependencies.store.ClearRuntimeIntent(ctx, run.RunID); err != nil {
		t.Fatal(err)
	}
}
