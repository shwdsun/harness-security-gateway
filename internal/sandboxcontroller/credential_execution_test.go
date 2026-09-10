package sandboxcontroller

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
)

// This constructor uses real store/controller code with constructed proof and
// a private handle seam. The durable service still exposes only a free mock;
// no executable enrollment config or real credential/mount path is enabled.
type credentialExecutionFixture struct {
	deps    testDependencies
	request executionwire.StartRunRequest
	gen     sandboxstore.CredentialGeneration
	proof   credentialsource.Proof
	binding credentialsource.Binding
}

func newCredentialExecutionFixture(t *testing.T, withProof bool) credentialExecutionFixture {
	t.Helper()
	free := controllerManifest("free", "free-r1", "free-workspace", targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly)
	bound := controllerManifest("bound", "bound-r1", "bound-workspace", targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly)
	f := credentialExecutionFixture{deps: newTestDependencies(t, free), request: controllerRequest("credential-run", bound, "synthetic input")}
	f.request.Deadline = time.Now().UTC().Add(30 * time.Second).Truncate(time.Millisecond)
	f.gen = sandboxstore.CredentialGeneration{SlotRef: "synthetic", Generation: 1,
		SourceDigest: strings.Repeat("b", 64), WorkspaceRef: bound.WorkspaceRef,
		AuthProfileRef: bound.AuthProfileRef, ScopeDigest: f.request.SessionScopeDigest}
	f.proof = credentialsource.Proof{Scheme: credentialsource.EnrollmentScheme, RootObjectDigest: strings.Repeat("c", 64),
		SlotObjectDigest: strings.Repeat("d", 64), LocatorDigest: strings.Repeat("e", 64)}
	f.binding = credentialsource.Binding{SlotRef: f.gen.SlotRef, Generation: 1, WorkspaceRef: f.gen.WorkspaceRef,
		AuthProfileRef: f.gen.AuthProfileRef, Root: filepath.Join(t.TempDir(), "missing-synthetic-root"), Directory: "slot-one"}
	var err error
	if withProof {
		err = f.deps.store.RegisterCredentialEnrollment(context.Background(), f.gen, f.proof)
	} else {
		err = f.deps.store.RegisterCredentialGeneration(context.Background(), f.gen)
	}
	if err != nil {
		t.Fatal(err)
	}
	f.deps.registry, err = targetregistry.New([]targetmanifest.Manifest{free, bound})
	if err != nil {
		t.Fatal(err)
	}
	authority := sandboxstore.TargetAuthority{
		TargetID: bound.ID, TargetRevision: bound.Revision, RevisionPin: strings.Repeat("f", 64),
		RunnerStateKind: targetmanifest.RunnerStatePersistent, RunnerStateRef: bound.StateRef,
		RunnerStatePathDigest: strings.Repeat("1", 64), StatePathAbsent: true,
		Credential: &sandboxstore.CredentialRef{SlotRef: f.gen.SlotRef, Generation: f.gen.Generation},
	}
	if withProof {
		err = f.deps.store.RegisterEnrolledTargetAuthorities(context.Background(), []sandboxstore.EnrolledTargetAuthority{{
			Target: authority, Scope: &sandboxstore.CredentialTargetScope{WorkspaceRef: bound.WorkspaceRef,
				AuthProfileRef: bound.AuthProfileRef, ScopeDigest: f.request.SessionScopeDigest},
		}})
	} else {
		err = f.deps.store.RegisterTargetAuthorities(context.Background(), []sandboxstore.TargetAuthority{authority})
	}
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f credentialExecutionFixture) controller(t *testing.T, store Store, runtime Runtime, open credentialOpener, extra ...Option) *Controller {
	t.Helper()
	supplied := []Option{WithCredentialBindings([]credentialsource.Binding{f.binding}), WithBridge(completeBridge),
		WithBootIDSource(fixedBootID(testBootID)), WithCleanupTimeout(time.Second), WithReconcileInterval(10 * time.Millisecond)}
	if open != nil {
		supplied = append(supplied, func(config *options) error { config.openCredential = open; return nil })
	}
	supplied = append(supplied, extra...)
	c, err := New(context.Background(), f.deps.durable, f.deps.registry, store, runtime, supplied...)
	if err != nil {
		t.Fatal(err)
	}
	// Fault cases explicitly inspect Close errors in the test. This last-resort
	// cleanup stops workers even if an assertion fails while authority is held.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = c.Close(ctx)
	})
	return c
}

func (f credentialExecutionFixture) admit(t *testing.T) {
	t.Helper()
	if _, _, err := f.deps.store.RegisterStart(context.Background(), f.request, f.request.ExpectedRevision, f.gen.WorkspaceRef,
		false, sandboxstore.SessionPolicy{Mode: targetmanifest.SessionNewOnly}); err != nil {
		t.Fatal(err)
	}
}

type fakeCredentialHandle struct {
	source    string
	proof     credentialsource.Proof
	verifyErr error
	closeErr  error
	onClose   func() error
	changed   atomic.Bool
	closed    atomic.Bool
	verifies  atomic.Int32
	closes    atomic.Int32
}

// Embedding the original interface intentionally hides credential support.
type credentialFreeRuntime struct{ Runtime }

func TestCredentialRunCannotFallBackToCredentialFreeCreate(t *testing.T) {
	f := newCredentialExecutionFixture(t, true)
	runtime := newFakeRuntime()
	h := &fakeCredentialHandle{source: f.gen.SourceDigest, proof: f.proof}
	c := f.controller(t, f.deps.store, credentialFreeRuntime{runtime}, func(_, _ string) (credentialHandle, error) { return h, nil })
	f.admit(t)
	if err := c.Offer(context.Background(), f.request); err != nil {
		t.Fatal(err)
	}
	run := awaitTerminal(t, f.deps.store, f.request.RunID)
	if run.State != executionwire.RunStateFailed || run.Failure == nil || run.Failure.Message != messagePolicyDenied ||
		run.CredentialLeaseHeld || h.closes.Load() != 1 || runtimeCreateCount(runtime, run.RunID) != 0 {
		t.Fatalf("credential-free fallback or retained source: %#v", run)
	}
	for _, call := range runtime.callSnapshot() {
		if strings.HasPrefix(call, "attach:") {
			t.Fatal("unsupported credential runtime attached")
		}
	}
}

func (h *fakeCredentialHandle) VerifyProof(source string, proof credentialsource.Proof) error {
	h.verifies.Add(1)
	if source != h.source || proof != h.proof {
		return credentialsource.ErrProofMismatch
	}
	return h.verifyErr
}

func (h *fakeCredentialHandle) Validate() error {
	if h.changed.Load() || h.closed.Load() {
		return credentialsource.ErrChanged
	}
	return nil
}

// Lifecycle seam only: the fake runtime does not inspect a native mount. A zero
// handoff is deliberately unusable by the real Docker consumer; native receiver
// validation is exercised separately by the opt-in integration.
func (h *fakeCredentialHandle) Handoff(string, string, credentialsource.Binding, string, credentialsource.Proof) (*credentialsource.Handoff, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	return &credentialsource.Handoff{}, nil
}

func (h *fakeCredentialHandle) Close() error {
	h.closes.Add(1)
	if h.onClose != nil {
		if err := h.onClose(); err != nil {
			return err
		}
	}
	h.closed.Store(true)
	return h.closeErr
}

func TestCredentialRunReopensOnceAndClosesBeforePublication(t *testing.T) {
	ctx := context.Background()
	f := newCredentialExecutionFixture(t, true)
	runtime := newFakeRuntime()
	h := &fakeCredentialHandle{source: f.gen.SourceDigest, proof: f.proof}
	entered, proceed := make(chan struct{}), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(proceed) })
	var opens atomic.Int32
	c := f.controller(t, f.deps.store, runtime, func(root, directory string) (credentialHandle, error) {
		opens.Add(1)
		if root != f.binding.Root || directory != f.binding.Directory {
			return nil, errors.New("wrong frozen locator")
		}
		close(entered)
		<-proceed
		return h, nil
	})
	runtime.createFn = func(ctx context.Context, runID string, _ targetmanifest.Definition) (string, error) {
		run, err := f.deps.store.GetRun(ctx, runID)
		if err != nil || !run.CredentialLeaseHeld || !run.RuntimeIntentPending || h.verifies.Load() != 1 || h.closed.Load() {
			return "", errors.New("Create preceded held proof or durable intent")
		}
		return runtime.installIntent(runID, dockerruntime.StateCreated), nil
	}
	h.onClose = func() error {
		run, err := f.deps.store.GetRun(ctx, f.request.RunID)
		if err != nil || !run.CredentialLeaseHeld || !run.TerminalPending || run.Output != nil {
			return errors.New("publication preceded physical close")
		}
		if _, err := runtime.Inspect(ctx, fakeContainerRef(run.RunID)); !errors.Is(err, dockerruntime.ErrNotFound) {
			return errors.New("physical close preceded runtime removal")
		}
		return nil
	}
	f.admit(t) // Constructor startup runs before this current-process admission.
	if err := c.Offer(ctx, f.request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not acquire")
	}
	for range 4 {
		f.admit(t) // Exact receipt replay must not cause another acquisition.
		if err := c.Offer(ctx, f.request); err != nil {
			t.Fatal(err)
		}
	}
	release.Do(func() { close(proceed) })
	run := awaitTerminal(t, f.deps.store, f.request.RunID)
	if run.State != executionwire.RunStateCompleted || run.CredentialLeaseHeld || !h.closed.Load() ||
		h.closes.Load() != 1 || opens.Load() != 1 || runtimeCreateCount(runtime, run.RunID) != 1 || c.hasRetainedCredentials() {
		t.Fatalf("credential execution/release: %#v opens=%d closes=%d", run, opens.Load(), h.closes.Load())
	}
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	// A clean completion does not retire its generation; fresh admission can
	// take the same source after both physical and durable release boundaries.
	f.request.RunID = "successor-run"
	f.admit(t)
	if _, created, err := f.deps.store.BeginRuntimeIntent(ctx, f.request.RunID, testBootID); err != nil || !created {
		t.Fatalf("successful release retired generation: %v", err)
	}
	if _, err := f.deps.store.ClearRuntimeIntent(ctx, f.request.RunID); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialRunRejectsUnresolvedBindingsAndProofBeforeCreate(t *testing.T) {
	for _, fault := range []string{"missing-binding", "wrong-generation", "wrong-workspace", "wrong-auth", "missing-file", "proof-mismatch", "missing-proof"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			f := newCredentialExecutionFixture(t, fault != "missing-proof")
			runtime := newFakeRuntime()
			h := &fakeCredentialHandle{source: f.gen.SourceDigest, proof: f.proof}
			var opens atomic.Int32
			open := credentialOpener(func(_, _ string) (credentialHandle, error) { opens.Add(1); return h, nil })
			bindings := []credentialsource.Binding{f.binding}
			switch fault {
			case "missing-binding":
				bindings = nil
			case "wrong-generation":
				bindings[0].Generation++
			case "wrong-workspace":
				bindings[0].WorkspaceRef = "foreign-workspace"
			case "wrong-auth":
				bindings[0].AuthProfileRef = "foreign.auth"
			case "missing-file":
				open = nil // Exercise the fixed native opener on a missing fixture.
			case "proof-mismatch":
				h.verifyErr = errors.New("synthetic private source diagnostic")
			}
			c := f.controller(t, f.deps.store, runtime, open, WithCredentialBindings(bindings))
			f.admit(t)
			if err := c.Offer(ctx, f.request); err != nil {
				t.Fatal(err)
			}
			run := awaitTerminal(t, f.deps.store, f.request.RunID)
			if run.State != executionwire.RunStateFailed || run.Failure == nil || run.Failure.Message != messagePolicyDenied ||
				run.CredentialLeaseHeld || c.hasRetainedCredentials() || runtimeCreateCount(runtime, run.RunID) != 0 {
				t.Fatalf("failed credential comparison: %#v", run)
			}
			if fault == "proof-mismatch" {
				if opens.Load() != 1 || h.closes.Load() != 1 {
					t.Fatal("failed proof lost its handle")
				}
			} else if opens.Load() != 0 {
				t.Fatal("invalid scope or absent proof reached file acquisition")
			}
			f.request.RunID = "retry-with-new-id"
			if _, _, err := f.deps.store.RegisterStart(ctx, f.request, f.request.ExpectedRevision, f.gen.WorkspaceRef,
				false, sandboxstore.SessionPolicy{Mode: targetmanifest.SessionNewOnly}); !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
				t.Fatalf("failed acquisition did not retire generation: %v", err)
			}
		})
	}
}

type credentialFaultStore struct {
	*sandboxstore.Store
	beforeIntent func(context.Context, string) error
	revoke       func(context.Context, string) error
	stage        func(context.Context, executionwire.RunEvent, *sandboxstore.SessionMapping) (sandboxstore.Run, error)
	confirm      func(context.Context, string) (sandboxstore.Run, error)
}

func (s *credentialFaultStore) BeginRuntimeIntent(ctx context.Context, id, boot string) (sandboxstore.Run, bool, error) {
	if s.beforeIntent != nil {
		if err := s.beforeIntent(ctx, id); err != nil {
			return sandboxstore.Run{}, false, err
		}
	}
	return s.Store.BeginRuntimeIntent(ctx, id, boot)
}

func (s *credentialFaultStore) RevokeRunCredential(ctx context.Context, id string) error {
	if s.revoke != nil {
		return s.revoke(ctx, id)
	}
	return s.Store.RevokeRunCredential(ctx, id)
}

func (s *credentialFaultStore) StageTerminal(ctx context.Context, event executionwire.RunEvent, mapping *sandboxstore.SessionMapping) (sandboxstore.Run, error) {
	if s.stage != nil {
		return s.stage(ctx, event, mapping)
	}
	return s.Store.StageTerminal(ctx, event, mapping)
}

func (s *credentialFaultStore) ConfirmRuntimeStopped(ctx context.Context, id string) (sandboxstore.Run, error) {
	if s.confirm != nil {
		return s.confirm(ctx, id)
	}
	return s.Store.ConfirmRuntimeStopped(ctx, id)
}

func TestCredentialRunRechecksAuthorityAfterReadAndSourceAfterCreate(t *testing.T) {
	for _, fault := range []string{"revoked-before-intent", "replaced-before-intent", "replaced-during-create", "replaced-during-remove"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			f := newCredentialExecutionFixture(t, true)
			runtime := newFakeRuntime()
			h := &fakeCredentialHandle{source: f.gen.SourceDigest, proof: f.proof}
			s := &credentialFaultStore{Store: f.deps.store}
			wantCreates := 0
			wantState := executionwire.RunStateFailed
			switch fault {
			case "revoked-before-intent":
				s.beforeIntent = f.deps.store.RevokeRunCredential
			case "replaced-before-intent":
				s.beforeIntent = func(context.Context, string) error { h.changed.Store(true); return nil }
			case "replaced-during-create":
				wantCreates = 1
				runtime.createFn = func(_ context.Context, id string, _ targetmanifest.Definition) (string, error) {
					h.changed.Store(true)
					return runtime.installIntent(id, dockerruntime.StateCreated), nil
				}
			case "replaced-during-remove":
				wantCreates, wantState = 1, executionwire.RunStateCompleted
				runtime.removeFn = func(_ context.Context, ref string) error {
					h.changed.Store(true)
					runtime.mu.Lock()
					defer runtime.mu.Unlock()
					delete(runtime.states, ref)
					delete(runtime.intents, f.request.RunID)
					return nil
				}
			}
			h.onClose = func() error {
				if _, err := runtime.Inspect(ctx, fakeContainerRef(f.request.RunID)); !errors.Is(err, dockerruntime.ErrNotFound) {
					return errors.New("invalidated source closed before runtime cleanup")
				}
				return nil
			}
			c := f.controller(t, s, runtime, func(_, _ string) (credentialHandle, error) { return h, nil })
			f.admit(t)
			if err := c.Offer(ctx, f.request); err != nil {
				t.Fatal(err)
			}
			run := awaitTerminal(t, f.deps.store, f.request.RunID)
			if run.State != wantState || run.CredentialLeaseHeld || h.closes.Load() != 1 ||
				h.verifies.Load() != 1 || runtimeCreateCount(runtime, run.RunID) != wantCreates {
				t.Fatalf("stale credential authority used: %#v", run)
			}
			for _, call := range runtime.callSnapshot() {
				if fault != "replaced-during-remove" && strings.HasPrefix(call, "attach:") {
					t.Fatal("invalidated credential reached AttachStart")
				}
			}
			f.request.RunID = "retry-after-invalidation"
			if _, _, err := f.deps.store.RegisterStart(ctx, f.request, f.request.ExpectedRevision, f.gen.WorkspaceRef,
				false, sandboxstore.SessionPolicy{Mode: targetmanifest.SessionNewOnly}); !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
				t.Fatalf("observed failure left generation usable: %v", err)
			}
		})
	}
}

func TestCredentialRunRetainsHandleThroughCleanupRevocationAndStagingFailure(t *testing.T) {
	for _, fault := range []string{"remove", "revoke", "stage"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			f := newCredentialExecutionFixture(t, true)
			runtime := newFakeRuntime()
			h := &fakeCredentialHandle{source: f.gen.SourceDigest, proof: f.proof}
			s := &credentialFaultStore{Store: f.deps.store}
			var healthy atomic.Bool
			var faults atomic.Int32
			failure := errors.New("synthetic boundary failure")
			switch fault {
			case "remove":
				runtime.removeFn = func(_ context.Context, ref string) error {
					if !healthy.Load() {
						faults.Add(1)
						return failure
					}
					runtime.mu.Lock()
					defer runtime.mu.Unlock()
					delete(runtime.states, ref)
					delete(runtime.intents, f.request.RunID)
					return nil
				}
			case "revoke":
				h.verifyErr = credentialsource.ErrProofMismatch
				s.revoke = func(ctx context.Context, id string) error {
					if !healthy.Load() {
						faults.Add(1)
						return failure
					}
					return s.Store.RevokeRunCredential(ctx, id)
				}
			case "stage":
				h.verifyErr = credentialsource.ErrProofMismatch
				s.stage = func(ctx context.Context, event executionwire.RunEvent, mapping *sandboxstore.SessionMapping) (sandboxstore.Run, error) {
					if !healthy.Load() {
						faults.Add(1)
						return sandboxstore.Run{}, failure
					}
					return s.Store.StageTerminal(ctx, event, mapping)
				}
			}
			h.onClose = func() error {
				run, err := f.deps.store.GetRun(ctx, f.request.RunID)
				if err != nil || !run.CredentialLeaseHeld || !run.TerminalPending || !healthy.Load() {
					return errors.New("failure dropped physical or durable authority")
				}
				if fault != "remove" {
					if _, _, err := f.deps.store.BeginRuntimeIntent(ctx, run.RunID, testBootID); !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
						return errors.New("physical close preceded durable revocation")
					}
				}
				return nil
			}
			c := f.controller(t, s, runtime, func(_, _ string) (credentialHandle, error) { return h, nil })
			f.admit(t)
			if err := c.Offer(ctx, f.request); err != nil {
				t.Fatal(err)
			}
			run := awaitRun(t, f.deps.store, f.request.RunID, func(r sandboxstore.Run) bool { return faults.Load() > 0 && r.CredentialLeaseHeld })
			if run.Output != nil || h.closed.Load() || h.closes.Load() != 0 || !c.hasRetainedCredentials() {
				t.Fatalf("failed boundary released source: %#v", run)
			}
			gateCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
			if c.waitForRuntimeQuiescence(gateCtx) {
				t.Fatal("retained physical authority did not fence the execution lane")
			}
			cancel()
			healthy.Store(true)
			run = awaitTerminal(t, f.deps.store, run.RunID)
			want := executionwire.RunStateFailed
			if fault == "remove" {
				want = executionwire.RunStateCompleted
			}
			if run.State != want || run.CredentialLeaseHeld || h.closes.Load() != 1 || c.hasRetainedCredentials() {
				t.Fatalf("reconciliation failed to release original attempt: %#v", run)
			}
		})
	}
}

func TestCredentialRunCloseFailureStaysBlockedUntilRestartRecovery(t *testing.T) {
	ctx := context.Background()
	f := newCredentialExecutionFixture(t, true)
	runtime := newFakeRuntime()
	h := &fakeCredentialHandle{source: f.gen.SourceDigest, proof: f.proof, closeErr: errors.New("synthetic uncertain close")}
	var opens atomic.Int32
	open := credentialOpener(func(_, _ string) (credentialHandle, error) { opens.Add(1); return h, nil })
	c := f.controller(t, f.deps.store, runtime, open)
	f.admit(t)
	if err := c.Offer(ctx, f.request); err != nil {
		t.Fatal(err)
	}
	run := awaitRun(t, f.deps.store, f.request.RunID, func(r sandboxstore.Run) bool { return r.TerminalPending && h.closes.Load() != 0 })
	if err := c.Close(ctx); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("uncertain close allowed shutdown success: %v", err)
	}
	if run.Output != nil || !run.CredentialLeaseHeld || !c.hasRetainedCredentials() {
		t.Fatal("uncertain close released occupancy or result")
	}
	// Even if a second underlying Close could report success, the controller
	// must retain the first failure. Workers have stopped before changing it.
	h.closeErr = nil
	if err := c.reconcile(ctx); !errors.Is(err, ErrCredentialUnavailable) || h.closes.Load() != 1 {
		t.Fatalf("uncertain close was retried into readiness: %v calls=%d", err, h.closes.Load())
	}
	if _, _, err := f.deps.store.BeginRuntimeIntent(ctx, run.RunID, testBootID); !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
		t.Fatalf("close failure did not retire source: %v", err)
	}
	// Simulate process death by constructing a new controller with no retained
	// volatile handles. This is not a real process/descriptor-death canary.
	_ = f.controller(t, f.deps.store, runtime, open)
	run, err := f.deps.store.GetRun(ctx, run.RunID)
	if err != nil || run.State != executionwire.RunStateCompleted || run.Output == nil || run.Output.Text != "done" ||
		run.CredentialLeaseHeld || opens.Load() != 1 || runtimeCreateCount(runtime, run.RunID) != 1 {
		t.Fatalf("restart reopened a source or replaced staged result: %#v %v", run, err)
	}
}

func TestCredentialRunPublicationFailureNeverReopensOrReclosesSource(t *testing.T) {
	for _, committed := range []bool{false, true} {
		name := "before-commit"
		if committed {
			name = "committed-response-lost"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			f := newCredentialExecutionFixture(t, true)
			runtime := newFakeRuntime()
			h := &fakeCredentialHandle{source: f.gen.SourceDigest, proof: f.proof}
			var publications, opens atomic.Int32
			s := &credentialFaultStore{Store: f.deps.store}
			s.confirm = func(ctx context.Context, id string) (sandboxstore.Run, error) {
				if !h.closed.Load() {
					return sandboxstore.Run{}, errors.New("publication preceded physical close")
				}
				if publications.Add(1) == 1 {
					if committed {
						if _, err := s.Store.ConfirmRuntimeStopped(ctx, id); err != nil {
							return sandboxstore.Run{}, err
						}
					}
					return sandboxstore.Run{}, errors.New("synthetic publication failure")
				}
				return s.Store.ConfirmRuntimeStopped(ctx, id)
			}
			c := f.controller(t, s, runtime, func(_, _ string) (credentialHandle, error) { opens.Add(1); return h, nil })
			f.admit(t)
			if err := c.Offer(ctx, f.request); err != nil {
				t.Fatal(err)
			}
			run := awaitTerminal(t, f.deps.store, f.request.RunID)
			if run.State != executionwire.RunStateCompleted || run.CredentialLeaseHeld || c.hasRetainedCredentials() ||
				opens.Load() != 1 || h.closes.Load() != 1 || runtimeCreateCount(runtime, run.RunID) != 1 {
				t.Fatalf("publication retry reacquired or leaked held authority: %#v", run)
			}
			gateCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			defer cancel()
			if !c.waitForRuntimeQuiescence(gateCtx) {
				t.Fatal("lost publication response left a stale volatile fence")
			}
		})
	}
}
