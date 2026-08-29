package sandboxservice

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
)

const testImageDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var testNow = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

func manifest(id, revision, workspace string, mode targetmanifest.WorkspaceMode) targetmanifest.Manifest {
	return targetmanifest.Manifest{
		Schema:   targetmanifest.SchemaV1,
		ID:       id,
		Revision: revision,
		Runner: targetmanifest.Runner{
			Family:           "codex",
			AdapterVersion:   "0.1.0",
			Protocol:         runnerwire.ProtocolV1,
			Image:            "registry.example/runner@sha256:" + testImageDigest,
			RequiredFeatures: []runnerwire.Feature{runnerwire.FeatureSessionResume},
		},
		WorkspaceRef:      workspace,
		WorkspaceMode:     mode,
		StateRef:          id + "-state",
		PolicyRef:         "reviewed-v1",
		AuthProfileRef:    "model-proxy-v1",
		SkillBundleRef:    "skills-v1",
		NetworkProfileRef: "proxy-only-v1",
		SessionMode:       targetmanifest.SessionOpaqueResume,
		Limits: targetmanifest.Limits{
			TimeoutSeconds:       900,
			MemoryBytes:          1 << 30,
			CPUMillis:            1000,
			PIDs:                 128,
			MaxInputBytes:        executionwire.MaxInputTextBytes,
			MaxOutputBytes:       executionwire.MaxOutputTextBytes,
			MaxProgressBytes:     runnerwire.MaxProgressTextBytes,
			MaxStderrBytes:       64 << 10,
			MaxEvents:            executionwire.MaxEvents,
			MaxSessionAgeSeconds: 7 * 24 * 60 * 60,
			MaxSessionTurns:      128,
		},
	}
}

func request(runID, targetID, revision string) executionwire.StartRunRequest {
	return executionwire.StartRunRequest{
		RunID:              runID,
		TargetID:           targetID,
		ExpectedRevision:   revision,
		SessionScopeDigest: strings.Repeat("a", 64),
		Input: executionwire.TextInput{
			MediaType: executionwire.MediaTypeTextPlain,
			Text:      "inspect the project",
		},
		Deadline: testNow.Add(time.Hour),
	}
}

func openStore(t *testing.T) *sandboxstore.Store {
	t.Helper()
	store, err := sandboxstore.Open(context.Background(), filepath.Join(t.TempDir(), "sandbox.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return store
}

func newRegistry(t *testing.T, manifests ...targetmanifest.Manifest) *targetregistry.Registry {
	t.Helper()
	registry, err := targetregistry.New(manifests)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func newService(t *testing.T, registry Registry, store Store) *Service {
	t.Helper()
	service, err := New(
		context.Background(),
		registry,
		store,
		testRunnerStateOwnership,
		WithClock(func() time.Time { return testNow }),
	)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testRunnerStateOwnership(
	manifest targetmanifest.Manifest,
) (string, string, bool, error) {
	fingerprint, err := manifest.Fingerprint()
	return manifest.StateRef, fingerprint, true, err
}

func requireServiceCode(t *testing.T, err error, want executionhttp.ErrorCode) {
	t.Helper()
	var serviceError *executionhttp.ServiceError
	if !errors.As(err, &serviceError) || serviceError == nil {
		t.Fatalf("error = %T %v, want ServiceError", err, err)
	}
	if serviceError.Code != want {
		t.Fatalf("ServiceError.Code = %q, want %q", serviceError.Code, want)
	}
	if got := err.Error(); got != "sandboxd service error: "+string(want) {
		t.Fatalf("public error = %q", got)
	}
}

func TestStartRunMapsTargetResolutionErrors(t *testing.T) {
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	service := newService(t, newRegistry(t, target), openStore(t))

	missing := request("run-missing", "target-missing", "target-missing-r1")
	_, err := service.StartRun(context.Background(), missing)
	requireServiceCode(t, err, executionhttp.ErrorTargetNotFound)

	wrongRevision := request("run-revision", target.ID, "target-a-r2")
	_, err = service.StartRun(context.Background(), wrongRevision)
	requireServiceCode(t, err, executionhttp.ErrorRevisionMismatch)
}

func TestNewFailsClosedOnTargetFingerprintConflict(t *testing.T) {
	store := openStore(t)
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	_, stateDigest, _, err := testRunnerStateOwnership(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterTargetAuthorities(context.Background(), []sandboxstore.TargetAuthority{{
		TargetID: target.ID, TargetRevision: target.Revision,
		RevisionPin: strings.Repeat("f", 64), RunnerStateRef: target.StateRef,
		RunnerStatePathDigest: stateDigest, StatePathAbsent: true,
	}}); err != nil {
		t.Fatal(err)
	}
	service, err := New(context.Background(), newRegistry(t, target), store, testRunnerStateOwnership)
	if service != nil {
		t.Fatal("New() returned a service after target revision conflict")
	}
	if !errors.Is(err, sandboxstore.ErrConflict) {
		t.Fatalf("New() error = %v, want ErrConflict", err)
	}
	requireServiceCode(t, err, executionhttp.ErrorConflict)
}

func TestWritableWorkspaceContentionIsSharedAcrossTargets(t *testing.T) {
	firstTarget := manifest("target-a", "target-a-r1", "workspace-shared", targetmanifest.WorkspaceReadWrite)
	secondTarget := manifest("target-b", "target-b-r1", "workspace-shared", targetmanifest.WorkspaceReadWrite)
	service := newService(t, newRegistry(t, firstTarget, secondTarget), openStore(t))

	firstStatus, err := service.StartRun(context.Background(), request("run-a", firstTarget.ID, firstTarget.Revision))
	if err != nil {
		t.Fatal(err)
	}
	if firstStatus.State != executionwire.RunStateAccepted {
		t.Fatalf("first status = %#v", firstStatus)
	}
	_, err = service.StartRun(context.Background(), request("run-b", secondTarget.ID, secondTarget.Revision))
	requireServiceCode(t, err, executionhttp.ErrorWorkspaceBusy)
}

func TestReadOnlyTargetsDoNotAcquireWriterLock(t *testing.T) {
	store := openStore(t)
	firstTarget := manifest("target-ro-a", "target-ro-a-r1", "workspace-shared", targetmanifest.WorkspaceReadOnly)
	secondTarget := manifest("target-ro-b", "target-ro-b-r1", "workspace-shared", targetmanifest.WorkspaceReadOnly)
	service := newService(t, newRegistry(t, firstTarget, secondTarget), store)

	for _, input := range []executionwire.StartRunRequest{
		request("run-ro-a", firstTarget.ID, firstTarget.Revision),
		request("run-ro-b", secondTarget.ID, secondTarget.Revision),
	} {
		if _, err := service.StartRun(context.Background(), input); err != nil {
			t.Fatal(err)
		}
		run, err := store.GetRun(context.Background(), input.RunID)
		if err != nil {
			t.Fatal(err)
		}
		if run.Writable || run.WorkspaceLockHeld {
			t.Fatalf("read-only run has writer authority: %#v", run)
		}
	}
}

func TestSessionReferenceCannotCrossTargetScope(t *testing.T) {
	store := openStore(t)
	firstTarget := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	secondTarget := manifest("target-b", "target-b-r1", "workspace-b", targetmanifest.WorkspaceReadWrite)
	service := newService(t, newRegistry(t, firstTarget, secondTarget), store)

	firstRequest := request("run-a", firstTarget.ID, firstTarget.Revision)
	if _, err := service.StartRun(context.Background(), firstRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendEvent(context.Background(), executionwire.RunEvent{
		RunID: firstRequest.RunID,
		Seq:   1,
		Type:  executionwire.RunEventStarted,
	}, nil); err != nil {
		t.Fatal(err)
	}
	sessionRef := "session-a"
	if _, err := store.AppendEvent(context.Background(), executionwire.RunEvent{
		RunID: firstRequest.RunID,
		Seq:   2,
		Type:  executionwire.RunEventCompleted,
		Result: &executionwire.RunResult{
			Output:     executionwire.TextOutput{MediaType: executionwire.MediaTypeTextPlain, Text: "done"},
			SessionRef: &sessionRef,
		},
	}, &sandboxstore.SessionMapping{Ref: sessionRef, VendorToken: "vendor-token-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmRuntimeStopped(context.Background(), firstRequest.RunID); err != nil {
		t.Fatal(err)
	}

	secondRequest := request("run-b", secondTarget.ID, secondTarget.Revision)
	secondRequest.SessionRef = &sessionRef
	_, err := service.StartRun(context.Background(), secondRequest)
	requireServiceCode(t, err, executionhttp.ErrorInvalidSession)
}

func TestStartRunIsIdempotent(t *testing.T) {
	store := openStore(t)
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	service := newService(t, newRegistry(t, target), store)
	input := request("run-a", target.ID, target.Revision)

	first, err := service.StartRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.StartRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("idempotent statuses differ: %#v != %#v", first, second)
	}
	runs, err := store.ListNonTerminal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].RunID != input.RunID {
		t.Fatalf("durable runs = %#v", runs)
	}
	changed := input
	changed.Input.Text = "different request with reused run ID"
	_, err = service.StartRun(context.Background(), changed)
	requireServiceCode(t, err, executionhttp.ErrorConflict)
}

func TestGetAndPreStartCancel(t *testing.T) {
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	service := newService(t, newRegistry(t, target), openStore(t))
	input := request("run-a", target.ID, target.Revision)
	if _, err := service.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}

	before, err := service.GetRun(context.Background(), executionwire.GetRunRequest{RunID: input.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if before.Status.State != executionwire.RunStateAccepted || len(before.Events) != 0 {
		t.Fatalf("initial snapshot = %#v", before)
	}
	cancelled, err := service.CancelRun(context.Background(), executionwire.CancelRunRequest{RunID: input.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.State != executionwire.RunStateCancelling || cancelled.LastEventSeq != 0 {
		t.Fatalf("cancel status = %#v", cancelled)
	}
	after, err := service.GetRun(context.Background(), executionwire.GetRunRequest{RunID: input.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != cancelled || len(after.Events) != 0 {
		t.Fatalf("cancel snapshot = %#v", after)
	}

	_, err = service.GetRun(context.Background(), executionwire.GetRunRequest{RunID: "missing-run"})
	requireServiceCode(t, err, executionhttp.ErrorRunNotFound)
}

func TestStartRunRejectsExpiredDeadline(t *testing.T) {
	store := openStore(t)
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	service := newService(t, newRegistry(t, target), store)
	input := request("run-expired", target.ID, target.Revision)
	input.Deadline = testNow

	_, err := service.StartRun(context.Background(), input)
	requireServiceCode(t, err, executionhttp.ErrorInvalidState)
	if _, err := store.GetRun(context.Background(), input.RunID); !errors.Is(err, sandboxstore.ErrNotFound) {
		t.Fatalf("expired run was persisted: %v", err)
	}
}

type fakeRegistry struct {
	entries    []targetregistry.Entry
	resolveErr error
}

func (r *fakeRegistry) Entries() []targetregistry.Entry {
	return append([]targetregistry.Entry(nil), r.entries...)
}

func (r *fakeRegistry) Resolve(string, string) (targetregistry.Entry, error) {
	if r.resolveErr != nil {
		return targetregistry.Entry{}, r.resolveErr
	}
	return r.entries[0], nil
}

type fakeStore struct {
	registerErr   error
	registerCalls int
	startErr      error
	getErr        error
	cancelErr     error
	registered    []sandboxstore.TargetAuthority
	lastPolicy    sandboxstore.SessionPolicy
}

func (s *fakeStore) RegisterTargetAuthorities(
	_ context.Context,
	authorities []sandboxstore.TargetAuthority,
) error {
	s.registerCalls++
	s.registered = append(s.registered, authorities...)
	return s.registerErr
}

func (s *fakeStore) RegisterStart(
	_ context.Context,
	_ executionwire.StartRunRequest,
	_ string,
	_ string,
	_ bool,
	policy sandboxstore.SessionPolicy,
) (sandboxstore.Run, bool, error) {
	s.lastPolicy = policy
	return sandboxstore.Run{}, false, s.startErr
}

func (s *fakeStore) GetSnapshot(context.Context, string) (executionwire.GetRunResponse, error) {
	return executionwire.GetRunResponse{}, s.getErr
}

func (s *fakeStore) MarkCancelling(context.Context, string) (sandboxstore.Run, error) {
	return sandboxstore.Run{}, s.cancelErr
}

func TestInternalFailuresAreClosedAndSanitized(t *testing.T) {
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	fingerprint, err := target.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	secretError := errors.New("database /host/private.sqlite contains SECRET_TOKEN")
	registry := &fakeRegistry{entries: []targetregistry.Entry{{Manifest: target, Fingerprint: fingerprint}}}
	initializationStore := &fakeStore{registerErr: secretError}
	if initialized, err := New(
		context.Background(), registry, initializationStore, testRunnerStateOwnership,
	); err == nil || initialized != nil {
		t.Fatalf("New() with failing store = %#v, %v", initialized, err)
	} else {
		requireServiceCode(t, err, executionhttp.ErrorInternal)
		if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("initialization error leaked internal cause: %q", err)
		}
	}
	store := &fakeStore{startErr: secretError, getErr: secretError, cancelErr: secretError}
	service := newService(t, registry, store)

	tests := []struct {
		name string
		call func() error
	}{
		{"start", func() error {
			_, err := service.StartRun(context.Background(), request("run-a", target.ID, target.Revision))
			return err
		}},
		{"get", func() error {
			_, err := service.GetRun(context.Background(), executionwire.GetRunRequest{RunID: "run-a"})
			return err
		}},
		{"cancel", func() error {
			_, err := service.CancelRun(context.Background(), executionwire.CancelRunRequest{RunID: "run-a"})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			requireServiceCode(t, err, executionhttp.ErrorInternal)
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("public error leaked internal cause: %q", err)
			}
		})
	}

	registry.resolveErr = secretError
	_, err = service.StartRun(context.Background(), request("run-b", target.ID, target.Revision))
	requireServiceCode(t, err, executionhttp.ErrorInternal)
}

func TestSessionAdmissionFailuresShareOneNonEnumeratingPublicError(t *testing.T) {
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	fingerprint, err := target.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	registry := &fakeRegistry{entries: []targetregistry.Entry{{Manifest: target, Fingerprint: fingerprint}}}

	for index, test := range []struct {
		name  string
		cause error
	}{
		{"unknown", fmt.Errorf("private unknown ref: %w", sandboxstore.ErrSessionScope)},
		{"wrong scope", fmt.Errorf("private scope mismatch: %w", sandboxstore.ErrSessionScope)},
		{"already used", fmt.Errorf("private consumed ref: %w", sandboxstore.ErrSessionScope)},
		{"expired", fmt.Errorf("private expiry: %w", sandboxstore.ErrSessionScope)},
		{"over turn", fmt.Errorf("private turn limit: %w", sandboxstore.ErrSessionScope)},
		{"clock rollback", fmt.Errorf("private clock floor: %w", sandboxstore.ErrSessionScope)},
		{"compatibility alias", sandboxstore.ErrSessionNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := newService(t, registry, &fakeStore{startErr: test.cause})
			_, err := service.StartRun(
				context.Background(), request(fmt.Sprintf("run-session-error-%d", index), target.ID, target.Revision),
			)
			requireServiceCode(t, err, executionhttp.ErrorInvalidSession)
			if strings.Contains(err.Error(), "private") {
				t.Fatalf("public session error leaked classification: %q", err)
			}
		})
	}
}

func TestNewRejectsNilDependenciesAndClock(t *testing.T) {
	store := openStore(t)
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	registry := newRegistry(t, target)
	if service, err := New(context.Background(), nil, store, testRunnerStateOwnership); err == nil || service != nil {
		t.Fatalf("New(nil registry) = %#v, %v", service, err)
	}
	if service, err := New(context.Background(), registry, nil, testRunnerStateOwnership); err == nil || service != nil {
		t.Fatalf("New(nil store) = %#v, %v", service, err)
	}
	if service, err := New(context.Background(), registry, store, nil); err == nil || service != nil {
		t.Fatalf("New(nil runner-state ownership) = %#v, %v", service, err)
	}
	if service, err := New(context.Background(), registry, store, testRunnerStateOwnership, WithClock(nil)); err == nil || service != nil {
		t.Fatalf("New(nil clock) = %#v, %v", service, err)
	}
	if service, err := New(context.Background(), registry, store, testRunnerStateOwnership, WithRevisionPin(nil)); err == nil || service != nil {
		t.Fatalf("New(nil revision pin) = %#v, %v", service, err)
	}
}

func TestRevisionPinDefaultsToManifestFingerprint(t *testing.T) {
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	fingerprint, err := target.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{}
	if _, err := New(context.Background(), newRegistry(t, target), store, testRunnerStateOwnership); err != nil {
		t.Fatal(err)
	}
	if len(store.registered) != 1 || store.registered[0] != (sandboxstore.TargetAuthority{
		TargetID: target.ID, TargetRevision: target.Revision, RevisionPin: fingerprint,
		RunnerStateRef: target.StateRef, RunnerStatePathDigest: fingerprint, StatePathAbsent: true,
	}) {
		t.Fatalf("target registrations = %#v", store.registered)
	}
}

func TestRunnerStateOwnershipIsValidatedAndRegisteredAsOneBatch(t *testing.T) {
	first := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	second := manifest("target-b", "target-b-r1", "workspace-b", targetmanifest.WorkspaceReadWrite)
	store := &fakeStore{}
	if _, err := New(
		context.Background(), newRegistry(t, first, second), store, testRunnerStateOwnership,
	); err != nil {
		t.Fatal(err)
	}
	if store.registerCalls != 1 || len(store.registered) != 2 {
		t.Fatalf("registration calls = %d, authorities = %#v", store.registerCalls, store.registered)
	}

	tests := []struct {
		name     string
		provider RunnerStateOwnershipFunc
	}{
		{
			name: "mismatched ref",
			provider: func(targetmanifest.Manifest) (string, string, bool, error) {
				return "different-state", strings.Repeat("a", 64), true, nil
			},
		},
		{
			name: "invalid path digest",
			provider: func(input targetmanifest.Manifest) (string, string, bool, error) {
				return input.StateRef, strings.Repeat("a", 63), true, nil
			},
		},
		{
			name: "provider error",
			provider: func(targetmanifest.Manifest) (string, string, bool, error) {
				return "", "", false, errors.New("ownership unavailable")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{}
			service, err := New(context.Background(), newRegistry(t, first), store, test.provider)
			if err == nil || service != nil {
				t.Fatalf("New() = %#v, %v", service, err)
			}
			if store.registerCalls != 0 || len(store.registered) != 0 {
				t.Fatalf("invalid ownership reached store: calls=%d, values=%#v", store.registerCalls, store.registered)
			}
		})
	}
}

func TestHistoricalRunnerStateOwnerSurvivesRegistryRemoval(t *testing.T) {
	store := openStore(t)
	pathDigest := strings.Repeat("d", 64)
	first := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	firstOwner := func(input targetmanifest.Manifest) (string, string, bool, error) {
		return input.StateRef, pathDigest, true, nil
	}
	if _, err := New(context.Background(), newRegistry(t, first), store, firstOwner); err != nil {
		t.Fatal(err)
	}

	second := manifest("target-b", "target-b-r1", "workspace-b", targetmanifest.WorkspaceReadWrite)
	secondOwner := func(input targetmanifest.Manifest) (string, string, bool, error) {
		return input.StateRef, pathDigest, false, nil
	}
	service, err := New(context.Background(), newRegistry(t, second), store, secondOwner)
	if service != nil || !errors.Is(err, sandboxstore.ErrConflict) {
		t.Fatalf("historical path reuse = %#v, %v", service, err)
	}
	requireServiceCode(t, err, executionhttp.ErrorConflict)
}

func TestExistingUnownedRunnerStateIsNotAdopted(t *testing.T) {
	store := openStore(t)
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	existing := func(input targetmanifest.Manifest) (string, string, bool, error) {
		return input.StateRef, strings.Repeat("e", 64), false, nil
	}
	service, err := New(context.Background(), newRegistry(t, target), store, existing)
	if service != nil || !errors.Is(err, sandboxstore.ErrRunnerStateOwnershipUnknown) {
		t.Fatalf("unowned existing state = %#v, %v", service, err)
	}
	requireServiceCode(t, err, executionhttp.ErrorConflict)
}

func TestConsumerRevisionPinIsValidatedAndFrozenAtNew(t *testing.T) {
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	manifestFingerprint, err := target.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{}
	pin := strings.Repeat("a", 64)
	calls := 0
	service, err := New(
		context.Background(),
		newRegistry(t, target),
		store,
		testRunnerStateOwnership,
		WithRevisionPin(func(got targetmanifest.Manifest, gotFingerprint string) (string, error) {
			calls++
			if got.ID != target.ID || gotFingerprint != manifestFingerprint {
				t.Fatalf("revision pin input = %#v, %q", got, gotFingerprint)
			}
			return pin, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(store.registered) != 1 || store.registered[0].RevisionPin != strings.Repeat("a", 64) {
		t.Fatalf("calls = %d, registrations = %#v", calls, store.registered)
	}

	pin = strings.Repeat("b", 64)
	registered := service.registered[targetKey{id: target.ID, revision: target.Revision}]
	if registered.revisionPin != strings.Repeat("a", 64) || registered.manifestFingerprint != manifestFingerprint {
		t.Fatalf("frozen target = %#v", registered)
	}
	if calls != 1 {
		t.Fatalf("revision pin function calls after New = %d", calls)
	}
}

func TestRevisionPinRejectsInvalidProviderOutput(t *testing.T) {
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	registry := newRegistry(t, target)
	tests := []struct {
		name     string
		provider RevisionPinFunc
	}{
		{"empty", func(targetmanifest.Manifest, string) (string, error) { return "", nil }},
		{"short", func(targetmanifest.Manifest, string) (string, error) { return strings.Repeat("a", 63), nil }},
		{"uppercase", func(targetmanifest.Manifest, string) (string, error) { return strings.Repeat("A", 64), nil }},
		{"provider error", func(targetmanifest.Manifest, string) (string, error) { return "", errors.New("pin unavailable") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{}
			service, err := New(context.Background(), registry, store, testRunnerStateOwnership, WithRevisionPin(test.provider))
			if err == nil || service != nil {
				t.Fatalf("New() = %#v, %v", service, err)
			}
			if len(store.registered) != 0 {
				t.Fatalf("invalid pin was registered: %#v", store.registered)
			}
		})
	}
}

func TestChangedLocalRevisionPinConflictsWithDurableRevision(t *testing.T) {
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	registry := newRegistry(t, target)
	store := openStore(t)
	provider := func(pin string) RevisionPinFunc {
		return func(targetmanifest.Manifest, string) (string, error) { return pin, nil }
	}
	if _, err := New(context.Background(), registry, store, testRunnerStateOwnership, WithRevisionPin(provider(strings.Repeat("a", 64)))); err != nil {
		t.Fatal(err)
	}
	service, err := New(context.Background(), registry, store, testRunnerStateOwnership, WithRevisionPin(provider(strings.Repeat("b", 64))))
	if service != nil || !errors.Is(err, sandboxstore.ErrConflict) {
		t.Fatalf("New() with changed binding = %#v, %v", service, err)
	}
	requireServiceCode(t, err, executionhttp.ErrorConflict)
}

func TestRevisionPinDoesNotReplaceRegistrySemanticChecks(t *testing.T) {
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadWrite)
	fingerprint, err := target.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	registry := &fakeRegistry{entries: []targetregistry.Entry{{Manifest: target, Fingerprint: fingerprint}}}
	providerCalls := 0
	service, err := New(
		context.Background(),
		registry,
		&fakeStore{},
		testRunnerStateOwnership,
		WithClock(func() time.Time { return testNow }),
		WithRevisionPin(func(targetmanifest.Manifest, string) (string, error) {
			providerCalls++
			return strings.Repeat("a", 64), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	changed := target
	changed.PolicyRef = "reviewed-v2"
	changedFingerprint, err := changed.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	registry.entries[0] = targetregistry.Entry{Manifest: changed, Fingerprint: changedFingerprint}
	_, err = service.StartRun(context.Background(), request("run-a", target.ID, target.Revision))
	requireServiceCode(t, err, executionhttp.ErrorInternal)
	if providerCalls != 1 {
		t.Fatalf("revision pin function was re-evaluated: %d calls", providerCalls)
	}
}
