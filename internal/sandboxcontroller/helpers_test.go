package sandboxcontroller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/runnerbridge"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
)

const (
	controllerImageDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testBootID            = "11111111-2222-3333-4444-555555555555"
	otherBootID           = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

func fixedBootID(value string) BootIDSource {
	return func() (string, error) { return value, nil }
}

func controllerManifest(
	id, revision, workspace string,
	workspaceMode targetmanifest.WorkspaceMode,
	sessionMode targetmanifest.SessionMode,
) targetmanifest.Manifest {
	features := []runnerwire.Feature{runnerwire.FeatureProgressText}
	if sessionMode == targetmanifest.SessionOpaqueResume {
		features = append(features, runnerwire.FeatureSessionResume)
	}
	manifest := targetmanifest.Manifest{
		Schema:   targetmanifest.SchemaV1,
		ID:       id,
		Revision: revision,
		Runner: targetmanifest.Runner{
			Family:           "mock",
			AdapterVersion:   "0.1.0",
			Protocol:         runnerwire.ProtocolV1,
			Image:            "registry.example/mock@sha256:" + controllerImageDigest,
			RequiredFeatures: features,
		},
		WorkspaceRef:      workspace,
		WorkspaceMode:     workspaceMode,
		StateRef:          id + "-state",
		PolicyRef:         "builtin.locked-down-v1",
		AuthProfileRef:    "builtin.none",
		SkillBundleRef:    "builtin.none",
		NetworkProfileRef: "builtin.none",
		SessionMode:       sessionMode,
		Limits: targetmanifest.Limits{
			TimeoutSeconds:   30,
			MemoryBytes:      64 << 20,
			CPUMillis:        100,
			PIDs:             16,
			MaxInputBytes:    4 << 10,
			MaxOutputBytes:   4 << 10,
			MaxProgressBytes: 1 << 10,
			MaxStderrBytes:   1 << 10,
			MaxEvents:        32,
		},
	}
	if sessionMode == targetmanifest.SessionOpaqueResume {
		manifest.Limits.MaxSessionAgeSeconds = 24 * 60 * 60
		manifest.Limits.MaxSessionTurns = 32
	}
	return manifest
}

func controllerRequest(runID string, manifest targetmanifest.Manifest, text string) executionwire.StartRunRequest {
	return executionwire.StartRunRequest{
		RunID:              runID,
		TargetID:           manifest.ID,
		ExpectedRevision:   manifest.Revision,
		SessionScopeDigest: strings.Repeat("a", 64),
		Input: executionwire.TextInput{
			MediaType: executionwire.MediaTypeTextPlain,
			Text:      text,
		},
		Deadline: time.Now().UTC().Add(10 * time.Second).Truncate(time.Millisecond),
	}
}

func controllerStateOwnership(
	manifest targetmanifest.Manifest,
) (string, string, bool, error) {
	fingerprint, err := manifest.Fingerprint()
	return manifest.StateRef, fingerprint, true, err
}

type testDependencies struct {
	store    *sandboxstore.Store
	registry *targetregistry.Registry
	durable  *sandboxservice.Service
	dbPath   string
}

func registerTestStart(
	dependencies testDependencies,
	ctx context.Context,
	request executionwire.StartRunRequest,
	resolvedRevision string,
	workspaceID string,
	writable bool,
) (sandboxstore.Run, bool, error) {
	entry, err := dependencies.registry.Resolve(request.TargetID, resolvedRevision)
	if err != nil {
		return sandboxstore.Run{}, false, err
	}
	return dependencies.store.RegisterStart(
		ctx, request, resolvedRevision, workspaceID, writable,
		sandboxstore.SessionPolicy{
			Mode:          entry.Manifest.SessionMode,
			MaxAgeSeconds: entry.Manifest.Limits.MaxSessionAgeSeconds,
			MaxTurns:      int64(entry.Manifest.Limits.MaxSessionTurns),
		},
	)
}

func newTestDependencies(t *testing.T, manifests ...targetmanifest.Manifest) testDependencies {
	t.Helper()
	registry, err := targetregistry.New(manifests)
	if err != nil {
		t.Fatalf("targetregistry.New() error = %v", err)
	}
	dbPath := filepath.Join(t.TempDir(), "sandbox.sqlite3")
	store, err := sandboxstore.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("sandboxstore.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("store.Close() error = %v", err)
		}
	})
	durable, err := sandboxservice.New(
		context.Background(), registry, store, controllerStateOwnership,
	)
	if err != nil {
		t.Fatalf("sandboxservice.New() error = %v", err)
	}
	return testDependencies{store: store, registry: registry, durable: durable, dbPath: dbPath}
}

func newTestController(
	t *testing.T,
	dependencies testDependencies,
	runtime Runtime,
	bridge BridgeFunc,
	extra ...Option,
) *Controller {
	t.Helper()
	options := []Option{
		WithCleanupTimeout(500 * time.Millisecond),
		WithWaitGrace(20 * time.Millisecond),
		WithReconcileInterval(10 * time.Millisecond),
		WithBootIDSource(fixedBootID(testBootID)),
	}
	if bridge != nil {
		options = append(options, WithBridge(bridge))
	}
	options = append(options, extra...)
	controller, err := New(
		context.Background(),
		dependencies.durable,
		dependencies.registry,
		dependencies.store,
		runtime,
		options...,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := controller.Close(ctx); err != nil {
			t.Errorf("Controller.Close() error = %v", err)
		}
	})
	return controller
}

type fakeRuntime struct {
	mu sync.Mutex

	states  map[string]dockerruntime.ContainerState
	intents map[string]string
	calls   []string

	managedFn func(context.Context) ([]string, error)
	createFn  func(context.Context, string, targetmanifest.Manifest) (string, error)
	lookupFn  func(context.Context, string, targetmanifest.Manifest) (string, bool, error)
	attachFn  func(context.Context, string) (Process, error)
	inspectFn func(context.Context, string) (dockerruntime.Inspection, error)
	removeFn  func(context.Context, string) error
	process   func() *fakeProcess

	stopLeavesRunning  bool
	stopErr            error
	killErr            error
	removeErr          error
	removeResponseLost bool
}

func (r *fakeRuntime) ListManaged(ctx context.Context) ([]string, error) {
	r.record("list-managed")
	if r.managedFn != nil {
		return r.managedFn(ctx)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	refs := make([]string, 0, len(r.states))
	for ref := range r.states {
		refs = append(refs, ref)
	}
	slices.Sort(refs)
	return refs, nil
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{
		states:  make(map[string]dockerruntime.ContainerState),
		intents: make(map[string]string),
		process: newFakeProcess,
	}
}

func (r *fakeRuntime) Create(ctx context.Context, runID string, manifest targetmanifest.Manifest) (string, error) {
	r.record("create:" + runID)
	if r.createFn != nil {
		return r.createFn(ctx, runID, manifest)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if ref := r.intents[runID]; ref != "" {
		return ref, nil
	}
	ref := fakeContainerRef(runID)
	r.intents[runID] = ref
	r.states[ref] = dockerruntime.StateCreated
	return ref, nil
}

func (r *fakeRuntime) LookupIntent(
	ctx context.Context,
	runID string,
	manifest targetmanifest.Manifest,
) (string, bool, error) {
	r.record("lookup:" + runID)
	if r.lookupFn != nil {
		return r.lookupFn(ctx, runID, manifest)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ref := r.intents[runID]
	if ref == "" {
		return "", false, nil
	}
	return ref, true, nil
}

func (r *fakeRuntime) AttachStart(ctx context.Context, ref string) (Process, error) {
	r.record("attach:" + ref)
	if r.attachFn != nil {
		return r.attachFn(ctx, ref)
	}
	r.mu.Lock()
	if _, exists := r.states[ref]; exists {
		r.states[ref] = dockerruntime.StateRunning
	}
	factory := r.process
	r.mu.Unlock()
	return factory(), nil
}

func (r *fakeRuntime) Inspect(ctx context.Context, ref string) (dockerruntime.Inspection, error) {
	r.record("inspect:" + ref)
	if r.inspectFn != nil {
		return r.inspectFn(ctx, ref)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	state, exists := r.states[ref]
	if !exists {
		return dockerruntime.Inspection{}, dockerruntime.ErrNotFound
	}
	return dockerruntime.Inspection{State: state}, nil
}

func (r *fakeRuntime) Stop(_ context.Context, ref string) error {
	r.record("stop:" + ref)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.states[ref]; !exists {
		return dockerruntime.ErrNotFound
	}
	if r.stopErr != nil {
		return r.stopErr
	}
	if !r.stopLeavesRunning {
		r.states[ref] = dockerruntime.StateExited
	}
	return nil
}

func (r *fakeRuntime) Kill(_ context.Context, ref string) error {
	r.record("kill:" + ref)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.states[ref]; !exists {
		return dockerruntime.ErrNotFound
	}
	if r.killErr != nil {
		return r.killErr
	}
	r.states[ref] = dockerruntime.StateExited
	return nil
}

func (r *fakeRuntime) RemoveStopped(ctx context.Context, ref string) error {
	r.record("remove:" + ref)
	if r.removeFn != nil {
		return r.removeFn(ctx, ref)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.states[ref]; !exists {
		return dockerruntime.ErrNotFound
	}
	if r.removeResponseLost {
		delete(r.states, ref)
		for runID, intentRef := range r.intents {
			if intentRef == ref {
				delete(r.intents, runID)
			}
		}
		return errors.New("lost remove response: private diagnostic")
	}
	if r.removeErr != nil {
		return r.removeErr
	}
	delete(r.states, ref)
	for runID, intentRef := range r.intents {
		if intentRef == ref {
			delete(r.intents, runID)
		}
	}
	return nil
}

func (r *fakeRuntime) record(call string) {
	r.mu.Lock()
	r.calls = append(r.calls, call)
	r.mu.Unlock()
}

func (r *fakeRuntime) callSnapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func (r *fakeRuntime) installIntent(runID string, state dockerruntime.ContainerState) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ref := fakeContainerRef(runID)
	r.intents[runID] = ref
	r.states[ref] = state
	return ref
}

func fakeContainerRef(runID string) string {
	digest := sha256.Sum256([]byte(runID))
	return hex.EncodeToString(digest[:])
}

type fakeProcess struct {
	input       *trackingWriteCloser
	output      io.ReadCloser
	diagnostics io.ReadCloser
	wait        <-chan error
}

func newFakeProcess() *fakeProcess {
	wait := make(chan error, 1)
	wait <- nil
	return &fakeProcess{
		input:       &trackingWriteCloser{},
		output:      io.NopCloser(strings.NewReader("")),
		diagnostics: io.NopCloser(strings.NewReader("private runner stderr")),
		wait:        wait,
	}
}

func (p *fakeProcess) Input() io.WriteCloser      { return p.input }
func (p *fakeProcess) Output() io.ReadCloser      { return p.output }
func (p *fakeProcess) Diagnostics() io.ReadCloser { return p.diagnostics }
func (p *fakeProcess) Wait() error                { return <-p.wait }

type trackingWriteCloser struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	closed bool
}

func (w *trackingWriteCloser) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	return w.buffer.Write(data)
}

func (w *trackingWriteCloser) Close() error {
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	return nil
}

func (w *trackingWriteCloser) snapshot() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buffer.Bytes()...), w.closed
}

func completeBridge(
	ctx context.Context,
	request executionwire.StartRunRequest,
	_ targetmanifest.Manifest,
	_ *string,
	_ io.Reader,
	_ io.Writer,
	sink runnerbridge.Sink,
) error {
	if err := sink(ctx, startedEmission(request.RunID)); err != nil {
		return err
	}
	return sink(ctx, completedEmission(request.RunID, 2, "done", nil))
}

func startedEmission(runID string) runnerbridge.Emission {
	return runnerbridge.Emission{Event: executionwire.RunEvent{
		RunID: runID,
		Seq:   1,
		Type:  executionwire.RunEventStarted,
	}}
}

func completedEmission(runID string, seq uint64, output string, token *string) runnerbridge.Emission {
	return runnerbridge.Emission{
		Event: executionwire.RunEvent{
			RunID: runID,
			Seq:   seq,
			Type:  executionwire.RunEventCompleted,
			Result: &executionwire.RunResult{Output: executionwire.TextOutput{
				MediaType: executionwire.MediaTypeTextPlain,
				Text:      output,
			}},
		},
		VendorSessionToken: token,
	}
}

func awaitRun(
	t *testing.T,
	store *sandboxstore.Store,
	runID string,
	predicate func(sandboxstore.Run) bool,
) sandboxstore.Run {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		run, err := store.GetRun(context.Background(), runID)
		if err == nil && predicate(run) {
			return run
		}
		time.Sleep(5 * time.Millisecond)
	}
	run, err := store.GetRun(context.Background(), runID)
	t.Fatalf("run %q did not reach expected state: run=%#v error=%v", runID, run, err)
	return sandboxstore.Run{}
}

func awaitTerminal(t *testing.T, store *sandboxstore.Store, runID string) sandboxstore.Run {
	t.Helper()
	return awaitRun(t, store, runID, func(run sandboxstore.Run) bool { return terminalState(run.State) })
}

func containsCall(calls []string, prefix string) bool {
	for _, call := range calls {
		if call == prefix || strings.HasPrefix(call, prefix) {
			return true
		}
	}
	return false
}

func callIndex(calls []string, exact string) int {
	for index, call := range calls {
		if call == exact {
			return index
		}
	}
	return -1
}
