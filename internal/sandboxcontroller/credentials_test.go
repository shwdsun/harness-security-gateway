package sandboxcontroller

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
)

// This injects synthetic credential authority directly into the store. No
// production resolver, service configuration or credential mount is exercised.
func TestCredentialOccupancyFencesLaneUntilReopenedControllerProvesCleanup(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "sandbox.sqlite3")
	store, err := sandboxstore.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manifest := controllerManifest("credential-target", "credential-r1", "credential-workspace",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly)
	request := controllerRequest("credential-run", manifest, "synthetic input")
	registry, err := targetregistry.New([]targetmanifest.Manifest{manifest})
	if err != nil {
		t.Fatal(err)
	}
	gen := sandboxstore.CredentialGeneration{SlotRef: "synthetic", Generation: 1,
		SourceDigest: strings.Repeat("b", 64), WorkspaceRef: manifest.WorkspaceRef,
		AuthProfileRef: "synthetic.auth", ScopeDigest: request.SessionScopeDigest}
	if err := store.RegisterCredentialGeneration(ctx, gen); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterTargetAuthorities(ctx, []sandboxstore.TargetAuthority{{
		TargetID: manifest.ID, TargetRevision: manifest.Revision, RevisionPin: strings.Repeat("c", 64),
		RunnerStateKind: targetmanifest.RunnerStatePersistent, RunnerStateRef: manifest.StateRef,
		RunnerStatePathDigest: strings.Repeat("d", 64), StatePathAbsent: true,
		Credential: &sandboxstore.CredentialRef{SlotRef: gen.SlotRef, Generation: gen.Generation},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RegisterStart(ctx, request, manifest.Revision, manifest.WorkspaceRef,
		false, sandboxstore.SessionPolicy{Mode: targetmanifest.SessionNewOnly}); err != nil {
		t.Fatal(err)
	}
	runtime := newFakeRuntime()
	c := &Controller{store: store, registry: registry, runtime: runtime,
		bootID: testBootID, cleanupTimeout: time.Second, reconcileEvery: time.Millisecond,
		reconcileWake: make(chan struct{}, 1)}
	gateCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	if !c.waitForRuntimeQuiescence(gateCtx) {
		t.Fatal("accepted Run's own occupancy deadlocked the execution lane")
	}
	cancel()
	if _, _, err := store.BeginRuntimeIntent(ctx, request.RunID, testBootID); err != nil {
		t.Fatal(err)
	}
	ref := runtime.installIntent(request.RunID, dockerruntime.StateRunning)
	if _, err := store.SetRuntimeRef(ctx, request.RunID, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendEvent(ctx, startedEmission(request.RunID).Event, nil); err != nil {
		t.Fatal(err)
	}
	event := completedEmission(request.RunID, 2, "synthetic result", nil).Event
	run, err := store.StageTerminal(ctx, event, nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime.removeErr = errors.New("synthetic cleanup failure")
	if err := c.reconcileRun(ctx, run); err == nil {
		t.Fatal("cleanup failure ignored")
	}
	gateCtx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
	if c.waitForRuntimeQuiescence(gateCtx) {
		t.Fatal("unproved cleanup opened the lane")
	}
	cancel()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sandboxstore.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	run, err = reopened.GetRun(ctx, request.RunID)
	if err != nil || !run.CredentialLeaseHeld || !run.TerminalPending || run.Output != nil || run.RuntimeRef == nil {
		t.Fatalf("reopen lost cleanup authority: %#v %v", run, err)
	}
	c.store = reopened
	runtime.removeErr = nil
	if err := c.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	run, err = reopened.GetRun(ctx, request.RunID)
	if err != nil || run.CredentialLeaseHeld || run.TerminalPending || run.RuntimeRef != nil ||
		run.State != executionwire.RunStateCompleted || run.Output == nil || run.Output.Text != "synthetic result" {
		t.Fatalf("reconciliation publication: %#v %v", run, err)
	}
	if runtimeCreateCount(runtime, request.RunID) != 0 {
		t.Fatal("reconciliation issued a new Create")
	}
	gateCtx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if !c.waitForRuntimeQuiescence(gateCtx) {
		t.Fatal("proved cleanup did not reopen the lane")
	}
}
