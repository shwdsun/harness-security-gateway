package sandboxcontroller

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/runnerbridge"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func assertInterruptedAfterBootFence(t *testing.T, deps testDependencies, runtime *fakeRuntime, id string) {
	t.Helper()
	before := runtimeCreateCount(runtime, id)
	restarted := newTestController(t, deps, runtime, nil, WithBootIDSource(fixedBootID(otherBootID)))
	snapshot, err := restarted.GetRun(context.Background(), executionwire.GetRunRequest{RunID: id})
	if err != nil || snapshot.Status.State != executionwire.RunStateInterrupted || len(snapshot.Events) != 1 ||
		snapshot.Events[0].Failure == nil || snapshot.Events[0].Failure.Message != messageInterrupted {
		t.Fatalf("original interrupted candidate did not publish: %#v, %v", snapshot, err)
	}
	if after := runtimeCreateCount(runtime, id); after != before {
		t.Fatalf("boot-fence reconciliation issued another Create: before=%d after=%d", before, after)
	}
}

func runtimeCreateCount(runtime *fakeRuntime, id string) int {
	count := 0
	for _, call := range runtime.callSnapshot() {
		if call == "create:"+id {
			count++
		}
	}
	return count
}

// Simulates a live container after the attached process has returned, failed
// removal, a controller restart with a reopened DB, and eventual cleanup. It
// proves controller/store ordering, not actual Docker descendant containment.
func TestStagedSuccessSurvivesCleanupFailureAndStoreReopen(t *testing.T) {
	manifest := controllerManifest("target-publish", "target-publish-r1", "workspace-publish",
		targetmanifest.WorkspaceReadWrite, targetmanifest.SessionOpaqueResume)
	deps := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	runtime.removeErr = errors.New("injected cleanup failure")
	var bridgeCalls atomic.Int32
	bridge := func(ctx context.Context, req executionwire.StartRunRequest, _ targetmanifest.Definition, _ *string,
		_ io.Reader, _ io.Writer, sink runnerbridge.Sink) error {
		bridgeCalls.Add(1)
		if err := sink(ctx, startedEmission(req.RunID)); err != nil {
			return err
		}
		token := "synthetic-private-token"
		return sink(ctx, completedEmission(req.RunID, 2, "exact original result", &token))
	}
	controller, err := New(context.Background(), deps.durable, deps.registry, deps.store, runtime,
		WithBridge(bridge), WithSessionRefGenerator(func() (string, error) { return "session_publish", nil }),
		WithBootIDSource(fixedBootID(testBootID)), WithCleanupTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	request := controllerRequest("run_publish", manifest, "work")
	if _, err := controller.StartRun(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	run := awaitRun(t, deps.store, request.RunID, func(r sandboxstore.Run) bool { return r.TerminalPending })
	if run.Output != nil || run.ResultSessionRef != nil || run.TerminalAt != nil || !run.WorkspaceLockHeld || run.RuntimeRef == nil {
		t.Fatalf("unproved cleanup exposed result/released authority: %#v", run)
	}
	snapshot, err := controller.GetRun(context.Background(), executionwire.GetRunRequest{RunID: request.RunID})
	if err != nil || snapshot.Status.State != executionwire.RunStateRunning || len(snapshot.Events) != 1 {
		t.Fatalf("Core-visible view contains terminal: %#v, %v", snapshot, err)
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := controller.Close(closeCtx); !errors.Is(err, ErrCleanup) {
		t.Fatalf("cleanup failure not retained: %v", err)
	}
	if err := deps.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sandboxstore.Open(context.Background(), deps.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	deps.store = reopened
	deps.durable, err = sandboxservice.New(context.Background(), deps.registry, reopened, controllerStateOwnership)
	if err != nil {
		t.Fatal(err)
	}
	// No controller is running while the fake runtime recovers.
	runtime.removeErr = nil
	restarted := newTestController(t, deps, runtime, bridge)
	snapshot, err = restarted.GetRun(context.Background(), executionwire.GetRunRequest{RunID: request.RunID})
	if err != nil || snapshot.Status.State != executionwire.RunStateCompleted || len(snapshot.Events) != 2 ||
		snapshot.Events[1].Result.Output.Text != "exact original result" {
		t.Fatalf("restart replaced/lost candidate: %#v, %v", snapshot, err)
	}
	if bridgeCalls.Load() != 1 {
		t.Fatalf("restart executed harness again: %d", bridgeCalls.Load())
	}
	run, err = reopened.GetRun(context.Background(), request.RunID)
	if err != nil || run.TerminalPending || run.RuntimeRef != nil || run.WorkspaceLockHeld || run.ResultSessionRef == nil || *run.ResultSessionRef != "session_publish" {
		t.Fatalf("publication did not release authority/bind session: %#v, %v", run, err)
	}
	creates := runtimeCreateCount(runtime, request.RunID)
	if creates != 1 {
		t.Fatalf("create count after restart = %d", creates)
	}
}

type lostStageResponseStore struct {
	*sandboxstore.Store
	calls atomic.Int32
}

func (s *lostStageResponseStore) StageTerminal(ctx context.Context, event executionwire.RunEvent, mapping *sandboxstore.SessionMapping) (sandboxstore.Run, error) {
	run, err := s.Store.StageTerminal(ctx, event, mapping)
	if s.calls.Add(1) == 1 && err == nil {
		return sandboxstore.Run{}, errors.New("injected lost staging response")
	}
	return run, err
}

func TestCommittedCandidateWinsLostStagingResponse(t *testing.T) {
	manifest := controllerManifest("target-stage-response", "target-stage-response-r1", "workspace-stage-response",
		targetmanifest.WorkspaceReadWrite, targetmanifest.SessionOpaqueResume)
	deps := newTestDependencies(t, manifest)
	store := &lostStageResponseStore{Store: deps.store}
	runtime := newFakeRuntime()
	var refs atomic.Int32
	bridge := func(ctx context.Context, req executionwire.StartRunRequest, _ targetmanifest.Definition, _ *string,
		_ io.Reader, _ io.Writer, sink runnerbridge.Sink) error {
		if err := sink(ctx, startedEmission(req.RunID)); err != nil {
			return err
		}
		token := "synthetic-lost-response-token"
		return sink(ctx, completedEmission(req.RunID, 2, "preserved success", &token))
	}
	controller, err := New(context.Background(), deps.durable, deps.registry, store, runtime,
		WithBridge(bridge), WithBootIDSource(fixedBootID(testBootID)),
		WithSessionRefGenerator(func() (string, error) {
			refs.Add(1)
			return "session_lost_stage_response", nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := controller.Close(ctx); err != nil {
			t.Errorf("close controller: %v", err)
		}
	})
	request := controllerRequest("run_lost_stage_response", manifest, "work")
	if _, err := controller.StartRun(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	run := awaitTerminal(t, deps.store, request.RunID)
	if run.State != executionwire.RunStateCompleted || run.TerminalPending || run.WorkspaceLockHeld || run.RuntimeRef != nil ||
		run.ResultSessionRef == nil || *run.ResultSessionRef != "session_lost_stage_response" || run.Output == nil || run.Output.Text != "preserved success" {
		t.Fatalf("ambiguous staging replaced/lost success: %#v", run)
	}
	snapshot, err := controller.GetRun(context.Background(), executionwire.GetRunRequest{RunID: request.RunID})
	if err != nil || len(snapshot.Events) != 2 || store.calls.Load() != 1 || refs.Load() != 1 || runtimeCreateCount(runtime, request.RunID) != 1 {
		t.Fatalf("ambiguous response duplicated execution or outcome: snapshot=%#v err=%v stages=%d refs=%d", snapshot, err, store.calls.Load(), refs.Load())
	}
}
