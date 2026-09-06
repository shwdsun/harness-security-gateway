package agentdispatch

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
)

// Exercises the two real SQLite stores and dispatch/service path. Runtime
// cleanup proof is supplied explicitly here; controller cleanup is tested in
// sandboxcontroller, and actual Docker containment is a separate live gate.
func TestCoreOutboxWaitsForSandboxTerminalPublication(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{now: time.Now().UTC().Truncate(time.Millisecond)}
	core, corePath, _ := openCoreStore(t, clock, &tokenSequence{})
	store, service := openSessionIntegrationSandbox(t, filepath.Join(t.TempDir(), "sandbox.sqlite3"), clock)
	defer store.Close()
	run := ingestSessionIntegrationRunAt(t, core, "run_staged_outbox", "event_staged_outbox", clock.Now())
	ref := "session_staged_outbox"
	sandbox := &committedServiceSandbox{service: service}
	sandbox.afterSave = func(ctx context.Context, request executionwire.StartRunRequest, _ executionwire.RunStatus) (executionwire.RunStatus, error) {
		if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
			RunID: request.RunID, Seq: 1, Type: executionwire.RunEventStarted,
		}, nil); err != nil {
			return executionwire.RunStatus{}, err
		}
		event := executionwire.RunEvent{RunID: request.RunID, Seq: 2, Type: executionwire.RunEventCompleted,
			Result: &executionwire.RunResult{Output: executionwire.TextOutput{
				MediaType: executionwire.MediaTypeTextPlain, Text: "result after cleanup",
			}, SessionRef: &ref}}
		if _, err := store.StageTerminal(ctx, event, &sandboxstore.SessionMapping{Ref: ref, VendorToken: "synthetic-staged-outbox-token"}); err != nil {
			return executionwire.RunStatus{}, err
		}
		snapshot, err := service.GetRun(ctx, executionwire.GetRunRequest{RunID: request.RunID})
		return snapshot.Status, err
	}
	engine := newEngine(t, core, sandbox, clock)
	result, claimed, err := engine.DispatchOne(ctx)
	if err != nil || !claimed || result.Finished || result.CoreState != corestore.RunRunning {
		t.Fatalf("staged dispatch = %#v claimed=%v err=%v", result, claimed, err)
	}
	db, err := sql.Open("sqlite", corePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	assertDeliveries := func(want int) {
		t.Helper()
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM text_deliveries WHERE run_id = ?`, run.ID).Scan(&count); err != nil || count != want {
			t.Fatalf("Core deliveries=%d want=%d err=%v", count, want, err)
		}
	}
	clock.Advance(48 * time.Hour)
	result, err = engine.Advance(ctx, run.ID)
	if err != nil || result.Finished || result.CoreState != corestore.RunRunning {
		t.Fatalf("Core deadline bypassed pending cleanup: %#v, %v", result, err)
	}
	assertDeliveries(0)
	if _, found, err := core.GetSession(ctx, sessionKeyForRun(run)); err != nil || found {
		t.Fatalf("Core exposed staged session: found=%v err=%v", found, err)
	}
	if _, err := store.ConfirmRuntimeStopped(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	assertDeliveries(0) // Sandbox publication is not a cross-database commit.
	for attempt := 0; attempt < 2; attempt++ {
		result, err = engine.Advance(ctx, run.ID)
		if err != nil || !result.Finished || result.CoreState != corestore.RunCompleted {
			t.Fatalf("published result not applied: %#v, %v", result, err)
		}
	}
	assertDeliveries(1)
	if current, found, err := core.GetSession(ctx, sessionKeyForRun(run)); err != nil || !found || current.Ref != ref || len(sandbox.Starts()) != 1 {
		t.Fatalf("publication lost session or retried Start: session=%#v found=%v err=%v", current, found, err)
	}
}
