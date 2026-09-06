package sandboxstore

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func stageFixture(t *testing.T, store *Store, id string, writable bool, mode targetmanifest.SessionMode) executionwire.StartRunRequest {
	t.Helper()
	ctx := context.Background()
	r := startRequest(id, "private task")
	policy := testSessionPolicy
	if mode == targetmanifest.SessionNewOnly {
		policy = SessionPolicy{Mode: mode}
	}
	if _, _, err := store.RegisterStart(ctx, r, r.ExpectedRevision, "workspace", writable, policy); err != nil {
		t.Fatal(err)
	}
	return r
}

func assertHiddenCandidate(t *testing.T, store *Store, id string, seq uint64) Run {
	t.Helper()
	ctx := context.Background()
	run, err := store.GetRun(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !run.TerminalPending || isTerminal(run.State) || run.Output != nil || run.Failure != nil || run.ResultSessionRef != nil || run.TerminalAt != nil || run.LastEventSeq != seq {
		t.Fatalf("candidate leaked through Run: %#v", run)
	}
	snapshot, err := store.GetSnapshot(ctx, id)
	if err != nil || isTerminal(snapshot.Status.State) || snapshot.Status.LastEventSeq != seq || len(snapshot.Events) != int(seq) {
		t.Fatalf("candidate leaked through snapshot: %#v, %v", snapshot, err)
	}
	var sessions int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("candidate prematurely bound a session: count=%d err=%v", sessions, err)
	}
	return run
}

func TestStagedTerminalHiddenAcrossReopenAndAtomicPublication(t *testing.T) {
	store, path := openTestStore(t)
	ctx := context.Background()
	r := stageFixture(t, store, "run_staged", true, targetmanifest.SessionOpaqueResume)
	if _, _, err := store.BeginRuntimeIntent(ctx, r.RunID, testBootID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetRuntimeRef(ctx, r.RunID, "runtime-staged"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendEvent(ctx, executionwire.RunEvent{RunID: r.RunID, Seq: 1, Type: executionwire.RunEventStarted}, nil); err != nil {
		t.Fatal(err)
	}
	ref := "session_staged"
	event := executionwire.RunEvent{RunID: r.RunID, Seq: 2, Type: executionwire.RunEventCompleted,
		Result: &executionwire.RunResult{Output: executionwire.TextOutput{MediaType: executionwire.MediaTypeTextPlain, Text: "private result"}, SessionRef: &ref}}
	mapping := &SessionMapping{Ref: ref, VendorToken: "private-synthetic-token"}
	if _, err := store.StageTerminal(ctx, event, mapping); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageTerminal(ctx, event, mapping); err != nil {
		t.Fatalf("exact staged replay: %v", err)
	}
	run := assertHiddenCandidate(t, store, r.RunID, 1)
	if !run.WorkspaceLockHeld || run.RuntimeRef == nil {
		t.Fatal("staging released authority")
	}
	if _, err := store.AppendEvent(ctx, event, mapping); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("direct publication bypass = %v", err)
	}
	if _, err := store.MarkCancelling(ctx, r.RunID); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("cancellation replaced staged decision: %v", err)
	}
	changed := *mapping
	changed.VendorToken = "different-token"
	if _, err := store.StageTerminal(ctx, event, &changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting stage = %v", err)
	}
	child := startRequest("run_early_child", "resume too soon")
	child.SessionRef = &ref
	if _, _, err := registerTestStart(store, ctx, child, child.ExpectedRevision, "another-workspace", false); !errors.Is(err, ErrSessionScope) {
		t.Fatalf("unpublished session usable: %v", err)
	}
	for _, query := range []string{
		`UPDATE staged_terminals SET message_text = 'changed'`,
		`DELETE FROM staged_terminals`,
	} {
		if _, err := store.db.Exec(query); err == nil {
			t.Fatalf("candidate mutation accepted: %s", query)
		}
	}
	// Fail late, after event/session creation, to prove they roll back together
	// with the runtime reference and writer lock. No actual runtime is used.
	if _, err := store.db.Exec(`CREATE TRIGGER fail_publication BEFORE DELETE ON workspace_locks
        BEGIN SELECT RAISE(ABORT, 'injected publication failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmRuntimeStopped(ctx, r.RunID); err == nil {
		t.Fatal("publication fault did not fire")
	}
	run = assertHiddenCandidate(t, store, r.RunID, 1)
	if !run.WorkspaceLockHeld || run.RuntimeRef == nil {
		t.Fatal("failed publication partially released authority")
	}
	if _, err := store.db.Exec(`DROP TRIGGER fail_publication`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertHiddenCandidate(t, reopened, r.RunID, 1)
	// Simulate the trusted controller's cleanup proof.
	run, err = reopened.ConfirmRuntimeStopped(ctx, r.RunID)
	if err != nil || run.State != executionwire.RunStateCompleted || run.TerminalPending || run.RuntimeRef != nil || run.WorkspaceLockHeld || run.ResultSessionRef == nil || *run.ResultSessionRef != ref {
		t.Fatalf("atomic publication = %#v, %v", run, err)
	}
	if _, err := reopened.ConfirmRuntimeStopped(ctx, r.RunID); err != nil {
		t.Fatalf("publication retry = %v", err)
	}
	snapshot, err := reopened.GetSnapshot(ctx, r.RunID)
	if err != nil || len(snapshot.Events) != 2 || snapshot.Events[1].Result.Output.Text != "private result" {
		t.Fatalf("published history = %#v, %v", snapshot, err)
	}
	if _, _, err := registerTestStart(reopened, ctx, child, child.ExpectedRevision, "workspace", true); err != nil {
		t.Fatalf("post-publication resume = %v", err)
	}
	token, err := reopened.ResolveSessionForRun(ctx, child.RunID, ref, child.TargetID, child.ExpectedRevision, child.SessionScopeDigest)
	if err != nil || token != mapping.VendorToken {
		t.Fatal("published successor did not resolve for its exact child")
	}
}

func TestStagedUncertainIntentCannotPublishBeforeProof(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	r := stageFixture(t, store, "run_uncertain_staged", false, targetmanifest.SessionNewOnly)
	if _, _, err := store.BeginRuntimeIntent(ctx, r.RunID, testBootID); err != nil {
		t.Fatal(err)
	}
	event := executionwire.RunEvent{RunID: r.RunID, Seq: 1, Type: executionwire.RunEventCancelled}
	if _, err := store.StageTerminal(ctx, event, nil); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("uncertain cancellation class allowed: %v", err)
	}
	event.Type = executionwire.RunEventInterrupted
	event.Failure = &executionwire.RunFailure{Code: executionwire.FailureRuntimeInterrupted, Message: "interrupted"}
	if _, err := store.StageTerminal(ctx, event, nil); err != nil {
		t.Fatal(err)
	}
	assertHiddenCandidate(t, store, r.RunID, 0)
	if _, _, err := store.BeginRuntimeIntent(ctx, r.RunID, testBootID); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("candidate minted Create authority: %v", err)
	}
	if _, err := store.ConfirmRuntimeStopped(ctx, r.RunID); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("pending intent published: %v", err)
	}
	if _, err := store.ClearRuntimeIntent(ctx, r.RunID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.BeginRuntimeIntent(ctx, r.RunID, testBootID); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("cleared candidate minted another Create: %v", err)
	}
	if _, err := store.ReconcileInterrupted(ctx, r.RunID, "replacement"); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("legacy reconciliation bypass = %v", err)
	}
	runs, err := store.ListUnreconciled(ctx)
	if err != nil || len(runs) != 1 || !runs[0].TerminalPending {
		t.Fatalf("read-only no-ref candidate lost: %#v, %v", runs, err)
	}
	if _, err := store.ConfirmRuntimeStopped(ctx, r.RunID); err != nil {
		t.Fatal(err)
	}
}

func TestStagedTerminalValidationAndCancellation(t *testing.T) {
	for _, typ := range []executionwire.RunEventType{executionwire.RunEventCancelled, executionwire.RunEventFailed} {
		t.Run(string(typ), func(t *testing.T) {
			store, _ := openTestStore(t)
			ctx := context.Background()
			r := stageFixture(t, store, "run_stage_failure", false, targetmanifest.SessionNewOnly)
			event := executionwire.RunEvent{RunID: r.RunID, Seq: 1, Type: typ}
			if typ == executionwire.RunEventFailed {
				event.Failure = &executionwire.RunFailure{Code: executionwire.FailureRunnerFailed, Message: "sanitized"}
			}
			if _, err := store.StageTerminal(ctx, event, &SessionMapping{Ref: "bad", VendorToken: "bad"}); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("non-completion mapping accepted: %v", err)
			}
			if _, err := store.StageTerminal(ctx, event, nil); err != nil {
				t.Fatal(err)
			}
			assertHiddenCandidate(t, store, r.RunID, 0)
			if _, err := store.ConfirmRuntimeStopped(ctx, r.RunID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMigrationEightPreservesVersionSevenEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v7.sqlite3")
	db := createLegacySandboxDatabase(t, path, 7)
	// Historical evidence is written with the historical schema, not today's
	// registration API (which now requires the explicit state-kind column).
	insertLegacyTargetAuthority(t, db,
		testTargetAuthority("target-codex", "target-codex-r1", "state-codex", 'a', '1', true))
	// A v7 public terminal may retain runtime authority. Migration must not
	// hide or relabel that historical outcome or pretend cleanup occurred.
	if _, err := db.Exec(`INSERT INTO runs(
        run_id, request_fingerprint, target_id, target_revision, workspace_id,
        writable, input_sha256, deadline_unix_ms, state, runtime_ref,
        session_scope_digest, session_mode, session_max_age_seconds,
        session_max_turns, session_turn_number, created_at_unix_ms, updated_at_unix_ms
    ) VALUES ('run_v7_history', ?, 'target-codex', 'target-codex-r1', 'workspace',
        0, ?, 1, 'accepted', 'legacy-runtime', ?, 'new_only', 0, 0, 0, 1, 1)`,
		strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO run_events(run_id, seq, event_type, created_at_unix_ms)
        VALUES ('run_v7_history', 1, 'cancelled', 2)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE runs SET state = 'cancelled', last_event_seq = 1,
        terminal_at_unix_ms = 2, updated_at_unix_ms = 2 WHERE run_id = 'run_v7_history'`); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := db.QueryRow(`SELECT group_concat(checksum, ',') FROM (SELECT checksum FROM schema_migrations ORDER BY version)`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var after string
	if err := store.db.QueryRow(`SELECT group_concat(checksum, ',') FROM (SELECT checksum FROM schema_migrations WHERE version <= 7 ORDER BY version)`).Scan(&after); err != nil || before != after {
		t.Fatalf("legacy migration checksums changed: %v", err)
	}
	run, err := store.GetRun(context.Background(), "run_v7_history")
	if err != nil || run.State != executionwire.RunStateCancelled || run.TerminalPending || run.RuntimeRef == nil ||
		*run.RuntimeRef != "legacy-runtime" || run.TerminalAt == nil || run.TerminalAt.UnixMilli() != 2 {
		t.Fatalf("migration rewrote legacy terminal/authority: %#v, %v", run, err)
	}
	snapshot, err := store.GetSnapshot(context.Background(), run.RunID)
	if err != nil || len(snapshot.Events) != 1 || snapshot.Events[0].Type != executionwire.RunEventCancelled {
		t.Fatalf("migration rewrote legacy event history: %#v, %v", snapshot, err)
	}
}
