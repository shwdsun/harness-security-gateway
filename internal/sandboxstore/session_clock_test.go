package sandboxstore

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
)

func TestSuccessorCreationRejectsClockRollbackBeforeRunAdmission(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()
	policy := lifecyclePolicy(60, 3)
	createLifecycleSession(t, store, "run_clock_parent", "session_clock_parent", policy, base)

	resume := startRequest("run_clock_child", "continue")
	resume.SessionRef = stringPointerValue("session_clock_parent")
	run, created, err := store.registerStartAt(
		ctx, resume, resume.ExpectedRevision, "workspace-clock-child", false, policy, base+20_000,
	)
	if err != nil || !created {
		t.Fatalf("register resumed Run = (%#v, %t, %v)", run, created, err)
	}
	if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
		RunID: run.RunID, Seq: 1, Type: executionwire.RunEventStarted,
	}, nil); err != nil {
		t.Fatal(err)
	}
	run, err = store.GetRun(ctx, run.RunID)
	if err != nil {
		t.Fatal(err)
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindSession(ctx, tx, run, SessionMapping{
		Ref: "session_clock_store_child", VendorToken: "vendor-clock-store",
	}, base+10_000); !errors.Is(err, ErrSessionScope) {
		_ = tx.Rollback()
		t.Fatalf("bindSession() rollback error = %v, want ErrSessionScope", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	if _, err := store.db.Exec(`INSERT INTO sessions(
        session_ref, target_id, target_revision, session_scope_digest,
        vendor_token, parent_session_ref, created_by_run_id,
        lineage_started_at_unix_ms, expires_at_unix_ms, turn_number,
        created_at_unix_ms
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session_clock_sql_child", run.TargetID, run.TargetRevision, run.SessionScopeDigest,
		"vendor-clock-sql", "session_clock_parent", run.RunID,
		base, base+60_000, 2, base+10_000,
	); err == nil {
		t.Fatal("schema accepted a successor created before its Run admission")
	}

	tx, err = store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindSession(ctx, tx, run, SessionMapping{
		Ref: "session_clock_valid_child", VendorToken: "vendor-clock-valid",
	}, base+20_001); err != nil {
		_ = tx.Rollback()
		t.Fatalf("bindSession() monotonic successor error = %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestSuccessorAdmissionRejectsClockBeforeParentConsumption(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	policy := lifecyclePolicy(60, 3)
	createLifecycleSession(
		t, store, "run_clock_chain_parent", "session_clock_chain_parent", policy,
		time.Now().UTC().Add(-time.Second).UnixMilli(),
	)

	var parentCreatedAtMS int64
	if err := store.db.QueryRow(`SELECT created_at_unix_ms FROM sessions
        WHERE session_ref = 'session_clock_chain_parent'`).Scan(&parentCreatedAtMS); err != nil {
		t.Fatal(err)
	}
	consumeAtMS := parentCreatedAtMS
	resume := startRequest("run_clock_chain_child", "continue")
	resume.SessionRef = stringPointerValue("session_clock_chain_parent")
	run, created, err := store.registerStartAt(
		ctx, resume, resume.ExpectedRevision, "workspace-clock-chain-child", false, policy, consumeAtMS,
	)
	if err != nil || !created {
		t.Fatalf("register resumed Run = (%#v, %t, %v)", run, created, err)
	}
	if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
		RunID: run.RunID, Seq: 1, Type: executionwire.RunEventStarted,
	}, nil); err != nil {
		t.Fatal(err)
	}
	childRef := "session_clock_chain_child"
	if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
		RunID: run.RunID,
		Seq:   2,
		Type:  executionwire.RunEventCompleted,
		Result: &executionwire.RunResult{
			Output: executionwire.TextOutput{
				MediaType: executionwire.MediaTypeTextPlain, Text: "done",
			},
			SessionRef: &childRef,
		},
	}, &SessionMapping{Ref: childRef, VendorToken: "vendor-clock-chain-child"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmRuntimeStopped(ctx, run.RunID); err != nil {
		t.Fatal(err)
	}

	var childCreatedAtMS int64
	if err := store.db.QueryRow(`SELECT created_at_unix_ms FROM sessions
        WHERE session_ref = ?`, childRef).Scan(&childCreatedAtMS); err != nil {
		t.Fatal(err)
	}
	if childCreatedAtMS < consumeAtMS {
		t.Fatalf("successor created_at = %d, want >= consuming Run time %d", childCreatedAtMS, consumeAtMS)
	}

	rollback := startRequest("run_clock_chain_rollback", "continue again")
	rollback.SessionRef = &childRef
	if _, _, err := store.registerStartAt(
		ctx, rollback, rollback.ExpectedRevision, "workspace-clock-chain-rollback", false,
		policy, consumeAtMS-1,
	); !errors.Is(err, ErrSessionScope) {
		t.Fatalf("successor admission before parent consumption error = %v, want ErrSessionScope", err)
	}
}

func TestRegisterStartSamplesLifecycleClockAfterSQLiteAuthority(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()
	policy := lifecyclePolicy(60, 3)
	createLifecycleSession(t, store, "run_wait_parent", "session_wait_parent", policy, base)

	blocker, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	baselineWaits := store.db.Stats().WaitCount

	resume := startRequest("run_wait_child", "continue")
	resume.SessionRef = stringPointerValue("session_wait_parent")
	type registrationResult struct {
		err error
	}
	result := make(chan registrationResult, 1)
	clockCalled := make(chan struct{})
	var authorityReleased atomic.Bool
	go func() {
		_, _, registrationErr := store.registerStartWithClock(
			ctx, resume, resume.ExpectedRevision, "workspace-wait-child", false, policy,
			func() int64 {
				close(clockCalled)
				if authorityReleased.Load() {
					return base + 60_000
				}
				return base + 59_999
			},
		)
		result <- registrationResult{err: registrationErr}
	}()

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for store.db.Stats().WaitCount == baselineWaits {
		select {
		case <-clockCalled:
			authorityReleased.Store(true)
			_ = blocker.Rollback()
			<-result
			t.Fatal("lifecycle clock was sampled before SQLite connection authority")
		case <-ticker.C:
		case <-deadline.C:
			authorityReleased.Store(true)
			_ = blocker.Rollback()
			<-result
			t.Fatal("registration did not wait for the Store's SQLite authority")
		}
	}
	select {
	case <-clockCalled:
		authorityReleased.Store(true)
		_ = blocker.Rollback()
		<-result
		t.Fatal("lifecycle clock was sampled while SQLite authority remained blocked")
	default:
	}

	authorityReleased.Store(true)
	if err := blocker.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-clockCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("lifecycle clock was not sampled after SQLite authority became available")
	}
	if got := <-result; !errors.Is(got.err, ErrSessionScope) {
		t.Fatalf("registration at expiry error = %v, want ErrSessionScope", got.err)
	}
}
