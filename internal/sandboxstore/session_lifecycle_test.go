package sandboxstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func lifecyclePolicy(ageSeconds, turns int64) SessionPolicy {
	return SessionPolicy{
		Mode:          targetmanifest.SessionOpaqueResume,
		MaxAgeSeconds: ageSeconds,
		MaxTurns:      turns,
	}
}

func createLifecycleSession(
	t *testing.T,
	store *Store,
	runID string,
	ref string,
	policy SessionPolicy,
	nowMS int64,
) executionwire.StartRunRequest {
	t.Helper()
	ctx := context.Background()
	request := startRequest(runID, "establish session")
	if _, _, err := store.registerStartAt(
		ctx, request, request.ExpectedRevision, "workspace-"+runID, false, policy, nowMS,
	); err != nil {
		t.Fatalf("register initial session Run: %v", err)
	}
	if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
		RunID: runID, Seq: 1, Type: executionwire.RunEventStarted,
	}, nil); err != nil {
		t.Fatalf("append initial started event: %v", err)
	}
	if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
		RunID: runID,
		Seq:   2,
		Type:  executionwire.RunEventCompleted,
		Result: &executionwire.RunResult{
			Output:     executionwire.TextOutput{MediaType: executionwire.MediaTypeTextPlain, Text: "done"},
			SessionRef: &ref,
		},
	}, &SessionMapping{Ref: ref, VendorToken: "vendor-" + runID}); err != nil {
		t.Fatalf("append initial completed event: %v", err)
	}
	if _, err := store.ConfirmRuntimeStopped(ctx, runID); err != nil {
		t.Fatalf("confirm initial Run stopped: %v", err)
	}
	return request
}

func TestSessionResumeIsOneUseAndExactRetryDoesNotRecharge(t *testing.T) {
	store, path := openTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()
	policy := lifecyclePolicy(60, 3)
	initial := createLifecycleSession(t, store, "run_initial", "session_parent", policy, base)

	resume := startRequest("run_resume", "continue")
	resume.SessionRef = stringPointerValue("session_parent")
	first, created, err := store.registerStartAt(
		ctx, resume, resume.ExpectedRevision, "workspace-resume", false, policy, base+1_000,
	)
	if err != nil || !created || first.SessionTurnNumber != 2 {
		t.Fatalf("first resume registration = (%#v, %t, %v)", first, created, err)
	}
	resolved, err := store.ResolveSessionForRun(
		ctx, resume.RunID, "session_parent", resume.TargetID,
		resume.ExpectedRevision, resume.SessionScopeDigest,
	)
	if err != nil || resolved != "vendor-"+initial.RunID {
		t.Fatalf("ResolveSessionForRun() = %q, %v", resolved, err)
	}

	again, created, err := store.registerStartAt(
		ctx, resume, resume.ExpectedRevision, "workspace-resume", false, policy, base+120_000,
	)
	if err != nil || created || again.RunID != resume.RunID || again.SessionTurnNumber != 2 {
		t.Fatalf("exact retry = (%#v, %t, %v)", again, created, err)
	}
	var uses int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM session_uses
        WHERE session_ref = 'session_parent' AND run_id = 'run_resume'`).Scan(&uses); err != nil {
		t.Fatal(err)
	}
	if uses != 1 {
		t.Fatalf("session use rows = %d, want 1", uses)
	}

	if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
		RunID: resume.RunID,
		Seq:   1,
		Type:  executionwire.RunEventFailed,
		Failure: &executionwire.RunFailure{
			Code: executionwire.FailureRunnerFailed, Message: "closed failure",
		},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResolveSessionForRun(
		ctx, resume.RunID, "session_parent", resume.TargetID,
		resume.ExpectedRevision, resume.SessionScopeDigest,
	); !errors.Is(err, ErrSessionScope) {
		t.Fatalf("terminal Run session resolve error = %v", err)
	}
	if _, err := store.ConfirmRuntimeStopped(ctx, resume.RunID); err != nil {
		t.Fatal(err)
	}
	stale := startRequest("run_stale", "retry stale parent")
	stale.SessionRef = stringPointerValue("session_parent")
	if _, _, err := store.registerStartAt(
		ctx, stale, stale.ExpectedRevision, "workspace-stale", false, policy, base+2_000,
	); !errors.Is(err, ErrSessionScope) {
		t.Fatalf("stale parent registration error = %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, _, err := reopened.registerStartAt(
		ctx, stale, stale.ExpectedRevision, "workspace-stale", false, policy, base+3_000,
	); !errors.Is(err, ErrSessionScope) {
		t.Fatalf("reopened stale parent registration error = %v", err)
	}
}

func TestSessionScopeAllowsOnlyOneLiveRunWithExactRetryPrecedence(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 16, 11, 0, 0, 0, time.UTC).UnixMilli()
	policy := lifecyclePolicy(60, 3)
	firstRequest := startRequest("run_scope_live_first", "first")

	first, created, err := store.registerStartAt(
		ctx, firstRequest, firstRequest.ExpectedRevision,
		"workspace-scope-live-first", false, policy, base,
	)
	if err != nil || !created {
		t.Fatalf("first registration = (%#v, %t, %v)", first, created, err)
	}
	retry, created, err := store.registerStartAt(
		ctx, firstRequest, firstRequest.ExpectedRevision,
		"workspace-scope-live-first", false, policy, base+1,
	)
	if err != nil || created || retry.RunID != first.RunID || retry.Fingerprint != first.Fingerprint {
		t.Fatalf("exact live retry = (%#v, %t, %v), want original Run", retry, created, err)
	}

	contender := startRequest("run_scope_live_contender", "contender")
	if _, _, err := store.registerStartAt(
		ctx, contender, contender.ExpectedRevision,
		"workspace-scope-live-contender", false, policy, base+2,
	); !errors.Is(err, ErrSessionBusy) {
		t.Fatalf("same-scope contender error = %v, want ErrSessionBusy", err)
	}
	if _, err := store.GetRun(ctx, contender.RunID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("same-scope contender was persisted: %v", err)
	}

	if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
		RunID: firstRequest.RunID,
		Seq:   1,
		Type:  executionwire.RunEventFailed,
		Failure: &executionwire.RunFailure{
			Code: executionwire.FailureRunnerFailed, Message: "closed failure",
		},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmRuntimeStopped(ctx, firstRequest.RunID); err != nil {
		t.Fatal(err)
	}
	accepted, created, err := store.registerStartAt(
		ctx, contender, contender.ExpectedRevision,
		"workspace-scope-live-contender", false, policy, base+3,
	)
	if err != nil || !created || accepted.RunID != contender.RunID {
		t.Fatalf("post-terminal registration = (%#v, %t, %v)", accepted, created, err)
	}
}

func TestSessionScopePartialUniqueIndexRejectsDirectSQLBypass(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 16, 11, 0, 0, 0, time.UTC).UnixMilli()
	policy := lifecyclePolicy(60, 3)
	request := startRequest("run_scope_sql_first", "first")
	if _, _, err := store.registerStartAt(
		ctx, request, request.ExpectedRevision,
		"workspace-scope-sql-first", false, policy, base,
	); err != nil {
		t.Fatal(err)
	}

	const bypassRunID = "run_scope_sql_bypass"
	_, err := store.db.Exec(`INSERT INTO runs(
	    run_id, request_fingerprint, target_id, target_revision,
	    workspace_id, writable, input_sha256, session_scope_digest,
	    session_mode, session_max_age_seconds, session_max_turns,
	    session_turn_number, deadline_unix_ms, state,
	    created_at_unix_ms, updated_at_unix_ms
	) VALUES (?, ?, ?, ?, ?, 0, ?, ?, 'opaque_resume', 60, 3, 1, ?,
	          'accepted', ?, ?)`,
		bypassRunID, strings.Repeat("b", 64), request.TargetID,
		request.ExpectedRevision, "workspace-scope-sql-bypass",
		strings.Repeat("c", 64), request.SessionScopeDigest,
		request.Deadline.UnixMilli(), base+1, base+1,
	)
	if err == nil {
		t.Fatal("partial unique index accepted a second live Run in the same session scope")
	}
	var persisted int
	if countErr := store.db.QueryRow(
		`SELECT COUNT(*) FROM runs WHERE run_id = ?`, bypassRunID,
	).Scan(&persisted); countErr != nil {
		t.Fatal(countErr)
	}
	if persisted != 0 {
		t.Fatalf("direct SQL bypass persisted %d Run(s)", persisted)
	}
}

func TestConsumedSessionParentRemainsSpentAcrossTerminalOutcomesAndReopen(t *testing.T) {
	tests := []struct {
		name    string
		event   executionwire.RunEventType
		failure *executionwire.RunFailure
	}{
		{
			name:  "failed",
			event: executionwire.RunEventFailed,
			failure: &executionwire.RunFailure{
				Code: executionwire.FailureRunnerFailed, Message: "closed failure",
			},
		},
		{name: "cancelled", event: executionwire.RunEventCancelled},
		{
			name:  "interrupted",
			event: executionwire.RunEventInterrupted,
			failure: &executionwire.RunFailure{
				Code: executionwire.FailureRuntimeInterrupted, Message: "closed interruption",
			},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store, path := openTestStore(t)
			base := time.Now().UTC().Add(-time.Hour).UnixMilli()
			resumeAt := base + int64((90*time.Minute)/time.Millisecond)
			policy := lifecyclePolicy(2*60*60, 4)
			parentRef := fmt.Sprintf("session_terminal_parent_%d", index)
			createLifecycleSession(
				t, store, fmt.Sprintf("run_terminal_parent_%d", index),
				parentRef, policy, base,
			)

			resume := startRequest(fmt.Sprintf("run_terminal_resume_%d", index), "resume")
			resume.SessionRef = &parentRef
			if _, created, err := store.registerStartAt(
				ctx, resume, resume.ExpectedRevision,
				fmt.Sprintf("workspace-terminal-resume-%d", index), false, policy, resumeAt,
			); err != nil || !created {
				t.Fatalf("resume registration = (%t, %v)", created, err)
			}
			if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
				RunID: resume.RunID, Seq: 1, Type: test.event, Failure: test.failure,
			}, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ConfirmRuntimeStopped(ctx, resume.RunID); err != nil {
				t.Fatal(err)
			}

			beforeReopen := startRequest(fmt.Sprintf("run_terminal_reuse_before_%d", index), "reuse")
			beforeReopen.SessionRef = &parentRef
			if _, _, err := store.registerStartAt(
				ctx, beforeReopen, beforeReopen.ExpectedRevision,
				fmt.Sprintf("workspace-terminal-reuse-before-%d", index), false, policy, resumeAt+1_000,
			); !errors.Is(err, ErrSessionScope) {
				t.Fatalf("parent reuse before reopen error = %v, want ErrSessionScope", err)
			}

			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			afterReopen := startRequest(fmt.Sprintf("run_terminal_reuse_after_%d", index), "reuse")
			afterReopen.SessionRef = &parentRef
			if _, _, err := reopened.registerStartAt(
				ctx, afterReopen, afterReopen.ExpectedRevision,
				fmt.Sprintf("workspace-terminal-reuse-after-%d", index), false, policy, resumeAt+2_000,
			); !errors.Is(err, ErrSessionScope) {
				t.Fatalf("parent reuse after reopen error = %v, want ErrSessionScope", err)
			}
		})
	}
}

func TestSessionAgeAndTurnLimitsFailClosedAtBoundary(t *testing.T) {
	tests := []struct {
		name       string
		ageSeconds int64
		maxTurns   int64
		offsetMS   int64
		wantError  bool
	}{
		{name: "before expiry", ageSeconds: 60, maxTurns: 2, offsetMS: 59_999},
		{name: "at expiry", ageSeconds: 60, maxTurns: 2, offsetMS: 60_000, wantError: true},
		{name: "after expiry", ageSeconds: 60, maxTurns: 2, offsetMS: 60_001, wantError: true},
		{name: "clock rollback", ageSeconds: 60, maxTurns: 2, offsetMS: -1, wantError: true},
		{name: "turn exhausted", ageSeconds: 60, maxTurns: 1, offsetMS: 1, wantError: true},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, _ := openTestStore(t)
			base := time.Now().UTC().UnixMilli()
			policy := lifecyclePolicy(test.ageSeconds, test.maxTurns)
			ref := fmt.Sprintf("session_limit_%d", index)
			createLifecycleSession(t, store, fmt.Sprintf("run_limit_%d", index), ref, policy, base)
			resume := startRequest(fmt.Sprintf("run_limit_resume_%d", index), "continue")
			resume.SessionRef = &ref
			_, _, err := store.registerStartAt(
				context.Background(), resume, resume.ExpectedRevision,
				fmt.Sprintf("workspace-limit-%d", index), false, policy, base+test.offsetMS,
			)
			if test.wantError && !errors.Is(err, ErrSessionScope) {
				t.Fatalf("registration error = %v, want ErrSessionScope", err)
			}
			if !test.wantError && err != nil {
				t.Fatalf("registration error = %v", err)
			}
		})
	}
}

func TestSessionAdmissionFailuresUseOneClosedError(t *testing.T) {
	for index, name := range []string{
		"unknown",
		"wrong target",
		"wrong revision",
		"wrong scope digest",
		"already used",
		"at expiry",
		"turn exhausted",
		"clock rollback",
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := openTestStore(t)
			ctx := context.Background()
			policy := lifecyclePolicy(600, 3)
			if name == "turn exhausted" {
				policy.MaxTurns = 1
			}
			parentRef := fmt.Sprintf("session_closed_error_%d", index)
			createLifecycleSession(
				t, store, fmt.Sprintf("run_closed_error_parent_%d", index), parentRef,
				policy, time.Now().UTC().Add(-time.Second).UnixMilli(),
			)

			var createdAtMS, expiresAtMS int64
			if err := store.db.QueryRow(`SELECT created_at_unix_ms, expires_at_unix_ms
                    FROM sessions WHERE session_ref = ?`, parentRef,
			).Scan(&createdAtMS, &expiresAtMS); err != nil {
				t.Fatal(err)
			}
			attempt := startRequest(fmt.Sprintf("run_closed_error_attempt_%d", index), "continue")
			attempt.SessionRef = &parentRef
			nowMS := createdAtMS

			switch name {
			case "unknown":
				unknown := fmt.Sprintf("session_closed_error_unknown_%d", index)
				attempt.SessionRef = &unknown
			case "wrong target":
				if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{
					testTargetAuthority("target-other", "target-other-r1", "state-other", 'b', '2', true),
				}); err != nil {
					t.Fatal(err)
				}
				attempt.TargetID = "target-other"
				attempt.ExpectedRevision = "target-other-r1"
			case "wrong revision":
				if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{
					testTargetAuthority("target-codex", "target-codex-r2", "state-codex-r2", 'c', '3', true),
				}); err != nil {
					t.Fatal(err)
				}
				attempt.ExpectedRevision = "target-codex-r2"
			case "wrong scope digest":
				attempt.SessionScopeDigest = strings.Repeat("b", 64)
			case "already used":
				owner := startRequest(fmt.Sprintf("run_closed_error_owner_%d", index), "consume")
				owner.SessionRef = &parentRef
				if _, created, err := store.registerStartAt(
					ctx, owner, owner.ExpectedRevision, fmt.Sprintf("workspace-closed-error-owner-%d", index),
					false, policy, createdAtMS,
				); err != nil || !created {
					t.Fatalf("consume parent = (created %t, error %v)", created, err)
				}
				nowMS++
			case "at expiry":
				nowMS = expiresAtMS
			case "turn exhausted":
			case "clock rollback":
				nowMS--
			}

			_, _, err := store.registerStartAt(
				ctx, attempt, attempt.ExpectedRevision,
				fmt.Sprintf("workspace-closed-error-attempt-%d", index), false, policy, nowMS,
			)
			if err != ErrSessionScope {
				t.Fatalf("session rejection = %T %v, want exact ErrSessionScope", err, err)
			}
		})
	}
}

func TestSessionPolicyHardBoundsAreMirroredByStoreAndSchema(t *testing.T) {
	tests := []struct {
		name   string
		policy SessionPolicy
		ok     bool
	}{
		{
			name: "exact maximum",
			policy: lifecyclePolicy(
				targetmanifest.MaxSessionAgeSeconds,
				int64(targetmanifest.MaxSessionTurns),
			),
			ok: true,
		},
		{
			name: "age above maximum",
			policy: lifecyclePolicy(
				targetmanifest.MaxSessionAgeSeconds+1,
				int64(targetmanifest.MaxSessionTurns),
			),
		},
		{
			name: "turns above maximum",
			policy: lifecyclePolicy(
				targetmanifest.MaxSessionAgeSeconds,
				int64(targetmanifest.MaxSessionTurns+1),
			),
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, _ := openTestStore(t)
			request := startRequest(fmt.Sprintf("run_policy_bound_%d", index), "bounded")
			_, _, err := store.RegisterStart(
				context.Background(), request, request.ExpectedRevision,
				fmt.Sprintf("workspace-policy-%d", index), false, test.policy,
			)
			if test.ok && err != nil {
				t.Fatalf("exact-bound policy rejected: %v", err)
			}
			if !test.ok && !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("out-of-bound policy error = %v, want ErrInvalidArgument", err)
			}
		})
	}

	store, _ := openTestStore(t)
	for index, limits := range [][2]int64{
		{targetmanifest.MaxSessionAgeSeconds + 1, 1},
		{1, int64(targetmanifest.MaxSessionTurns + 1)},
	} {
		_, err := store.db.Exec(`INSERT INTO runs(
            run_id, request_fingerprint, target_id, target_revision,
            workspace_id, writable, input_sha256, session_scope_digest,
            session_mode, session_max_age_seconds, session_max_turns,
            session_turn_number, deadline_unix_ms, state,
            created_at_unix_ms, updated_at_unix_ms
        ) VALUES (?, ?, 'target-codex', 'target-codex-r1', ?, 0, ?, ?,
                  'opaque_resume', ?, ?, 1, ?, 'accepted', ?, ?)`,
			fmt.Sprintf("run_schema_bound_%d", index), strings.Repeat("b", 64),
			fmt.Sprintf("workspace-schema-%d", index), strings.Repeat("c", 64),
			strings.Repeat("a", 64), limits[0], limits[1],
			time.Now().Add(time.Hour).UnixMilli(), time.Now().UnixMilli(), time.Now().UnixMilli(),
		)
		if err == nil {
			t.Fatalf("schema accepted out-of-bound lifecycle limits %#v", limits)
		}
	}
}

func TestCompletedEventMustMatchDurableSessionMode(t *testing.T) {
	t.Run("opaque resume requires successor", func(t *testing.T) {
		store, _ := openTestStore(t)
		ctx := context.Background()
		request := startRequest("run_missing_successor", "finish")
		if _, _, err := registerTestStart(
			store, ctx, request, request.ExpectedRevision, "workspace-missing-successor", false,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
			RunID: request.RunID, Seq: 1, Type: executionwire.RunEventStarted,
		}, nil); err != nil {
			t.Fatal(err)
		}
		completed := executionwire.RunEvent{
			RunID: request.RunID, Seq: 2, Type: executionwire.RunEventCompleted,
			Result: &executionwire.RunResult{Output: executionwire.TextOutput{
				MediaType: executionwire.MediaTypeTextPlain, Text: "done",
			}},
		}
		if _, err := store.AppendEvent(ctx, completed, nil); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("opaque completion without successor error = %v", err)
		}
		if _, err := store.db.Exec(`INSERT INTO run_events(
            run_id, seq, event_type, message_text, output_media_type,
            created_at_unix_ms
        ) VALUES (?, 2, 'completed', 'done', 'text/plain', ?)`,
			request.RunID, time.Now().UnixMilli()); err == nil {
			t.Fatal("schema accepted opaque completion without successor")
		}
	})

	t.Run("new only forbids successor", func(t *testing.T) {
		store, _ := openTestStore(t)
		ctx := context.Background()
		request := startRequest("run_new_only", "finish")
		policy := SessionPolicy{Mode: targetmanifest.SessionNewOnly}
		if _, _, err := store.RegisterStart(
			ctx, request, request.ExpectedRevision, "workspace-new-only", false, policy,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
			RunID: request.RunID, Seq: 1, Type: executionwire.RunEventStarted,
		}, nil); err != nil {
			t.Fatal(err)
		}
		ref := "forbidden_successor"
		completed := executionwire.RunEvent{
			RunID: request.RunID, Seq: 2, Type: executionwire.RunEventCompleted,
			Result: &executionwire.RunResult{
				Output:     executionwire.TextOutput{MediaType: executionwire.MediaTypeTextPlain, Text: "done"},
				SessionRef: &ref,
			},
		}
		if _, err := store.AppendEvent(
			ctx, completed, &SessionMapping{Ref: ref, VendorToken: "forbidden"},
		); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("new_only completion with successor error = %v", err)
		}
		completed.Result.SessionRef = nil
		if _, err := store.AppendEvent(ctx, completed, nil); err != nil {
			t.Fatalf("new_only completion without successor: %v", err)
		}
	})
}

func TestSuccessfulResumeCreatesImmutableSuccessorLineage(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()
	policy := lifecyclePolicy(60, 3)
	createLifecycleSession(t, store, "run_parent", "session_parent", policy, base)
	var parentCreatedAt int64
	if err := store.db.QueryRow(`SELECT created_at_unix_ms FROM sessions
        WHERE session_ref = 'session_parent'`).Scan(&parentCreatedAt); err != nil {
		t.Fatal(err)
	}

	resume := startRequest("run_child", "continue")
	resume.SessionRef = stringPointerValue("session_parent")
	if _, _, err := store.registerStartAt(
		ctx, resume, resume.ExpectedRevision, "workspace-child", false, policy, parentCreatedAt,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
		RunID: resume.RunID, Seq: 1, Type: executionwire.RunEventStarted,
	}, nil); err != nil {
		t.Fatal(err)
	}
	childRef := "session_child"
	if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
		RunID: resume.RunID,
		Seq:   2,
		Type:  executionwire.RunEventCompleted,
		Result: &executionwire.RunResult{
			Output:     executionwire.TextOutput{MediaType: executionwire.MediaTypeTextPlain, Text: "done"},
			SessionRef: &childRef,
		},
	}, &SessionMapping{Ref: childRef, VendorToken: "vendor-run_parent"}); err != nil {
		t.Fatal(err)
	}
	var parent string
	var origin, expiry, turn int64
	if err := store.db.QueryRow(`SELECT parent_session_ref,
        lineage_started_at_unix_ms, expires_at_unix_ms, turn_number
        FROM sessions WHERE session_ref = ?`, childRef).Scan(&parent, &origin, &expiry, &turn); err != nil {
		t.Fatal(err)
	}
	if parent != "session_parent" || origin != base || expiry != base+60_000 || turn != 2 {
		t.Fatalf("successor lineage = parent %q origin %d expiry %d turn %d", parent, origin, expiry, turn)
	}
	if _, err := store.db.Exec(`INSERT INTO run_events(
        run_id, seq, event_type, message_text, output_media_type,
        result_session_ref, created_at_unix_ms
    ) VALUES (?, 3, 'completed', 'forged', 'text/plain', ?, ?)`,
		resume.RunID, "session_parent", time.Now().UTC().UnixMilli(),
	); err == nil {
		t.Fatal("schema accepted a completed event pointing at another Run's session")
	}
	for _, mutation := range []string{
		`UPDATE session_uses SET run_id = 'other' WHERE session_ref = 'session_parent'`,
		`DELETE FROM session_uses WHERE session_ref = 'session_parent'`,
		`UPDATE sessions SET turn_number = 1 WHERE session_ref = 'session_child'`,
	} {
		if _, err := store.db.Exec(mutation); err == nil {
			t.Fatalf("immutable lifecycle mutation succeeded: %s", mutation)
		}
	}
}

func TestMigrationSevenRefusesUnprovenSessionLifecycleBeforeDDL(t *testing.T) {
	// The concrete setup lives in store_test.go helpers; keep the assertions
	// here explicit so a future migration cannot silently adopt either shape.
	for _, kind := range []string{"session", "live_run"} {
		t.Run(kind, func(t *testing.T) {
			path := fmt.Sprintf("%s/sandbox-v6-%s.sqlite3", t.TempDir(), kind)
			db := createLegacySandboxDatabase(t, path, 6)
			insertLegacyTarget(t, db)
			if _, err := db.Exec(`INSERT INTO runner_state_owners(
                runner_state_path_digest, runner_state_ref, target_id, target_revision,
                registered_at_unix_ms
            ) VALUES (?, 'state-codex', 'target-codex', 'target-codex-r1', 1)`,
				strings.Repeat("1", 64)); err != nil {
				t.Fatal(err)
			}
			if kind == "live_run" {
				if _, err := db.Exec(`INSERT INTO runs(
                    run_id, request_fingerprint, target_id, target_revision,
                    workspace_id, writable, input_sha256,
                    session_scope_digest, deadline_unix_ms, state,
                    created_at_unix_ms, updated_at_unix_ms
                ) VALUES ('legacy_live', ?, 'target-codex', 'target-codex-r1',
                    'workspace', 0, ?, ?, 1, 'accepted', 1, 1)`,
					strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("a", 64)); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := db.Exec(`INSERT INTO sessions(
                    session_ref, target_id, target_revision, session_scope_digest,
                    vendor_token, created_at_unix_ms
                ) VALUES ('legacy_ref','target-codex','target-codex-r1',?, 'legacy-token',1)`,
					strings.Repeat("a", 64)); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			store, err := Open(context.Background(), path)
			if store != nil {
				_ = store.Close()
			}
			if !errors.Is(err, ErrUnsafeSessionLifecycleState) {
				t.Fatalf("Open() error = %v, want ErrUnsafeSessionLifecycleState", err)
			}
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version int
			if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
				t.Fatal(err)
			}
			var usesTables int
			if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master
                WHERE type='table' AND name='session_uses'`).Scan(&usesTables); err != nil {
				t.Fatal(err)
			}
			if version != 6 || usesTables != 0 {
				t.Fatalf("refused migration changed state: version=%d session_uses=%d", version, usesTables)
			}
		})
	}
}

func stringPointerValue(value string) *string { return &value }
