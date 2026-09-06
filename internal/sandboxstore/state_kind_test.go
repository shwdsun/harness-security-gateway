package sandboxstore

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func insertLegacyTargetAuthority(t *testing.T, db *sql.DB, authority TargetAuthority) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO target_revisions
        (target_id, revision, semantic_fingerprint, registered_at_unix_ms)
        VALUES (?, ?, ?, 1)`, authority.TargetID, authority.TargetRevision, authority.RevisionPin); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO runner_state_owners
        (target_id, target_revision, runner_state_ref, runner_state_path_digest, registered_at_unix_ms)
        VALUES (?, ?, ?, ?, 1)`, authority.TargetID, authority.TargetRevision,
		authority.RunnerStateRef, authority.RunnerStatePathDigest); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestReopenRejectsContradictoryStateEvidence(t *testing.T) {
	for _, shape := range []string{"persistent-without-owner", "none-with-owner", "none-with-session"} {
		t.Run(shape, func(t *testing.T) {
			store, path := openTestStore(t)
			switch shape {
			case "none-with-owner":
				a := noStateAuthority()
				if err := store.RegisterTargetAuthorities(context.Background(), []TargetAuthority{a}); err != nil {
					t.Fatal(err)
				}
				if _, err := store.db.Exec("DROP TRIGGER runner_state_owner_requires_persistent"); err != nil {
					t.Fatal(err)
				}
				if _, err := store.db.Exec(`INSERT INTO runner_state_owners
     (target_id,target_revision,runner_state_ref,runner_state_path_digest,registered_at_unix_ms)
     VALUES (?,?,'injected',?,1)`, a.TargetID, a.TargetRevision, strings.Repeat("9", 64)); err != nil {
					t.Fatal(err)
				}
			default:
				if shape == "none-with-session" {
					createLifecycleSession(t, store, "run-corrupt-kind", "session-corrupt-kind", lifecyclePolicy(60, 3), time.Now().UnixMilli())
				}
				if _, err := store.db.Exec("DROP TRIGGER runner_state_owners_immutable_delete; DELETE FROM runner_state_owners"); err != nil {
					t.Fatal(err)
				}
				if shape == "none-with-session" {
					if _, err := store.db.Exec("DROP TRIGGER target_revisions_immutable_update; UPDATE target_revisions SET runner_state_kind = 'none'"); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(context.Background(), path)
			if reopened != nil {
				reopened.Close()
				t.Fatal("reopened contradictory authority")
			}
			if !errors.Is(err, ErrRunnerStateOwnershipUnknown) {
				t.Fatalf("contradictory reopen error: %v", err)
			}
		})
	}
}

func TestNoStateSQLGuardsRejectSessionAuthority(t *testing.T) {
	store, _ := openTestStore(t)
	a := noStateAuthority()
	if err := store.RegisterTargetAuthorities(context.Background(), []TargetAuthority{a}); err != nil {
		t.Fatal(err)
	}
	for _, requested := range []any{nil, "session-forbidden"} {
		mode, age, turns, turn := "opaque_resume", 60, 3, 1
		if requested != nil {
			mode, age, turns, turn = "new_only", 0, 0, 0
		}
		_, err := store.db.Exec(`INSERT INTO runs(
   run_id,request_fingerprint,target_id,target_revision,workspace_id,writable,input_sha256,
   session_scope_digest,session_mode,session_max_age_seconds,session_max_turns,session_turn_number,
   requested_session_ref,deadline_unix_ms,state,created_at_unix_ms,updated_at_unix_ms)
   VALUES ('run-forbidden',?,?,?,'workspace',0,?,?, ?,?,?,?, ?,10000,'accepted',1,1)`,
			strings.Repeat("a", 64), a.TargetID, a.TargetRevision, strings.Repeat("b", 64), strings.Repeat("c", 64),
			mode, age, turns, turn, requested)
		if err == nil || !strings.Contains(err.Error(), "no-state target requires new-only execution") {
			t.Fatalf("v9 guard did not reject forbidden session authority: %v", err)
		}
	}
	_, err := store.db.Exec(`INSERT INTO sessions(
  session_ref,target_id,target_revision,session_scope_digest,vendor_token,parent_session_ref,
  created_by_run_id,lineage_started_at_unix_ms,expires_at_unix_ms,turn_number,created_at_unix_ms)
  VALUES ('session-forbidden',?,?,?,'synthetic',NULL,'run-forbidden',1,10000,1,1)`,
		a.TargetID, a.TargetRevision, strings.Repeat("c", 64))
	if err == nil || !strings.Contains(err.Error(), "provider session requires persistent target") {
		t.Fatalf("v9 session guard missing: %v", err)
	}
}

func noStateAuthority() TargetAuthority {
	return TargetAuthority{TargetID: "target-none", TargetRevision: "none-r1",
		RevisionPin: strings.Repeat("c", 64), RunnerStateKind: targetmanifest.RunnerStateNone}
}

func TestNoStateRegistrationSurvivesReopenWithoutOwner(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.sqlite3")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	authority := noStateAuthority()
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{authority}); err != nil {
		t.Fatal(err)
	}
	var before int64
	if err := store.db.QueryRow(`SELECT registered_at_unix_ms FROM target_revisions`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{authority}); err != nil {
		t.Fatal(err)
	}
	var kind string
	var owners, after int64
	if err := store.db.QueryRow(`SELECT runner_state_kind, registered_at_unix_ms FROM target_revisions`).Scan(&kind, &after); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM runner_state_owners`).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if kind != "none" || owners != 0 || before != after {
		t.Fatalf("kind=%s owners=%d timestamps=%d/%d", kind, owners, before, after)
	}
	request := startRequest("run_none", "test")
	request.TargetID, request.ExpectedRevision = authority.TargetID, authority.TargetRevision
	if _, _, err := store.RegisterStart(ctx, request, authority.TargetRevision, "workspace", true,
		SessionPolicy{Mode: targetmanifest.SessionNewOnly}); err != nil {
		t.Fatal(err)
	}
	request.RunID = "run_none_resume"
	if _, _, err := store.RegisterStart(ctx, request, authority.TargetRevision, "workspace", true,
		testSessionPolicy); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("none admitted opaque resume: %v", err)
	}
}

func TestStateKindRegistrationRejectsMixedEvidenceAndRollsBack(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	for name, mutate := range map[string]func(*TargetAuthority){
		"missing kind":     func(a *TargetAuthority) { a.RunnerStateKind = "" },
		"unknown kind":     func(a *TargetAuthority) { a.RunnerStateKind = "ephemeral" },
		"none ref":         func(a *TargetAuthority) { a.RunnerStateRef = "state" },
		"none path":        func(a *TargetAuthority) { a.RunnerStatePathDigest = strings.Repeat("d", 64) },
		"none observation": func(a *TargetAuthority) { a.StatePathAbsent = true },
	} {
		t.Run(name, func(t *testing.T) {
			a := noStateAuthority()
			mutate(&a)
			if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{a}); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("mixed evidence accepted: %v", err)
			}
		})
	}
	none := noStateAuthority()
	unknown := testTargetAuthority("unknown", "unknown-r1", "unknown", 'e', 'e', false)
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{none, unknown}); !errors.Is(err, ErrRunnerStateOwnershipUnknown) {
		t.Fatal(err)
	}
	var rows int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM target_revisions WHERE target_id = ?`, none.TargetID).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("failed batch retained none target: %d %v", rows, err)
	}
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{none}); err != nil {
		t.Fatal(err)
	}
	changed := testTargetAuthority(none.TargetID, none.TargetRevision, "new-state", 'c', 'f', true)
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{changed}); !errors.Is(err, ErrConflict) {
		t.Fatalf("same pin allowed a kind change: %v", err)
	}
	if _, err := store.db.Exec(`UPDATE target_revisions SET runner_state_kind = 'persistent' WHERE target_id = ?`, none.TargetID); err == nil {
		t.Fatal("SQL allowed state-kind mutation")
	}
	if _, err := store.db.Exec(`INSERT INTO runner_state_owners
        (target_id,target_revision,runner_state_ref,runner_state_path_digest,registered_at_unix_ms)
        VALUES (?, ?, 'forbidden', ?, 1)`, none.TargetID, none.TargetRevision, strings.Repeat("f", 64)); err == nil {
		t.Fatal("SQL allowed a none target to own persistent state")
	}
}

func TestMigrationNinePreservesOwnersAndRejectsMissingHistory(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned", true: "missing"}[missing], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "v8.sqlite3")
			db := createLegacySandboxDatabase(t, path, 8)
			a := testTargetAuthority("legacy", "legacy-r1", "legacy-state", 'd', 'e', true)
			insertLegacyTargetAuthority(t, db, a)
			if missing {
				if _, err := db.Exec(`DROP TRIGGER runner_state_owners_immutable_delete; DELETE FROM runner_state_owners`); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			store, err := Open(context.Background(), path)
			if missing {
				if !errors.Is(err, ErrRunnerStateOwnershipUnknown) {
					t.Fatalf("missing legacy owner became none: %v", err)
				}
				check, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				defer check.Close()
				var version int
				if err := check.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != 8 {
					t.Fatalf("failed migration changed history: %d %v", version, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := store.RegisterTargetAuthorities(context.Background(), []TargetAuthority{a}); err != nil {
				t.Fatal(err)
			}
			var pin, kind, ref, digest string
			if err := store.db.QueryRow(`SELECT tr.semantic_fingerprint, tr.runner_state_kind,
                rso.runner_state_ref, rso.runner_state_path_digest FROM target_revisions tr
                JOIN runner_state_owners rso ON tr.target_id = rso.target_id AND tr.revision = rso.target_revision`).Scan(&pin, &kind, &ref, &digest); err != nil {
				t.Fatal(err)
			}
			if pin != a.RevisionPin || kind != "persistent" || ref != a.RunnerStateRef || digest != a.RunnerStatePathDigest {
				t.Fatal("historical authority changed during migration")
			}
		})
	}
}
