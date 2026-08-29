package sandboxstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

const testBootID = "01234567-89ab-cdef-0123-456789abcdef"

var testSessionPolicy = SessionPolicy{
	Mode:          targetmanifest.SessionOpaqueResume,
	MaxAgeSeconds: 24 * 60 * 60,
	MaxTurns:      50,
}

func registerTestStart(
	store *Store,
	ctx context.Context,
	request executionwire.StartRunRequest,
	resolvedRevision string,
	workspaceID string,
	writable bool,
) (Run, bool, error) {
	return store.RegisterStart(ctx, request, resolvedRevision, workspaceID, writable, testSessionPolicy)
}

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sandbox.sqlite3")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := store.RegisterTargetAuthorities(context.Background(), []TargetAuthority{
		testTargetAuthority("target-codex", "target-codex-r1", "state-codex", 'a', '1', true),
	}); err != nil {
		t.Fatalf("RegisterTargetAuthorities() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return store, path
}

func testTargetAuthority(targetID, revision, stateRef string, pinByte, pathByte byte, absent bool) TargetAuthority {
	return TargetAuthority{
		TargetID:              targetID,
		TargetRevision:        revision,
		RevisionPin:           strings.Repeat(string(pinByte), 64),
		RunnerStateRef:        stateRef,
		RunnerStatePathDigest: strings.Repeat(string(pathByte), 64),
		StatePathAbsent:       absent,
	}
}

func startRequest(runID, text string) executionwire.StartRunRequest {
	return executionwire.StartRunRequest{
		RunID:              runID,
		TargetID:           "target-codex",
		ExpectedRevision:   "target-codex-r1",
		SessionScopeDigest: strings.Repeat("a", 64),
		Input: executionwire.TextInput{
			MediaType: executionwire.MediaTypeTextPlain,
			Text:      text,
		},
		Deadline: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
	}
}

func TestOpenConfiguresSecureRollbackDatabaseAndMigrates(t *testing.T) {
	store, path := openTestStore(t)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database mode = %o, want 600", got)
	}
	if got := store.db.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("MaxOpenConnections = %d, want 1", got)
	}

	var foreignKeys int
	if err := store.db.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d", foreignKeys)
	}
	var journal string
	if err := store.db.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(journal, "delete") {
		t.Fatalf("journal_mode = %q", journal)
	}
	var version int
	if err := store.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != CurrentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, CurrentSchemaVersion)
	}
}

func TestOpenConfiguresReplacementSQLiteConnections(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()
	policy := lifecyclePolicy(600, 3)
	createLifecycleSession(t, store, "run_replace_parent", "session_replace_parent", policy, base)
	var parentCreatedAtMS int64
	if err := store.db.QueryRow(`SELECT created_at_unix_ms FROM sessions
        WHERE session_ref = 'session_replace_parent'`).Scan(&parentCreatedAtMS); err != nil {
		t.Fatalf("read parent session creation time: %v", err)
	}
	resume := startRequest("run_replace_resume", "continue")
	resume.SessionRef = stringPointerValue("session_replace_parent")
	if _, created, err := store.registerStartAt(
		ctx, resume, resume.ExpectedRevision, "workspace-replace", false, policy, parentCreatedAtMS+1,
	); err != nil || !created {
		t.Fatalf("register resumed Run = (created %t, error %v)", created, err)
	}

	// MaxOpenConns(1) does not pin one physical driver connection. Closing the
	// idle connection forces database/sql to create a replacement for the next
	// query, which must receive the same connection-local safety PRAGMAs.
	before := store.db.Stats().MaxIdleClosed
	store.db.SetMaxIdleConns(0)
	if after := store.db.Stats().MaxIdleClosed; after <= before {
		t.Fatalf("MaxIdleClosed = %d after forcing replacement, want > %d", after, before)
	}
	store.db.SetMaxIdleConns(1)

	checks := []struct {
		pragma string
		want   int
	}{
		{pragma: "busy_timeout", want: busyTimeoutMS},
		{pragma: "foreign_keys", want: 1},
		{pragma: "recursive_triggers", want: 1},
		{pragma: "synchronous", want: 2}, // SQLITE_SYNC_FULL
		{pragma: "trusted_schema", want: 0},
	}
	for _, check := range checks {
		var got int
		if err := store.db.QueryRow(`PRAGMA ` + check.pragma).Scan(&got); err != nil {
			t.Fatalf("PRAGMA %s error = %v", check.pragma, err)
		}
		if got != check.want {
			t.Fatalf("PRAGMA %s = %d, want %d", check.pragma, got, check.want)
		}
	}

	var journal string
	if err := store.db.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil {
		t.Fatalf("PRAGMA journal_mode error = %v", err)
	}
	if !strings.EqualFold(journal, "delete") {
		t.Fatalf("PRAGMA journal_mode = %q, want DELETE", journal)
	}

	// INSERT OR REPLACE deletes the conflicting row before inserting its
	// replacement. SQLite fires that implicit DELETE's triggers only when
	// recursive_triggers is enabled. Use a complete, valid one-use binding so
	// neither a foreign key nor the insert-authority trigger can accidentally
	// provide the rejection being tested here.
	if _, err := store.db.Exec(`INSERT OR REPLACE INTO session_uses(
        session_ref, run_id, used_at_unix_ms
    ) SELECT session_ref, run_id, used_at_unix_ms
      FROM session_uses
      WHERE session_ref = 'session_replace_parent'
        AND run_id = 'run_replace_resume'`); err == nil ||
		!strings.Contains(err.Error(), "session use deletion is forbidden") {
		t.Fatalf("replacement session-use error = %v, want delete-forbidden trigger", err)
	}
}

func TestSandboxSessionSQLHasNoReplacementWrite(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate sandboxstore source")
	}
	packageDir := filepath.Dir(currentFile)
	for _, name := range []string{"sessions.go", "runs.go", "events.go", "migrate.go"} {
		contents, err := os.ReadFile(filepath.Join(packageDir, name))
		if err != nil {
			t.Fatal(err)
		}
		normalized := strings.ToUpper(strings.Join(strings.Fields(string(contents)), " "))
		if strings.Contains(normalized, "INSERT OR REPLACE INTO SESSIONS") ||
			strings.Contains(normalized, "REPLACE INTO SESSIONS") {
			t.Fatalf("%s contains replacement write to sessions", name)
		}
	}
}

func TestSandboxStoreRefusesFutureMigrationVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox-future.sqlite3")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version, checksum, applied_at_unix_ms)
        VALUES (?, ?, 1)`, CurrentSchemaVersion+1, strings.Repeat("f", 64)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path)
	if reopened != nil {
		_ = reopened.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("Open() future-version error = %v", err)
	}
}

func TestOpenRejectsRelativeAndSymlinkPaths(t *testing.T) {
	if _, err := Open(context.Background(), "sandbox.sqlite3"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("relative path error = %v", err)
	}

	directory := t.TempDir()
	target := filepath.Join(directory, "target.sqlite3")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.sqlite3")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), link); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("symlink path error = %v", err)
	}

	permissive := filepath.Join(directory, "permissive.sqlite3")
	if err := os.WriteFile(permissive, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(permissive, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), permissive); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("permissive existing file error = %v", err)
	}
}

func TestOpenMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox.sqlite3")
	first, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	defer second.Close()
	var count int
	if err := second.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != CurrentSchemaVersion {
		t.Fatalf("migration row count = %d", count)
	}
}

func TestOpenRejectsNonEmptyV1DatabaseWithoutChangingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox-v1.sqlite3")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY,
        checksum TEXT NOT NULL,
        applied_at_unix_ms INTEGER NOT NULL,
        CHECK (length(checksum) = 64)
    ) STRICT`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(migrations[0]); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO schema_migrations(version, checksum, applied_at_unix_ms) VALUES (1, ?, 1)`,
		migrationChecksum(migrations[0])); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO target_revisions(
        target_id, revision, semantic_fingerprint, registered_at_unix_ms
    ) VALUES ('target-codex', 'target-codex-r1', ?, 1)`, strings.Repeat("a", 64)); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(
        run_id, request_fingerprint, target_id, target_revision, workspace_id,
        writable, input_sha256, deadline_unix_ms, state, runtime_ref,
        created_at_unix_ms, updated_at_unix_ms
    ) VALUES ('run_v1', ?, 'target-codex', 'target-codex-r1', 'workspace-v1',
        0, ?, 1, 'accepted', 'container:v1', 1, 1)`,
		strings.Repeat("b", 64), strings.Repeat("c", 64)); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(
        run_id, request_fingerprint, target_id, target_revision, workspace_id,
        writable, input_sha256, deadline_unix_ms, state,
        created_at_unix_ms, updated_at_unix_ms, terminal_at_unix_ms
    ) VALUES ('run_v1_terminal_no_ref', ?, 'target-codex', 'target-codex-r1', 'workspace-v1-terminal',
        0, ?, 1, 'cancelled', 1, 1, 1)`,
		strings.Repeat("f", 64), strings.Repeat("1", 64)); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(
        run_id, request_fingerprint, target_id, target_revision, workspace_id,
        writable, input_sha256, deadline_unix_ms, state,
        created_at_unix_ms, updated_at_unix_ms
    ) VALUES ('run_v1_no_ref', ?, 'target-codex', 'target-codex-r1', 'workspace-v1-pending',
        0, ?, 1, 'accepted', 1, 1)`,
		strings.Repeat("d", 64), strings.Repeat("e", 64)); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(context.Background(), path); !errors.Is(err, ErrColdMigrationRequired) {
		t.Fatalf("Open() error = %v, want ErrColdMigrationRequired", err)
	}

	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version, count int
	if err := db.QueryRow(`SELECT MAX(version), COUNT(*) FROM schema_migrations`).Scan(&version, &count); err != nil {
		t.Fatal(err)
	}
	if version != 1 || count != 1 {
		t.Fatalf("migration state = version %d count %d", version, count)
	}
	if tableHasColumn(t, db, "runs", "runtime_intent_pending") || tableHasColumn(t, db, "runs", "runtime_intent_boot_id") {
		t.Fatal("failed v1 migration changed the runs schema")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM runs`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("run count = %d, want 3", count)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM runs
        WHERE (run_id = 'run_v1' AND state = 'accepted' AND runtime_ref = 'container:v1')
           OR (run_id = 'run_v1_no_ref' AND state = 'accepted' AND runtime_ref IS NULL)
           OR (run_id = 'run_v1_terminal_no_ref' AND state = 'cancelled'
               AND runtime_ref IS NULL AND terminal_at_unix_ms = 1)`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("unchanged legacy run count = %d, want 3", count)
	}
}

func TestOpenRejectsNonEmptyV2DatabaseWithoutChangingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox-v2.sqlite3")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY,
        checksum TEXT NOT NULL,
        applied_at_unix_ms INTEGER NOT NULL,
        CHECK (length(checksum) = 64)
    ) STRICT`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	for version := 1; version <= 2; version++ {
		if _, err := db.Exec(migrations[version-1]); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
		if _, err := db.Exec(
			`INSERT INTO schema_migrations(version, checksum, applied_at_unix_ms) VALUES (?, ?, 1)`,
			version, migrationChecksum(migrations[version-1])); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO target_revisions(
        target_id, revision, semantic_fingerprint, registered_at_unix_ms
    ) VALUES ('target-codex', 'target-codex-r1', ?, 1)`, strings.Repeat("a", 64)); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(
        run_id, request_fingerprint, target_id, target_revision, workspace_id,
        writable, input_sha256, deadline_unix_ms, state,
        runtime_intent_pending, created_at_unix_ms, updated_at_unix_ms
    ) VALUES ('run_v2_pending', ?, 'target-codex', 'target-codex-r1', 'workspace-v2',
        1, ?, 1, 'accepted', 1, 1, 1)`,
		strings.Repeat("b", 64), strings.Repeat("c", 64)); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO workspace_locks(workspace_id, run_id, acquired_at_unix_ms)
        VALUES ('workspace-v2', 'run_v2_pending', 1)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(context.Background(), path); !errors.Is(err, ErrColdMigrationRequired) {
		t.Fatalf("Open() error = %v, want ErrColdMigrationRequired", err)
	}

	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version, count int
	if err := db.QueryRow(`SELECT MAX(version), COUNT(*) FROM schema_migrations`).Scan(&version, &count); err != nil {
		t.Fatal(err)
	}
	if version != 2 || count != 2 {
		t.Fatalf("migration state = version %d count %d", version, count)
	}
	if !tableHasColumn(t, db, "runs", "runtime_intent_pending") || tableHasColumn(t, db, "runs", "runtime_intent_boot_id") {
		t.Fatal("failed v2 migration changed the runs schema")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM runs
        WHERE run_id = 'run_v2_pending' AND state = 'accepted'
          AND runtime_ref IS NULL AND runtime_intent_pending = 1`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("unchanged legacy run count = %d, want 1", count)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM workspace_locks
        WHERE workspace_id = 'workspace-v2' AND run_id = 'run_v2_pending'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("unchanged workspace lock count = %d, want 1", count)
	}
}

func TestOpenUpgradesEmptyOlderDatabase(t *testing.T) {
	for legacyVersion := 1; legacyVersion < CurrentSchemaVersion; legacyVersion++ {
		t.Run(fmt.Sprintf("v%d", legacyVersion), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sandbox.sqlite3")
			file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                checksum TEXT NOT NULL,
                applied_at_unix_ms INTEGER NOT NULL,
                CHECK (length(checksum) = 64)
            ) STRICT`); err != nil {
				_ = db.Close()
				t.Fatal(err)
			}
			for version := 1; version <= legacyVersion; version++ {
				if _, err := db.Exec(migrations[version-1]); err != nil {
					_ = db.Close()
					t.Fatal(err)
				}
				if _, err := db.Exec(
					`INSERT INTO schema_migrations(version, checksum, applied_at_unix_ms) VALUES (?, ?, 1)`,
					version, migrationChecksum(migrations[version-1])); err != nil {
					_ = db.Close()
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			store, err := Open(context.Background(), path)
			if err != nil {
				t.Fatalf("Open() empty v%d database error = %v", legacyVersion, err)
			}
			defer store.Close()
			var version, count int
			if err := store.db.QueryRow(`SELECT MAX(version), COUNT(*) FROM schema_migrations`).Scan(&version, &count); err != nil {
				t.Fatal(err)
			}
			if version != CurrentSchemaVersion || count != CurrentSchemaVersion {
				t.Fatalf("migration state = version %d count %d", version, count)
			}
			if !tableHasColumn(t, store.db, "runs", "runtime_intent_boot_id") {
				t.Fatal("upgraded database is missing runtime_intent_boot_id")
			}
			if !tableHasColumn(t, store.db, "runs", "session_scope_digest") ||
				!tableHasColumn(t, store.db, "sessions", "session_scope_digest") {
				t.Fatal("upgraded database is missing exact session scope columns")
			}
		})
	}
}

func TestOpenRejectsLedgerlessPreexistingAuthorityTablesWithoutWritingLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox-ledgerless.sqlite3")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(migrations[0]); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	insertLegacyTarget(t, db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(context.Background(), path)
	if store != nil {
		_ = store.Close()
	}
	if err == nil {
		t.Fatal("Open() accepted authority tables without a migration ledger")
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var ledgerTables, revisions int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master
        WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&ledgerTables); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM target_revisions`).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if ledgerTables != 0 || revisions != 1 {
		t.Fatalf("ledgerless refusal changed state: ledgers=%d revisions=%d", ledgerTables, revisions)
	}
}

func TestMigrationSixRejectsEveryPreOwnershipTargetBeforeDDL(t *testing.T) {
	for legacyVersion := 1; legacyVersion < runnerStateOwnershipVersion; legacyVersion++ {
		t.Run(fmt.Sprintf("v%d", legacyVersion), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), fmt.Sprintf("sandbox-v%d-target.sqlite3", legacyVersion))
			db := createLegacySandboxDatabase(t, path, legacyVersion)
			insertLegacyTarget(t, db)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			store, err := Open(context.Background(), path)
			if store != nil {
				_ = store.Close()
			}
			if !errors.Is(err, ErrRunnerStateOwnershipUnknown) {
				t.Fatalf("Open() error = %v, want ErrRunnerStateOwnershipUnknown", err)
			}
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version, count, ownerTables int
			if err := db.QueryRow(`SELECT MAX(version), COUNT(*) FROM schema_migrations`).Scan(&version, &count); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master
                WHERE type = 'table' AND name = 'runner_state_owners'`).Scan(&ownerTables); err != nil {
				t.Fatal(err)
			}
			if version != legacyVersion || count != legacyVersion || ownerTables != 0 {
				t.Fatalf("refused v6 migration changed schema: version=%d count=%d owner_tables=%d",
					version, count, ownerTables)
			}
		})
	}
}

func TestOpenRejectsLegacyTargetRevisionWithoutRunnerStateOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox-v3-clean.sqlite3")
	db := createLegacySandboxDatabase(t, path, 3)
	if _, err := db.Exec(`INSERT INTO target_revisions(
        target_id, revision, semantic_fingerprint, registered_at_unix_ms
    ) VALUES ('target-codex', 'target-codex-r1', ?, 1)`, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(
        run_id, request_fingerprint, target_id, target_revision, workspace_id,
        writable, input_sha256, deadline_unix_ms, state,
        runtime_intent_pending, runtime_intent_boot_id,
        created_at_unix_ms, updated_at_unix_ms, terminal_at_unix_ms
    ) VALUES ('run_v3_clean', ?, 'target-codex', 'target-codex-r1', 'workspace-v3',
		0, ?, 1, 'cancelled', 0, NULL, 1, 1, 1)`,
		strings.Repeat("b", 64), strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(context.Background(), path)
	if store != nil {
		_ = store.Close()
	}
	if !errors.Is(err, ErrRunnerStateOwnershipUnknown) {
		t.Fatalf("Open() legacy target database error = %v, want ErrRunnerStateOwnershipUnknown", err)
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version, ownerTables int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master
        WHERE type = 'table' AND name = 'runner_state_owners'`).Scan(&ownerTables); err != nil {
		t.Fatal(err)
	}
	if version != 3 || ownerTables != 0 {
		t.Fatalf("refused ownership migration changed schema: version=%d owner_tables=%d", version, ownerTables)
	}
}

func TestMigrationFiveRejectsEveryLegacySessionAuthorityShape(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *sql.DB)
	}{
		{
			name: "session mapping",
			setup: func(t *testing.T, db *sql.DB) {
				insertLegacyTarget(t, db)
				if _, err := db.Exec(`INSERT INTO sessions(
                    session_ref, target_id, target_revision, vendor_token, created_at_unix_ms
                ) VALUES ('legacy-session', 'target-codex', 'target-codex-r1', 'token', 1)`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "nonterminal Run",
			setup: func(t *testing.T, db *sql.DB) {
				insertLegacyTarget(t, db)
				insertLegacyRun(t, db, "run-nonterminal", "accepted", nil, nil)
			},
		},
		{
			name: "requested session ref",
			setup: func(t *testing.T, db *sql.DB) {
				insertLegacyTarget(t, db)
				insertLegacyRun(t, db, "run-requested", "cancelled", testStringPointer("legacy-requested"), nil)
			},
		},
		{
			name: "result session ref",
			setup: func(t *testing.T, db *sql.DB) {
				insertLegacyTarget(t, db)
				insertLegacyRun(t, db, "run-result", "completed", nil, testStringPointer("legacy-result"))
			},
		},
		{
			name: "event session ref",
			setup: func(t *testing.T, db *sql.DB) {
				insertLegacyTarget(t, db)
				insertLegacyRun(t, db, "run-event", "completed", nil, nil)
				if _, err := db.Exec(`INSERT INTO run_events(
                    run_id, seq, event_type, message_text, output_media_type,
                    result_session_ref, created_at_unix_ms
                ) VALUES ('run-event', 1, 'completed', 'done', 'text/plain',
                    'legacy-event-session', 1)`); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sandbox-v4.sqlite3")
			db := createLegacySandboxDatabase(t, path, 4)
			test.setup(t, db)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			store, err := Open(context.Background(), path)
			if store != nil {
				_ = store.Close()
			}
			if !errors.Is(err, ErrUnsafeLegacySessionState) {
				t.Fatalf("Open() error = %v, want ErrUnsafeLegacySessionState", err)
			}
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version, digestColumns int
			if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('runs')
                    WHERE name = 'session_scope_digest'`).Scan(&digestColumns); err != nil {
				t.Fatal(err)
			}
			if version != 4 || digestColumns != 0 {
				t.Fatalf("refused migration changed schema: version=%d digest_columns=%d", version, digestColumns)
			}
		})
	}
}

func insertLegacyTarget(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO target_revisions(
        target_id, revision, semantic_fingerprint, registered_at_unix_ms
    ) VALUES ('target-codex', 'target-codex-r1', ?, 1)`, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
}

func testStringPointer(value string) *string { return &value }

func insertLegacyRun(t *testing.T, db *sql.DB, runID, state string, requestedRef, resultRef *string) {
	t.Helper()
	terminal := any(nil)
	outputMedia := any(nil)
	outputText := any(nil)
	if state == "completed" || state == "cancelled" {
		terminal = int64(1)
	}
	if state == "completed" {
		outputMedia = "text/plain"
		outputText = "done"
	}
	if _, err := db.Exec(`INSERT INTO runs(
        run_id, request_fingerprint, target_id, target_revision, workspace_id,
        writable, input_sha256, requested_session_ref, deadline_unix_ms, state,
        output_media_type, output_text, result_session_ref,
        created_at_unix_ms, updated_at_unix_ms, terminal_at_unix_ms
    ) VALUES (?, ?, 'target-codex', 'target-codex-r1', 'workspace', 0, ?, ?, 1, ?, ?, ?, ?, 1, 1, ?)`,
		runID, strings.Repeat("b", 64), strings.Repeat("c", 64), nullableString(requestedRef),
		state, outputMedia, outputText, nullableString(resultRef), terminal); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsUnsafeTerminalPendingV3DatabaseWithoutChangingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox-v3-unsafe.sqlite3")
	db := createLegacySandboxDatabase(t, path, 3)
	if _, err := db.Exec(`INSERT INTO target_revisions(
        target_id, revision, semantic_fingerprint, registered_at_unix_ms
    ) VALUES ('target-codex', 'target-codex-r1', ?, 1)`, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(
        run_id, request_fingerprint, target_id, target_revision, workspace_id,
        writable, input_sha256, deadline_unix_ms, state,
        runtime_intent_pending, runtime_intent_boot_id,
        failure_code, failure_message, terminal_at_unix_ms,
        created_at_unix_ms, updated_at_unix_ms
    ) VALUES ('run_v3_unsafe', ?, 'target-codex', 'target-codex-r1', 'workspace-v3',
        0, ?, 1, 'failed', 1, ?, 'internal', 'old misclassification', 1, 1, 1)`,
		strings.Repeat("b", 64), strings.Repeat("c", 64), testBootID); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(context.Background(), path); !errors.Is(err, ErrUnsafeIntentState) {
		t.Fatalf("Open() error = %v, want ErrUnsafeIntentState", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version, count int
	if err := db.QueryRow(`SELECT MAX(version), COUNT(*) FROM schema_migrations`).Scan(&version, &count); err != nil {
		t.Fatal(err)
	}
	if version != 3 || count != 3 {
		t.Fatalf("rejected migration changed ledger: version=%d count=%d", version, count)
	}
}

func createLegacySandboxDatabase(t *testing.T, path string, version int) *sql.DB {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY,
        checksum TEXT NOT NULL,
        applied_at_unix_ms INTEGER NOT NULL,
        CHECK (length(checksum) = 64)
    ) STRICT`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	for candidate := 1; candidate <= version; candidate++ {
		if _, err := db.Exec(migrations[candidate-1]); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
		if _, err := db.Exec(
			`INSERT INTO schema_migrations(version, checksum, applied_at_unix_ms) VALUES (?, ?, 1)`,
			candidate, migrationChecksum(migrations[candidate-1])); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	return db
}

func tableHasColumn(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		if name == column {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return false
}

func TestMigrationChecksumMismatchIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox.sqlite3")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE schema_migrations SET checksum = ? WHERE version = 1`, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("checksum mismatch error = %v", err)
	}
}

func TestEveryMigrationChecksumIsVerified(t *testing.T) {
	for version := 1; version <= CurrentSchemaVersion; version++ {
		t.Run(fmt.Sprintf("version-%d", version), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sandbox.sqlite3")
			store, err := Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(`UPDATE schema_migrations SET checksum = ? WHERE version = ?`,
				strings.Repeat("0", 64), version); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(context.Background(), path); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
				t.Fatalf("checksum mismatch error = %v", err)
			}
		})
	}
}

func TestTargetAuthorityRegistrationIsImmutableAndIdempotent(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	for _, invalidRef := range []string{"State-Upper", "state-é", ".", ".."} {
		invalid := testTargetAuthority("target-invalid", "target-invalid-r1", invalidRef, 'c', '3', true)
		if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{invalid}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("runner-state ref %q error = %v, want ErrInvalidArgument", invalidRef, err)
		}
	}
	authority := testTargetAuthority("target-claude", "target-claude-r1", "state-claude", 'b', '2', true)
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{authority}); err != nil {
		t.Fatalf("first RegisterTargetAuthorities() = %v", err)
	}
	authority.StatePathAbsent = false
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{authority}); err != nil {
		t.Fatalf("idempotent RegisterTargetAuthorities() = %v", err)
	}
	changed := authority
	changed.RevisionPin = strings.Repeat("c", 64)
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{changed}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed target fingerprint error = %v", err)
	}
	changed = authority
	changed.RunnerStateRef = "state-claude-other"
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{changed}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed runner-state ref error = %v", err)
	}
	changed = authority
	changed.RunnerStatePathDigest = strings.Repeat("3", 64)
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{changed}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed runner-state path error = %v", err)
	}

	unknown := testTargetAuthority("target-unknown", "target-unknown-r1", "state-unknown", 'c', '3', false)
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{unknown}); !errors.Is(err, ErrRunnerStateOwnershipUnknown) {
		t.Fatalf("unknown existing state error = %v", err)
	}
	var unknownRevisions int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM target_revisions WHERE target_id = 'target-unknown'`).Scan(&unknownRevisions); err != nil {
		t.Fatal(err)
	}
	if unknownRevisions != 0 {
		t.Fatal("unknown state registration retained a target revision")
	}

	unregistered := startRequest("run_missing_target", "inspect")
	unregistered.TargetID = "target-missing"
	unregistered.ExpectedRevision = "target-missing-r1"
	if _, _, err := registerTestStart(store, ctx, unregistered, unregistered.ExpectedRevision, "workspace-missing", true); !errors.Is(err, ErrTargetRevisionNotFound) {
		t.Fatalf("unregistered target revision error = %v", err)
	}
}

func TestExactTargetAuthorityRetryAfterReopenPreservesRowsAndTimestamps(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sandbox.sqlite3")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	current := store
	t.Cleanup(func() {
		if current != nil {
			if err := current.Close(); err != nil {
				t.Errorf("Close() error = %v", err)
			}
		}
	})

	authority := testTargetAuthority("target-restart", "target-restart-r1", "state-restart", 'd', '4', true)
	if err := current.RegisterTargetAuthorities(ctx, []TargetAuthority{authority}); err != nil {
		t.Fatalf("first RegisterTargetAuthorities() = %v", err)
	}
	type snapshot struct {
		pin, stateRef, pathDigest        string
		revisionRegistered, ownerClaimed int64
		revisionRows, ownerRows          int
	}
	read := func() snapshot {
		t.Helper()
		var got snapshot
		if err := current.db.QueryRow(`SELECT semantic_fingerprint, registered_at_unix_ms
            FROM target_revisions WHERE target_id = ? AND revision = ?`,
			authority.TargetID, authority.TargetRevision).Scan(&got.pin, &got.revisionRegistered); err != nil {
			t.Fatal(err)
		}
		if err := current.db.QueryRow(`SELECT runner_state_ref, runner_state_path_digest, registered_at_unix_ms
            FROM runner_state_owners WHERE target_id = ? AND target_revision = ?`,
			authority.TargetID, authority.TargetRevision).Scan(&got.stateRef, &got.pathDigest, &got.ownerClaimed); err != nil {
			t.Fatal(err)
		}
		if err := current.db.QueryRow(`SELECT COUNT(*) FROM target_revisions
            WHERE target_id = ? AND revision = ?`, authority.TargetID, authority.TargetRevision).Scan(&got.revisionRows); err != nil {
			t.Fatal(err)
		}
		if err := current.db.QueryRow(`SELECT COUNT(*) FROM runner_state_owners
            WHERE target_id = ? AND target_revision = ?`, authority.TargetID, authority.TargetRevision).Scan(&got.ownerRows); err != nil {
			t.Fatal(err)
		}
		return got
	}
	before := read()
	if err := current.Close(); err != nil {
		t.Fatal(err)
	}
	current = nil

	current, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	// A crash may occur after the ownership commit and before the state leaf is
	// created. The exact retry must therefore remain idempotent even when the
	// trusted startup observation still reports the path absent.
	if err := current.RegisterTargetAuthorities(ctx, []TargetAuthority{authority}); err != nil {
		t.Fatalf("post-reopen exact RegisterTargetAuthorities() = %v", err)
	}
	after := read()
	if after != before || after.revisionRows != 1 || after.ownerRows != 1 {
		t.Fatalf("registration changed across exact retry: before=%#v after=%#v", before, after)
	}
}

func TestTargetAuthorityNamespaceConflictsAndBatchRollback(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()

	refReuse := testTargetAuthority("target-ref", "target-ref-r1", "state-codex", 'b', '2', true)
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{refReuse}); !errors.Is(err, ErrConflict) {
		t.Fatalf("state-ref reuse error = %v", err)
	}
	pathReuse := testTargetAuthority("target-path", "target-path-r1", "state-path", 'b', '1', true)
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{pathReuse}); !errors.Is(err, ErrConflict) {
		t.Fatalf("state-path reuse error = %v", err)
	}
	sameTargetNewRevision := testTargetAuthority("target-codex", "target-codex-r2", "state-codex-r2", 'b', '1', true)
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{sameTargetNewRevision}); !errors.Is(err, ErrConflict) {
		t.Fatalf("same target new revision reused path error = %v", err)
	}

	first := testTargetAuthority("target-batch-first", "target-batch-first-r1", "state-batch-first", 'c', '3', true)
	second := testTargetAuthority("target-batch-second", "target-batch-second-r1", "state-batch-second", 'd', '1', true)
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{first, second}); !errors.Is(err, ErrConflict) {
		t.Fatalf("batch conflict error = %v", err)
	}
	var rows int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM target_revisions
        WHERE target_id IN ('target-batch-first', 'target-batch-second')`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("failed batch retained %d target revisions", rows)
	}

	validNewRevision := testTargetAuthority("target-codex", "target-codex-r2", "state-codex-r2", 'b', '4', true)
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{validNewRevision}); err != nil {
		t.Fatalf("same target new revision with new state error = %v", err)
	}
}

func TestRunnerStateOwnersAreAppendOnlyAndRequiredForRuns(t *testing.T) {
	store, _ := openTestStore(t)
	var beforePin, beforeRef, beforeDigest string
	var beforeRevisionRegistered, beforeOwnerClaimed int64
	if err := store.db.QueryRow(`SELECT tr.semantic_fingerprint, tr.registered_at_unix_ms,
        rso.runner_state_ref, rso.runner_state_path_digest, rso.registered_at_unix_ms
        FROM target_revisions tr JOIN runner_state_owners rso
          ON rso.target_id = tr.target_id AND rso.target_revision = tr.revision
        WHERE tr.target_id = 'target-codex' AND tr.revision = 'target-codex-r1'`).Scan(
		&beforePin, &beforeRevisionRegistered, &beforeRef, &beforeDigest, &beforeOwnerClaimed,
	); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE runner_state_owners SET runner_state_ref = 'changed' WHERE target_id = 'target-codex'`,
		`DELETE FROM runner_state_owners WHERE target_id = 'target-codex'`,
		`INSERT OR REPLACE INTO runner_state_owners(
            runner_state_path_digest, runner_state_ref, target_id, target_revision,
            registered_at_unix_ms
        ) SELECT runner_state_path_digest, runner_state_ref, target_id, target_revision, 2
          FROM runner_state_owners WHERE target_id = 'target-codex'`,
		`INSERT INTO runner_state_owners(
            runner_state_path_digest, runner_state_ref, target_id, target_revision,
            registered_at_unix_ms
        ) SELECT runner_state_path_digest, runner_state_ref, target_id, target_revision, 2
          FROM runner_state_owners WHERE target_id = 'target-codex'
          ON CONFLICT(runner_state_path_digest) DO UPDATE
          SET registered_at_unix_ms = excluded.registered_at_unix_ms`,
		`UPDATE target_revisions SET semantic_fingerprint = '` + strings.Repeat("b", 64) + `'
          WHERE target_id = 'target-codex' AND revision = 'target-codex-r1'`,
		`INSERT INTO target_revisions(
            target_id, revision, semantic_fingerprint, registered_at_unix_ms
        ) VALUES ('target-codex', 'target-codex-r1', '` + strings.Repeat("b", 64) + `', 2)
          ON CONFLICT(target_id, revision) DO UPDATE
          SET semantic_fingerprint = excluded.semantic_fingerprint,
              registered_at_unix_ms = excluded.registered_at_unix_ms`,
	} {
		if _, err := store.db.Exec(statement); err == nil {
			t.Fatalf("authority mutation succeeded: %s", statement)
		}
	}
	var afterPin, afterRef, afterDigest string
	var afterRevisionRegistered, afterOwnerClaimed int64
	if err := store.db.QueryRow(`SELECT tr.semantic_fingerprint, tr.registered_at_unix_ms,
        rso.runner_state_ref, rso.runner_state_path_digest, rso.registered_at_unix_ms
        FROM target_revisions tr JOIN runner_state_owners rso
          ON rso.target_id = tr.target_id AND rso.target_revision = tr.revision
        WHERE tr.target_id = 'target-codex' AND tr.revision = 'target-codex-r1'`).Scan(
		&afterPin, &afterRevisionRegistered, &afterRef, &afterDigest, &afterOwnerClaimed,
	); err != nil {
		t.Fatal(err)
	}
	if afterPin != beforePin || afterRef != beforeRef || afterDigest != beforeDigest ||
		afterRevisionRegistered != beforeRevisionRegistered || afterOwnerClaimed != beforeOwnerClaimed {
		t.Fatalf("authority row changed: before=(%q,%d,%q,%q,%d) after=(%q,%d,%q,%q,%d)",
			beforePin, beforeRevisionRegistered, beforeRef, beforeDigest, beforeOwnerClaimed,
			afterPin, afterRevisionRegistered, afterRef, afterDigest, afterOwnerClaimed)
	}
	if _, err := store.db.Exec(`INSERT INTO target_revisions(
        target_id, revision, semantic_fingerprint, registered_at_unix_ms
    ) VALUES ('target-orphan', 'target-orphan-r1', ?, 1)`, strings.Repeat("e", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO runner_state_owners(
        runner_state_path_digest, runner_state_ref, target_id, target_revision,
        registered_at_unix_ms
    ) VALUES (?, 'State-orphan', 'target-orphan', 'target-orphan-r1', 1)`, strings.Repeat("f", 64)); err == nil {
		t.Fatal("database accepted a noncanonical runner-state ref")
	}
	request := startRequest("run-orphan", "inspect")
	request.TargetID = "target-orphan"
	request.ExpectedRevision = "target-orphan-r1"
	if _, _, err := registerTestStart(store, context.Background(), request, request.ExpectedRevision,
		"workspace-orphan", false); !errors.Is(err, ErrTargetRevisionNotFound) {
		t.Fatalf("ownerless target StartRun error = %v", err)
	}
}

func TestRegisterStartIsIdempotentAndWorkspaceScoped(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	request := startRequest("run_01", "secret prompt that must not be stored")

	first, created, err := registerTestStart(store, ctx, request, request.ExpectedRevision, "workspace-alpha", true)
	if err != nil {
		t.Fatal(err)
	}
	if !created || first.State != executionwire.RunStateAccepted || !first.WorkspaceLockHeld {
		t.Fatalf("registered run = %#v, created = %v", first, created)
	}
	if !first.Writable {
		t.Fatal("writable run was not recorded as writable")
	}
	if len(first.InputSHA256) != 64 {
		t.Fatalf("input digest = %q", first.InputSHA256)
	}

	again, created, err := registerTestStart(store, ctx, request, request.ExpectedRevision, "workspace-alpha", true)
	if err != nil {
		t.Fatal(err)
	}
	if created || again.Fingerprint != first.Fingerprint {
		t.Fatalf("idempotent registration = %#v, created = %v", again, created)
	}

	changed := request
	changed.Input.Text = "changed payload"
	if _, _, err := registerTestStart(store, ctx, changed, changed.ExpectedRevision, "workspace-alpha", true); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed-payload error = %v", err)
	}

	other := startRequest("run_02", "another prompt")
	other.SessionScopeDigest = strings.Repeat("b", 64)
	if _, _, err := registerTestStart(store, ctx, other, other.ExpectedRevision, "workspace-alpha", true); !errors.Is(err, ErrWorkspaceBusy) {
		t.Fatalf("workspace contention error = %v", err)
	}
	if _, err := store.GetRun(ctx, "run_02"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rolled-back contending run error = %v", err)
	}

	wrongRevision := startRequest("run_03", "prompt")
	if _, _, err := registerTestStart(store, ctx, wrongRevision, "different-r2", "workspace-beta", true); !errors.Is(err, ErrRevisionMismatch) {
		t.Fatalf("revision mismatch error = %v", err)
	}
}

func TestReadOnlyRunsDoNotAcquireWriterLock(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	firstRequest := startRequest("run_ro_1", "read one")
	first, _, err := registerTestStart(store, ctx, firstRequest, firstRequest.ExpectedRevision, "workspace-shared", false)
	if err != nil {
		t.Fatal(err)
	}
	if first.Writable || first.WorkspaceLockHeld {
		t.Fatalf("read-only run acquired writer authority: %#v", first)
	}
	secondRequest := startRequest("run_ro_2", "read two")
	secondRequest.SessionScopeDigest = strings.Repeat("b", 64)
	if _, _, err := registerTestStart(store, ctx, secondRequest, secondRequest.ExpectedRevision, "workspace-shared", false); err != nil {
		t.Fatalf("second read-only run was serialized: %v", err)
	}
	writer := startRequest("run_rw_1", "write")
	writer.SessionScopeDigest = strings.Repeat("c", 64)
	if _, _, err := registerTestStart(store, ctx, writer, writer.ExpectedRevision, "workspace-shared", true); err != nil {
		t.Fatalf("first writer could not coexist with readers: %v", err)
	}
	secondWriter := startRequest("run_rw_2", "write again")
	secondWriter.SessionScopeDigest = strings.Repeat("d", 64)
	if _, _, err := registerTestStart(store, ctx, secondWriter, secondWriter.ExpectedRevision, "workspace-shared", true); !errors.Is(err, ErrWorkspaceBusy) {
		t.Fatalf("second writer error = %v", err)
	}
}

func TestRegisterStartDoesNotPersistFullPrompt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox.sqlite3")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	secret := "PROMPT-CANARY-4d715c43d754" // gitleaks:allow -- deterministic test canary, not a credential
	request := startRequest("run_canary", secret)
	if err := store.RegisterTargetAuthorities(context.Background(), []TargetAuthority{
		testTargetAuthority(request.TargetID, request.ExpectedRevision, "state-canary", 'a', '5', true),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := registerTestStart(store, context.Background(), request, request.ExpectedRevision, "workspace-canary", true); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(contents, []byte(secret)) {
		t.Fatal("database contains the full prompt canary")
	}
}

func TestLifecycleKeepsLockUntilRuntimeConfirmation(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	request := startRequest("run_01", "inspect")
	if _, _, err := registerTestStart(store, ctx, request, request.ExpectedRevision, "workspace-alpha", true); err != nil {
		t.Fatal(err)
	}

	run, created, err := store.BeginRuntimeIntent(ctx, request.RunID, testBootID)
	if err != nil || !created || !run.RuntimeIntentPending {
		t.Fatalf("BeginRuntimeIntent() = (%#v, %t, %v)", run, created, err)
	}
	run, err = store.SetRuntimeRef(ctx, request.RunID, "container:abc123")
	if err != nil {
		t.Fatal(err)
	}
	if run.RuntimeIntentPending || run.RuntimeRef == nil || *run.RuntimeRef != "container:abc123" {
		t.Fatalf("runtime ref = %#v", run.RuntimeRef)
	}
	if _, err := store.SetRuntimeRef(ctx, request.RunID, "container:abc123"); err != nil {
		t.Fatalf("idempotent SetRuntimeRef error = %v", err)
	}
	if _, err := store.SetRuntimeRef(ctx, request.RunID, "container:different"); !errors.Is(err, ErrConflict) {
		t.Fatalf("runtime replacement error = %v", err)
	}
	if _, err := store.SetRuntimeRef(ctx, request.RunID, "../../runtime.sock"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("path-like runtime ref error = %v", err)
	}

	progress := executionwire.RunEvent{
		RunID: request.RunID,
		Seq:   1,
		Type:  executionwire.RunEventProgress,
		Progress: &executionwire.RunProgress{
			Kind: executionwire.ProgressStatus,
			Text: "working",
		},
	}
	if _, err := store.AppendEvent(ctx, progress, nil); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("progress-before-start error = %v", err)
	}
	startedGap := executionwire.RunEvent{RunID: request.RunID, Seq: 2, Type: executionwire.RunEventStarted}
	if _, err := store.AppendEvent(ctx, startedGap, nil); !errors.Is(err, ErrEventSequence) {
		t.Fatalf("non-contiguous first sequence error = %v", err)
	}
	started := executionwire.RunEvent{RunID: request.RunID, Seq: 1, Type: executionwire.RunEventStarted}
	if _, err := store.AppendEvent(ctx, started, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendEvent(ctx, started, nil); !errors.Is(err, ErrEventSequence) {
		t.Fatalf("duplicate sequence error = %v", err)
	}
	progress.Seq = 3
	if _, err := store.AppendEvent(ctx, progress, nil); !errors.Is(err, ErrEventSequence) {
		t.Fatalf("gapped sequence error = %v", err)
	}
	if _, err := store.MarkCancelling(ctx, request.RunID); err != nil {
		t.Fatal(err)
	}
	progress.Seq = 2
	if _, err := store.AppendEvent(ctx, progress, nil); err != nil {
		t.Fatal(err)
	}

	sessionRef := "session_01"
	completed := executionwire.RunEvent{
		RunID: request.RunID,
		Seq:   3,
		Type:  executionwire.RunEventCompleted,
		Result: &executionwire.RunResult{
			Output:     executionwire.TextOutput{MediaType: executionwire.MediaTypeTextPlain, Text: "done"},
			SessionRef: &sessionRef,
		},
	}
	mapping := &SessionMapping{Ref: sessionRef, VendorToken: "vendor-session-token"}
	run, err = store.AppendEvent(ctx, completed, mapping)
	if err != nil {
		t.Fatal(err)
	}
	if run.State != executionwire.RunStateCompleted || !run.WorkspaceLockHeld || run.RuntimeRef == nil {
		t.Fatalf("terminal-but-unconfirmed run = %#v", run)
	}
	if _, err := store.ConfirmRuntimeStopped(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing confirmation error = %v", err)
	}

	contender := startRequest("run_02", "wait")
	if _, _, err := registerTestStart(store, ctx, contender, contender.ExpectedRevision, "workspace-alpha", true); !errors.Is(err, ErrWorkspaceBusy) {
		t.Fatalf("workspace unlocked before runtime confirmation: %v", err)
	}
	nonterminal, err := store.ListNonTerminal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonterminal) != 0 {
		t.Fatalf("nonterminal runs = %#v", nonterminal)
	}
	unreconciled, err := store.ListUnreconciled(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unreconciled) != 1 || unreconciled[0].RunID != request.RunID {
		t.Fatalf("unreconciled runs = %#v", unreconciled)
	}

	snapshot, err := store.GetSnapshot(ctx, request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status.State != executionwire.RunStateCompleted || len(snapshot.Events) != 3 {
		t.Fatalf("snapshot = %#v", snapshot)
	}

	run, err = store.ConfirmRuntimeStopped(ctx, request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.WorkspaceLockHeld || run.RuntimeRef != nil {
		t.Fatalf("confirmed run still owns runtime authority: %#v", run)
	}
	if _, _, err := registerTestStart(store, ctx, contender, contender.ExpectedRevision, "workspace-alpha", true); err != nil {
		t.Fatalf("workspace not reusable after confirmation: %v", err)
	}
}

func TestRuntimeIntentCASAndDatabaseGuards(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	request := startRequest("run_intent", "inspect")
	if _, _, err := registerTestStart(store, ctx, request, request.ExpectedRevision, "workspace-intent", false); err != nil {
		t.Fatal(err)
	}

	if _, err := store.SetRuntimeRef(ctx, request.RunID, "container:no-intent"); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("unfenced SetRuntimeRef error = %v", err)
	}
	run, created, err := store.BeginRuntimeIntent(ctx, request.RunID, testBootID)
	if err != nil || !created || !run.RuntimeIntentPending || run.RuntimeIntentBootID == nil || *run.RuntimeIntentBootID != testBootID || run.RuntimeRef != nil {
		t.Fatalf("first BeginRuntimeIntent() = (%#v, %t, %v)", run, created, err)
	}
	run, created, err = store.BeginRuntimeIntent(ctx, request.RunID, testBootID)
	if err != nil || created || !run.RuntimeIntentPending {
		t.Fatalf("idempotent BeginRuntimeIntent() = (%#v, %t, %v)", run, created, err)
	}
	otherBootID := "fedcba98-7654-3210-fedc-ba9876543210"
	if _, _, err := store.BeginRuntimeIntent(ctx, request.RunID, otherBootID); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-boot BeginRuntimeIntent error = %v", err)
	}
	if _, _, err := store.BeginRuntimeIntent(ctx, request.RunID, "not-a-boot-id"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid boot ID error = %v", err)
	}
	run, err = store.ClearRuntimeIntent(ctx, request.RunID)
	if err != nil || run.RuntimeIntentPending || run.RuntimeIntentBootID != nil {
		t.Fatalf("ClearRuntimeIntent() = (%#v, %v)", run, err)
	}
	if _, err := store.ClearRuntimeIntent(ctx, request.RunID); err != nil {
		t.Fatalf("idempotent ClearRuntimeIntent() error = %v", err)
	}
	if _, _, err := store.BeginRuntimeIntent(ctx, request.RunID, testBootID); err != nil {
		t.Fatal(err)
	}
	run, err = store.SetRuntimeRef(ctx, request.RunID, "container:intent")
	if err != nil || run.RuntimeIntentPending || run.RuntimeIntentBootID != nil || run.RuntimeRef == nil || *run.RuntimeRef != "container:intent" {
		t.Fatalf("fenced SetRuntimeRef() = (%#v, %v)", run, err)
	}
	if _, _, err := store.BeginRuntimeIntent(ctx, request.RunID, testBootID); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("BeginRuntimeIntent with ref error = %v", err)
	}
	if _, err := store.ClearRuntimeIntent(ctx, request.RunID); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("ClearRuntimeIntent with ref error = %v", err)
	}
	if _, err := store.db.Exec(`UPDATE runs SET runtime_ref = 'container:replacement' WHERE run_id = ?`, request.RunID); err == nil {
		t.Fatal("database trigger replaced an immutable runtime reference")
	}

	withoutIntent := startRequest("run_direct_ref", "inspect")
	withoutIntent.SessionScopeDigest = strings.Repeat("b", 64)
	if _, _, err := registerTestStart(store, ctx, withoutIntent, withoutIntent.ExpectedRevision, "workspace-direct", false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE runs SET runtime_ref = 'container:direct' WHERE run_id = ?`, withoutIntent.RunID); err == nil {
		t.Fatal("database trigger accepted a runtime reference without an intent")
	}
	if _, _, err := store.BeginRuntimeIntent(ctx, withoutIntent.RunID, testBootID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetRuntimeRef(ctx, withoutIntent.RunID, "container:intent"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate runtime reference error = %v", err)
	}
	stillPending, err := store.GetRun(ctx, withoutIntent.RunID)
	if err != nil || !stillPending.RuntimeIntentPending || stillPending.RuntimeRef != nil {
		t.Fatalf("conflicting bind changed intent = (%#v, %v)", stillPending, err)
	}

	cancelling := startRequest("run_cancelling_intent", "inspect")
	cancelling.SessionScopeDigest = strings.Repeat("c", 64)
	if _, _, err := registerTestStart(store, ctx, cancelling, cancelling.ExpectedRevision, "workspace-cancel-intent", false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkCancelling(ctx, cancelling.RunID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.BeginRuntimeIntent(ctx, cancelling.RunID, testBootID); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("cancelling BeginRuntimeIntent error = %v", err)
	}
	if _, err := store.db.Exec(`UPDATE runs SET runtime_intent_pending = 1 WHERE run_id = ?`, cancelling.RunID); err == nil {
		t.Fatal("database trigger granted fresh Create authority to cancelling run")
	}
	guarded := startRequest("run_boot_guard", "inspect")
	guarded.SessionScopeDigest = strings.Repeat("d", 64)
	if _, _, err := registerTestStart(store, ctx, guarded, guarded.ExpectedRevision, "workspace-boot-guard", false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE runs SET runtime_intent_pending = 1 WHERE run_id = ?`, guarded.RunID); err == nil {
		t.Fatal("database trigger accepted a fresh intent without a boot identifier")
	}
	if _, err := store.db.Exec(`UPDATE runs SET runtime_intent_boot_id = ? WHERE run_id = ?`, testBootID, guarded.RunID); err == nil {
		t.Fatal("database trigger accepted a boot identifier without an intent")
	}
}

func TestTerminalPendingIntentRemainsUnreconciledUntilConfirmation(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	request := startRequest("run_terminal_pending", "inspect")
	if _, _, err := registerTestStart(store, ctx, request, request.ExpectedRevision, "workspace-terminal", false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.BeginRuntimeIntent(ctx, request.RunID, testBootID); err != nil {
		t.Fatal(err)
	}
	failed := executionwire.RunEvent{
		RunID: request.RunID,
		Seq:   1,
		Type:  executionwire.RunEventFailed,
		Failure: &executionwire.RunFailure{
			Code:    executionwire.FailureRunnerFailed,
			Message: "create outcome requires reconciliation",
		},
	}
	if _, err := store.AppendEvent(ctx, failed, nil); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("pending failed event error = %v", err)
	}
	cancelled := executionwire.RunEvent{RunID: request.RunID, Seq: 1, Type: executionwire.RunEventCancelled}
	if _, err := store.AppendEvent(ctx, cancelled, nil); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("pending cancelled event error = %v", err)
	}
	if _, err := store.db.Exec(`UPDATE runs SET state = 'failed', terminal_at_unix_ms = 1
        WHERE run_id = ?`, request.RunID); err == nil {
		t.Fatal("database trigger accepted a failed terminal state with pending intent")
	}
	interrupted := executionwire.RunEvent{
		RunID: request.RunID,
		Seq:   1,
		Type:  executionwire.RunEventInterrupted,
		Failure: &executionwire.RunFailure{
			Code: executionwire.FailureRuntimeInterrupted, Message: "create outcome requires reconciliation",
		},
	}
	run, err := store.AppendEvent(ctx, interrupted, nil)
	if err != nil {
		t.Fatalf("pending interrupted event error = %v", err)
	}
	if _, err := store.db.Exec(`UPDATE run_events SET event_type = 'cancelled'
        WHERE run_id = ? AND seq = 1`, request.RunID); err == nil {
		t.Fatal("database accepted mutation of an immutable run event")
	}
	if _, err := store.db.Exec(`DELETE FROM run_events WHERE run_id = ? AND seq = 1`, request.RunID); err == nil {
		t.Fatal("database accepted deletion of an immutable run event")
	}
	if !run.RuntimeIntentPending || !isTerminal(run.State) {
		t.Fatalf("terminal event lost pending intent: %#v", run)
	}
	unreconciled, err := store.ListUnreconciled(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unreconciled) != 1 || unreconciled[0].RunID != request.RunID || !unreconciled[0].RuntimeIntentPending {
		t.Fatalf("unreconciled terminal intent = %#v", unreconciled)
	}
	if _, err := store.ConfirmRuntimeStopped(ctx, request.RunID); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("confirmation bypassed pending intent: %v", err)
	}
	run, err = store.ClearRuntimeIntent(ctx, request.RunID)
	if err != nil || run.RuntimeIntentPending {
		t.Fatalf("terminal fence clear = (%#v, %v)", run, err)
	}
	if _, err := store.ClearRuntimeIntent(ctx, request.RunID); err != nil {
		t.Fatalf("idempotent terminal fence clear error = %v", err)
	}
	run, err = store.ConfirmRuntimeStopped(ctx, request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.RuntimeIntentPending {
		t.Fatalf("confirmation retained runtime intent: %#v", run)
	}
	unreconciled, err = store.ListUnreconciled(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unreconciled) != 0 {
		t.Fatalf("confirmed read-only run remains unreconciled: %#v", unreconciled)
	}
}

func TestSessionMappingIsBoundedAndRevisionScoped(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	request := startRequest("run_01", "inspect")
	if _, _, err := registerTestStart(store, ctx, request, request.ExpectedRevision, "workspace-alpha", true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendEvent(ctx,
		executionwire.RunEvent{RunID: request.RunID, Seq: 1, Type: executionwire.RunEventStarted}, nil); err != nil {
		t.Fatal(err)
	}
	sessionRef := "session_01"
	completed := executionwire.RunEvent{
		RunID: request.RunID,
		Seq:   2,
		Type:  executionwire.RunEventCompleted,
		Result: &executionwire.RunResult{
			Output:     executionwire.TextOutput{MediaType: executionwire.MediaTypeTextPlain, Text: "done"},
			SessionRef: &sessionRef,
		},
	}
	if _, err := store.AppendEvent(ctx, completed, &SessionMapping{Ref: sessionRef, VendorToken: "unsafe token"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("unsafe vendor session token error = %v", err)
	}
	if _, err := store.AppendEvent(ctx, completed, &SessionMapping{Ref: sessionRef, VendorToken: strings.Repeat("a", 1025)}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("oversized vendor session token error = %v", err)
	}
	if _, err := store.AppendEvent(ctx, completed, &SessionMapping{Ref: sessionRef, VendorToken: "token-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResolveSessionForRun(ctx, "not_a_resume", sessionRef, request.TargetID,
		request.ExpectedRevision, request.SessionScopeDigest); !errors.Is(err, ErrSessionScope) {
		t.Fatalf("unconsumed session resolve error = %v", err)
	}
	var eventTokenRows int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM run_events
        WHERE COALESCE(message_text, '') LIKE '%token-1%'`).Scan(&eventTokenRows); err != nil {
		t.Fatal(err)
	}
	if eventTokenRows != 0 {
		t.Fatal("vendor token leaked into durable event payload")
	}

	for _, mutation := range []string{
		`UPDATE sessions SET target_id = 'other' WHERE session_ref = 'session_01'`,
		`UPDATE sessions SET session_scope_digest = '` + strings.Repeat("b", 64) + `' WHERE session_ref = 'session_01'`,
		`UPDATE sessions SET vendor_token = 'other-token' WHERE session_ref = 'session_01'`,
		`DELETE FROM sessions WHERE session_ref = 'session_01'`,
		`INSERT OR REPLACE INTO sessions(
            session_ref, target_id, target_revision, session_scope_digest,
            vendor_token, created_at_unix_ms
         ) VALUES ('session_01', 'target-codex', 'target-codex-r1', '` + strings.Repeat("b", 64) + `', 'other-token', 1)`,
	} {
		if _, err := store.db.Exec(mutation); err == nil {
			t.Fatalf("session authority mutation succeeded: %s", mutation)
		}
	}
	for _, mutation := range []string{
		`UPDATE runs SET request_fingerprint = '` + strings.Repeat("b", 64) + `' WHERE run_id = 'run_01'`,
		`UPDATE runs SET target_id = 'other' WHERE run_id = 'run_01'`,
		`UPDATE runs SET target_revision = 'other' WHERE run_id = 'run_01'`,
		`UPDATE runs SET requested_session_ref = 'other' WHERE run_id = 'run_01'`,
		`UPDATE runs SET session_scope_digest = '` + strings.Repeat("b", 64) + `' WHERE run_id = 'run_01'`,
	} {
		if _, err := store.db.Exec(mutation); err == nil {
			t.Fatalf("Run session authority mutation succeeded: %s", mutation)
		}
	}

	if _, err := store.ConfirmRuntimeStopped(ctx, request.RunID); err != nil {
		t.Fatal(err)
	}
	resume := startRequest("run_02", "continue")
	resume.SessionRef = &sessionRef
	if _, _, err := registerTestStart(store, ctx, resume, resume.ExpectedRevision, "workspace-alpha", true); err != nil {
		t.Fatalf("same-scope resume registration error = %v", err)
	}
	token, err := store.ResolveSessionForRun(ctx, resume.RunID, sessionRef, request.TargetID,
		request.ExpectedRevision, request.SessionScopeDigest)
	if err != nil || token != "token-1" {
		t.Fatalf("ResolveSessionForRun() = %q, %v", token, err)
	}
	if _, err := store.ResolveSessionForRun(ctx, resume.RunID, sessionRef, request.TargetID,
		"target-codex-r2", request.SessionScopeDigest); !errors.Is(err, ErrSessionScope) {
		t.Fatalf("cross-revision resolve error = %v", err)
	}
	if _, err := store.ResolveSessionForRun(ctx, resume.RunID, sessionRef, request.TargetID,
		request.ExpectedRevision, strings.Repeat("b", 64)); !errors.Is(err, ErrSessionScope) {
		t.Fatalf("cross-digest resolve error = %v", err)
	}
	if _, err := store.ResolveSessionForRun(ctx, resume.RunID, "unknown_session", request.TargetID,
		request.ExpectedRevision, request.SessionScopeDigest); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("unknown session error = %v", err)
	}

	wrongScope := startRequest("run_03", "continue elsewhere")
	wrongScope.TargetID = "target-claude"
	wrongScope.SessionRef = &sessionRef
	if err := store.RegisterTargetAuthorities(ctx, []TargetAuthority{
		testTargetAuthority(wrongScope.TargetID, wrongScope.ExpectedRevision, "state-claude", 'b', '6', true),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := registerTestStart(store, ctx, wrongScope, wrongScope.ExpectedRevision, "workspace-beta", true); !errors.Is(err, ErrSessionScope) {
		t.Fatalf("cross-target resume registration error = %v", err)
	}
}

func TestReconcileInterruptedIsTerminalAndReleasesLock(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	request := startRequest("run_01", "inspect")
	if _, _, err := registerTestStart(store, ctx, request, request.ExpectedRevision, "workspace-alpha", true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.BeginRuntimeIntent(ctx, request.RunID, testBootID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetRuntimeRef(ctx, request.RunID, "container:abc"); err != nil {
		t.Fatal(err)
	}
	nonterminal, err := store.ListNonTerminal(ctx)
	if err != nil || len(nonterminal) != 1 {
		t.Fatalf("ListNonTerminal() = %#v, %v", nonterminal, err)
	}

	if _, err := store.ReconcileInterrupted(ctx, request.RunID, "must not bypass runtime cleanup"); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("runtime-bearing reconciliation error = %v", err)
	}
	interrupted := executionwire.RunEvent{
		RunID: request.RunID,
		Seq:   1,
		Type:  executionwire.RunEventInterrupted,
		Failure: &executionwire.RunFailure{
			Code:    executionwire.FailureRuntimeInterrupted,
			Message: "runtime state was uncertain after restart",
		},
	}
	run, err := store.AppendEvent(ctx, interrupted, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !run.WorkspaceLockHeld || run.RuntimeRef == nil {
		t.Fatalf("terminal event discarded runtime authority: %#v", run)
	}
	run, err = store.ConfirmRuntimeStopped(ctx, request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.State != executionwire.RunStateInterrupted || run.WorkspaceLockHeld || run.RuntimeRef != nil {
		t.Fatalf("reconciled run = %#v", run)
	}
	snapshot, err := store.GetSnapshot(ctx, request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Events) != 1 || snapshot.Events[0].Type != executionwire.RunEventInterrupted {
		t.Fatalf("reconciled snapshot = %#v", snapshot)
	}
	if _, err := store.ReconcileInterrupted(ctx, request.RunID, "ignored on terminal retry"); err != nil {
		t.Fatalf("idempotent terminal reconciliation error = %v", err)
	}

	contender := startRequest("run_02", "new work")
	if _, _, err := registerTestStart(store, ctx, contender, contender.ExpectedRevision, "workspace-alpha", true); err != nil {
		t.Fatalf("workspace remained locked after reconciliation: %v", err)
	}
}

func TestPreStartCancellationAndLockReleaseGuard(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	request := startRequest("run_cancel", "cancel before launch")
	if _, _, err := registerTestStart(store, ctx, request, request.ExpectedRevision, "workspace-cancel", true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`DELETE FROM workspace_locks WHERE run_id = ?`, request.RunID); err == nil {
		t.Fatal("database trigger released a nonterminal writer lock")
	}
	run, err := store.MarkCancelling(ctx, request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.State != executionwire.RunStateCancelling || run.LastEventSeq != 0 {
		t.Fatalf("pre-start cancelling run = %#v", run)
	}
	snapshot, err := store.GetSnapshot(ctx, request.RunID)
	if err != nil {
		t.Fatalf("GetSnapshot() during pre-start cancellation error = %v", err)
	}
	if snapshot.Status.State != executionwire.RunStateCancelling || len(snapshot.Events) != 0 {
		t.Fatalf("pre-start cancellation snapshot = %#v", snapshot)
	}
	cancelled := executionwire.RunEvent{RunID: request.RunID, Seq: 1, Type: executionwire.RunEventCancelled}
	if _, err := store.AppendEvent(ctx, cancelled, nil); err != nil {
		t.Fatal(err)
	}
	run, err = store.ConfirmRuntimeStopped(ctx, request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.WorkspaceLockHeld {
		t.Fatal("pre-start cancelled run retained writer lock")
	}
}

func TestTerminalPayloadsAreBounded(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	request := startRequest("run_01", "inspect")
	if _, _, err := registerTestStart(store, ctx, request, request.ExpectedRevision, "workspace-alpha", true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendEvent(ctx,
		executionwire.RunEvent{RunID: request.RunID, Seq: 1, Type: executionwire.RunEventStarted}, nil); err != nil {
		t.Fatal(err)
	}
	oversized := executionwire.RunEvent{
		RunID: request.RunID,
		Seq:   2,
		Type:  executionwire.RunEventCompleted,
		Result: &executionwire.RunResult{Output: executionwire.TextOutput{
			MediaType: executionwire.MediaTypeTextPlain,
			Text:      strings.Repeat("x", executionwire.MaxOutputTextBytes+1),
		}},
	}
	if _, err := store.AppendEvent(ctx, oversized, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("oversized terminal output error = %v", err)
	}
	run, err := store.GetRun(ctx, request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.State != executionwire.RunStateRunning || run.LastEventSeq != 1 {
		t.Fatalf("rejected terminal event changed run = %#v", run)
	}
}

func TestSQLiteVersionComparison(t *testing.T) {
	tests := []struct {
		got  string
		want bool
	}{
		{"3.51.2", false},
		{"3.51.3", true},
		{"3.53.0", true},
		{"4.0.0", true},
	}
	for _, test := range tests {
		actual, err := sqliteVersionAtLeast(test.got, minimumSQLiteVersion)
		if err != nil {
			t.Fatalf("sqliteVersionAtLeast(%q) error = %v", test.got, err)
		}
		if actual != test.want {
			t.Fatalf("sqliteVersionAtLeast(%q) = %v, want %v", test.got, actual, test.want)
		}
	}
	if _, err := sqliteVersionAtLeast("3.51", minimumSQLiteVersion); err == nil {
		t.Fatal("malformed SQLite version accepted")
	}
}
