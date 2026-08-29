package corestore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

type tokenSequence struct {
	mu   sync.Mutex
	next int
}

func (sequence *tokenSequence) Next() (string, error) {
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	sequence.next++
	return fmt.Sprintf("lease_%03d", sequence.next), nil
}

func openTestStore(t *testing.T) (*Store, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)}
	tokens := &tokenSequence{}
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "agentd.sqlite3"), Options{
		Clock:         clock.Now,
		NewLeaseToken: tokens.Next,
		Admission:     testAdmissionOptions(),
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return store, clock
}

func testAdmissionOptions() AdmissionOptions {
	return AdmissionOptions{
		AcceptWindow:                      time.Hour,
		ReceiptWindow:                     24 * time.Hour,
		FutureSkew:                        5 * time.Minute,
		MaxReceiptsPerConnector:           1_000,
		MaxQueuedRunsPerConnector:         1_000,
		MaxNonTerminalRunsPerConnector:    1_000,
		MaxPendingDeliveriesPerConnector:  1_000,
		MaxRetainedInputBytesPerConnector: 32 << 20,
		MaxDatabasePages:                  100_000,
	}
}

func baseIngest(eventID string) IngestTextRunInput {
	return IngestTextRunInput{
		ConnectorID:      "discord-personal",
		EventID:          eventID,
		PayloadHash:      sha256.Sum256([]byte("payload:" + eventID)),
		ActorRef:         "user/" + eventID,
		ConversationRef:  "dm/demo",
		MessageRef:       "message/" + eventID,
		OccurredAtUnixMS: 1786881600000,
		Text:             "Inspect the project",
	}
}

func ingestAs(store *Store, input IngestTextRunInput, runID string) (IngestResult, error) {
	return store.IngestTextRun(
		context.Background(),
		input,
		func() (TextRunAuthorization, error) {
			return testTextRunAuthorization(), nil
		},
		func() (string, error) { return runID, nil },
	)
}

func testTextRunAuthorization() TextRunAuthorization {
	return TextRunAuthorization{
		TargetID: "project-codex", TargetRevision: "project-codex-r1",
		BindingFingerprint: strings.Repeat("a", SHA256HexBytes),
		PolicyRevision:     strings.Repeat("b", SHA256HexBytes),
	}
}

func mustIngest(t *testing.T, store *Store, runID string, input IngestTextRunInput) Run {
	t.Helper()
	result, err := ingestAs(store, input, runID)
	if err != nil {
		t.Fatalf("IngestTextRun() error = %v", err)
	}
	if result.Duplicate {
		t.Fatal("first ingest reported duplicate")
	}
	return result.Run
}

func mustPrepareNoSession(t *testing.T, store *Store, run Run) PreparedRunStart {
	t.Helper()
	prepared, err := store.PrepareRunStart(context.Background(), PrepareRunStartInput{
		RunID: run.ID, DispatchToken: run.DispatchToken,
		Deadline: time.Date(2027, 8, 16, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("PrepareRunStart(%q) error = %v", run.ID, err)
	}
	return prepared
}

func sessionKeyFromTestRun(run Run) SessionKey {
	return SessionKey{
		BindingFingerprint: run.BindingFingerprint,
		ConnectorID:        run.ConnectorID,
		ActorRef:           run.ActorRef,
		ConversationRef:    run.ConversationRef,
		TargetID:           run.TargetID,
		TargetRevision:     run.TargetRevision,
	}
}

// PutSession exists only in the corestore test build. The production Store
// intentionally has no arbitrary session-mint method.
func (s *Store) PutSession(ctx context.Context, session Session) error {
	if err := validateSessionKey(session.SessionKey); err != nil {
		return err
	}
	if err := validateSessionRef(session.Ref); err != nil {
		return err
	}
	now, err := s.nowMillis()
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := putSessionTx(ctx, tx, session, now); err != nil {
		return err
	}
	return tx.Commit()
}

func finishNextRunWithReply(
	t *testing.T,
	store *Store,
	wantRunID string,
	reply TextDeliveryInput,
) Run {
	t.Helper()
	run, ok, err := store.ClaimQueuedRun(context.Background(), 30*time.Second)
	if err != nil || !ok || run.ID != wantRunID {
		t.Fatalf("ClaimQueuedRun() = %#v, %v, %v, want %q", run, ok, err, wantRunID)
	}
	mustPrepareNoSession(t, store, run)
	if err := store.MarkRunRunning(context.Background(), run.ID, run.DispatchToken); err != nil {
		t.Fatalf("MarkRunRunning(%q): %v", run.ID, err)
	}
	if err := store.FinishRun(context.Background(), FinishRunInput{
		RunID: run.ID, DispatchToken: run.DispatchToken,
		State: RunCompleted, OutputText: reply.Text,
	}, &reply); err != nil {
		t.Fatalf("FinishRun(%q): %v", run.ID, err)
	}
	return run
}

func TestOpenRequiresSecureLocalDatabaseAndConfiguresSQLite(t *testing.T) {
	clock := Clock(func() time.Time { return time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC) })
	if _, err := Open(context.Background(), "relative.sqlite3", Options{Clock: clock}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relative path error = %v, want ErrInvalid", err)
	}
	if _, err := Open(context.Background(), "/tmp/query.sqlite3?mode=memory", Options{Clock: clock}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("URI-like path error = %v, want ErrInvalid", err)
	}

	directoryPath := t.TempDir()
	if _, err := Open(context.Background(), directoryPath, Options{Clock: clock}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("directory path error = %v, want ErrInvalid", err)
	}
	target := filepath.Join(t.TempDir(), "target.sqlite3")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "database.sqlite3")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), link, Options{Clock: clock}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink path error = %v, want ErrInvalid", err)
	}
	insecure := filepath.Join(t.TempDir(), "insecure.sqlite3")
	if err := os.WriteFile(insecure, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(insecure, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), insecure, Options{Clock: clock}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("insecure file mode error = %v, want ErrInvalid", err)
	}

	path := filepath.Join(t.TempDir(), "agentd.sqlite3")
	store, err := Open(context.Background(), path, Options{Clock: clock, Admission: testAdmissionOptions()})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	info, err := os.Lstat(path)
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
	if err := store.db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d, err = %v", foreignKeys, err)
	}
	var synchronous int
	if err := store.db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
		t.Fatalf("synchronous = %d, err = %v", synchronous, err)
	}
	var trustedSchema int
	if err := store.db.QueryRow("PRAGMA trusted_schema").Scan(&trustedSchema); err != nil || trustedSchema != 0 {
		t.Fatalf("trusted_schema = %d, err = %v", trustedSchema, err)
	}
	var journal string
	if err := store.db.QueryRow("PRAGMA journal_mode").Scan(&journal); err != nil || !strings.EqualFold(journal, "delete") {
		t.Fatalf("journal_mode = %q, err = %v", journal, err)
	}
	var migrationCount int
	migrationSet, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&migrationCount); err != nil || migrationCount != len(migrationSet) {
		t.Fatalf("migration count = %d, err = %v", migrationCount, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(context.Background(), path, Options{Clock: clock, Admission: testAdmissionOptions()})
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsHardLinkedDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "core.sqlite3")
	store, err := Open(ctx, path, Options{Admission: testAdmissionOptions()})
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	alias := filepath.Join(filepath.Dir(path), "core-alias.sqlite3")
	if err := os.Link(path, alias); err != nil {
		t.Fatalf("create hard link: %v", err)
	}

	for _, candidate := range []string{path, alias} {
		opened, err := Open(ctx, candidate, Options{Admission: testAdmissionOptions()})
		if opened != nil || !errors.Is(err, ErrInvalid) {
			if opened != nil {
				_ = opened.Close()
			}
			t.Fatalf("Open(%q) = %#v, %v; want nil, ErrInvalid", candidate, opened, err)
		}
	}
}

func TestMigrationChecksumAndClosedStateConstraints(t *testing.T) {
	store, _ := openTestStore(t)
	_, err := store.db.Exec(`
INSERT INTO runs(
    id, connector_id, event_id, actor_ref, conversation_ref, message_ref,
    target_id, target_revision, binding_fingerprint, policy_revision,
    input_text, state, created_at_ms, updated_at_ms
) VALUES ('run_bad', 'c', 'e', 'a', 'v', 'm', 't', 'r', ?, ?, 'x', 'arbitrary', 1, 1)`,
		strings.Repeat("a", SHA256HexBytes), strings.Repeat("b", SHA256HexBytes))
	if err == nil {
		t.Fatal("database accepted an open-ended run state")
	}
	_, err = store.db.Exec(`
INSERT INTO runs(
    id, connector_id, event_id, actor_ref, conversation_ref, message_ref,
    target_id, target_revision, input_text, state, created_at_ms, updated_at_ms
) VALUES ('run_no_evidence', 'c', 'e2', 'a', 'v', 'm', 't', 'r', 'x', 'queued', 1, 1)`)
	if err == nil {
		t.Fatal("database accepted a new Run without exact binding evidence")
	}
	for _, conflictClause := range []string{"OR IGNORE", "OR REPLACE"} {
		_, err = store.db.Exec(fmt.Sprintf(`
INSERT %s INTO runs(
    id, connector_id, event_id, actor_ref, conversation_ref, message_ref,
    target_id, target_revision, input_text, state, created_at_ms, updated_at_ms
) VALUES ('run_no_evidence_%s', 'c', 'e_%s', 'a', 'v', 'm', 't', 'r', 'x', 'queued', 1, 1)`,
			conflictClause, strings.ReplaceAll(conflictClause, " ", "_"), strings.ReplaceAll(conflictClause, " ", "_")))
		if err == nil {
			t.Fatalf("database accepted missing evidence with INSERT %s", conflictClause)
		}
	}
	var evidenceBypassRuns int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM runs WHERE id LIKE 'run_no_evidence_%'`).Scan(&evidenceBypassRuns); err != nil {
		t.Fatal(err)
	}
	if evidenceBypassRuns != 0 {
		t.Fatalf("conflict-clause evidence bypass persisted %d Runs", evidenceBypassRuns)
	}
	parent := mustIngest(t, store, "run_delivery_parent", baseIngest("delivery_parent"))
	_, err = store.db.Exec(`
INSERT INTO text_deliveries(
    id, run_id, text, state, available_at_ms, created_at_ms, updated_at_ms
) VALUES ('delivery_bad', ?, 'x', 'unknown', 1, 1, 1)`, parent.ID)
	if err == nil {
		t.Fatal("database accepted an open-ended delivery state")
	}
	if _, err := store.db.Exec("UPDATE schema_migrations SET sha256 = zeroblob(32)"); err != nil {
		t.Fatal(err)
	}
	if err := store.applyMigrations(context.Background()); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("tampered migration error = %v, want checksum failure", err)
	}
}

func TestMigrationsThreeThroughSevenUpgradeOriginalVersionTwoDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agentd.sqlite3")
	if err := prepareDatabaseFile(path); err != nil {
		t.Fatal(err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) != 7 || migrations[0].version != 1 ||
		migrations[1].version != 2 || migrations[2].version != 3 ||
		migrations[3].version != 4 || migrations[4].version != 5 || migrations[5].version != 6 || migrations[6].version != 7 {
		t.Fatalf("migration lineage = %#v, want versions 1 through 7", migrations)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range migrations[:2] {
		if _, err := db.Exec(string(candidate.contents)); err != nil {
			_ = db.Close()
			t.Fatalf("apply fixture migration %d: %v", candidate.version, err)
		}
	}
	if _, err := db.Exec(`
CREATE TABLE schema_migrations (
    version       INTEGER PRIMARY KEY CHECK (version > 0),
    name          TEXT NOT NULL UNIQUE,
    sha256        BLOB NOT NULL CHECK (length(sha256) = 32),
    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms > 0)
) STRICT`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	for _, candidate := range migrations[:2] {
		if _, err := db.Exec(`INSERT INTO schema_migrations(version, name, sha256, applied_at_ms)
            VALUES (?, ?, ?, 1)`, candidate.version, candidate.name, candidate.hash[:]); err != nil {
			_ = db.Close()
			t.Fatalf("record fixture migration %d: %v", candidate.version, err)
		}
	}
	if _, err := db.Exec(`
INSERT INTO runs(
    id, connector_id, event_id, actor_ref, conversation_ref, message_ref,
    target_id, target_revision, input_text, state, dispatch_token,
    start_prepared, start_deadline_ms, output_text, created_at_ms, updated_at_ms
) VALUES ('run_pre_v3', 'discord-personal', 'event_pre_v3', 'user/demo', 'dm/demo',
    'message/pre-v3', 'project-codex', 'project-codex-r1', 'legacy', 'completed',
    'dispatch_pre_v3', 1, 2, 'done', 1, 1);
INSERT INTO inbound_events(
    connector_id, event_id, payload_hash, run_id, occurred_at_ms, received_at_ms
) VALUES ('discord-personal', 'event_pre_v3', zeroblob(32), 'run_pre_v3', 1, 1)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	clock := Clock(func() time.Time { return time.UnixMilli(2) })
	store, err := Open(context.Background(), path, Options{
		Clock: clock, Admission: testAdmissionOptions(),
	})
	if err != nil {
		t.Fatalf("upgrade original version-two database: %v", err)
	}
	defer store.Close()
	var hashVersion, migrationCount int
	var bindingFingerprint, policyRevision string
	if err := store.db.QueryRow(`SELECT payload_hash_version FROM inbound_events
        WHERE connector_id = 'discord-personal' AND event_id = 'event_pre_v3'`).Scan(&hashVersion); err != nil {
		t.Fatal(err)
	}
	if hashVersion != 1 {
		t.Fatalf("pre-v3 receipt hash version = %d, want 1", hashVersion)
	}
	if err := store.db.QueryRow(`SELECT COALESCE(binding_fingerprint, ''), COALESCE(policy_revision, '')
        FROM runs WHERE id = 'run_pre_v3'`).Scan(&bindingFingerprint, &policyRevision); err != nil {
		t.Fatal(err)
	}
	if bindingFingerprint != "" || policyRevision != "" {
		t.Fatalf("legacy Run received fabricated EBA evidence: %q %q", bindingFingerprint, policyRevision)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatal(err)
	}
	if migrationCount != 7 {
		t.Fatalf("migration count after upgrade = %d, want 7", migrationCount)
	}
	if _, err := store.db.Exec(`UPDATE runs SET binding_fingerprint = ?, policy_revision = ?
        WHERE id = 'run_pre_v3'`, strings.Repeat("a", 64), strings.Repeat("b", 64)); err == nil {
		t.Fatal("legacy Run accepted fabricated EBA evidence")
	}
	replay, err := store.IngestTextRun(context.Background(), IngestTextRunInput{
		ConnectorID: "discord-personal", EventID: "event_pre_v3",
		ActorRef: "user/demo", ConversationRef: "dm/demo", MessageRef: "message/pre-v3",
		OccurredAtUnixMS: 1, Text: "legacy",
	}, func() (TextRunAuthorization, error) {
		t.Fatal("retained legacy replay consulted current authorization")
		return TextRunAuthorization{}, errors.New("unreachable")
	}, func() (string, error) {
		t.Fatal("retained legacy replay consumed a new Run ID")
		return "", errors.New("unreachable")
	})
	if err != nil || !replay.Duplicate || replay.Run.ID != "run_pre_v3" ||
		replay.Run.BindingFingerprint != "" || replay.Run.PolicyRevision != "" {
		t.Fatalf("retained legacy replay = %#v, err = %v", replay, err)
	}
}

func TestCoreStoreRefusesFutureMigrationVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core-future.sqlite3")
	store, err := Open(context.Background(), path, Options{Admission: testAdmissionOptions()})
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
	if _, err := db.Exec(`INSERT INTO schema_migrations(version, name, sha256, applied_at_ms)
		VALUES (8, '008_future.sql', zeroblob(32), 1)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path, Options{Admission: testAdmissionOptions()})
	if reopened != nil {
		_ = reopened.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "unknown migration version 8") {
		t.Fatalf("Open() future-version error = %v", err)
	}
}

func TestMigrationSevenRefusesDuplicateLiveSessionScopesBeforeDDL(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "core-v6-duplicate-scope.sqlite3")
	clock := &fakeClock{now: time.UnixMilli(baseIngest("clock").OccurredAtUnixMS).UTC()}
	options := Options{Clock: clock.Now, Admission: testAdmissionOptions()}
	store, err := Open(ctx, path, options)
	if err != nil {
		t.Fatal(err)
	}
	mustIngest(t, store, "run_scope_first", baseIngest("event_scope_first"))
	if _, err := store.db.Exec(`DROP INDEX runs_one_nonterminal_session_scope`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`DELETE FROM schema_migrations WHERE version = 7`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO runs(
        id, connector_id, event_id, actor_ref, conversation_ref, message_ref,
        target_id, target_revision, binding_fingerprint, policy_revision,
        input_text, state, created_at_ms, updated_at_ms
    ) SELECT 'run_scope_second', connector_id, 'event_scope_second', actor_ref,
        conversation_ref, 'message/scope-second', target_id, target_revision,
        binding_fingerprint, policy_revision, input_text, 'queued',
        created_at_ms + 1, updated_at_ms + 1
      FROM runs WHERE id = 'run_scope_first'`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path, options)
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrUnsafeLegacySessionLifecycleState) {
		t.Fatalf("Open() error = %v, want ErrUnsafeLegacySessionLifecycleState", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var maxVersion int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&maxVersion); err != nil {
		t.Fatal(err)
	}
	if maxVersion != 6 {
		t.Fatalf("migration ledger advanced to %d, want 6", maxVersion)
	}
	var indexCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master
        WHERE type = 'index' AND name = 'runs_one_nonterminal_session_scope'`).Scan(&indexCount); err != nil {
		t.Fatal(err)
	}
	if indexCount != 0 {
		t.Fatalf("migration DDL landed despite gate: index count = %d", indexCount)
	}
}

func TestMigrationFourRefusesLegacyNonterminalRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agentd.sqlite3")
	if err := prepareDatabaseFile(path); err != nil {
		t.Fatal(err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range migrations[:3] {
		if _, err := db.Exec(string(candidate.contents)); err != nil {
			_ = db.Close()
			t.Fatalf("apply fixture migration %d: %v", candidate.version, err)
		}
	}
	if _, err := db.Exec(`
CREATE TABLE schema_migrations (
    version       INTEGER PRIMARY KEY CHECK (version > 0),
    name          TEXT NOT NULL UNIQUE,
    sha256        BLOB NOT NULL CHECK (length(sha256) = 32),
    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms > 0)
) STRICT`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	for _, candidate := range migrations[:3] {
		if _, err := db.Exec(`INSERT INTO schema_migrations(version, name, sha256, applied_at_ms)
            VALUES (?, ?, ?, 1)`, candidate.version, candidate.name, candidate.hash[:]); err != nil {
			_ = db.Close()
			t.Fatalf("record fixture migration %d: %v", candidate.version, err)
		}
	}
	if _, err := db.Exec(`
INSERT INTO runs(
    id, connector_id, event_id, actor_ref, conversation_ref, message_ref,
    target_id, target_revision, input_text, state, created_at_ms, updated_at_ms
) VALUES ('run_legacy_queued', 'discord-personal', 'event_legacy_queued', 'user/demo',
    'dm/demo', 'message/legacy', 'project-codex', 'project-codex-r1', 'legacy',
    'queued', 1, 1)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	clock := Clock(func() time.Time { return time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC) })
	store, err := Open(context.Background(), path, Options{
		Clock: clock, Admission: testAdmissionOptions(),
	})
	if store != nil {
		_ = store.Close()
	}
	if !errors.Is(err, ErrUnsafeLegacyAdmissionState) {
		t.Fatalf("legacy nonterminal upgrade error = %v, want ErrUnsafeLegacyAdmissionState", err)
	}

	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var migrationCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatal(err)
	}
	if migrationCount != 3 {
		t.Fatalf("refused upgrade migration count = %d, want 3", migrationCount)
	}
}

func TestLegacyExactBindingGateUsesTerminalStateComplement(t *testing.T) {
	tests := []struct {
		state       RunState
		dispatching bool
		started     bool
		output      *string
		failure     *string
		wantUnsafe  bool
	}{
		{state: RunQueued, wantUnsafe: true},
		{state: RunDispatching, dispatching: true, wantUnsafe: true},
		{state: RunRunning, started: true, wantUnsafe: true},
		{state: RunCompleted, started: true, output: stringPointer("done")},
		{state: RunFailed, started: true, failure: stringPointer(string(RunFailureInternal))},
		{state: RunCancelled, started: true},
		{state: RunInterrupted, started: true, failure: stringPointer(string(RunFailureRuntimeInterrupted))},
	}
	for _, test := range tests {
		t.Run(string(test.state), func(t *testing.T) {
			store, _ := openTestStore(t)
			if _, err := store.db.Exec(`DROP TRIGGER runs_require_exact_binding_evidence_insert`); err != nil {
				t.Fatal(err)
			}
			var dispatchToken, dispatchExpires, startDeadline any
			if test.state != RunQueued {
				dispatchToken = "legacy-dispatch"
			}
			if test.dispatching {
				dispatchExpires = int64(2)
			}
			startPrepared := 0
			if test.started {
				startPrepared = 1
				startDeadline = int64(2)
			}
			if _, err := store.db.Exec(`
INSERT INTO runs(
    id, connector_id, event_id, actor_ref, conversation_ref, message_ref,
    target_id, target_revision, input_text, state, dispatch_token,
    dispatch_expires_at_ms, start_prepared, start_deadline_ms, output_text,
    failure_code, created_at_ms, updated_at_ms
) VALUES ('legacy_state', 'c', 'e', 'a', 'v', 'm', 't', 'r', 'x', ?, ?, ?, ?, ?, ?, ?, 1, 1)`,
				string(test.state), dispatchToken, dispatchExpires, startPrepared, startDeadline,
				test.output, test.failure); err != nil {
				t.Fatal(err)
			}
			tx, err := store.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			err = requireNoLegacyNonterminalRuns(context.Background(), tx)
			if test.wantUnsafe && !errors.Is(err, ErrUnsafeLegacyAdmissionState) {
				t.Fatalf("gate error = %v, want ErrUnsafeLegacyAdmissionState", err)
			}
			if !test.wantUnsafe && err != nil {
				t.Fatalf("terminal state rejected: %v", err)
			}
		})
	}
}

func TestMigrationFourSerializesLegacyWriterBeforeGate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agentd.sqlite3")
	prepareVersionThreeDatabase(t, path)

	legacyDB, err := sql.Open("sqlite", path+"?_txlock=immediate&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer legacyDB.Close()
	legacyTx, err := legacyDB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyTx.Exec(`
INSERT INTO runs(
    id, connector_id, event_id, actor_ref, conversation_ref, message_ref,
    target_id, target_revision, input_text, state, created_at_ms, updated_at_ms
) VALUES ('run_concurrent_legacy', 'discord-personal', 'event_concurrent_legacy',
    'user/demo', 'dm/demo', 'message/concurrent', 'project-codex',
    'project-codex-r1', 'legacy', 'queued', 1, 1)`); err != nil {
		_ = legacyTx.Rollback()
		t.Fatal(err)
	}

	openResult := make(chan error, 1)
	go func() {
		store, openErr := Open(context.Background(), path, Options{
			Clock:     Clock(func() time.Time { return time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC) }),
			Admission: testAdmissionOptions(),
		})
		if store != nil {
			_ = store.Close()
		}
		openResult <- openErr
	}()

	select {
	case openErr := <-openResult:
		_ = legacyTx.Rollback()
		t.Fatalf("upgrade completed before active legacy writer committed: %v", openErr)
	case <-time.After(100 * time.Millisecond):
	}
	if err := legacyTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-openResult; !errors.Is(err, ErrUnsafeLegacyAdmissionState) {
		t.Fatalf("serialized upgrade error = %v, want ErrUnsafeLegacyAdmissionState", err)
	}

	var migrationCount int
	if err := legacyDB.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatal(err)
	}
	if migrationCount != 3 {
		t.Fatalf("refused concurrent upgrade migration count = %d, want 3", migrationCount)
	}
}

func TestMigrationFiveRefusesUnsafeLegacyDeliveryScope(t *testing.T) {
	tests := []struct {
		name            string
		runID           any
		connectorID     string
		conversationRef string
		replyToRef      any
		includeSafe     bool
	}{
		{
			name: "unparented", runID: nil, connectorID: "connector-a",
			conversationRef: "conversation-a", replyToRef: "message-a",
		},
		{
			name: "dangling_parent", runID: "missing-run", connectorID: "connector-a",
			conversationRef: "conversation-a", replyToRef: "message-a",
		},
		{
			name: "connector_mismatch", runID: "run-parent", connectorID: "connector-b",
			conversationRef: "conversation-a", replyToRef: "message-a",
		},
		{
			name: "conversation_mismatch", runID: "run-parent", connectorID: "connector-a",
			conversationRef: "conversation-b", replyToRef: "message-a",
		},
		{
			name: "reply_mismatch", runID: "run-parent", connectorID: "connector-a",
			conversationRef: "conversation-a", replyToRef: "message-b",
		},
		{
			name: "null_reply", runID: "run-parent", connectorID: "connector-a",
			conversationRef: "conversation-a", replyToRef: nil,
		},
		{
			name: "mixed_safe_and_unsafe", runID: "run-parent", connectorID: "connector-b",
			conversationRef: "conversation-a", replyToRef: "message-a", includeSafe: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agentd.sqlite3")
			prepareVersionFourDatabase(t, path)
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			insertVersionFourRun(t, db, "run-parent", "connector-a", "conversation-a", "message-a")
			if test.includeSafe {
				insertVersionFourRun(t, db, "run-safe", "connector-safe", "conversation-safe", "message-safe")
				if _, err := db.Exec(`
INSERT INTO text_deliveries(
    id, run_id, connector_id, conversation_ref, reply_to_ref, text,
    state, available_at_ms, created_at_ms, updated_at_ms
) VALUES ('safe-delivery', 'run-safe', 'connector-safe', 'conversation-safe',
    'message-safe', 'safe output', 'pending', 1, 1, 1)`); err != nil {
					_ = db.Close()
					t.Fatal(err)
				}
			}
			if _, err := db.Exec(`
INSERT INTO text_deliveries(
    id, run_id, connector_id, conversation_ref, reply_to_ref, text,
    state, available_at_ms, created_at_ms, updated_at_ms
) VALUES ('legacy-delivery', ?, ?, ?, ?, 'legacy output', 'pending', 1, 1, 1)`,
				test.runID, test.connectorID, test.conversationRef, test.replyToRef); err != nil {
				_ = db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			store, err := Open(context.Background(), path, Options{
				Clock: Clock(func() time.Time {
					return time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
				}),
				Admission: testAdmissionOptions(),
			})
			if store != nil {
				_ = store.Close()
			}
			if !errors.Is(err, ErrUnsafeLegacyDeliveryState) {
				t.Fatalf("unsafe delivery upgrade error = %v, want ErrUnsafeLegacyDeliveryState", err)
			}

			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var migrationCount, deliveryCount, stagedTableCount int
			if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationCount); err != nil {
				t.Fatal(err)
			}
			if migrationCount != 4 {
				t.Fatalf("refused upgrade migration count = %d, want 4", migrationCount)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM text_deliveries`).Scan(&deliveryCount); err != nil {
				t.Fatal(err)
			}
			wantDeliveries := 1
			if test.includeSafe {
				wantDeliveries = 2
			}
			if deliveryCount != wantDeliveries {
				t.Fatalf("legacy delivery count after refusal = %d, want %d", deliveryCount, wantDeliveries)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master
                WHERE type = 'table' AND name = 'text_deliveries_v5'`).Scan(&stagedTableCount); err != nil {
				t.Fatal(err)
			}
			if stagedTableCount != 0 {
				t.Fatal("refused migration left a staged v5 table")
			}
		})
	}
}

func TestMigrationFivePreservesSafeLegacyDeliveries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agentd.sqlite3")
	prepareVersionFourDatabase(t, path)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	type legacyDelivery struct {
		id              string
		state           DeliveryState
		leaseToken      any
		leaseExpires    any
		providerMessage any
		failureCode     any
	}
	fixtures := []legacyDelivery{
		{id: "pending", state: DeliveryPending},
		{id: "leased", state: DeliveryLeased, leaseToken: "lease-leased", leaseExpires: int64(2_000_000_000_000)},
		{id: "delivered", state: DeliveryDelivered, leaseToken: "lease-delivered", providerMessage: "provider/delivered"},
		{id: "permanent", state: DeliveryPermanentFailed, leaseToken: "lease-permanent", failureCode: string(DeliveryFailureRecipientUnavailable)},
	}
	for index, fixture := range fixtures {
		runID := "run-" + fixture.id
		connectorID := fmt.Sprintf("connector-%d", index)
		conversationRef := fmt.Sprintf("conversation-%d", index)
		messageRef := fmt.Sprintf("message-%d", index)
		insertVersionFourRun(t, db, runID, connectorID, conversationRef, messageRef)
		if _, err := db.Exec(`
INSERT INTO text_deliveries(
    id, run_id, connector_id, conversation_ref, reply_to_ref, text, state,
    lease_token, lease_expires_at_ms, attempt_count, available_at_ms,
    provider_message_ref, failure_code, created_at_ms, updated_at_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?, 1, 1)`,
			fixture.id, runID, connectorID, conversationRef, messageRef,
			"output-"+fixture.id, string(fixture.state), fixture.leaseToken,
			fixture.leaseExpires, fixture.providerMessage, fixture.failureCode); err != nil {
			_ = db.Close()
			t.Fatalf("insert %s fixture: %v", fixture.id, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(context.Background(), path, Options{
		Clock: Clock(func() time.Time {
			return time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
		}),
		Admission: testAdmissionOptions(),
	})
	if err != nil {
		t.Fatalf("upgrade safe v4 deliveries: %v", err)
	}
	defer store.Close()
	var migrationCount, deliveryCount, triggerCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatal(err)
	}
	if migrationCount != 7 {
		t.Fatalf("migration count = %d, want 7", migrationCount)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM text_deliveries`).Scan(&deliveryCount); err != nil {
		t.Fatal(err)
	}
	if deliveryCount != len(fixtures) {
		t.Fatalf("delivery count = %d, want %d", deliveryCount, len(fixtures))
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master
        WHERE type = 'trigger' AND name IN (
            'runs_disclosure_scope_immutable', 'text_deliveries_run_immutable'
        )`).Scan(&triggerCount); err != nil {
		t.Fatal(err)
	}
	if triggerCount != 2 {
		t.Fatalf("v5 immutability trigger count = %d, want 2", triggerCount)
	}
	assertRunDerivedDeliveryColumns(t, store.db)
	var integrity string
	if err := store.db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatal(err)
	}
	if integrity != "ok" {
		t.Fatalf("integrity_check = %q, want ok", integrity)
	}
	for _, fixture := range fixtures {
		var state DeliveryState
		var text, leaseToken, providerMessage, failureCode string
		var leaseExpires, attempts, availableAt, createdAt, updatedAt int64
		if err := store.db.QueryRow(`
SELECT state, text, COALESCE(lease_token, ''), COALESCE(lease_expires_at_ms, 0),
       attempt_count, available_at_ms, COALESCE(provider_message_ref, ''),
       COALESCE(failure_code, ''), created_at_ms, updated_at_ms
FROM text_deliveries WHERE id = ?`, fixture.id).Scan(
			&state, &text, &leaseToken, &leaseExpires, &attempts, &availableAt,
			&providerMessage, &failureCode, &createdAt, &updatedAt,
		); err != nil {
			t.Fatal(err)
		}
		if state != fixture.state || text != "output-"+fixture.id {
			t.Fatalf("migrated %s = (%q, %q)", fixture.id, state, text)
		}
		wantLeaseToken, _ := fixture.leaseToken.(string)
		wantLeaseExpires, _ := fixture.leaseExpires.(int64)
		wantProviderMessage, _ := fixture.providerMessage.(string)
		wantFailureCode, _ := fixture.failureCode.(string)
		if leaseToken != wantLeaseToken || leaseExpires != wantLeaseExpires ||
			attempts != 1 || availableAt != 1 || providerMessage != wantProviderMessage ||
			failureCode != wantFailureCode || createdAt != 1 || updatedAt != 1 {
			t.Fatalf("migrated %s retained fields changed", fixture.id)
		}
	}
}

func TestRunDerivedDeliveryAPIHasNoDestinationAuthority(t *testing.T) {
	deliveryInput := reflect.TypeOf(TextDeliveryInput{})
	if deliveryInput.NumField() != 2 || deliveryInput.Field(0).Name != "ID" ||
		deliveryInput.Field(1).Name != "Text" {
		t.Fatalf("TextDeliveryInput fields = %#v, want exactly ID and Text", deliveryInput)
	}
	operations := reflect.TypeOf((*Operations)(nil)).Elem()
	if _, found := operations.MethodByName("EnqueueText"); found {
		t.Fatal("Operations exposes EnqueueText")
	}
	if _, found := operations.MethodByName("PutSession"); found {
		t.Fatal("Operations exposes arbitrary session mint authority")
	}
}

func TestCoreStoreSourceHasNoRunOrDeliveryReplacementWrites(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate corestore test source")
	}
	packageDir := filepath.Dir(currentFile)
	entries, err := os.ReadDir(packageDir)
	if err != nil {
		t.Fatal(err)
	}
	inspectSQL := func(origin, query string) {
		t.Helper()
		for _, statement := range strings.Split(query, ";") {
			normalized := strings.ToUpper(strings.Join(strings.Fields(statement), " "))
			if strings.Contains(normalized, "INSERT OR REPLACE") ||
				strings.Contains(normalized, "REPLACE INTO") {
				t.Fatalf("%s contains replacement SQL", origin)
			}
			for _, table := range []string{"RUNS", "TEXT_DELIVERIES"} {
				if strings.Contains(normalized, "INSERT INTO "+table) &&
					strings.Contains(normalized, "ON CONFLICT") &&
					strings.Contains(normalized, "DO UPDATE") {
					t.Fatalf("%s contains an upsert targeting %s", origin, table)
				}
			}
		}
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(packageDir, entry.Name())
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatalf("unquote string in %s: %v", entry.Name(), err)
			}
			inspectSQL(entry.Name(), value)
			return true
		})
	}
	migrationEntries, err := os.ReadDir(filepath.Join(packageDir, "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range migrationEntries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(packageDir, "migrations", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		inspectSQL(entry.Name(), string(contents))
	}
}

func TestRunDerivedDeliveryScopeRejectsSQLBypasses(t *testing.T) {
	store, _ := openTestStore(t)
	firstInput := baseIngest("derived-scope-1")
	firstInput.ConnectorID = "connector-a"
	firstInput.ConversationRef = "conversation-a"
	firstInput.MessageRef = "message-a"
	secondInput := baseIngest("derived-scope-2")
	secondInput.ConnectorID = "connector-b"
	secondInput.ConversationRef = "conversation-b"
	secondInput.MessageRef = "message-b"
	mustIngest(t, store, "run-derived-1", firstInput)
	mustIngest(t, store, "run-derived-2", secondInput)
	finishNextRunWithReply(t, store, "run-derived-1", TextDeliveryInput{
		ID: "delivery-derived", Text: "derived output",
	})

	assertRunDerivedDeliveryColumns(t, store.db)
	for _, mutation := range []struct {
		name string
		sql  string
		args []any
	}{
		{
			name: "move_delivery_to_another_run",
			sql:  `UPDATE text_deliveries SET run_id = ? WHERE id = ?`,
			args: []any{"run-derived-2", "delivery-derived"},
		},
		{
			name: "change_run_connector",
			sql:  `UPDATE runs SET connector_id = 'connector-b' WHERE id = 'run-derived-1'`,
		},
		{
			name: "change_run_conversation",
			sql:  `UPDATE runs SET conversation_ref = 'conversation-b' WHERE id = 'run-derived-1'`,
		},
		{
			name: "change_run_message",
			sql:  `UPDATE runs SET message_ref = 'message-b' WHERE id = 'run-derived-1'`,
		},
		{
			name: "delete_parent_run",
			sql:  `DELETE FROM runs WHERE id = 'run-derived-1'`,
		},
		{
			name: "replace_parent_run",
			sql:  `INSERT OR REPLACE INTO runs SELECT * FROM runs WHERE id = 'run-derived-1'`,
		},
		{
			name: "replace_ingested_run_without_delivery",
			sql:  `INSERT OR REPLACE INTO runs SELECT * FROM runs WHERE id = 'run-derived-2'`,
		},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if _, err := store.db.Exec(mutation.sql, mutation.args...); err == nil {
				t.Fatalf("database accepted %s", mutation.name)
			}
		})
	}
	if _, err := store.db.Exec(`UPDATE runs SET connector_id = connector_id,
        conversation_ref = conversation_ref, message_ref = message_ref,
        updated_at_ms = updated_at_ms WHERE id = 'run-derived-1'`); err != nil {
		t.Fatalf("no-op scope update failed: %v", err)
	}
	if _, err := store.db.Exec(`
INSERT INTO text_deliveries(
    id, run_id, text, state, available_at_ms, created_at_ms, updated_at_ms
) VALUES ('delivery-duplicate-run', 'run-derived-1', 'other', 'pending', 1, 1, 1)`); err == nil {
		t.Fatal("database accepted a second delivery for one Run")
	}
	if _, err := store.db.Exec(`
INSERT INTO text_deliveries(
    id, run_id, text, state, available_at_ms, created_at_ms, updated_at_ms
) VALUES ('delivery-missing-run', 'missing-run', 'other', 'pending', 1, 1, 1)`); err == nil {
		t.Fatal("database accepted a delivery with a missing Run")
	}
	if _, err := store.db.Exec(`
INSERT INTO text_deliveries(
    id, run_id, text, state, available_at_ms, created_at_ms, updated_at_ms
) VALUES ('delivery-null-run', NULL, 'other', 'pending', 1, 1, 1)`); err == nil {
		t.Fatal("database accepted a delivery without a Run")
	}
	if _, err := store.db.Exec(`
INSERT INTO text_deliveries(
    id, run_id, connector_id, text, state, available_at_ms, created_at_ms, updated_at_ms
) VALUES ('delivery-with-destination', 'run-derived-2', 'connector-a', 'other', 'pending', 1, 1, 1)`); err == nil {
		t.Fatal("database accepted a removed destination column")
	}

	claimed, err := store.ClaimTextDeliveries(context.Background(), "connector-a", 1, 30*time.Second)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimTextDeliveries() = %#v, %v", claimed, err)
	}
	delivery := claimed[0]
	if delivery.RunID != "run-derived-1" || delivery.ConnectorID != "connector-a" ||
		delivery.ConversationRef != "conversation-a" || delivery.ReplyToRef != "message-a" {
		t.Fatalf("joined delivery scope = %#v", delivery)
	}
	if err := store.CompleteDelivery(context.Background(), CompleteDeliveryInput{
		ConnectorID: "connector-b", DeliveryID: delivery.ID, LeaseToken: delivery.LeaseToken,
		Outcome: DeliveryOutcomeDelivered, ProviderMessageRef: "provider/wrong",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-connector completion error = %v, want ErrNotFound", err)
	}
}

func assertRunDerivedDeliveryColumns(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(text_deliveries)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	foundRunID := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		switch name {
		case "connector_id", "conversation_ref", "reply_to_ref":
			t.Fatalf("text_deliveries retained destination column %q", name)
		case "run_id":
			foundRunID = true
			if notNull != 1 {
				t.Fatal("text_deliveries.run_id is nullable")
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !foundRunID {
		t.Fatal("text_deliveries lacks run_id")
	}
}

func prepareVersionThreeDatabase(t *testing.T, path string) {
	t.Helper()
	if err := prepareDatabaseFile(path); err != nil {
		t.Fatal(err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, candidate := range migrations[:3] {
		if _, err := db.Exec(string(candidate.contents)); err != nil {
			t.Fatalf("apply fixture migration %d: %v", candidate.version, err)
		}
	}
	if _, err := db.Exec(`
CREATE TABLE schema_migrations (
    version       INTEGER PRIMARY KEY CHECK (version > 0),
    name          TEXT NOT NULL UNIQUE,
    sha256        BLOB NOT NULL CHECK (length(sha256) = 32),
    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms > 0)
) STRICT`); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range migrations[:3] {
		if _, err := db.Exec(`INSERT INTO schema_migrations(version, name, sha256, applied_at_ms)
            VALUES (?, ?, ?, 1)`, candidate.version, candidate.name, candidate.hash[:]); err != nil {
			t.Fatalf("record fixture migration %d: %v", candidate.version, err)
		}
	}
}

func prepareVersionFourDatabase(t *testing.T, path string) {
	t.Helper()
	if err := prepareDatabaseFile(path); err != nil {
		t.Fatal(err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, candidate := range migrations[:4] {
		if _, err := db.Exec(string(candidate.contents)); err != nil {
			t.Fatalf("apply fixture migration %d: %v", candidate.version, err)
		}
	}
	if _, err := db.Exec(`
CREATE TABLE schema_migrations (
    version       INTEGER PRIMARY KEY CHECK (version > 0),
    name          TEXT NOT NULL UNIQUE,
    sha256        BLOB NOT NULL CHECK (length(sha256) = 32),
    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms > 0)
) STRICT`); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range migrations[:4] {
		if _, err := db.Exec(`INSERT INTO schema_migrations(version, name, sha256, applied_at_ms)
            VALUES (?, ?, ?, 1)`, candidate.version, candidate.name, candidate.hash[:]); err != nil {
			t.Fatalf("record fixture migration %d: %v", candidate.version, err)
		}
	}
}

func prepareVersionFiveDatabase(t *testing.T, path string) {
	t.Helper()
	prepareVersionFourDatabase(t, path)
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(string(migrations[4].contents)); err != nil {
		t.Fatalf("apply fixture migration 5: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version, name, sha256, applied_at_ms)
        VALUES (?, ?, ?, 1)`, migrations[4].version, migrations[4].name, migrations[4].hash[:]); err != nil {
		t.Fatalf("record fixture migration 5: %v", err)
	}
}

func insertVersionFourRun(
	t *testing.T,
	db *sql.DB,
	runID string,
	connectorID string,
	conversationRef string,
	messageRef string,
) {
	t.Helper()
	if _, err := db.Exec(`
INSERT INTO runs(
    id, connector_id, event_id, actor_ref, conversation_ref, message_ref,
    target_id, target_revision, binding_fingerprint, policy_revision,
    input_text, state, dispatch_token, start_prepared, start_deadline_ms,
    output_text, created_at_ms, updated_at_ms
) VALUES (?, ?, ?, 'actor', ?, ?, 'target', 'revision', ?, ?, 'input',
          'completed', ?, 1, 1, 'done', 1, 1)`,
		runID, connectorID, "event-"+runID, conversationRef, messageRef,
		strings.Repeat("a", SHA256HexBytes), strings.Repeat("b", SHA256HexBytes),
		"dispatch-"+runID); err != nil {
		t.Fatalf("insert v4 Run %q: %v", runID, err)
	}
}

func stringPointer(value string) *string {
	return &value
}

func TestInboundDedupeCreatesExactlyOneQueuedRun(t *testing.T) {
	store, _ := openTestStore(t)
	input := baseIngest("event_001")
	first := mustIngest(t, store, "run_001", input)
	if first.State != RunQueued {
		t.Fatalf("state = %q, want queued", first.State)
	}
	wantAuthorization := testTextRunAuthorization()
	if first.BindingFingerprint != wantAuthorization.BindingFingerprint ||
		first.PolicyRevision != wantAuthorization.PolicyRevision {
		t.Fatalf("Run admission evidence = %#v", first)
	}
	var occurredAt int64
	if err := store.db.QueryRow(`
SELECT occurred_at_ms FROM inbound_events WHERE connector_id = ? AND event_id = ?`,
		input.ConnectorID, input.EventID).Scan(&occurredAt); err != nil || occurredAt != input.OccurredAtUnixMS {
		t.Fatalf("occurred_at_ms = %d, err = %v", occurredAt, err)
	}

	duplicateInput := input
	duplicateInput.Text = "ignored because canonical payload hash is the same"
	duplicate, err := ingestAs(store, duplicateInput, "run_should_not_be_created")
	if err != nil {
		t.Fatalf("duplicate ingest error = %v", err)
	}
	if !duplicate.Duplicate || duplicate.Run.ID != first.ID {
		t.Fatalf("duplicate result = %#v, want original run", duplicate)
	}

	changed := input
	changed.PayloadHash = sha256.Sum256([]byte("changed payload"))
	if _, err := ingestAs(store, changed, "run_changed"); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed hash error = %v, want ErrConflict", err)
	}
	var runs, events int
	if err := store.db.QueryRow("SELECT count(*) FROM runs").Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM inbound_events").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || events != 1 {
		t.Fatalf("runs = %d, events = %d, want one each", runs, events)
	}

	collision := baseIngest("event_002")
	if _, err := ingestAs(store, collision, first.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("run ID collision error = %v, want ErrConflict", err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM inbound_events").Scan(&events); err != nil || events != 1 {
		t.Fatalf("inbound count after rollback = %d, err = %v", events, err)
	}
}

func TestInboundAdmissionAllowsOnlyOneNonterminalRunPerExactSessionScope(t *testing.T) {
	store, _ := openTestStore(t)
	firstInput := baseIngest("event_scope_busy_first")
	first := mustIngest(t, store, "run_scope_busy_first", firstInput)

	secondInput := baseIngest("event_scope_busy_second")
	secondInput.ActorRef = firstInput.ActorRef
	if _, err := ingestAs(store, secondInput, "run_scope_busy_second"); !errors.Is(err, ErrSessionScopeBusy) {
		t.Fatalf("second exact-scope ingest error = %v, want ErrSessionScopeBusy", err)
	}
	var secondReceipts int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM inbound_events
        WHERE connector_id = ? AND event_id = ?`, secondInput.ConnectorID, secondInput.EventID).Scan(&secondReceipts); err != nil {
		t.Fatal(err)
	}
	if secondReceipts != 0 {
		t.Fatalf("busy ingest persisted %d receipt(s)", secondReceipts)
	}
	replay, err := ingestAs(store, firstInput, "run_replay_must_not_exist")
	if err != nil || !replay.Duplicate || replay.Run.ID != first.ID {
		t.Fatalf("exact replay under busy scope = %#v, err=%v", replay, err)
	}

	finishNextRunWithReply(t, store, first.ID, TextDeliveryInput{ID: "delivery_scope_busy", Text: "done"})
	accepted, err := ingestAs(store, secondInput, "run_scope_busy_second")
	if err != nil || accepted.Duplicate || accepted.Run.ID != "run_scope_busy_second" {
		t.Fatalf("post-terminal ingest = %#v, err=%v", accepted, err)
	}
}

func TestInboundAdmissionRequiresValidExactBindingEvidence(t *testing.T) {
	store, _ := openTestStore(t)
	input := baseIngest("event_invalid_evidence")
	valid := testTextRunAuthorization()
	tests := []struct {
		name          string
		authorization TextRunAuthorization
	}{
		{name: "missing", authorization: TextRunAuthorization{TargetID: "project-codex", TargetRevision: "r1"}},
		{name: "binding short", authorization: authorizationWithBinding(valid, strings.Repeat("a", SHA256HexBytes-1))},
		{name: "binding long", authorization: authorizationWithBinding(valid, strings.Repeat("a", SHA256HexBytes+1))},
		{name: "binding uppercase", authorization: authorizationWithBinding(valid, strings.Repeat("A", SHA256HexBytes))},
		{name: "binding nonhex", authorization: authorizationWithBinding(valid, strings.Repeat("a", SHA256HexBytes-1)+"g")},
		{name: "policy short", authorization: authorizationWithPolicy(valid, strings.Repeat("b", SHA256HexBytes-1))},
		{name: "policy long", authorization: authorizationWithPolicy(valid, strings.Repeat("b", SHA256HexBytes+1))},
		{name: "policy uppercase", authorization: authorizationWithPolicy(valid, strings.Repeat("B", SHA256HexBytes))},
		{name: "policy nonhex", authorization: authorizationWithPolicy(valid, strings.Repeat("b", SHA256HexBytes-1)+"g")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorization := test.authorization
			_, err := store.IngestTextRun(context.Background(), input,
				func() (TextRunAuthorization, error) { return authorization, nil },
				func() (string, error) { return "run_invalid_evidence", nil },
			)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("authorization %#v error = %v, want ErrInvalid", authorization, err)
			}
		})
	}
	var runs, receipts int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM runs`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM inbound_events`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if runs != 0 || receipts != 0 {
		t.Fatalf("invalid evidence persisted runs=%d receipts=%d", runs, receipts)
	}
}

func authorizationWithBinding(authorization TextRunAuthorization, value string) TextRunAuthorization {
	authorization.BindingFingerprint = value
	return authorization
}

func authorizationWithPolicy(authorization TextRunAuthorization, value string) TextRunAuthorization {
	authorization.PolicyRevision = value
	return authorization
}

func TestInboundReplayWindowAndDurableEvictionHorizon(t *testing.T) {
	store, clock := openTestStore(t)
	input := baseIngest("event_window")
	authorizeCalls := 0
	runIDCalls := 0
	authorize := func() (TextRunAuthorization, error) {
		authorizeCalls++
		return testTextRunAuthorization(), nil
	}
	newRunID := func() (string, error) {
		runIDCalls++
		return fmt.Sprintf("run_window_%d", runIDCalls), nil
	}
	first, err := store.IngestTextRun(context.Background(), input, authorize, newRunID)
	if err != nil {
		t.Fatal(err)
	}

	// The first-admission window has elapsed, but the receipt window has not.
	// Exact replay must return the frozen Run without consulting current policy
	// or consuming a second identifier.
	clock.Advance(2 * time.Hour)
	replay, err := store.IngestTextRun(
		context.Background(), input,
		func() (TextRunAuthorization, error) {
			t.Fatal("exact retained replay re-authorized")
			return TextRunAuthorization{}, errors.New("unreachable")
		},
		func() (string, error) {
			t.Fatal("exact retained replay consumed a Run ID")
			return "", errors.New("unreachable")
		},
	)
	if err != nil || !replay.Duplicate || replay.Run.ID != first.Run.ID {
		t.Fatalf("retained replay = %#v, err=%v", replay, err)
	}
	changed := input
	changed.PayloadHash = sha256.Sum256([]byte("changed within receipt window"))
	if _, err := store.IngestTextRun(context.Background(), changed, authorize, newRunID); !errors.Is(err, ErrConflict) {
		t.Fatalf("retained changed hash error = %v, want ErrConflict", err)
	}
	if authorizeCalls != 1 || runIDCalls != 1 {
		t.Fatalf("retained decisions re-ran admission: authorize=%d runID=%d", authorizeCalls, runIDCalls)
	}

	clock.Advance(23 * time.Hour)
	if _, err := store.IngestTextRun(context.Background(), input, authorize, newRunID); !errors.Is(err, ErrEventExpired) {
		t.Fatalf("evicted exact replay error = %v, want ErrEventExpired", err)
	}
	var receipts int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM inbound_events
        WHERE connector_id = ? AND event_id = ?`, input.ConnectorID, input.EventID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 0 {
		t.Fatalf("expired physical receipts = %d, want 0", receipts)
	}

	// A host-clock regression cannot move the durable horizon backwards.
	clock.Advance(-24 * time.Hour)
	if _, err := store.IngestTextRun(context.Background(), input, authorize, newRunID); !errors.Is(err, ErrEventExpired) {
		t.Fatalf("regressed-clock replay error = %v, want ErrEventExpired", err)
	}

	// Once the receipt is gone, the same event ID with a fresh timestamp and a
	// different full hash is a new normalized event, as the public contract
	// explicitly permits.
	clock.Advance(24 * time.Hour)
	fresh := changed
	fresh.ActorRef = "user/fresh-post-horizon"
	fresh.OccurredAtUnixMS = clock.Now().UnixMilli()
	fresh.PayloadHash = sha256.Sum256([]byte("fresh normalized event"))
	accepted, err := store.IngestTextRun(context.Background(), fresh, authorize, newRunID)
	if err != nil || accepted.Duplicate || accepted.Run.ID == first.Run.ID {
		t.Fatalf("fresh post-horizon event = %#v, err=%v", accepted, err)
	}
}

func TestLegacyV1ReceiptUsesLegacyHashUntilEviction(t *testing.T) {
	store, _ := openTestStore(t)
	input := baseIngest("event_legacy_hash")
	first := mustIngest(t, store, "run_legacy_hash", input)
	legacyHash := sha256.Sum256([]byte("legacy-v1-hash"))
	if _, err := store.db.Exec(`UPDATE inbound_events
        SET payload_hash = ?, payload_hash_version = 1
        WHERE connector_id = ? AND event_id = ?`,
		legacyHash[:], input.ConnectorID, input.EventID); err != nil {
		t.Fatal(err)
	}
	input.PayloadHash = sha256.Sum256([]byte("new-v2-hash-including-connector"))
	input.LegacyPayloadHash = legacyHash
	replay, err := ingestAs(store, input, "run_must_not_be_allocated")
	if err != nil || !replay.Duplicate || replay.Run.ID != first.ID {
		t.Fatalf("legacy retained replay = %#v, err=%v", replay, err)
	}
	input.LegacyPayloadHash = sha256.Sum256([]byte("changed-legacy-event"))
	if _, err := ingestAs(store, input, "run_changed_legacy"); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed legacy hash error = %v, want ErrConflict", err)
	}
}

func TestInboundDenyAndQuotaDoNotFreezePerEventDecision(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)}
	options := testAdmissionOptions()
	options.MaxReceiptsPerConnector = 1
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "agentd.sqlite3"), Options{
		Clock: clock.Now, Admission: options,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	denied := baseIngest("event_denied")
	policyDeny := errors.New("test policy deny")
	if _, err := store.IngestTextRun(
		context.Background(), denied,
		func() (TextRunAuthorization, error) { return TextRunAuthorization{}, policyDeny },
		func() (string, error) { return "run_denied", nil },
	); !errors.Is(err, policyDeny) {
		t.Fatalf("deny error = %v", err)
	}
	var receipts int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM inbound_events`).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatalf("deny receipts = %d, err=%v", receipts, err)
	}
	if _, err := ingestAs(store, denied, "run_after_policy_change"); err != nil {
		t.Fatalf("retry after policy change error = %v", err)
	}

	quotaEvent := baseIngest("event_quota")
	if _, err := ingestAs(store, quotaEvent, "run_quota_blocked"); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("quota error = %v, want ErrQuotaExceeded", err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM inbound_events`).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("quota changed receipt count = %d, err=%v", receipts, err)
	}

	clock.Advance(25 * time.Hour)
	quotaEvent.OccurredAtUnixMS = clock.Now().UnixMilli()
	quotaEvent.PayloadHash = sha256.Sum256([]byte("quota retry under fresh capacity"))
	if _, err := ingestAs(store, quotaEvent, "run_quota_retry"); err != nil {
		t.Fatalf("fresh retry after receipt eviction error = %v", err)
	}
}

func TestPendingDeliveryQuotaIsEnforcedAtInsertion(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)}
	options := testAdmissionOptions()
	options.MaxPendingDeliveriesPerConnector = 1
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "agentd.sqlite3"), Options{
		Clock: clock.Now, Admission: options,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	mustIngest(t, store, "run_quota_1", baseIngest("event_quota_1"))
	mustIngest(t, store, "run_quota_2", baseIngest("event_quota_2"))
	first := TextDeliveryInput{ID: "delivery_quota_1", Text: "first"}
	firstRun := finishNextRunWithReply(t, store, "run_quota_1", first)
	if err := store.FinishRun(context.Background(), FinishRunInput{
		RunID: firstRun.ID, DispatchToken: firstRun.DispatchToken,
		State: RunCompleted, OutputText: first.Text,
	}, &first); err != nil {
		t.Fatalf("idempotent delivery replay failed at quota: %v", err)
	}
	second, ok, err := store.ClaimQueuedRun(context.Background(), 30*time.Second)
	if err != nil || !ok || second.ID != "run_quota_2" {
		t.Fatalf("second claim = %#v, %v, %v", second, ok, err)
	}
	mustPrepareNoSession(t, store, second)
	if err := store.MarkRunRunning(context.Background(), second.ID, second.DispatchToken); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishRun(context.Background(), FinishRunInput{
		RunID: second.ID, DispatchToken: second.DispatchToken,
		State: RunCompleted, OutputText: "second",
	}, &TextDeliveryInput{ID: "delivery_quota_2", Text: "second"}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("second FinishRun error = %v, want ErrQuotaExceeded", err)
	}
}

func TestRunDispatchLeaseExpiresAndRejectsStaleWorker(t *testing.T) {
	store, clock := openTestStore(t)
	mustIngest(t, store, "run_001", baseIngest("event_001"))
	mustIngest(t, store, "run_002", baseIngest("event_002"))

	first, ok, err := store.ClaimQueuedRun(context.Background(), 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("first dispatch = %#v, ok = %v, err = %v", first, ok, err)
	}
	if first.DispatchToken == "" || first.DispatchExpiresAt.IsZero() || first.DispatchAttemptCount != 1 {
		t.Fatalf("first dispatch lease = %#v", first)
	}
	for attempt := 0; attempt < 3; attempt++ {
		if _, ok, err := store.ClaimQueuedRun(context.Background(), 10*time.Second); err != nil || ok {
			t.Fatalf("claim before expiry attempt %d: ok = %v, err = %v", attempt, ok, err)
		}
	}
	unchanged, err := store.GetRun(context.Background(), first.ID)
	if err != nil || unchanged.DispatchToken != first.DispatchToken ||
		unchanged.DispatchAttemptCount != first.DispatchAttemptCount ||
		!unchanged.DispatchExpiresAt.Equal(first.DispatchExpiresAt) {
		t.Fatalf("gated claim mutated active dispatch = %#v, err=%v", unchanged, err)
	}
	newer, err := store.GetRun(context.Background(), "run_002")
	if err != nil || newer.State != RunQueued || newer.DispatchAttemptCount != 0 || newer.DispatchToken != "" {
		t.Fatalf("active dispatch did not gate newer queue = %#v, err=%v", newer, err)
	}

	clock.Advance(11 * time.Second)
	second, ok, err := store.ClaimQueuedRun(context.Background(), 10*time.Second)
	if err != nil || !ok || second.ID != first.ID {
		t.Fatalf("reclaimed dispatch = %#v, ok = %v, err = %v", second, ok, err)
	}
	if second.DispatchToken == first.DispatchToken || second.DispatchAttemptCount != 2 {
		t.Fatalf("reclaimed token/attempt = %#v", second)
	}
	if err := store.MarkRunRunning(context.Background(), first.ID, first.DispatchToken); !errors.Is(err, ErrDispatchLost) {
		t.Fatalf("stale MarkRunRunning error = %v, want ErrDispatchLost", err)
	}
	if err := store.FinishRun(context.Background(), FinishRunInput{
		RunID: first.ID, DispatchToken: first.DispatchToken,
		State: RunCompleted, OutputText: "stale",
	}, nil); !errors.Is(err, ErrDispatchLost) {
		t.Fatalf("stale FinishRun error = %v, want ErrDispatchLost", err)
	}
	mustPrepareNoSession(t, store, second)
	if err := store.MarkRunRunning(context.Background(), second.ID, second.DispatchToken); err != nil {
		t.Fatalf("current MarkRunRunning error = %v", err)
	}
	got, err := store.GetRun(context.Background(), second.ID)
	if err != nil || got.State != RunRunning || got.DispatchToken != second.DispatchToken || !got.DispatchExpiresAt.IsZero() {
		t.Fatalf("running Run = %#v, err = %v", got, err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		if _, ok, err := store.ClaimQueuedRun(context.Background(), 10*time.Second); err != nil || ok {
			t.Fatalf("claim while Run is running attempt %d: ok = %v, err = %v", attempt, ok, err)
		}
	}
	stillRunning, err := store.GetRun(context.Background(), second.ID)
	if err != nil || stillRunning.State != RunRunning ||
		stillRunning.DispatchToken != second.DispatchToken ||
		stillRunning.DispatchAttemptCount != second.DispatchAttemptCount {
		t.Fatalf("gated claim mutated running Run = %#v, err = %v", stillRunning, err)
	}
	if err := store.FinishRun(context.Background(), FinishRunInput{
		RunID: second.ID, DispatchToken: second.DispatchToken,
		State: RunCompleted, OutputText: "done",
	}, nil); err != nil {
		t.Fatalf("finish running Run: %v", err)
	}
	next, ok, err := store.ClaimQueuedRun(context.Background(), 10*time.Second)
	if err != nil || !ok || next.ID != "run_002" {
		t.Fatalf("claim after terminal transition = %#v, ok = %v, err = %v", next, ok, err)
	}
}

func TestPrepareRunStartIsImmutableAcrossCrashReclaimAndReopen(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)}
	tokens := &tokenSequence{}
	path := filepath.Join(t.TempDir(), "agentd.sqlite3")
	options := Options{Clock: clock.Now, NewLeaseToken: tokens.Next, Admission: testAdmissionOptions()}
	store, err := Open(ctx, path, options)
	if err != nil {
		t.Fatal(err)
	}

	run := mustIngest(t, store, "run_prepare", baseIngest("event_prepare"))
	key := sessionKeyFromTestRun(run)
	const originalSession = "session_original"
	if err := store.PutSession(ctx, Session{SessionKey: key, Ref: originalSession}); err != nil {
		t.Fatal(err)
	}
	firstDispatch, ok, err := store.ClaimQueuedRun(ctx, 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("first dispatch = %#v, ok = %v, err = %v", firstDispatch, ok, err)
	}
	originalDeadline := clock.Now().Add(time.Hour).Add(987654 * time.Nanosecond)
	originalRef := originalSession
	first, err := store.PrepareRunStart(ctx, PrepareRunStartInput{
		RunID: firstDispatch.ID, DispatchToken: firstDispatch.DispatchToken,
		SessionRef: &originalRef, Deadline: originalDeadline,
	})
	if err != nil {
		t.Fatalf("first PrepareRunStart() error = %v", err)
	}
	wantDeadline := time.UnixMilli(originalDeadline.UnixMilli()).UTC()
	if first.SessionRef == nil || *first.SessionRef != originalSession || !first.Deadline.Equal(wantDeadline) {
		t.Fatalf("first prepared value = %#v, want session %q deadline %s", first, originalSession, wantDeadline)
	}
	stored, err := store.GetRun(ctx, run.ID)
	if err != nil || !stored.StartPrepared || stored.StartSessionRef == nil ||
		*stored.StartSessionRef != originalSession || !stored.StartDeadline.Equal(wantDeadline) {
		t.Fatalf("stored prepared Run = %#v, err = %v", stored, err)
	}
	firstFingerprint := startFingerprint(t, stored, first)

	// Crash A/B recovery waits for the dispatch lease, then obtains a new
	// capability. The old worker must not be able to read the prepared session.
	clock.Advance(11 * time.Second)
	reclaimed, ok, err := store.ClaimQueuedRun(ctx, 10*time.Second)
	if err != nil || !ok || reclaimed.ID != run.ID {
		t.Fatalf("reclaimed dispatch = %#v, ok = %v, err = %v", reclaimed, ok, err)
	}
	if !reclaimed.StartPrepared || reclaimed.StartSessionRef == nil ||
		*reclaimed.StartSessionRef != originalSession || !reclaimed.StartDeadline.Equal(wantDeadline) {
		t.Fatalf("reclaim did not return persisted start values: %#v", reclaimed)
	}
	changedDeadline := clock.Now().Add(2 * time.Hour)
	if got, err := store.PrepareRunStart(ctx, PrepareRunStartInput{
		RunID: run.ID, DispatchToken: firstDispatch.DispatchToken,
		SessionRef: &originalRef, Deadline: changedDeadline,
	}); !errors.Is(err, ErrDispatchLost) || got.SessionRef != nil || !got.Deadline.IsZero() {
		t.Fatalf("stale prepare = %#v, error = %v, want ErrDispatchLost without values", got, err)
	}

	// Even if the conversation's current session advances, an already prepared
	// StartRun must retain the exact original fingerprint fields.
	const newerSession = "session_newer"
	if err := store.PutSession(ctx, Session{SessionKey: key, Ref: newerSession}); err != nil {
		t.Fatal(err)
	}
	newerRef := newerSession
	second, err := store.PrepareRunStart(ctx, PrepareRunStartInput{
		RunID: reclaimed.ID, DispatchToken: reclaimed.DispatchToken,
		SessionRef: &newerRef, Deadline: changedDeadline,
	})
	if err != nil {
		t.Fatalf("reclaimed PrepareRunStart() error = %v", err)
	}
	if second.SessionRef == nil || *second.SessionRef != originalSession || !second.Deadline.Equal(wantDeadline) {
		t.Fatalf("reclaimed prepared value = %#v, want immutable original", second)
	}
	if got := startFingerprint(t, reclaimed, second); got != firstFingerprint {
		t.Fatalf("reclaimed StartRun fingerprint = %q, want %q", got, firstFingerprint)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path, options)
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened store: %v", err)
		}
	})
	afterRestart, err := reopened.PrepareRunStart(ctx, PrepareRunStartInput{
		RunID: reclaimed.ID, DispatchToken: reclaimed.DispatchToken,
		SessionRef: &newerRef, Deadline: clock.Now().Add(3 * time.Hour),
	})
	if err != nil {
		t.Fatalf("PrepareRunStart() after reopen error = %v", err)
	}
	if afterRestart.SessionRef == nil || *afterRestart.SessionRef != originalSession ||
		!afterRestart.Deadline.Equal(wantDeadline) {
		t.Fatalf("prepared value after reopen = %#v", afterRestart)
	}
	if got := startFingerprint(t, reclaimed, afterRestart); got != firstFingerprint {
		t.Fatalf("reopened StartRun fingerprint = %q, want %q", got, firstFingerprint)
	}
}

func TestPrepareRunStartPersistsNilSessionAndChecksExactCurrentScope(t *testing.T) {
	ctx := context.Background()
	store, clock := openTestStore(t)
	run := mustIngest(t, store, "run_nil", baseIngest("event_nil"))
	dispatch, ok, err := store.ClaimQueuedRun(ctx, 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("claim nil-session run: %#v, %v, %v", dispatch, ok, err)
	}
	before, err := store.GetRun(ctx, run.ID)
	if err != nil || before.StartPrepared || before.StartSessionRef != nil || !before.StartDeadline.IsZero() {
		t.Fatalf("unprepared Run = %#v, err = %v", before, err)
	}
	if err := store.MarkRunRunning(ctx, dispatch.ID, dispatch.DispatchToken); !errors.Is(err, ErrStartUnprepared) {
		t.Fatalf("unprepared MarkRunRunning error = %v, want ErrStartUnprepared", err)
	}
	prepared, err := store.PrepareRunStart(ctx, PrepareRunStartInput{
		RunID: run.ID, DispatchToken: dispatch.DispatchToken,
		Deadline: clock.Now().Add(time.Hour),
	})
	if err != nil || prepared.SessionRef != nil {
		t.Fatalf("nil-session prepare = %#v, err = %v", prepared, err)
	}
	after, err := store.GetRun(ctx, run.ID)
	if err != nil || !after.StartPrepared || after.StartSessionRef != nil || after.StartDeadline.IsZero() {
		t.Fatalf("prepared-with-nil Run = %#v, err = %v", after, err)
	}

	// A later session must not turn the explicitly prepared nil into a resume.
	key := sessionKeyFromTestRun(run)
	const laterSession = "session_later"
	if err := store.PutSession(ctx, Session{SessionKey: key, Ref: laterSession}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(11 * time.Second)
	reclaimed, ok, err := store.ClaimQueuedRun(ctx, 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("reclaim nil-session run: %#v, %v, %v", reclaimed, ok, err)
	}
	laterRef := laterSession
	repeated, err := store.PrepareRunStart(ctx, PrepareRunStartInput{
		RunID: run.ID, DispatchToken: reclaimed.DispatchToken,
		SessionRef: &laterRef, Deadline: clock.Now().Add(2 * time.Hour),
	})
	if err != nil || repeated.SessionRef != nil || !repeated.Deadline.Equal(prepared.Deadline) {
		t.Fatalf("reclaimed nil-session prepare = %#v, err = %v", repeated, err)
	}
	if err := store.MarkRunRunning(ctx, reclaimed.ID, reclaimed.DispatchToken); err != nil {
		t.Fatalf("mark reclaimed nil-session Run running: %v", err)
	}
	if err := store.FinishRun(ctx, FinishRunInput{
		RunID: reclaimed.ID, DispatchToken: reclaimed.DispatchToken,
		State: RunCompleted, OutputText: "done",
	}, nil); err != nil {
		t.Fatalf("finish nil-session Run: %v", err)
	}

	// A fresh Run may resume only the exact current session from its four-part
	// scope. A session under another revision is not sufficient.
	otherInput := baseIngest("event_scoped")
	otherInput.ActorRef = run.ActorRef
	other := mustIngest(t, store, "run_scoped", otherInput)
	otherDispatch, ok, err := store.ClaimQueuedRun(ctx, 30*time.Second)
	if err != nil || !ok || otherDispatch.ID != other.ID {
		t.Fatalf("claim scoped run: %#v, %v, %v", otherDispatch, ok, err)
	}
	invalidRef := "../../session"
	if _, err := store.PrepareRunStart(ctx, PrepareRunStartInput{
		RunID: other.ID, DispatchToken: otherDispatch.DispatchToken,
		SessionRef: &invalidRef, Deadline: clock.Now().Add(time.Hour),
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid session grammar error = %v, want ErrInvalid", err)
	}
	if _, err := store.PrepareRunStart(ctx, PrepareRunStartInput{
		RunID: other.ID, DispatchToken: otherDispatch.DispatchToken,
		Deadline: clock.Now(),
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("past deadline error = %v, want ErrInvalid", err)
	}
	if _, err := store.PrepareRunStart(ctx, PrepareRunStartInput{
		RunID: other.ID, DispatchToken: otherDispatch.DispatchToken,
		Deadline: clock.Now().Add(time.Hour),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("fresh prepare with exact current session error = %v, want ErrConflict", err)
	}
	unprepared, err := store.GetRun(ctx, other.ID)
	if err != nil || unprepared.StartPrepared {
		t.Fatalf("rejected fresh prepare changed Run = %#v, err = %v", unprepared, err)
	}
	wrongScope := key
	wrongScope.TargetRevision = "project-codex-r2"
	const wrongRefValue = "session_wrong_scope"
	if err := store.PutSession(ctx, Session{SessionKey: wrongScope, Ref: wrongRefValue}); err != nil {
		t.Fatal(err)
	}
	wrongRef := wrongRefValue
	if _, err := store.PrepareRunStart(ctx, PrepareRunStartInput{
		RunID: other.ID, DispatchToken: otherDispatch.DispatchToken,
		SessionRef: &wrongRef, Deadline: clock.Now().Add(time.Hour),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong-scope session error = %v, want ErrConflict", err)
	}
	current, found, err := store.GetSession(ctx, key)
	if err != nil || !found {
		t.Fatalf("current exact session = %#v, %v, %v", current, found, err)
	}
	if _, err := store.PrepareRunStart(ctx, PrepareRunStartInput{
		RunID: other.ID, DispatchToken: otherDispatch.DispatchToken,
		SessionRef: &current.Ref, Deadline: clock.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("exact current session prepare error = %v", err)
	}
}

func startFingerprint(t *testing.T, run Run, prepared PreparedRunStart) string {
	t.Helper()
	scopeDigest, err := sessionauth.Digest(sessionauth.Scope{
		BindingFingerprint: run.BindingFingerprint,
		ConnectorID:        run.ConnectorID,
		ActorRef:           run.ActorRef,
		ConversationRef:    run.ConversationRef,
		TargetID:           run.TargetID,
		TargetRevision:     run.TargetRevision,
	})
	if err != nil {
		t.Fatalf("session scope digest: %v", err)
	}
	fingerprint, err := executionwire.StartRunFingerprint(executionwire.StartRunRequest{
		RunID: run.ID, TargetID: run.TargetID, ExpectedRevision: run.TargetRevision,
		SessionScopeDigest: scopeDigest, SessionRef: prepared.SessionRef,
		Input: executionwire.TextInput{
			MediaType: executionwire.MediaTypeTextPlain,
			Text:      run.InputText,
		},
		Deadline: prepared.Deadline,
	})
	if err != nil {
		t.Fatalf("StartRunFingerprint() error = %v", err)
	}
	return fingerprint
}

func TestListRunningRunsIsBoundedOrderedAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)}
	tokens := &tokenSequence{}
	path := filepath.Join(t.TempDir(), "agentd.sqlite3")
	options := Options{Clock: clock.Now, NewLeaseToken: tokens.Next, Admission: testAdmissionOptions()}
	store, err := Open(ctx, path, options)
	if err != nil {
		t.Fatal(err)
	}

	// A terminal Run created first proves the operation is a closed state query,
	// not a broad unfinished-runs filter.
	mustIngest(t, store, "run_terminal", baseIngest("event_terminal"))
	terminal, ok, err := store.ClaimQueuedRun(ctx, 30*time.Second)
	if err != nil || !ok {
		t.Fatalf("claim terminal fixture: %#v, %v, %v", terminal, ok, err)
	}
	mustPrepareNoSession(t, store, terminal)
	if err := store.MarkRunRunning(ctx, terminal.ID, terminal.DispatchToken); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishRun(ctx, FinishRunInput{
		RunID: terminal.ID, DispatchToken: terminal.DispatchToken,
		State: RunCompleted, OutputText: "done",
	}, nil); err != nil {
		t.Fatal(err)
	}

	clock.Advance(time.Second)
	// Equal creation timestamps exercise the stable ID tie-breaker.
	for _, fixture := range []struct{ runID, eventID string }{
		{"run_b", "event_b"}, {"run_a", "event_a"},
		{"run_c", "event_c"}, {"run_d", "event_d"},
	} {
		mustIngest(t, store, fixture.runID, baseIngest(fixture.eventID))
	}
	// The public transition APIs enforce one global active Run. Seed multiple
	// active rows directly to exercise defensive restart reconciliation against
	// a database produced before that invariant or restored from a backup.
	deadline := clock.Now().Add(time.Hour).UnixMilli()
	for _, runID := range []string{"run_a", "run_b"} {
		if _, err := store.db.ExecContext(ctx, `
UPDATE runs
SET state = 'running', dispatch_token = ?, dispatch_attempt_count = 1,
    start_prepared = 1, start_deadline_ms = ?, updated_at_ms = ?
WHERE id = ?`, "fixture_token_"+runID, deadline, clock.Now().UnixMilli(), runID); err != nil {
			t.Fatalf("seed running fixture %s: %v", runID, err)
		}
	}
	if _, err := store.db.ExecContext(ctx, `
UPDATE runs
SET state = 'dispatching', dispatch_token = 'fixture_token_run_c',
    dispatch_expires_at_ms = ?, dispatch_attempt_count = 1, updated_at_ms = ?
WHERE id = 'run_c'`, clock.Now().Add(30*time.Second).UnixMilli(), clock.Now().UnixMilli()); err != nil {
		t.Fatalf("seed dispatching fixture: %v", err)
	}
	// run_c is dispatching and run_d is queued; neither may leak into the
	// reconciliation result.

	if _, err := store.ListRunningRuns(ctx, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero limit error = %v, want ErrInvalid", err)
	}
	if _, err := store.ListRunningRuns(ctx, MaxReconcileRuns+1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("large limit error = %v, want ErrInvalid", err)
	}
	one, err := store.ListRunningRuns(ctx, 1)
	if err != nil || len(one) != 1 || one[0].ID != "run_a" {
		t.Fatalf("bounded list = %#v, err = %v", one, err)
	}
	wantIDs := []string{"run_a", "run_b"}
	assertRunningIDs := func(label string, runs []Run, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s list error = %v", label, err)
		}
		if len(runs) != len(wantIDs) {
			t.Fatalf("%s runs = %#v", label, runs)
		}
		for index, run := range runs {
			if run.ID != wantIDs[index] || run.State != RunRunning {
				t.Fatalf("%s runs = %#v, want ordered running IDs %v", label, runs, wantIDs)
			}
		}
	}
	runs, err := store.ListRunningRuns(ctx, MaxReconcileRuns)
	assertRunningIDs("before restart", runs, err)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path, options)
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened store: %v", err)
		}
	})
	runs, err = reopened.ListRunningRuns(ctx, MaxReconcileRuns)
	assertRunningIDs("after restart", runs, err)
}

func TestRunLifecycleAtomicallyPersistsReplyAndSession(t *testing.T) {
	store, _ := openTestStore(t)
	mustIngest(t, store, "run_001", baseIngest("event_001"))
	mustIngest(t, store, "run_002", baseIngest("event_002"))

	claimed, ok, err := store.ClaimQueuedRun(context.Background(), 30*time.Second)
	if err != nil || !ok || claimed.ID != "run_001" || claimed.State != RunDispatching {
		t.Fatalf("first claim = %#v, ok = %v, err = %v", claimed, ok, err)
	}
	mustPrepareNoSession(t, store, claimed)
	if err := store.MarkRunRunning(context.Background(), claimed.ID, claimed.DispatchToken); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkRunRunning(context.Background(), claimed.ID, claimed.DispatchToken); err != nil {
		t.Fatalf("idempotent running transition error = %v", err)
	}

	finish := FinishRunInput{
		RunID: "run_001", DispatchToken: claimed.DispatchToken,
		State: RunCompleted, OutputText: "Inspection complete",
		ResultSessionRef: "session_001",
	}
	reply := TextDeliveryInput{ID: "delivery_001", Text: "Inspection complete"}
	if err := store.FinishRun(context.Background(), finish, &reply); err != nil {
		t.Fatalf("FinishRun() error = %v", err)
	}
	if err := store.FinishRun(context.Background(), finish, &reply); err != nil {
		t.Fatalf("idempotent FinishRun() error = %v", err)
	}
	replayedReply := reply
	replayedReply.ID = "delivery_replayed_random_id"
	if err := store.FinishRun(context.Background(), finish, &replayedReply); err != nil {
		t.Fatalf("idempotent FinishRun() with regenerated delivery ID error = %v", err)
	}
	run, err := store.GetRun(context.Background(), finish.RunID)
	if err != nil || run.State != RunCompleted || run.OutputText == nil || *run.OutputText != finish.OutputText {
		t.Fatalf("finished run = %#v, err = %v", run, err)
	}
	if run.ResultSessionRef == nil || *run.ResultSessionRef != finish.ResultSessionRef {
		t.Fatalf("run result session ref = %#v", run.ResultSessionRef)
	}
	key := sessionKeyFromTestRun(run)
	session, found, err := store.GetSession(context.Background(), key)
	if err != nil || !found || session.Ref != finish.ResultSessionRef {
		t.Fatalf("session = %#v, found = %v, err = %v", session, found, err)
	}
	var deliveries int
	if err := store.db.QueryRow("SELECT count(*) FROM text_deliveries WHERE run_id = ?", finish.RunID).Scan(&deliveries); err != nil || deliveries != 1 {
		t.Fatalf("delivery count = %d, err = %v", deliveries, err)
	}

	changed := finish
	changed.OutputText = "different"
	if err := store.FinishRun(context.Background(), changed, &reply); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed terminal result error = %v, want ErrConflict", err)
	}
	changed = finish
	changed.ResultSessionRef = "session_changed"
	if err := store.FinishRun(context.Background(), changed, &reply); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed terminal session error = %v, want ErrConflict", err)
	}

	second, ok, err := store.ClaimQueuedRun(context.Background(), 30*time.Second)
	if err != nil || !ok || second.ID != "run_002" {
		t.Fatalf("second claim = %#v, ok = %v, err = %v", second, ok, err)
	}
	mustPrepareNoSession(t, store, second)
	if err := store.MarkRunRunning(context.Background(), second.ID, second.DispatchToken); err != nil {
		t.Fatal(err)
	}
	collidingReply := TextDeliveryInput{ID: reply.ID, Text: "different content"}
	if err := store.FinishRun(context.Background(), FinishRunInput{
		RunID: second.ID, DispatchToken: second.DispatchToken,
		State: RunCompleted, OutputText: "second",
	}, &collidingReply); !errors.Is(err, ErrConflict) {
		t.Fatalf("delivery collision error = %v, want ErrConflict", err)
	}
	second, err = store.GetRun(context.Background(), second.ID)
	if err != nil || second.State != RunRunning {
		t.Fatalf("atomic rollback left run = %#v, err = %v", second, err)
	}
}

func TestSessionsAreScopedByCompleteExactBindingTuple(t *testing.T) {
	store, _ := openTestStore(t)
	base := Session{SessionKey: SessionKey{
		BindingFingerprint: strings.Repeat("a", SHA256HexBytes),
		ConnectorID:        "connector-a", ActorRef: "actor-a", ConversationRef: "conversation-a",
		TargetID: "target-a", TargetRevision: "revision-a",
	}, Ref: "session-base"}
	sessions := []Session{base}
	changedBinding := base
	changedBinding.BindingFingerprint, changedBinding.Ref = strings.Repeat("b", SHA256HexBytes), "session-binding"
	sessions = append(sessions, changedBinding)
	changedConnector := base
	changedConnector.ConnectorID, changedConnector.Ref = "connector-b", "session-connector"
	sessions = append(sessions, changedConnector)
	changedActor := base
	changedActor.ActorRef, changedActor.Ref = "actor-b", "session-actor"
	sessions = append(sessions, changedActor)
	changedConversation := base
	changedConversation.ConversationRef, changedConversation.Ref = "conversation-b", "session-conversation"
	sessions = append(sessions, changedConversation)
	changedTarget := base
	changedTarget.TargetID, changedTarget.Ref = "target-b", "session-target"
	sessions = append(sessions, changedTarget)
	changedRevision := base
	changedRevision.TargetRevision, changedRevision.Ref = "revision-b", "session-revision"
	sessions = append(sessions, changedRevision)

	for _, session := range sessions {
		if err := store.PutSession(context.Background(), session); err != nil {
			t.Fatalf("PutSession(%q) error = %v", session.Ref, err)
		}
	}
	for _, want := range sessions {
		got, found, err := store.GetSession(context.Background(), want.SessionKey)
		if err != nil || !found || got.Ref != want.Ref {
			t.Fatalf("GetSession(%#v) = %#v, %v, %v", want.SessionKey, got, found, err)
		}
	}
	base.Ref = "session-new"
	if err := store.PutSession(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.GetSession(context.Background(), base.SessionKey)
	if err != nil || !found || got.Ref != base.Ref {
		t.Fatalf("updated session = %#v, found = %v, err = %v", got, found, err)
	}
}

func TestMigrationSixRefusesLegacySessionAuthorityWithoutDDL(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *sql.DB)
	}{
		{
			name: "session row",
			setup: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`INSERT INTO sessions(
                    connector_id, conversation_ref, target_id, target_revision,
                    session_ref, updated_at_ms
                ) VALUES ('connector', 'conversation', 'target', 'revision', 'session', 1)`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "nonterminal Run",
			setup: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`INSERT INTO runs(
                    id, connector_id, event_id, actor_ref, conversation_ref, message_ref,
                    target_id, target_revision, binding_fingerprint, policy_revision,
                    input_text, state, created_at_ms, updated_at_ms
                ) VALUES ('run-queued', 'connector', 'event', 'actor', 'conversation',
                    'message', 'target', 'revision', ?, ?, 'input', 'queued', 1, 1)`,
					strings.Repeat("a", 64), strings.Repeat("b", 64)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "prepared session ref",
			setup: func(t *testing.T, db *sql.DB) {
				insertVersionFourRun(t, db, "run-start-ref", "connector", "conversation", "message")
				if _, err := db.Exec(`UPDATE runs SET start_session_ref = 'legacy-start'
                    WHERE id = 'run-start-ref'`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "result session ref",
			setup: func(t *testing.T, db *sql.DB) {
				insertVersionFourRun(t, db, "run-result-ref", "connector", "conversation", "message")
				if _, err := db.Exec(`UPDATE runs SET result_session_ref = 'legacy-result'
                    WHERE id = 'run-result-ref'`); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "core-v5.sqlite3")
			prepareVersionFiveDatabase(t, path)
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			test.setup(t, db)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			store, err := Open(context.Background(), path, Options{Admission: testAdmissionOptions()})
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
			var version, newColumns int
			if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sessions')
                    WHERE name IN ('binding_fingerprint','actor_ref')`).Scan(&newColumns); err != nil {
				t.Fatal(err)
			}
			if version != 5 || newColumns != 0 {
				t.Fatalf("refused migration changed schema: version=%d new_columns=%d", version, newColumns)
			}
		})
	}
}

func TestMigrationSixCreatesFrozenSixFieldSessionScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core-v5-safe.sqlite3")
	prepareVersionFiveDatabase(t, path)
	store, err := Open(context.Background(), path, Options{Admission: testAdmissionOptions()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	rows, err := store.db.Query(`PRAGMA table_info(sessions)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	primary := make(map[string]int)
	for rows.Next() {
		var cid, notNull, pk int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		primary[name] = pk
	}
	want := []string{"binding_fingerprint", "connector_id", "actor_ref", "conversation_ref", "target_id", "target_revision"}
	for index, column := range want {
		if primary[column] != index+1 {
			t.Fatalf("primary-key position for %s = %d, want %d", column, primary[column], index+1)
		}
	}
	var triggers int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'
        AND name IN ('runs_session_scope_immutable','sessions_scope_key_immutable')`).Scan(&triggers); err != nil {
		t.Fatal(err)
	}
	if triggers != 2 {
		t.Fatalf("session immutability triggers = %d, want 2", triggers)
	}
}

func TestSessionScopeTablesRejectDirectKeyMutation(t *testing.T) {
	store, _ := openTestStore(t)
	run := mustIngest(t, store, "run-session-scope", baseIngest("session-scope"))
	for _, mutation := range []string{
		`UPDATE runs SET binding_fingerprint = '` + strings.Repeat("b", 64) + `' WHERE id = 'run-session-scope'`,
		`UPDATE runs SET connector_id = 'connector-other' WHERE id = 'run-session-scope'`,
		`UPDATE runs SET actor_ref = 'actor-other' WHERE id = 'run-session-scope'`,
		`UPDATE runs SET conversation_ref = 'conversation-other' WHERE id = 'run-session-scope'`,
		`UPDATE runs SET target_id = 'target-other' WHERE id = 'run-session-scope'`,
		`UPDATE runs SET target_revision = 'revision-other' WHERE id = 'run-session-scope'`,
	} {
		if _, err := store.db.Exec(mutation); err == nil {
			t.Fatalf("Run scope mutation succeeded: %s", mutation)
		}
	}
	session := Session{SessionKey: sessionKeyFromTestRun(run), Ref: "session-scope-ref"}
	if err := store.PutSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{
		"binding_fingerprint", "connector_id", "actor_ref", "conversation_ref", "target_id", "target_revision",
	} {
		value := "changed"
		if column == "binding_fingerprint" {
			value = strings.Repeat("b", 64)
		}
		query := fmt.Sprintf("UPDATE sessions SET %s = ? WHERE session_ref = ?", column)
		if _, err := store.db.Exec(query, value, session.Ref); err == nil {
			t.Fatalf("session key mutation succeeded for %s", column)
		}
	}
}

func TestOutboxLeaseExpiryRetryAndCompletionOutcomes(t *testing.T) {
	store, clock := openTestStore(t)
	firstInput := baseIngest("event_outbox_1")
	firstInput.ConnectorID, firstInput.ConversationRef, firstInput.MessageRef = "connector-a", "dm/a", "message/a1"
	secondInput := baseIngest("event_outbox_2")
	secondInput.ConnectorID, secondInput.ConversationRef, secondInput.MessageRef = "connector-a", "dm/a", "message/a2"
	otherInput := baseIngest("event_outbox_other")
	otherInput.ConnectorID, otherInput.ConversationRef, otherInput.MessageRef = "connector-b", "dm/b", "message/b1"
	mustIngest(t, store, "run_outbox_1", firstInput)
	mustIngest(t, store, "run_outbox_2", secondInput)
	mustIngest(t, store, "run_outbox_other", otherInput)
	firstRun := finishNextRunWithReply(t, store, "run_outbox_1", TextDeliveryInput{ID: "delivery_001", Text: "one"})
	finishNextRunWithReply(t, store, "run_outbox_2", TextDeliveryInput{ID: "delivery_002", Text: "two"})
	finishNextRunWithReply(t, store, "run_outbox_other", TextDeliveryInput{ID: "delivery_other", Text: "other"})
	if err := store.FinishRun(context.Background(), FinishRunInput{
		RunID: firstRun.ID, DispatchToken: firstRun.DispatchToken,
		State: RunCompleted, OutputText: "one",
	}, &TextDeliveryInput{ID: "delivery_001", Text: "changed"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed delivery replay error = %v, want ErrConflict", err)
	}

	claimed, err := store.ClaimTextDeliveries(context.Background(), "connector-a", 1, 30*time.Second)
	if err != nil || len(claimed) != 1 || claimed[0].ID != "delivery_001" || claimed[0].AttemptCount != 1 {
		t.Fatalf("first claim = %#v, err = %v", claimed, err)
	}
	firstToken := claimed[0].LeaseToken
	if _, err := store.ClaimTextDeliveries(context.Background(), "connector-a", 1, 30*time.Second); err != nil {
		t.Fatalf("claim second pending error = %v", err)
	}
	if err := store.CompleteDelivery(context.Background(), CompleteDeliveryInput{
		ConnectorID: "connector-a", DeliveryID: "delivery_001", LeaseToken: "wrong",
		Outcome: DeliveryOutcomeDelivered, ProviderMessageRef: "provider/1",
	}); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("wrong token error = %v, want ErrLeaseLost", err)
	}

	clock.Advance(31 * time.Second)
	reclaimed, err := store.ClaimTextDeliveries(context.Background(), "connector-a", 2, 30*time.Second)
	if err != nil || len(reclaimed) != 2 {
		t.Fatalf("reclaim = %#v, err = %v", reclaimed, err)
	}
	var first, second TextDelivery
	for _, delivery := range reclaimed {
		switch delivery.ID {
		case "delivery_001":
			first = delivery
		case "delivery_002":
			second = delivery
		}
	}
	if first.AttemptCount != 2 || first.LeaseToken == firstToken || second.AttemptCount != 2 {
		t.Fatalf("reclaimed first = %#v, second = %#v", first, second)
	}

	delivered := CompleteDeliveryInput{
		ConnectorID: "connector-a", DeliveryID: first.ID, LeaseToken: first.LeaseToken,
		Outcome: DeliveryOutcomeDelivered, ProviderMessageRef: "provider/1",
	}
	if err := store.CompleteDelivery(context.Background(), delivered); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteDelivery(context.Background(), delivered); err != nil {
		t.Fatalf("idempotent delivered completion error = %v", err)
	}
	delivered.ProviderMessageRef = "provider/changed"
	if err := store.CompleteDelivery(context.Background(), delivered); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed completion error = %v, want ErrConflict", err)
	}

	if err := store.CompleteDelivery(context.Background(), CompleteDeliveryInput{
		ConnectorID: "connector-a", DeliveryID: second.ID, LeaseToken: second.LeaseToken,
		Outcome: DeliveryOutcomeRetry, FailureCode: DeliveryFailureTemporary,
	}); err != nil {
		t.Fatalf("retry completion error = %v", err)
	}
	if err := store.CompleteDelivery(context.Background(), CompleteDeliveryInput{
		ConnectorID: "connector-a", DeliveryID: second.ID, LeaseToken: second.LeaseToken,
		Outcome: DeliveryOutcomeRetry, FailureCode: DeliveryFailureTemporary,
	}); err != nil {
		t.Fatalf("idempotent retry completion error = %v", err)
	}
	var availableAt int64
	if err := store.db.QueryRow("SELECT available_at_ms FROM text_deliveries WHERE id = ?", second.ID).Scan(&availableAt); err != nil {
		t.Fatal(err)
	}
	if got := timeFromMillis(availableAt).Sub(clock.Now()); got != time.Minute {
		t.Fatalf("agentd retry backoff = %s, want 1m for attempt two", got)
	}
	none, err := store.ClaimTextDeliveries(context.Background(), "connector-a", 2, 30*time.Second)
	if err != nil || len(none) != 0 {
		t.Fatalf("claim before retry = %#v, err = %v", none, err)
	}
	clock.Advance(time.Minute)
	retried, err := store.ClaimTextDeliveries(context.Background(), "connector-a", 2, 30*time.Second)
	if err != nil || len(retried) != 1 || retried[0].ID != second.ID || retried[0].AttemptCount != 3 {
		t.Fatalf("retry claim = %#v, err = %v", retried, err)
	}
	permanent := CompleteDeliveryInput{
		ConnectorID: "connector-a", DeliveryID: second.ID, LeaseToken: retried[0].LeaseToken,
		Outcome: DeliveryOutcomePermanentFailure, FailureCode: DeliveryFailureRecipientUnavailable,
	}
	if err := store.CompleteDelivery(context.Background(), permanent); err != nil {
		t.Fatalf("permanent completion error = %v", err)
	}
	if err := store.CompleteDelivery(context.Background(), permanent); err != nil {
		t.Fatalf("idempotent permanent completion error = %v", err)
	}

	other, err := store.ClaimTextDeliveries(context.Background(), "connector-b", 1, 30*time.Second)
	if err != nil || len(other) != 1 || other[0].ID != "delivery_other" {
		t.Fatalf("connector scoped claim = %#v, err = %v", other, err)
	}
}

func TestSchemaStoresNoRawPayloadOrArbitraryJSON(t *testing.T) {
	store, _ := openTestStore(t)
	rows, err := store.db.Query(`
SELECT name, sql FROM sqlite_master
WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, definition string
		if err := rows.Scan(&name, &definition); err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(definition)
		for _, forbidden := range []string{"raw_payload", "metadata", "provider_options", " json"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("table %s contains forbidden open-ended storage %q", name, forbidden)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
