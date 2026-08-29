package corestore

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openMaintenanceFixture(t *testing.T) (string, *Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "core.sqlite3")
	clock := &fakeClock{now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)}
	store, err := Open(context.Background(), path, Options{
		Clock: clock.Now, Admission: testAdmissionOptions(),
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return path, store
}

func maintenanceTestSession() Session {
	return Session{SessionKey: SessionKey{
		BindingFingerprint: strings.Repeat("a", SHA256HexBytes),
		ConnectorID:        "discord-personal",
		ActorRef:           "user/maintenance",
		ConversationRef:    "dm/maintenance",
		TargetID:           "project-codex",
		TargetRevision:     "project-codex-r1",
	}, Ref: "session_maintenance_1"}
}

func closeStoreForMaintenance(t *testing.T, store *Store) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestMaintenanceCurrentSchemaInspectAndReset(t *testing.T) {
	ctx := context.Background()
	path, store := openMaintenanceFixture(t)
	want := maintenanceTestSession()
	if err := store.PutSession(ctx, want); err != nil {
		t.Fatal(err)
	}
	closeStoreForMaintenance(t, store)

	maintenance, err := OpenCurrentForMaintenance(ctx, path)
	if err != nil {
		t.Fatalf("OpenCurrentForMaintenance() error = %v", err)
	}
	defer maintenance.Close()
	status, err := maintenance.InspectSession(ctx, want.SessionKey)
	if err != nil || !status.Found || status.Session.Ref != want.Ref ||
		status.Session.SessionKey != want.SessionKey || status.NonterminalRunID != "" {
		t.Fatalf("InspectSession() = %#v, err=%v", status, err)
	}
	result, err := maintenance.ResetSession(ctx, want.SessionKey, want.Ref)
	if err != nil || result != SessionResetDone {
		t.Fatalf("ResetSession() = %q, err=%v", result, err)
	}
	status, err = maintenance.InspectSession(ctx, want.SessionKey)
	if err != nil || status.Found || status.NonterminalRunID != "" {
		t.Fatalf("InspectSession() after reset = %#v, err=%v", status, err)
	}
}

func TestMaintenanceMissingDatabaseIsNotCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.sqlite3")
	store, err := OpenCurrentForMaintenance(context.Background(), path)
	if store != nil || err == nil {
		t.Fatalf("OpenCurrentForMaintenance() = %#v, %v", store, err)
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("missing database was created or changed: %v", statErr)
	}
}

func TestMaintenanceSQLiteOpenCannotRecreatePathRemovedAfterPreflight(t *testing.T) {
	path := filepath.Join(t.TempDir(), "removed after preflight %.sqlite3")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", sqliteExistingDSN(path))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	pingErr := db.PingContext(context.Background())
	if closeErr := db.Close(); closeErr != nil {
		t.Fatalf("Close() error = %v", closeErr)
	}
	if pingErr == nil {
		t.Fatal("existing-only SQLite DSN recreated a removed database")
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("removed database was recreated or changed: %v", statErr)
	}
}

func TestMaintenanceSQLiteExistingURIKeepsPathBytesSeparateFromQuery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core % authority.sqlite3")
	store, err := Open(context.Background(), path, Options{Admission: testAdmissionOptions()})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	closeStoreForMaintenance(t, store)

	maintenance, err := OpenCurrentForMaintenance(context.Background(), path)
	if err != nil {
		t.Fatalf("OpenCurrentForMaintenance() error = %v", err)
	}
	if err := maintenance.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestMaintenanceRejectsUnsafeDatabasePaths(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	regular := filepath.Join(root, "regular.sqlite3")
	if err := os.WriteFile(regular, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "symlink.sqlite3")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative.sqlite3", "file:" + regular, regular, symlink} {
		store, err := OpenCurrentForMaintenance(ctx, path)
		if store != nil || err == nil {
			t.Fatalf("OpenCurrentForMaintenance(%q) = %#v, %v", path, store, err)
		}
	}
	if store, err := OpenCurrentForMaintenance(nil, regular); store != nil || !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil-context maintenance open = %#v, %v", store, err)
	}
}

func TestMaintenanceRejectsHardLinkedDatabase(t *testing.T) {
	ctx := context.Background()
	path, store := openMaintenanceFixture(t)
	closeStoreForMaintenance(t, store)
	alias := filepath.Join(filepath.Dir(path), "core-alias.sqlite3")
	if err := os.Link(path, alias); err != nil {
		t.Fatalf("create hard link: %v", err)
	}

	for _, candidate := range []string{path, alias} {
		maintenance, err := OpenCurrentForMaintenance(ctx, candidate)
		if maintenance != nil || !errors.Is(err, ErrInvalid) {
			if maintenance != nil {
				_ = maintenance.Close()
			}
			t.Fatalf("OpenCurrentForMaintenance(%q) = %#v, %v; want nil, ErrInvalid", candidate, maintenance, err)
		}
	}
}

func TestMaintenanceRefusesLedgerDriftWithoutRepair(t *testing.T) {
	ctx := context.Background()
	path, store := openMaintenanceFixture(t)
	closeStoreForMaintenance(t, store)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE schema_migrations SET sha256 = zeroblob(32) WHERE version = 7`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	maintenance, err := OpenCurrentForMaintenance(ctx, path)
	if maintenance != nil || err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("drifted ledger open = %#v, %v", maintenance, err)
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var hash []byte
	if err := db.QueryRow(`SELECT sha256 FROM schema_migrations WHERE version = 7`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if len(hash) != 32 || !allZero(hash) {
		t.Fatalf("maintenance repaired or changed drifted hash: %x", hash)
	}
}

func TestMaintenanceRefusesOldSchemaWithoutMigrating(t *testing.T) {
	ctx := context.Background()
	path, store := openMaintenanceFixture(t)
	if _, err := store.db.Exec(`DROP INDEX runs_one_nonterminal_session_scope`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`DELETE FROM schema_migrations WHERE version = 7`); err != nil {
		t.Fatal(err)
	}
	closeStoreForMaintenance(t, store)

	maintenance, err := OpenCurrentForMaintenance(ctx, path)
	if maintenance != nil || err == nil || !strings.Contains(err.Error(), "schema is not current") {
		t.Fatalf("old schema open = %#v, %v", maintenance, err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var migrationSeven, indexCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 7`).Scan(&migrationSeven); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master
		WHERE type = 'index' AND name = 'runs_one_nonterminal_session_scope'`).Scan(&indexCount); err != nil {
		t.Fatal(err)
	}
	if migrationSeven != 0 || indexCount != 0 {
		t.Fatalf("maintenance migrated old database: ledger=%d index=%d", migrationSeven, indexCount)
	}
}

func TestMaintenanceResetNotFoundAndExpectedRefMismatchDoNotMutate(t *testing.T) {
	ctx := context.Background()
	path, store := openMaintenanceFixture(t)
	want := maintenanceTestSession()
	if err := store.PutSession(ctx, want); err != nil {
		t.Fatal(err)
	}
	closeStoreForMaintenance(t, store)
	maintenance, err := OpenCurrentForMaintenance(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer maintenance.Close()

	result, err := maintenance.ResetSession(ctx, want.SessionKey, "session_wrong_ref")
	if err != nil || result != SessionResetRefMismatch {
		t.Fatalf("mismatched ResetSession() = %q, %v", result, err)
	}
	status, err := maintenance.InspectSession(ctx, want.SessionKey)
	if err != nil || !status.Found || status.Session.Ref != want.Ref {
		t.Fatalf("mismatch changed session: %#v, %v", status, err)
	}
	missing := want.SessionKey
	missing.ActorRef = "user/missing"
	result, err = maintenance.ResetSession(ctx, missing, want.Ref)
	if err != nil || result != SessionResetNotFound {
		t.Fatalf("absent ResetSession() = %q, %v", result, err)
	}
	status, err = maintenance.InspectSession(ctx, want.SessionKey)
	if err != nil || !status.Found || status.Session.Ref != want.Ref {
		t.Fatalf("not-found reset changed other session: %#v, %v", status, err)
	}
}

func TestMaintenanceResetScopeBlocking(t *testing.T) {
	t.Run("exact nonterminal Run blocks", func(t *testing.T) {
		ctx := context.Background()
		path, store := openMaintenanceFixture(t)
		session := maintenanceTestSession()
		input := baseIngest("event_maintenance_live")
		input.ActorRef, input.ConversationRef = session.ActorRef, session.ConversationRef
		run := mustIngest(t, store, "run_maintenance_live", input)
		if sessionKeyFromTestRun(run) != session.SessionKey {
			t.Fatalf("fixture scope mismatch: %#v != %#v", sessionKeyFromTestRun(run), session.SessionKey)
		}
		if err := store.PutSession(ctx, session); err != nil {
			t.Fatal(err)
		}
		closeStoreForMaintenance(t, store)
		maintenance, err := OpenCurrentForMaintenance(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		defer maintenance.Close()
		status, err := maintenance.InspectSession(ctx, session.SessionKey)
		if err != nil || status.NonterminalRunID != run.ID {
			t.Fatalf("InspectSession() = %#v, %v", status, err)
		}
		result, err := maintenance.ResetSession(ctx, session.SessionKey, session.Ref)
		if !errors.Is(err, ErrSessionScopeBusy) || result != "" {
			t.Fatalf("blocked ResetSession() = %q, %v", result, err)
		}
		status, err = maintenance.InspectSession(ctx, session.SessionKey)
		if err != nil || !status.Found || status.Session.Ref != session.Ref {
			t.Fatalf("blocked reset changed session: %#v, %v", status, err)
		}
	})

	for _, test := range []struct {
		name       string
		otherScope bool
	}{
		{name: "terminal exact-scope Run does not block"},
		{name: "other-scope live Run does not block", otherScope: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			path, store := openMaintenanceFixture(t)
			session := maintenanceTestSession()
			input := baseIngest("event_maintenance_allowed")
			if !test.otherScope {
				input.ActorRef, input.ConversationRef = session.ActorRef, session.ConversationRef
			}
			run := mustIngest(t, store, "run_maintenance_allowed", input)
			if !test.otherScope {
				finishNextRunWithReply(t, store, run.ID, TextDeliveryInput{
					ID: "delivery_maintenance_allowed", Text: "done",
				})
			}
			if err := store.PutSession(ctx, session); err != nil {
				t.Fatal(err)
			}
			closeStoreForMaintenance(t, store)
			maintenance, err := OpenCurrentForMaintenance(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer maintenance.Close()
			result, err := maintenance.ResetSession(ctx, session.SessionKey, session.Ref)
			if err != nil || result != SessionResetDone {
				t.Fatalf("allowed ResetSession() = %q, %v", result, err)
			}
		})
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
