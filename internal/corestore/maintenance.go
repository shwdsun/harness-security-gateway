package corestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// MaintenanceStore is the deliberately narrow offline Core authority surface.
// It never creates or migrates a database and exposes no Run admission or
// dispatch operations.
type MaintenanceStore struct {
	db *sql.DB
}

type MaintenanceSessionStatus struct {
	Session          Session
	Found            bool
	NonterminalRunID string
}

type SessionResetResult string

const (
	SessionResetDone        SessionResetResult = "reset"
	SessionResetNotFound    SessionResetResult = "not_found"
	SessionResetRefMismatch SessionResetResult = "ref_mismatch"
)

// OpenCurrentForMaintenance opens an existing Core database only when its
// immutable migration ledger exactly matches this binary. Unlike Open, it
// cannot create a database, apply DDL, or change the configured page limit.
// The caller must first hold the agentconfig-derived Core process lock.
func OpenCurrentForMaintenance(ctx context.Context, path string) (_ *MaintenanceStore, err error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalid)
	}
	clean, err := inspectExistingDatabasePath(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", sqliteExistingDSN(clean))
	if err != nil {
		return nil, fmt.Errorf("open maintenance SQLite database: %w", err)
	}
	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxIdleTime(0)
	db.SetConnMaxLifetime(0)
	if err = db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping maintenance SQLite database: %w", err)
	}
	if err = requireSQLiteVersion(ctx, db); err != nil {
		return nil, err
	}
	if err = configureSQLite(ctx, db); err != nil {
		return nil, err
	}
	if err = requireExactMigrationLedger(ctx, db); err != nil {
		return nil, err
	}
	if err = verifyMaintenanceIntegrity(ctx, db); err != nil {
		return nil, err
	}
	return &MaintenanceStore{db: db}, nil
}

func (s *MaintenanceStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *MaintenanceStore) InspectSession(
	ctx context.Context,
	key SessionKey,
) (MaintenanceSessionStatus, error) {
	if s == nil || s.db == nil {
		return MaintenanceSessionStatus{}, errors.New("corestore: maintenance store is not open")
	}
	if ctx == nil {
		return MaintenanceSessionStatus{}, fmt.Errorf("%w: nil context", ErrInvalid)
	}
	if err := validateSessionKey(key); err != nil {
		return MaintenanceSessionStatus{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return MaintenanceSessionStatus{}, fmt.Errorf("begin maintenance session inspection: %w", err)
	}
	defer tx.Rollback()
	status, err := inspectMaintenanceSessionTx(ctx, tx, key)
	if err != nil {
		return MaintenanceSessionStatus{}, err
	}
	if err := tx.Commit(); err != nil {
		return MaintenanceSessionStatus{}, fmt.Errorf("commit maintenance session inspection: %w", err)
	}
	return status, nil
}

// ResetSession atomically refuses any exact-scope live Run, compares the
// operator-observed opaque ref, and detaches Core's current pointer. sandboxd's
// private append-only vendor-token history is deliberately untouched.
func (s *MaintenanceStore) ResetSession(
	ctx context.Context,
	key SessionKey,
	expectedRef string,
) (SessionResetResult, error) {
	if s == nil || s.db == nil {
		return "", errors.New("corestore: maintenance store is not open")
	}
	if ctx == nil {
		return "", fmt.Errorf("%w: nil context", ErrInvalid)
	}
	if err := validateSessionKey(key); err != nil {
		return "", err
	}
	if err := validateSessionRef(expectedRef); err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin offline session reset: %w", err)
	}
	defer tx.Rollback()
	status, err := inspectMaintenanceSessionTx(ctx, tx, key)
	if err != nil {
		return "", err
	}
	if status.NonterminalRunID != "" {
		return "", ErrSessionScopeBusy
	}
	if !status.Found {
		if err := tx.Commit(); err != nil {
			return "", fmt.Errorf("commit absent session reset: %w", err)
		}
		return SessionResetNotFound, nil
	}
	if status.Session.Ref != expectedRef {
		if err := tx.Commit(); err != nil {
			return "", fmt.Errorf("commit mismatched session reset: %w", err)
		}
		return SessionResetRefMismatch, nil
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM sessions
        WHERE binding_fingerprint = ? AND connector_id = ? AND actor_ref = ?
          AND conversation_ref = ? AND target_id = ? AND target_revision = ?
          AND session_ref = ?`,
		key.BindingFingerprint, key.ConnectorID, key.ActorRef,
		key.ConversationRef, key.TargetID, key.TargetRevision, expectedRef,
	)
	if err != nil {
		return "", fmt.Errorf("delete current offline session pointer: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("inspect offline session reset: %w", err)
	}
	if affected != 1 {
		return "", fmt.Errorf("offline session reset changed %d rows, want 1", affected)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit offline session reset: %w", err)
	}
	return SessionResetDone, nil
}

func inspectMaintenanceSessionTx(
	ctx context.Context,
	tx *sql.Tx,
	key SessionKey,
) (MaintenanceSessionStatus, error) {
	status := MaintenanceSessionStatus{}
	var updatedAt int64
	err := tx.QueryRowContext(ctx, `SELECT binding_fingerprint, connector_id,
        actor_ref, conversation_ref, target_id, target_revision,
        session_ref, updated_at_ms
        FROM sessions
        WHERE binding_fingerprint = ? AND connector_id = ? AND actor_ref = ?
          AND conversation_ref = ? AND target_id = ? AND target_revision = ?`,
		key.BindingFingerprint, key.ConnectorID, key.ActorRef,
		key.ConversationRef, key.TargetID, key.TargetRevision,
	).Scan(
		&status.Session.BindingFingerprint, &status.Session.ConnectorID,
		&status.Session.ActorRef, &status.Session.ConversationRef,
		&status.Session.TargetID, &status.Session.TargetRevision,
		&status.Session.Ref, &updatedAt,
	)
	switch {
	case err == nil:
		status.Found = true
		status.Session.UpdatedAt = timeFromMillis(updatedAt)
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return MaintenanceSessionStatus{}, fmt.Errorf("inspect current offline session: %w", err)
	}
	err = tx.QueryRowContext(ctx, `SELECT id FROM runs
        WHERE binding_fingerprint = ? AND connector_id = ? AND actor_ref = ?
          AND conversation_ref = ? AND target_id = ? AND target_revision = ?
          AND state IN ('queued','dispatching','running')
        ORDER BY created_at_ms, id LIMIT 1`,
		key.BindingFingerprint, key.ConnectorID, key.ActorRef,
		key.ConversationRef, key.TargetID, key.TargetRevision,
	).Scan(&status.NonterminalRunID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return MaintenanceSessionStatus{}, fmt.Errorf("inspect live Run before session reset: %w", err)
	}
	return status, nil
}

func inspectExistingDatabasePath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || strings.HasPrefix(path, "file:") ||
		strings.IndexByte(path, 0) >= 0 || strings.ContainsAny(path, "?#") {
		return "", fmt.Errorf("%w: database path must be an absolute local path", ErrInvalid)
	}
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err != nil {
		return "", fmt.Errorf("inspect existing maintenance database: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 || !hasSingleHardLink(info) {
		return "", fmt.Errorf("%w: existing database must be a regular non-symlink 0600 file with exactly one hard link", ErrInvalid)
	}
	return clean, nil
}

func requireExactMigrationLedger(ctx context.Context, db *sql.DB) error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx,
		`SELECT version, name, sha256 FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("read exact maintenance migration ledger: %w", err)
	}
	defer rows.Close()
	seen := make(map[int]struct{}, len(migrations))
	for rows.Next() {
		var version int
		var name string
		var hash []byte
		if err := rows.Scan(&version, &name, &hash); err != nil {
			return fmt.Errorf("scan exact maintenance migration ledger: %w", err)
		}
		if version < 1 || version > len(migrations) {
			return fmt.Errorf("maintenance database contains unknown migration version %d", version)
		}
		candidate := migrations[version-1]
		if candidate.version != version || candidate.name != name || !equalBytes(candidate.hash[:], hash) {
			return fmt.Errorf("maintenance migration %d does not match the embedded name and checksum", version)
		}
		seen[version] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate exact maintenance migration ledger: %w", err)
	}
	if len(seen) != len(migrations) {
		return fmt.Errorf("maintenance database schema is not current: found %d of %d migrations",
			len(seen), len(migrations))
	}
	return nil
}

func verifyMaintenanceIntegrity(ctx context.Context, db *sql.DB) error {
	var result string
	if err := db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&result); err != nil {
		return fmt.Errorf("check maintenance database integrity: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("maintenance SQLite quick_check returned %q", result)
	}
	rows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("check maintenance foreign keys: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("maintenance SQLite foreign_key_check found a violation")
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate maintenance foreign key check: %w", err)
	}
	return nil
}
