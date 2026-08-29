package corestore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const (
	minimumExactBindingEvidenceVersion = 4
	runDerivedDeliveryScopeVersion     = 5
	exactSessionScopeVersion           = 6
	oneNonterminalSessionScopeVersion  = 7
)

type migration struct {
	version  int
	name     string
	contents []byte
	hash     [sha256.Size]byte
}

func loadMigrations() ([]migration, error) {
	names, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return nil, fmt.Errorf("list embedded migrations: %w", err)
	}
	sort.Strings(names)
	result := make([]migration, 0, len(names))
	for _, name := range names {
		base := filepath.Base(name)
		prefix, _, ok := strings.Cut(base, "_")
		if !ok {
			return nil, fmt.Errorf("migration %q lacks a numeric prefix", base)
		}
		version, err := strconv.Atoi(prefix)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("migration %q has an invalid version", base)
		}
		if len(result) > 0 && version <= result[len(result)-1].version {
			return nil, fmt.Errorf("migration version %d is duplicated or unordered", version)
		}
		contents, err := migrationFiles.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read embedded migration %q: %w", base, err)
		}
		result = append(result, migration{
			version:  version,
			name:     base,
			contents: contents,
			hash:     sha256.Sum256(contents),
		})
	}
	if len(result) == 0 {
		return nil, errors.New("no embedded core store migrations")
	}
	return result, nil
}

func (s *Store) applyMigrations(ctx context.Context) error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version       INTEGER PRIMARY KEY CHECK (version > 0),
    name          TEXT NOT NULL UNIQUE,
    sha256        BLOB NOT NULL CHECK (length(sha256) = 32),
    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms > 0)
) STRICT`); err != nil {
		return fmt.Errorf("bootstrap migration ledger: %w", err)
	}

	applied := make(map[int]struct {
		name string
		hash []byte
	})
	rows, err := s.db.QueryContext(ctx, "SELECT version, name, sha256 FROM schema_migrations ORDER BY version")
	if err != nil {
		return fmt.Errorf("read migration ledger: %w", err)
	}
	for rows.Next() {
		var version int
		var name string
		var hash []byte
		if err := rows.Scan(&version, &name, &hash); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan migration ledger: %w", err)
		}
		applied[version] = struct {
			name string
			hash []byte
		}{name: name, hash: append([]byte(nil), hash...)}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close migration ledger rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate migration ledger: %w", err)
	}

	known := make(map[int]migration, len(migrations))
	for _, candidate := range migrations {
		known[candidate.version] = candidate
	}
	for version, record := range applied {
		candidate, ok := known[version]
		if !ok {
			return fmt.Errorf("database contains unknown migration version %d", version)
		}
		if record.name != candidate.name || !equalBytes(record.hash, candidate.hash[:]) {
			return fmt.Errorf("migration %d does not match the embedded name and checksum", version)
		}
	}
	for _, candidate := range migrations {
		if _, ok := applied[candidate.version]; ok {
			continue
		}
		if err := s.applyMigration(ctx, candidate); err != nil {
			return err
		}
	}
	return nil
}

func requireNoLegacyNonterminalRuns(ctx context.Context, tx *sql.Tx) error {
	var count int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs
        WHERE state NOT IN ('completed', 'failed', 'cancelled', 'interrupted')`).Scan(&count); err != nil {
		return fmt.Errorf("inspect legacy Run admission state: %w", err)
	}
	if count != 0 {
		return fmt.Errorf("%w: found %d nonterminal Run(s)", ErrUnsafeLegacyAdmissionState, count)
	}
	return nil
}

func requireSafeLegacyDeliveries(ctx context.Context, tx *sql.Tx) error {
	var count int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*)
        FROM text_deliveries AS d
        LEFT JOIN runs AS r ON r.id = d.run_id
        WHERE d.run_id IS NULL
           OR r.id IS NULL
           OR d.connector_id IS NOT r.connector_id
           OR d.conversation_ref IS NOT r.conversation_ref
           OR COALESCE(d.reply_to_ref, '') IS NOT COALESCE(r.message_ref, '')`).Scan(&count); err != nil {
		return fmt.Errorf("inspect legacy delivery disclosure scope: %w", err)
	}
	if count != 0 {
		return fmt.Errorf("%w: found %d unsafe delivery row(s)", ErrUnsafeLegacyDeliveryState, count)
	}
	return nil
}

func requireSafeLegacySessions(ctx context.Context, tx *sql.Tx) error {
	var sessions int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil {
		return fmt.Errorf("inspect legacy sessions: %w", err)
	}
	var runs int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs
        WHERE state NOT IN ('completed', 'failed', 'cancelled', 'interrupted')
           OR start_session_ref IS NOT NULL
           OR result_session_ref IS NOT NULL`).Scan(&runs); err != nil {
		return fmt.Errorf("inspect legacy Run session state: %w", err)
	}
	if sessions != 0 || runs != 0 {
		return fmt.Errorf("%w: found %d session row(s) and %d unsafe Run(s)",
			ErrUnsafeLegacySessionState, sessions, runs)
	}
	return nil
}

func requireOneNonterminalRunPerSessionScope(ctx context.Context, tx *sql.Tx) error {
	var duplicateScopes int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (
        SELECT 1 FROM runs
        WHERE state IN ('queued', 'dispatching', 'running')
        GROUP BY binding_fingerprint, connector_id, actor_ref, conversation_ref,
                 target_id, target_revision
        HAVING COUNT(*) > 1
    )`).Scan(&duplicateScopes); err != nil {
		return fmt.Errorf("inspect legacy nonterminal session scopes: %w", err)
	}
	if duplicateScopes != 0 {
		return fmt.Errorf("%w: found %d duplicate scope(s)",
			ErrUnsafeLegacySessionLifecycleState, duplicateScopes)
	}
	return nil
}

func (s *Store) applyMigration(ctx context.Context, candidate migration) error {
	appliedAt, err := s.nowMillis()
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %d: %w", candidate.version, err)
	}
	defer tx.Rollback()
	// Migration 4's legacy gate must run after this immediate writer
	// transaction has acquired SQLite authority and before its evidence columns
	// and triggers land. An older process either commits first and is counted,
	// or waits until the new insert trigger requires evidence.
	if candidate.version == minimumExactBindingEvidenceVersion {
		if err := requireNoLegacyNonterminalRuns(ctx, tx); err != nil {
			return err
		}
	}
	// Migration 5 removes the legacy destination columns. Refuse before DDL
	// rather than silently rewriting an unparented or mismatched destination to
	// the parent Run's current scope.
	if candidate.version == runDerivedDeliveryScopeVersion {
		if err := requireSafeLegacyDeliveries(ctx, tx); err != nil {
			return err
		}
	}
	// Migration 6 cannot infer actor/binding scope for an old opaque reference,
	// and a nonterminal Run was prepared against the v1 execution fingerprint.
	// Refuse before DDL rather than laundering or stranding either authority.
	if candidate.version == exactSessionScopeVersion {
		if err := requireSafeLegacySessions(ctx, tx); err != nil {
			return err
		}
	}
	if candidate.version == oneNonterminalSessionScopeVersion {
		if err := requireOneNonterminalRunPerSessionScope(ctx, tx); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, string(candidate.contents)); err != nil {
		return fmt.Errorf("apply migration %d (%s): %w", candidate.version, candidate.name, err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO schema_migrations(version, name, sha256, applied_at_ms) VALUES (?, ?, ?, ?)",
		candidate.version, candidate.name, candidate.hash[:], appliedAt,
	); err != nil {
		return fmt.Errorf("record migration %d: %w", candidate.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %d: %w", candidate.version, err)
	}
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
