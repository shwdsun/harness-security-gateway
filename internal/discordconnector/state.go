package discordconnector

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

// StateSchemaVersion is the Connector's own private ingress state. It holds no
// message content, no credential and no Core data.
const StateSchemaVersion = 1

const stateDDL = `
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cursor(
    channel_id TEXT PRIMARY KEY,
    last_message_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sent_deliveries(
    delivery_id TEXT PRIMARY KEY,
    provider_message_ref TEXT NOT NULL,
    sent_at_unix_ms INTEGER NOT NULL
);`

// Store keeps the durable cursor and the record of deliveries already sent to
// the platform, so a re-leased delivery is completed instead of resent.
type Store struct {
	db *sql.DB
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	if ctx == nil {
		return nil, errors.New("discordconnector: nil context")
	}
	clean, err := prepareStateFile(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", fmt.Sprintf("%s?_pragma=busy_timeout(5000)", clean)+
		"&_pragma=foreign_keys(ON)&_pragma=journal_mode(DELETE)&_pragma=synchronous(FULL)&_pragma=trusted_schema(OFF)")
	if err != nil {
		return nil, fmt.Errorf("open connector state: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, stateDDL); err != nil {
		return fmt.Errorf("create connector state: %w", err)
	}
	var version int
	err := s.db.QueryRowContext(ctx, `SELECT version FROM schema_version`).Scan(&version)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := s.db.ExecContext(ctx, `INSERT INTO schema_version(version) VALUES (?)`, StateSchemaVersion); err != nil {
			return fmt.Errorf("record connector state version: %w", err)
		}
	case err != nil:
		return fmt.Errorf("read connector state version: %w", err)
	case version != StateSchemaVersion:
		// A newer or unknown lineage is not silently adopted or rewritten.
		return fmt.Errorf("discordconnector: unsupported state schema version %d", version)
	}
	return nil
}

// Cursor reports the last message handed to Core, or reports that this channel
// has no cursor yet.
func (s *Store) Cursor(ctx context.Context, channelID string) (string, bool, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT last_message_id FROM cursor WHERE channel_id = ?`, channelID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read ingress cursor: %w", err)
	}
	return id, true, nil
}

// SetCursor advances the cursor only forward. It is called after Core durably
// acknowledged a message, or after the message was filtered out and can never
// become admissible.
func (s *Store) SetCursor(ctx context.Context, channelID, messageID string) error {
	if validateSnowflake("channel_id", channelID) != nil {
		return errors.New("discordconnector: refusing a malformed channel cursor")
	}
	if messageID != "0" && validateSnowflake("message_id", messageID) != nil {
		return errors.New("discordconnector: refusing a malformed cursor position")
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO cursor(channel_id, last_message_id) VALUES (?, ?)
ON CONFLICT(channel_id) DO UPDATE SET last_message_id = excluded.last_message_id
WHERE CAST(excluded.last_message_id AS INTEGER) > CAST(cursor.last_message_id AS INTEGER)`, channelID, messageID)
	if err != nil {
		return fmt.Errorf("advance ingress cursor: %w", err)
	}
	return nil
}

// RecordSent remembers one completed platform send before its lease is
// completed, so a lost completion response cannot cause a second send.
func (s *Store) RecordSent(ctx context.Context, deliveryID, providerRef string, nowUnixMS int64) error {
	if deliveryID == "" || providerRef == "" {
		return errors.New("discordconnector: incomplete sent-delivery record")
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO sent_deliveries(delivery_id, provider_message_ref, sent_at_unix_ms) VALUES (?, ?, ?)
ON CONFLICT(delivery_id) DO NOTHING`, deliveryID, providerRef, nowUnixMS)
	if err != nil {
		return fmt.Errorf("record sent delivery: %w", err)
	}
	return nil
}

func (s *Store) SentDelivery(ctx context.Context, deliveryID string) (string, bool, error) {
	var ref string
	err := s.db.QueryRowContext(ctx,
		`SELECT provider_message_ref FROM sent_deliveries WHERE delivery_id = ?`, deliveryID).Scan(&ref)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read sent delivery: %w", err)
	}
	return ref, true, nil
}

// PruneSent bounds this table. Core retains a delivery only while its parent
// Run's receipt lives, so older local records can never be needed again.
func (s *Store) PruneSent(ctx context.Context, olderThanUnixMS int64) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM sent_deliveries WHERE sent_at_unix_ms < ?`, olderThanUnixMS); err != nil {
		return fmt.Errorf("prune sent deliveries: %w", err)
	}
	return nil
}

func prepareStateFile(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00?#") {
		return "", fmt.Errorf("%w: state_database must be an absolute URI-free path", ErrInvalid)
	}
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", fmt.Errorf("%w: state database must be a regular non-symlink file", ErrInvalid)
		}
		if info.Mode().Perm() != 0o600 {
			return "", fmt.Errorf("%w: state database mode must be exactly 0600", ErrInvalid)
		}
		return clean, nil
	case !errors.Is(err, os.ErrNotExist):
		return "", fmt.Errorf("inspect connector state path: %w", err)
	}
	file, err := os.OpenFile(clean, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create connector state: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close new connector state: %w", err)
	}
	return clean, nil
}
