// Package sandboxstore owns sandboxd's small runtime-reconciliation database.
// It is intentionally separate from agentd's business database.
//
// The schema stores only resolved logical identifiers, request/input digests,
// bounded typed events, opaque runtime references, and sandbox-private session
// mappings. It never stores a prompt, host path, image, argv, environment,
// mount, network setting, or raw JSON payload.
package sandboxstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/hostepoch"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

const (
	minimumSQLiteVersion = "3.51.3"
	busyTimeoutMS        = 5000

	MaxWorkspaceIDBytes = 128
	MaxRuntimeRefBytes  = 256
)

var (
	ErrNotFound               = errors.New("sandboxstore: not found")
	ErrConflict               = errors.New("sandboxstore: idempotency conflict")
	ErrWorkspaceBusy          = errors.New("sandboxstore: workspace already has a writer")
	ErrSessionBusy            = errors.New("sandboxstore: session scope already has a nonterminal Run")
	ErrRevisionMismatch       = errors.New("sandboxstore: resolved target revision mismatch")
	ErrTargetRevisionNotFound = errors.New("sandboxstore: target revision is not registered")
	ErrIllegalTransition      = errors.New("sandboxstore: illegal state transition")
	ErrEventSequence          = errors.New("sandboxstore: invalid event sequence")
	ErrSessionScope           = errors.New("sandboxstore: invalid session scope")
	// ErrSessionNotFound is retained as a compatibility name but deliberately
	// aliases the same closed error so reference existence is not an oracle.
	ErrSessionNotFound             = ErrSessionScope
	ErrInvalidArgument             = errors.New("sandboxstore: invalid argument")
	ErrColdMigrationRequired       = errors.New("sandboxstore: non-empty pre-v3 database requires reviewed cold migration")
	ErrUnsafeIntentState           = errors.New("sandboxstore: pre-v4 database contains a non-interrupted terminal run with pending runtime intent")
	ErrUnsafeLegacySessionState    = errors.New("sandboxstore: legacy session state lacks exact binding scope")
	ErrUnsafeSessionLifecycleState = errors.New("sandboxstore: legacy session lifecycle authority cannot be proven")
	ErrRunnerStateOwnershipUnknown = errors.New("sandboxstore: runner-state ownership cannot be proven")
)

// TargetAuthority is sandboxd's durable registration input for one exact
// TargetRevision and its historically exclusive runner-state namespace.
// RunnerStatePathDigest is a domain-separated digest of the resolved host path;
// the path itself never enters this store. StatePathAbsent is evidence supplied
// by the trusted local configuration layer that the state directory did not
// exist before this registration attempt. It authorizes first ownership only;
// it never permits adoption of an unowned existing directory.
type TargetAuthority struct {
	TargetID              string
	TargetRevision        string
	RevisionPin           string
	RunnerStateRef        string
	RunnerStatePathDigest string
	StatePathAbsent       bool
}

type Store struct {
	db *sql.DB
}

// Run is sandboxd's durable execution record. InputSHA256 and Fingerprint are
// digests; the full prompt is deliberately absent.
type Run struct {
	RunID                string
	Fingerprint          string
	TargetID             string
	TargetRevision       string
	WorkspaceID          string
	Writable             bool
	InputSHA256          string
	RequestedSessionRef  *string
	SessionScopeDigest   string
	SessionMode          targetmanifest.SessionMode
	SessionMaxAgeSeconds int64
	SessionMaxTurns      int64
	SessionTurnNumber    int64
	Deadline             time.Time
	State                executionwire.RunState
	LastEventSeq         uint64
	RuntimeRef           *string
	// RuntimeIntentPending means sandboxd has durably authorized one
	// deterministic runtime Create, but has not yet bound the resulting
	// container reference or crossed a definitive recovery boundary.
	RuntimeIntentPending bool
	// RuntimeIntentBootID records the host boot in which Create authority was
	// granted. It is nil only for no intent or a legacy pending v2 row; a
	// legacy nil value can never prove that an in-flight Create has stopped.
	RuntimeIntentBootID *string
	Output              *executionwire.TextOutput
	ResultSessionRef    *string
	Failure             *executionwire.RunFailure
	CreatedAt           time.Time
	UpdatedAt           time.Time
	TerminalAt          *time.Time
	WorkspaceLockHeld   bool
}

func validateBootID(value string) error {
	if err := hostepoch.Validate(value); err != nil {
		return fmt.Errorf("%w: invalid runtime intent boot identifier", ErrInvalidArgument)
	}
	return nil
}

// SessionMapping binds an externally opaque sandbox session reference to the
// vendor token required by the pinned harness adapter. VendorToken never
// crosses the agentd/sandboxd boundary.
type SessionMapping struct {
	Ref         string
	VendorToken string
}

// SessionPolicy is the narrow TargetRevision-authored lifecycle authority
// accepted by the persistence layer. No value is ever sourced from StartRun.
type SessionPolicy struct {
	Mode          targetmanifest.SessionMode
	MaxAgeSeconds int64
	MaxTurns      int64
}

// Open opens or creates one local SQLite database. The path must be absolute;
// an existing path must be a regular non-symlink file. New files are created
// with mode 0600 before SQLite sees them.
func Open(ctx context.Context, path string) (*Store, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidArgument)
	}
	cleanPath, created, err := prepareDatabaseFile(path)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", sqliteDSN(cleanPath))
	if err != nil {
		return nil, fmt.Errorf("open sandbox database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	store := &Store{db: db}
	if err := store.configure(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.verifyIntegrity(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if created {
		if err := os.Chmod(cleanPath, 0o600); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("secure new sandbox database: %w", err)
		}
	}
	return store, nil
}

// sqliteDSN asks modernc.org/sqlite to apply these PRAGMAs whenever
// database/sql opens a physical connection. MaxOpenConns(1) bounds
// concurrency, but it does not promise that one physical connection lives
// forever, so configure-only connection settings would be lost on replacement.
func sqliteDSN(cleanPath string) string {
	return fmt.Sprintf("%s?_pragma=busy_timeout(%d)", cleanPath, busyTimeoutMS) +
		"&_pragma=foreign_keys(ON)" +
		"&_pragma=journal_mode(DELETE)" +
		"&_pragma=recursive_triggers(ON)" +
		"&_pragma=synchronous(FULL)" +
		"&_pragma=trusted_schema(OFF)"
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) configure(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping sandbox database: %w", err)
	}

	var version string
	if err := s.db.QueryRowContext(ctx, `SELECT sqlite_version()`).Scan(&version); err != nil {
		return fmt.Errorf("query SQLite version: %w", err)
	}
	compatible, err := sqliteVersionAtLeast(version, minimumSQLiteVersion)
	if err != nil {
		return err
	}
	if !compatible {
		return fmt.Errorf("sandboxstore: SQLite %s is older than required %s", version, minimumSQLiteVersion)
	}

	if _, err := s.db.ExecContext(ctx, fmt.Sprintf(`PRAGMA busy_timeout = %d`, busyTimeoutMS)); err != nil {
		return fmt.Errorf("set SQLite busy timeout: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("enable SQLite foreign keys: %w", err)
	}
	var foreignKeys int
	if err := s.db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		return fmt.Errorf("verify SQLite foreign keys: %w", err)
	}
	if foreignKeys != 1 {
		return errors.New("sandboxstore: SQLite foreign keys did not remain enabled")
	}

	var journalMode string
	if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode = DELETE`).Scan(&journalMode); err != nil {
		return fmt.Errorf("set SQLite rollback journal: %w", err)
	}
	if !strings.EqualFold(journalMode, "delete") {
		return fmt.Errorf("sandboxstore: SQLite journal mode is %q, want DELETE", journalMode)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA synchronous = FULL`); err != nil {
		return fmt.Errorf("set SQLite synchronous mode: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA trusted_schema = OFF`); err != nil {
		return fmt.Errorf("disable SQLite trusted schema: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA recursive_triggers = ON`); err != nil {
		return fmt.Errorf("enable recursive SQLite triggers: %w", err)
	}
	var recursiveTriggers int
	if err := s.db.QueryRowContext(ctx, `PRAGMA recursive_triggers`).Scan(&recursiveTriggers); err != nil {
		return fmt.Errorf("verify recursive SQLite triggers: %w", err)
	}
	if recursiveTriggers != 1 {
		return errors.New("sandboxstore: SQLite recursive triggers did not remain enabled")
	}
	return nil
}

func prepareDatabaseFile(path string) (cleanPath string, created bool, err error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", false, fmt.Errorf("%w: database path must be absolute", ErrInvalidArgument)
	}
	if strings.ContainsAny(path, "\x00?#") {
		return "", false, fmt.Errorf("%w: database path contains URI or NUL characters", ErrInvalidArgument)
	}
	cleanPath = filepath.Clean(path)

	info, statErr := os.Lstat(cleanPath)
	switch {
	case statErr == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", false, fmt.Errorf("%w: existing database path must be a regular non-symlink file", ErrInvalidArgument)
		}
		if info.Mode().Perm() != 0o600 {
			return "", false, fmt.Errorf("%w: existing database mode must be exactly 0600", ErrInvalidArgument)
		}
		return cleanPath, false, nil
	case !errors.Is(statErr, os.ErrNotExist):
		return "", false, fmt.Errorf("inspect sandbox database path: %w", statErr)
	}

	file, openErr := os.OpenFile(cleanPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if openErr != nil {
		return "", false, fmt.Errorf("create sandbox database: %w", openErr)
	}
	if closeErr := file.Close(); closeErr != nil {
		return "", false, fmt.Errorf("close new sandbox database: %w", closeErr)
	}
	return cleanPath, true, nil
}

func sqliteVersionAtLeast(got, minimum string) (bool, error) {
	gotParts, err := parseSQLiteVersion(got)
	if err != nil {
		return false, fmt.Errorf("parse SQLite version %q: %w", got, err)
	}
	minimumParts, err := parseSQLiteVersion(minimum)
	if err != nil {
		return false, fmt.Errorf("parse minimum SQLite version %q: %w", minimum, err)
	}
	for index := range gotParts {
		if gotParts[index] > minimumParts[index] {
			return true, nil
		}
		if gotParts[index] < minimumParts[index] {
			return false, nil
		}
	}
	return true, nil
}

func parseSQLiteVersion(value string) ([3]int, error) {
	var parsed [3]int
	parts := strings.Split(value, ".")
	if len(parts) != len(parsed) {
		return parsed, errors.New("expected major.minor.patch")
	}
	for index, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return parsed, errors.New("version component is not a non-negative integer")
		}
		parsed[index] = number
	}
	return parsed, nil
}
