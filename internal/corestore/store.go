package corestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const minimumSQLiteVersion = "3.51.3"

const (
	defaultRetryDelay = 30 * time.Second
	maxRetryDelay     = time.Hour
)

type Store struct {
	db            *sql.DB
	clock         Clock
	newLeaseToken LeaseTokenSource
	retryDelay    time.Duration
	admission     AdmissionOptions
}

var _ Operations = (*Store)(nil)

// Open opens one local SQLite database. The database path must be absolute;
// URI filenames, in-memory databases, symlinks, and non-regular files are not
// accepted. A database created by Open begins with mode 0600.
func Open(ctx context.Context, path string, options Options) (_ *Store, err error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalid)
	}
	if path == "" || !filepath.IsAbs(path) || strings.HasPrefix(path, "file:") ||
		strings.IndexByte(path, 0) >= 0 || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("%w: database path must be an absolute local path", ErrInvalid)
	}
	path = filepath.Clean(path)
	retryDelay := options.RetryDelay
	if retryDelay == 0 {
		retryDelay = defaultRetryDelay
	}
	if retryDelay < time.Second || retryDelay > maxRetryDelay {
		return nil, fmt.Errorf("%w: retry delay must be between one second and one hour", ErrInvalid)
	}
	if err := validateAdmissionOptions(options.Admission); err != nil {
		return nil, err
	}

	if err := prepareDatabaseFile(path); err != nil {
		return nil, err
	}

	clock := options.Clock
	if clock == nil {
		clock = defaultClock
	}
	newLeaseToken := options.NewLeaseToken
	if newLeaseToken == nil {
		newLeaseToken = defaultLeaseToken
	}

	// The internally constructed DSN repeats connection-local security and
	// durability settings for any replacement connection database/sql may open.
	// The caller cannot inject DSN parameters because '?' and '#' were rejected.
	dsn := sqliteDSN(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()

	// PRAGMAs are connection-local. Keeping exactly one live connection makes
	// their enforcement stable and avoids SQLite writer fan-out in agentd.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxIdleTime(0)
	db.SetConnMaxLifetime(0)

	if err = db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping SQLite database: %w", err)
	}
	if err = requireSQLiteVersion(ctx, db); err != nil {
		return nil, err
	}
	if err = configureSQLite(ctx, db); err != nil {
		return nil, err
	}

	store := &Store{
		db: db, clock: clock, newLeaseToken: newLeaseToken,
		retryDelay: retryDelay, admission: options.Admission,
	}
	if _, err = store.nowMillis(); err != nil {
		return nil, err
	}
	if err = store.applyMigrations(ctx); err != nil {
		return nil, err
	}
	if err = store.configurePageLimit(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

const sqliteConnectionQuery = "_txlock=immediate" +
	"&_pragma=foreign_keys(1)" +
	"&_pragma=busy_timeout(5000)" +
	"&_pragma=synchronous(FULL)" +
	"&_pragma=trusted_schema(OFF)" +
	"&_pragma=journal_mode(DELETE)"

func sqliteDSN(path string) string {
	return path + "?" + sqliteConnectionQuery
}

// sqliteExistingDSN lets SQLite itself enforce the maintenance opener's
// existing-file-only contract. The URI path is escaped independently from the
// fixed query so a path cannot become URI authority or query input.
func sqliteExistingDSN(path string) string {
	uri := url.URL{Scheme: "file", Path: path}
	uri.RawQuery = "mode=rw&" + sqliteConnectionQuery
	return uri.String()
}

func validateAdmissionOptions(options AdmissionOptions) error {
	if options.AcceptWindow < time.Second || options.AcceptWindow > 30*24*time.Hour {
		return fmt.Errorf("%w: admission accept window must be between one second and 30 days", ErrInvalid)
	}
	if options.ReceiptWindow <= options.AcceptWindow || options.ReceiptWindow > 365*24*time.Hour {
		return fmt.Errorf("%w: admission receipt window must exceed accept window and be at most 365 days", ErrInvalid)
	}
	if options.FutureSkew < 0 || options.FutureSkew > 24*time.Hour {
		return fmt.Errorf("%w: admission future skew must be between zero and 24 hours", ErrInvalid)
	}
	for name, value := range map[string]int64{
		"receipts per connector":           options.MaxReceiptsPerConnector,
		"queued runs per connector":        options.MaxQueuedRunsPerConnector,
		"nonterminal runs per connector":   options.MaxNonTerminalRunsPerConnector,
		"pending deliveries per connector": options.MaxPendingDeliveriesPerConnector,
	} {
		if value < 1 || value > 1_000_000_000 {
			return fmt.Errorf("%w: admission %s must be between 1 and 1000000000", ErrInvalid, name)
		}
	}
	if options.MaxQueuedRunsPerConnector > options.MaxNonTerminalRunsPerConnector {
		return fmt.Errorf("%w: queued run quota cannot exceed nonterminal run quota", ErrInvalid)
	}
	if options.MaxRetainedInputBytesPerConnector < MaxTextBytes ||
		options.MaxRetainedInputBytesPerConnector > 1<<40 {
		return fmt.Errorf("%w: retained input quota must be between %d bytes and 1 TiB", ErrInvalid, MaxTextBytes)
	}
	if options.MaxDatabasePages < 64 || options.MaxDatabasePages > 2_147_483_646 {
		return fmt.Errorf("%w: database page limit must be between 64 and 2147483646", ErrInvalid)
	}
	return nil
}

func (s *Store) configurePageLimit(ctx context.Context) error {
	var pageCount int64
	if err := s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
		return fmt.Errorf("read SQLite page count: %w", err)
	}
	if pageCount > s.admission.MaxDatabasePages {
		return fmt.Errorf("%w: existing database uses %d pages, configured maximum is %d",
			ErrInvalid, pageCount, s.admission.MaxDatabasePages)
	}
	var applied int64
	statement := fmt.Sprintf("PRAGMA max_page_count = %d", s.admission.MaxDatabasePages)
	if err := s.db.QueryRowContext(ctx, statement).Scan(&applied); err != nil {
		return fmt.Errorf("set SQLite maximum page count: %w", err)
	}
	if applied != s.admission.MaxDatabasePages {
		return fmt.Errorf("SQLite refused maximum page count: got %d, want %d", applied, s.admission.MaxDatabasePages)
	}
	return nil
}

func prepareDatabaseFile(path string) error {
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: database path must name a regular non-symlink file", ErrInvalid)
		}
		if info.Mode().Perm() != 0o600 {
			return fmt.Errorf("%w: existing database file must have mode 0600", ErrInvalid)
		}
		if !hasSingleHardLink(info) {
			return fmt.Errorf("%w: existing database file must have exactly one hard link", ErrInvalid)
		}
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("inspect database path: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create database file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close new database file: %w", err)
	}
	info, err = os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect new database path: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: new database file is not a regular 0600 file", ErrInvalid)
	}
	if !hasSingleHardLink(info) {
		return fmt.Errorf("%w: new database file must have exactly one hard link", ErrInvalid)
	}
	return nil
}

func requireSQLiteVersion(ctx context.Context, db *sql.DB) error {
	var version string
	if err := db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&version); err != nil {
		return fmt.Errorf("query SQLite version: %w", err)
	}
	got, err := parseVersion(version)
	if err != nil {
		return fmt.Errorf("parse SQLite version %q: %w", version, err)
	}
	minimum, _ := parseVersion(minimumSQLiteVersion)
	for index := range minimum {
		if got[index] > minimum[index] {
			return nil
		}
		if got[index] < minimum[index] {
			return fmt.Errorf("SQLite %s is too old; need at least %s", version, minimumSQLiteVersion)
		}
	}
	return nil
}

func parseVersion(value string) ([3]int, error) {
	var result [3]int
	parts := strings.Split(value, ".")
	if len(parts) < len(result) {
		return result, errors.New("expected major.minor.patch")
	}
	for index := range result {
		part := parts[index]
		if index == 2 {
			part, _, _ = strings.Cut(part, "-")
		}
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return result, errors.New("invalid numeric version component")
		}
		result[index] = number
	}
	return result, nil
}

func configureSQLite(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("enable SQLite foreign keys: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err != nil {
		return fmt.Errorf("set SQLite busy timeout: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA synchronous = FULL"); err != nil {
		return fmt.Errorf("enable SQLite full synchronization: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA trusted_schema = OFF"); err != nil {
		return fmt.Errorf("disable SQLite trusted schema: %w", err)
	}
	var journalMode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode = DELETE").Scan(&journalMode); err != nil {
		return fmt.Errorf("select SQLite rollback journal: %w", err)
	}
	if !strings.EqualFold(journalMode, "delete") {
		return fmt.Errorf("SQLite refused rollback journal mode: got %q", journalMode)
	}
	var foreignKeys int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return fmt.Errorf("verify SQLite foreign keys: %w", err)
	}
	if foreignKeys != 1 {
		return errors.New("SQLite foreign key enforcement is disabled")
	}
	var synchronous int
	if err := db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		return fmt.Errorf("verify SQLite synchronization: %w", err)
	}
	if synchronous != 2 {
		return fmt.Errorf("SQLite refused synchronous FULL: got %d", synchronous)
	}
	var trustedSchema int
	if err := db.QueryRowContext(ctx, "PRAGMA trusted_schema").Scan(&trustedSchema); err != nil {
		return fmt.Errorf("verify SQLite trusted schema: %w", err)
	}
	if trustedSchema != 0 {
		return errors.New("SQLite trusted schema remains enabled")
	}
	return nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) nowMillis() (int64, error) {
	now := s.clock()
	if now.IsZero() {
		return 0, fmt.Errorf("%w: clock returned zero time", ErrInvalid)
	}
	millis := now.UTC().UnixMilli()
	if millis <= 0 {
		return 0, fmt.Errorf("%w: clock must be after Unix epoch", ErrInvalid)
	}
	return millis, nil
}

func timeFromMillis(value int64) time.Time {
	return time.UnixMilli(value).UTC()
}
