package sandboxstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	CurrentSchemaVersion               = 7
	minimumCreateIntentEvidenceVersion = 3
	exactSessionScopeVersion           = 5
	runnerStateOwnershipVersion        = 6
	sessionLifecycleVersion            = 7
)

var migrations = []string{
	`CREATE TABLE target_revisions (
    target_id TEXT NOT NULL,
    revision TEXT NOT NULL,
    semantic_fingerprint TEXT NOT NULL,
    registered_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (target_id, revision),
    CHECK (length(target_id) BETWEEN 1 AND 128),
    CHECK (length(revision) BETWEEN 1 AND 160),
    CHECK (length(semantic_fingerprint) = 64)
) STRICT;

CREATE TABLE sessions (
    session_ref TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    target_revision TEXT NOT NULL,
    vendor_token TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    CHECK (length(session_ref) BETWEEN 1 AND 512),
    CHECK (length(CAST(vendor_token AS BLOB)) BETWEEN 1 AND 1024),
    FOREIGN KEY (target_id, target_revision)
        REFERENCES target_revisions(target_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    request_fingerprint TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_revision TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    writable INTEGER NOT NULL CHECK (writable IN (0, 1)),
    input_sha256 TEXT NOT NULL,
    requested_session_ref TEXT,
    deadline_unix_ms INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('accepted','running','cancelling','completed','failed','cancelled','interrupted')),
    last_event_seq INTEGER NOT NULL DEFAULT 0 CHECK (last_event_seq BETWEEN 0 AND 512),
    runtime_ref TEXT,
    output_media_type TEXT,
    output_text TEXT,
    result_session_ref TEXT,
    failure_code TEXT,
    failure_message TEXT,
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    terminal_at_unix_ms INTEGER,
    CHECK (length(request_fingerprint) = 64),
    CHECK (length(input_sha256) = 64),
    CHECK (length(workspace_id) BETWEEN 1 AND 128),
    CHECK (runtime_ref IS NULL OR length(runtime_ref) BETWEEN 1 AND 256),
    CHECK (output_text IS NULL OR length(CAST(output_text AS BLOB)) <= 32768),
    CHECK (failure_message IS NULL OR length(CAST(failure_message AS BLOB)) <= 4096),
    CHECK (result_session_ref IS NULL OR length(result_session_ref) BETWEEN 1 AND 512),
    CHECK ((state IN ('completed','failed','cancelled','interrupted')) = (terminal_at_unix_ms IS NOT NULL)),
    FOREIGN KEY (target_id, target_revision)
        REFERENCES target_revisions(target_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (requested_session_ref) REFERENCES sessions(session_ref) ON DELETE RESTRICT,
    FOREIGN KEY (result_session_ref) REFERENCES sessions(session_ref) ON DELETE RESTRICT
) STRICT;

CREATE TABLE workspace_locks (
    workspace_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE REFERENCES runs(run_id) ON DELETE RESTRICT,
    acquired_at_unix_ms INTEGER NOT NULL,
    CHECK (length(workspace_id) BETWEEN 1 AND 128)
) STRICT;

CREATE TABLE run_events (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
    seq INTEGER NOT NULL CHECK (seq BETWEEN 1 AND 512),
    event_type TEXT NOT NULL CHECK (event_type IN ('started','progress','completed','failed','cancelled','interrupted')),
    progress_kind TEXT,
    message_text TEXT,
    output_media_type TEXT,
    result_session_ref TEXT REFERENCES sessions(session_ref) ON DELETE RESTRICT,
    failure_code TEXT,
    created_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (run_id, seq),
    CHECK (message_text IS NULL OR length(CAST(message_text AS BLOB)) <= 32768),
    CHECK (
        (event_type IN ('started','cancelled') AND progress_kind IS NULL AND message_text IS NULL AND output_media_type IS NULL AND result_session_ref IS NULL AND failure_code IS NULL)
        OR (event_type = 'progress' AND progress_kind IN ('status','output_delta') AND message_text IS NOT NULL AND output_media_type IS NULL AND result_session_ref IS NULL AND failure_code IS NULL)
        OR (event_type = 'completed' AND progress_kind IS NULL AND message_text IS NOT NULL AND output_media_type = 'text/plain' AND failure_code IS NULL)
        OR (event_type IN ('failed','interrupted') AND progress_kind IS NULL AND message_text IS NOT NULL AND output_media_type IS NULL AND result_session_ref IS NULL AND failure_code IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX runs_runtime_ref_unique
    ON runs(runtime_ref) WHERE runtime_ref IS NOT NULL;
CREATE INDEX runs_state_index ON runs(state, created_at_unix_ms);
CREATE INDEX sessions_scope_index ON sessions(target_id, target_revision);
CREATE INDEX run_events_run_index ON run_events(run_id, seq);

CREATE TRIGGER runs_state_transition_guard
BEFORE UPDATE OF state ON runs
WHEN NOT (
    OLD.state = NEW.state
    OR (OLD.state = 'accepted' AND NEW.state IN ('running','cancelling','failed','cancelled','interrupted'))
    OR (OLD.state = 'running' AND NEW.state IN ('cancelling','completed','failed','cancelled','interrupted'))
    OR (OLD.state = 'cancelling' AND NEW.state IN ('completed','failed','cancelled','interrupted'))
)
BEGIN
    SELECT RAISE(ABORT, 'illegal run state transition');
END;

CREATE TRIGGER run_event_sequence_guard
BEFORE INSERT ON run_events
WHEN NEW.seq != (SELECT last_event_seq + 1 FROM runs WHERE run_id = NEW.run_id)
BEGIN
    SELECT RAISE(ABORT, 'run event sequence must be contiguous');
END;

CREATE TRIGGER workspace_lock_release_guard
BEFORE DELETE ON workspace_locks
WHEN (SELECT state FROM runs WHERE run_id = OLD.run_id)
    NOT IN ('completed','failed','cancelled','interrupted')
BEGIN
    SELECT RAISE(ABORT, 'workspace lock release requires terminal run');
END;`,
	`ALTER TABLE runs ADD COLUMN runtime_intent_pending INTEGER NOT NULL DEFAULT 0
    CHECK (runtime_intent_pending IN (0, 1));

CREATE INDEX runs_runtime_intent_index
    ON runs(runtime_intent_pending, state, created_at_unix_ms);

CREATE TRIGGER runs_runtime_intent_insert_guard
BEFORE INSERT ON runs
WHEN NEW.runtime_intent_pending = 1 AND NEW.runtime_ref IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'runtime intent and runtime reference are mutually exclusive');
END;

CREATE TRIGGER runs_runtime_intent_update_guard
BEFORE UPDATE OF runtime_intent_pending, runtime_ref ON runs
WHEN
    (NEW.runtime_intent_pending = 1 AND NEW.runtime_ref IS NOT NULL)
    OR (
        OLD.runtime_intent_pending = 0
        AND NEW.runtime_intent_pending = 1
        AND (OLD.runtime_ref IS NOT NULL OR OLD.state != 'accepted')
    )
    OR (
        OLD.runtime_ref IS NULL
        AND NEW.runtime_ref IS NOT NULL
        AND NOT (OLD.runtime_intent_pending = 1 AND NEW.runtime_intent_pending = 0)
    )
    OR (
        OLD.runtime_ref IS NOT NULL
        AND NEW.runtime_ref IS NOT NULL
        AND OLD.runtime_ref != NEW.runtime_ref
    )
BEGIN
    SELECT RAISE(ABORT, 'illegal runtime intent transition');
END;`,
	`ALTER TABLE runs ADD COLUMN runtime_intent_boot_id TEXT
    CHECK (
        runtime_intent_boot_id IS NULL
        OR (
            length(runtime_intent_boot_id) = 36
            AND substr(runtime_intent_boot_id, 9, 1) = '-'
            AND substr(runtime_intent_boot_id, 14, 1) = '-'
            AND substr(runtime_intent_boot_id, 19, 1) = '-'
            AND substr(runtime_intent_boot_id, 24, 1) = '-'
            AND length(replace(runtime_intent_boot_id, '-', '')) = 32
            AND replace(runtime_intent_boot_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    );

CREATE TRIGGER runs_runtime_intent_boot_insert_guard
BEFORE INSERT ON runs
WHEN
    (NEW.runtime_intent_pending = 0 AND NEW.runtime_intent_boot_id IS NOT NULL)
    OR (NEW.runtime_intent_pending = 1 AND NEW.runtime_intent_boot_id IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'runtime intent boot identifier does not match intent');
END;

CREATE TRIGGER runs_runtime_intent_boot_update_guard
BEFORE UPDATE OF runtime_intent_pending, runtime_intent_boot_id, runtime_ref ON runs
WHEN
    (NEW.runtime_intent_pending = 0 AND NEW.runtime_intent_boot_id IS NOT NULL)
    OR (
        OLD.runtime_intent_pending = 0
        AND NEW.runtime_intent_pending = 1
        AND NEW.runtime_intent_boot_id IS NULL
    )
    OR (
        OLD.runtime_intent_pending = 1
        AND NEW.runtime_intent_pending = 1
        AND NEW.runtime_intent_boot_id IS NOT OLD.runtime_intent_boot_id
    )
BEGIN
    SELECT RAISE(ABORT, 'illegal runtime intent boot transition');
END;`,
	`CREATE TRIGGER runs_pending_intent_terminal_insert_guard
BEFORE INSERT ON runs
WHEN NEW.runtime_intent_pending = 1
    AND NEW.state IN ('completed','failed','cancelled')
BEGIN
    SELECT RAISE(ABORT, 'pending runtime intent permits only interrupted terminal state');
END;

CREATE TRIGGER runs_pending_intent_terminal_update_guard
BEFORE UPDATE OF state, runtime_intent_pending ON runs
WHEN NEW.runtime_intent_pending = 1
    AND NEW.state IN ('completed','failed','cancelled')
BEGIN
    SELECT RAISE(ABORT, 'pending runtime intent permits only interrupted terminal state');
END;

CREATE TRIGGER run_events_pending_intent_terminal_guard
BEFORE INSERT ON run_events
WHEN NEW.event_type IN ('completed','failed','cancelled')
    AND (SELECT runtime_intent_pending FROM runs WHERE run_id = NEW.run_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'pending runtime intent permits only interrupted terminal event');
END;

CREATE TRIGGER run_events_immutable_update_guard
BEFORE UPDATE ON run_events
BEGIN
    SELECT RAISE(ABORT, 'run events are immutable');
END;

CREATE TRIGGER run_events_immutable_delete_guard
BEFORE DELETE ON run_events
BEGIN
    SELECT RAISE(ABORT, 'run events are immutable');
END;`,
	`ALTER TABLE runs ADD COLUMN session_scope_digest TEXT
    CHECK (
        session_scope_digest IS NULL
        OR (
            length(session_scope_digest) = 64
            AND session_scope_digest NOT GLOB '*[^0-9a-f]*'
        )
    );

DROP INDEX sessions_scope_index;
DROP TABLE sessions;

CREATE TABLE sessions (
    session_ref TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    target_revision TEXT NOT NULL,
    session_scope_digest TEXT NOT NULL CHECK (
        length(session_scope_digest) = 64
        AND session_scope_digest NOT GLOB '*[^0-9a-f]*'
    ),
    vendor_token TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    CHECK (length(session_ref) BETWEEN 1 AND 512),
    CHECK (length(CAST(vendor_token AS BLOB)) BETWEEN 1 AND 1024),
    FOREIGN KEY (target_id, target_revision)
        REFERENCES target_revisions(target_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE INDEX sessions_scope_index
    ON sessions(target_id, target_revision, session_scope_digest);

CREATE TRIGGER runs_require_session_scope_insert
BEFORE INSERT ON runs
WHEN NEW.session_scope_digest IS NULL
BEGIN
    SELECT RAISE(ABORT, 'new Run requires a session scope digest');
END;

CREATE TRIGGER runs_session_authority_immutable
BEFORE UPDATE OF request_fingerprint, target_id, target_revision,
                 requested_session_ref, session_scope_digest ON runs
WHEN NEW.request_fingerprint IS NOT OLD.request_fingerprint
  OR NEW.target_id IS NOT OLD.target_id
  OR NEW.target_revision IS NOT OLD.target_revision
  OR NEW.requested_session_ref IS NOT OLD.requested_session_ref
  OR NEW.session_scope_digest IS NOT OLD.session_scope_digest
BEGIN
    SELECT RAISE(ABORT, 'Run session authority is immutable');
END;

CREATE TRIGGER sessions_authority_immutable
BEFORE UPDATE OF session_ref, target_id, target_revision,
                 session_scope_digest, vendor_token ON sessions
WHEN NEW.session_ref IS NOT OLD.session_ref
  OR NEW.target_id IS NOT OLD.target_id
  OR NEW.target_revision IS NOT OLD.target_revision
  OR NEW.session_scope_digest IS NOT OLD.session_scope_digest
  OR NEW.vendor_token IS NOT OLD.vendor_token
BEGIN
    SELECT RAISE(ABORT, 'session authority is immutable');
END;

CREATE TRIGGER sessions_delete_forbidden
BEFORE DELETE ON sessions
BEGIN
    SELECT RAISE(ABORT, 'session deletion requires a future reviewed lifecycle');
END;`,
	`CREATE TABLE runner_state_owners (
    runner_state_path_digest TEXT PRIMARY KEY,
    runner_state_ref TEXT NOT NULL UNIQUE,
    target_id TEXT NOT NULL,
    target_revision TEXT NOT NULL,
    registered_at_unix_ms INTEGER NOT NULL,
    UNIQUE (target_id, target_revision),
    CHECK (
        length(runner_state_path_digest) = 64
        AND runner_state_path_digest NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (
        length(runner_state_ref) BETWEEN 1 AND 128
        AND runner_state_ref NOT IN ('.', '..')
        AND runner_state_ref NOT GLOB '*[^a-z0-9._-]*'
    ),
    FOREIGN KEY (target_id, target_revision)
        REFERENCES target_revisions(target_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER runner_state_owners_immutable_update
BEFORE UPDATE ON runner_state_owners
BEGIN
    SELECT RAISE(ABORT, 'runner-state ownership is immutable');
END;

CREATE TRIGGER runner_state_owners_immutable_delete
BEFORE DELETE ON runner_state_owners
BEGIN
    SELECT RAISE(ABORT, 'runner-state ownership is permanent');
END;

CREATE TRIGGER target_revisions_immutable_update
BEFORE UPDATE ON target_revisions
BEGIN
    SELECT RAISE(ABORT, 'target revision registration is immutable');
END;`,
	`ALTER TABLE runs ADD COLUMN session_mode TEXT
    CHECK (session_mode IS NULL OR session_mode IN ('new_only', 'opaque_resume'));

ALTER TABLE runs ADD COLUMN session_max_age_seconds INTEGER
    CHECK (session_max_age_seconds IS NULL
        OR session_max_age_seconds BETWEEN 0 AND 2592000);

ALTER TABLE runs ADD COLUMN session_max_turns INTEGER
    CHECK (session_max_turns IS NULL
        OR session_max_turns BETWEEN 0 AND 1024);

ALTER TABLE runs ADD COLUMN session_turn_number INTEGER
    CHECK (session_turn_number IS NULL OR session_turn_number >= 0);

DROP INDEX sessions_scope_index;
DROP TABLE sessions;

CREATE TABLE sessions (
    session_ref TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    target_revision TEXT NOT NULL,
    session_scope_digest TEXT NOT NULL CHECK (
        length(session_scope_digest) = 64
        AND session_scope_digest NOT GLOB '*[^0-9a-f]*'
    ),
    vendor_token TEXT NOT NULL,
    parent_session_ref TEXT UNIQUE REFERENCES sessions(session_ref) ON DELETE RESTRICT,
    created_by_run_id TEXT NOT NULL UNIQUE REFERENCES runs(run_id) ON DELETE RESTRICT,
    lineage_started_at_unix_ms INTEGER NOT NULL CHECK (lineage_started_at_unix_ms > 0),
    expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms > lineage_started_at_unix_ms),
    turn_number INTEGER NOT NULL CHECK (turn_number >= 1),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= lineage_started_at_unix_ms),
    CHECK (length(session_ref) BETWEEN 1 AND 512),
    CHECK (length(CAST(vendor_token AS BLOB)) BETWEEN 1 AND 1024),
    FOREIGN KEY (target_id, target_revision)
        REFERENCES target_revisions(target_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE INDEX sessions_scope_index
    ON sessions(target_id, target_revision, session_scope_digest);

CREATE TABLE session_uses (
    session_ref TEXT PRIMARY KEY REFERENCES sessions(session_ref) ON DELETE RESTRICT,
    run_id TEXT NOT NULL UNIQUE REFERENCES runs(run_id) ON DELETE RESTRICT,
    used_at_unix_ms INTEGER NOT NULL CHECK (used_at_unix_ms > 0)
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX runs_one_nonterminal_per_session_scope
    ON runs(target_id, target_revision, session_scope_digest)
    WHERE state IN ('accepted', 'running', 'cancelling');

CREATE TRIGGER runs_require_session_lifecycle_insert
BEFORE INSERT ON runs
WHEN NEW.session_mode IS NULL
  OR NEW.session_max_age_seconds IS NULL
  OR NEW.session_max_turns IS NULL
  OR NEW.session_turn_number IS NULL
  OR NOT (
      (NEW.session_mode = 'new_only'
       AND NEW.session_max_age_seconds = 0
       AND NEW.session_max_turns = 0
       AND NEW.session_turn_number = 0
       AND NEW.requested_session_ref IS NULL)
      OR
      (NEW.session_mode = 'opaque_resume'
       AND NEW.session_max_age_seconds BETWEEN 1 AND 2592000
       AND NEW.session_max_turns BETWEEN 1 AND 1024
       AND NEW.session_turn_number BETWEEN 1 AND NEW.session_max_turns)
  )
BEGIN
    SELECT RAISE(ABORT, 'new Run requires valid session lifecycle authority');
END;

CREATE TRIGGER runs_session_lifecycle_immutable
BEFORE UPDATE OF session_mode, session_max_age_seconds,
                 session_max_turns, session_turn_number ON runs
WHEN NEW.session_mode IS NOT OLD.session_mode
  OR NEW.session_max_age_seconds IS NOT OLD.session_max_age_seconds
  OR NEW.session_max_turns IS NOT OLD.session_max_turns
  OR NEW.session_turn_number IS NOT OLD.session_turn_number
BEGIN
    SELECT RAISE(ABORT, 'Run session lifecycle authority is immutable');
END;

CREATE TRIGGER sessions_authority_immutable
BEFORE UPDATE ON sessions
BEGIN
    SELECT RAISE(ABORT, 'session authority is immutable');
END;

CREATE TRIGGER sessions_delete_forbidden
BEFORE DELETE ON sessions
BEGIN
    SELECT RAISE(ABORT, 'session deletion is forbidden');
END;

CREATE TRIGGER session_uses_authority_insert
BEFORE INSERT ON session_uses
WHEN NOT EXISTS (
    SELECT 1
    FROM runs AS r
    JOIN sessions AS s ON s.session_ref = NEW.session_ref
    WHERE r.run_id = NEW.run_id
      AND r.session_mode = 'opaque_resume'
      AND r.state = 'accepted'
      AND r.requested_session_ref = NEW.session_ref
      AND r.target_id = s.target_id
      AND r.target_revision = s.target_revision
      AND r.session_scope_digest = s.session_scope_digest
      AND r.session_turn_number = s.turn_number + 1
      AND NEW.used_at_unix_ms >= r.created_at_unix_ms
      AND NEW.used_at_unix_ms >= s.created_at_unix_ms
      AND NEW.used_at_unix_ms < s.expires_at_unix_ms
)
BEGIN
    SELECT RAISE(ABORT, 'session use does not match Run authority');
END;

CREATE TRIGGER session_uses_immutable_update
BEFORE UPDATE ON session_uses
BEGIN
    SELECT RAISE(ABORT, 'session use is immutable');
END;

CREATE TRIGGER session_uses_delete_forbidden
BEFORE DELETE ON session_uses
BEGIN
    SELECT RAISE(ABORT, 'session use deletion is forbidden');
END;

CREATE TRIGGER sessions_lineage_insert_guard
BEFORE INSERT ON sessions
WHEN NOT EXISTS (
    SELECT 1
    FROM runs AS r
    WHERE r.run_id = NEW.created_by_run_id
      AND r.session_mode = 'opaque_resume'
      AND r.state IN ('running', 'cancelling')
      AND r.target_id = NEW.target_id
      AND r.target_revision = NEW.target_revision
      AND r.session_scope_digest = NEW.session_scope_digest
      AND NEW.created_at_unix_ms >= r.created_at_unix_ms
      AND EXISTS (
          SELECT 1 FROM run_events AS started
          WHERE started.run_id = r.run_id
            AND started.seq = 1
            AND started.event_type = 'started'
      )
      AND (
          (r.requested_session_ref IS NULL
           AND NEW.parent_session_ref IS NULL
           AND NEW.turn_number = 1
           AND NEW.lineage_started_at_unix_ms = r.created_at_unix_ms
           AND NEW.expires_at_unix_ms =
               r.created_at_unix_ms + (r.session_max_age_seconds * 1000))
          OR
          (r.requested_session_ref = NEW.parent_session_ref
           AND EXISTS (
               SELECT 1
               FROM sessions AS parent
               JOIN session_uses AS used
                 ON used.session_ref = parent.session_ref
                AND used.run_id = r.run_id
               WHERE parent.session_ref = NEW.parent_session_ref
                 AND parent.target_id = NEW.target_id
                 AND parent.target_revision = NEW.target_revision
                 AND parent.session_scope_digest = NEW.session_scope_digest
                 AND NEW.lineage_started_at_unix_ms = parent.lineage_started_at_unix_ms
                 AND NEW.expires_at_unix_ms = parent.expires_at_unix_ms
                 AND NEW.turn_number = parent.turn_number + 1
           ))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'session lineage does not match Run authority');
END;

CREATE TRIGGER run_events_session_completion_guard
BEFORE INSERT ON run_events
WHEN NEW.event_type = 'completed'
  AND NOT EXISTS (
      SELECT 1 FROM runs AS r
      WHERE r.run_id = NEW.run_id
        AND (
            (r.session_mode = 'new_only' AND NEW.result_session_ref IS NULL)
            OR (r.session_mode = 'opaque_resume'
                AND NEW.result_session_ref IS NOT NULL
                AND EXISTS (
                    SELECT 1 FROM sessions AS successor
                    WHERE successor.session_ref = NEW.result_session_ref
                      AND successor.created_by_run_id = NEW.run_id
                      AND successor.target_id = r.target_id
                      AND successor.target_revision = r.target_revision
                      AND successor.session_scope_digest = r.session_scope_digest
                ))
        )
  )
BEGIN
    SELECT RAISE(ABORT, 'completed event does not match session lifecycle mode');
END;`,
}

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin sandbox migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        checksum TEXT NOT NULL,
        applied_at_unix_ms INTEGER NOT NULL,
        CHECK (length(checksum) = 64)
    ) STRICT`); err != nil {
		return fmt.Errorf("create sandbox migration table: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("read sandbox migrations: %w", err)
	}
	current := 0
	for rows.Next() {
		var version int
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan sandbox migration: %w", err)
		}
		if version != current+1 {
			_ = rows.Close()
			return fmt.Errorf("sandboxstore: migration sequence has gap before version %d", version)
		}
		if version > CurrentSchemaVersion {
			_ = rows.Close()
			return fmt.Errorf("sandboxstore: database schema %d is newer than supported %d", version, CurrentSchemaVersion)
		}
		if checksum != migrationChecksum(migrations[version-1]) {
			_ = rows.Close()
			return fmt.Errorf("sandboxstore: migration %d checksum mismatch", version)
		}
		current = version
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close sandbox migration rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate sandbox migrations: %w", err)
	}
	// Schemas before v3 did not persist the host epoch for a Create intent and
	// in some recovery paths could issue another deterministic Create. No row
	// shape can prove that every old daemon handler has stopped: this includes
	// rows with a ref, without a ref, and already-terminal historical rows.
	// Pretending to migrate a non-empty database would therefore manufacture a
	// safety fact. Empty development databases can upgrade automatically; any
	// database containing a Run requires a reviewed cold migration after the old
	// runtime authority has been shut down.
	if current > 0 && current < minimumCreateIntentEvidenceVersion {
		var legacyRuns int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs`).Scan(&legacyRuns); err != nil {
			return fmt.Errorf("inspect pre-v3 sandbox runs: %w", err)
		}
		if legacyRuns != 0 {
			return ErrColdMigrationRequired
		}
	}
	// v4 makes the pending-intent terminal invariant enforceable in SQLite.
	// Rows produced by older controller behavior cannot be silently relabeled:
	// their terminal classification is already externally visible evidence.
	if current == minimumCreateIntentEvidenceVersion && current < CurrentSchemaVersion {
		var unsafeRows int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs
            WHERE runtime_intent_pending = 1
              AND state IN ('completed','failed','cancelled')`).Scan(&unsafeRows); err != nil {
			return fmt.Errorf("inspect pre-v4 pending terminal runs: %w", err)
		}
		if unsafeRows != 0 {
			return ErrUnsafeIntentState
		}
	}
	// v5 cannot infer EBA scope for an existing vendor token or for any Run
	// which could still execute, reconcile, or refer to a legacy session. The
	// old execution fingerprint also lacks the required digest. Refuse before
	// DDL and require a quiescent, no-session cold boundary.
	if current > 0 && current < exactSessionScopeVersion {
		var sessions int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil {
			return fmt.Errorf("inspect legacy sandbox sessions: %w", err)
		}
		var runs int64
		runQuery := `SELECT COUNT(*) FROM runs`
		if current >= minimumCreateIntentEvidenceVersion {
			runQuery = `SELECT COUNT(*) FROM runs
                WHERE state NOT IN ('completed','failed','cancelled','interrupted')
                   OR requested_session_ref IS NOT NULL
                   OR result_session_ref IS NOT NULL
                   OR runtime_ref IS NOT NULL
                   OR runtime_intent_pending = 1
                   OR EXISTS(SELECT 1 FROM workspace_locks wl WHERE wl.run_id = runs.run_id)`
		}
		if err := tx.QueryRowContext(ctx, runQuery).Scan(&runs); err != nil {
			return fmt.Errorf("inspect legacy sandbox Run session state: %w", err)
		}
		var events int64
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM run_events WHERE result_session_ref IS NOT NULL`).Scan(&events); err != nil {
			return fmt.Errorf("inspect legacy sandbox event session state: %w", err)
		}
		if sessions != 0 || runs != 0 || events != 0 {
			return fmt.Errorf("%w: found %d session row(s), %d unsafe Run(s), and %d session event(s)",
				ErrUnsafeLegacySessionState, sessions, runs, events)
		}
	}
	// v6 assigns each resolved runner-state path permanently to one exact
	// TargetRevision. Earlier schemas retained only an aggregate revision pin;
	// they cannot reveal the path identity or prove that an absent owner row
	// represents a directory which never existed. Refuse before DDL rather than
	// adopting current configuration as fabricated historical evidence.
	if current > 0 && current < runnerStateOwnershipVersion {
		var revisions int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM target_revisions`).Scan(&revisions); err != nil {
			return fmt.Errorf("inspect legacy target revisions for runner-state ownership: %w", err)
		}
		if revisions != 0 {
			return ErrRunnerStateOwnershipUnknown
		}
	}
	// v7 defines every resumable reference as a one-use capability with an
	// absolute lineage expiry and a monotonically increasing turn number. An
	// older session row has none of that provenance, while an older nonterminal
	// Run has already been fingerprinted and admitted without a frozen Target
	// session policy. Refuse before DDL instead of guessing either authority.
	if current > 0 && current < sessionLifecycleVersion {
		var sessions int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil {
			return fmt.Errorf("inspect legacy session lifecycle rows: %w", err)
		}
		var runs int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs
            WHERE state NOT IN ('completed','failed','cancelled','interrupted')`).Scan(&runs); err != nil {
			return fmt.Errorf("inspect legacy live Runs for session lifecycle: %w", err)
		}
		if sessions != 0 || runs != 0 {
			return fmt.Errorf("%w: found %d session row(s) and %d nonterminal Run(s)",
				ErrUnsafeSessionLifecycleState, sessions, runs)
		}
	}

	for version := current + 1; version <= CurrentSchemaVersion; version++ {
		migration := migrations[version-1]
		if _, err := tx.ExecContext(ctx, migration); err != nil {
			return fmt.Errorf("apply sandbox migration %d: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, checksum, applied_at_unix_ms) VALUES (?, ?, ?)`,
			version, migrationChecksum(migration), time.Now().UTC().UnixMilli()); err != nil {
			return fmt.Errorf("record sandbox migration %d: %w", version, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sandbox migrations: %w", err)
	}
	return nil
}

func (s *Store) verifyIntegrity(ctx context.Context) error {
	var result string
	if err := s.db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&result); err != nil {
		return fmt.Errorf("check sandbox database integrity: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("sandboxstore: SQLite quick_check returned %q", result)
	}
	rows, err := s.db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("check sandbox foreign keys: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("sandboxstore: SQLite foreign_key_check found a violation")
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate sandbox foreign key check: %w", err)
	}
	return nil
}

func migrationChecksum(migration string) string {
	digest := sha256.Sum256([]byte(migration))
	return hex.EncodeToString(digest[:])
}
