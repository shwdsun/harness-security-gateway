package sandboxstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

const runSelectColumns = `
r.run_id,
	r.request_fingerprint,
	r.target_id,
	r.target_revision,
	r.workspace_id,
	r.writable,
	r.input_sha256,
	r.requested_session_ref,
	r.session_scope_digest,
	r.session_mode,
	r.session_max_age_seconds,
	r.session_max_turns,
	r.session_turn_number,
	r.deadline_unix_ms,
	r.state,
	r.last_event_seq,
	r.runtime_ref,
	r.runtime_intent_pending,
	r.runtime_intent_boot_id,
	r.output_media_type,
	r.output_text,
	r.result_session_ref,
	r.failure_code,
	r.failure_message,
	r.created_at_unix_ms,
	r.updated_at_unix_ms,
	r.terminal_at_unix_ms,
	EXISTS(SELECT 1 FROM workspace_locks wl WHERE wl.run_id = r.run_id)`

// RegisterStart durably registers a StartRun and, for writable targets,
// acquires the workspace writer lock in the same transaction. Read-only Runs
// do not serialize each other or a writer. The full input text is hashed and
// discarded.
// A repeated run_id with the same executionwire fingerprint returns the
// existing Run with created=false. A changed payload returns ErrConflict.
func (s *Store) RegisterStart(
	ctx context.Context,
	request executionwire.StartRunRequest,
	resolvedRevision string,
	workspaceID string,
	writable bool,
	sessionPolicy SessionPolicy,
) (run Run, created bool, err error) {
	return s.registerStartWithClock(
		ctx, request, resolvedRevision, workspaceID, writable, sessionPolicy,
		func() int64 { return time.Now().UTC().UnixMilli() },
	)
}

func (s *Store) registerStartAt(
	ctx context.Context,
	request executionwire.StartRunRequest,
	resolvedRevision string,
	workspaceID string,
	writable bool,
	sessionPolicy SessionPolicy,
	now int64,
) (run Run, created bool, err error) {
	return s.registerStartWithClock(
		ctx, request, resolvedRevision, workspaceID, writable, sessionPolicy,
		func() int64 { return now },
	)
}

// registerStartWithClock samples lifecycle time only after the StartRun
// transaction owns the Store's sole SQLite connection and after exact replay
// has been ruled out. A request waiting for that authority therefore cannot
// consume a ref using a pre-wait age or rollback observation.
func (s *Store) registerStartWithClock(
	ctx context.Context,
	request executionwire.StartRunRequest,
	resolvedRevision string,
	workspaceID string,
	writable bool,
	sessionPolicy SessionPolicy,
	nowMillis func() int64,
) (run Run, created bool, err error) {
	if err := s.ready(ctx); err != nil {
		return Run{}, false, err
	}
	if nowMillis == nil {
		return Run{}, false, fmt.Errorf("%w: nil session lifecycle clock", ErrInvalidArgument)
	}
	if err := request.Validate(); err != nil {
		return Run{}, false, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if err := validateLogicalID("resolved revision", resolvedRevision, executionwire.MaxRevisionBytes); err != nil {
		return Run{}, false, err
	}
	if request.ExpectedRevision != resolvedRevision {
		return Run{}, false, ErrRevisionMismatch
	}
	if err := validateLogicalID("workspace_id", workspaceID, MaxWorkspaceIDBytes); err != nil {
		return Run{}, false, err
	}
	if err := validateSessionPolicy(sessionPolicy); err != nil {
		return Run{}, false, err
	}
	if request.SessionRef != nil && sessionPolicy.Mode != targetmanifest.SessionOpaqueResume {
		return Run{}, false, ErrSessionScope
	}
	fingerprint, err := executionwire.StartRunFingerprint(request)
	if err != nil {
		return Run{}, false, fmt.Errorf("%w: fingerprint StartRun: %v", ErrInvalidArgument, err)
	}
	inputDigest := sha256.Sum256([]byte(request.Input.Text))

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return Run{}, false, fmt.Errorf("begin StartRun registration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	existing, getErr := getRunQuerier(ctx, tx, request.RunID)
	switch {
	case getErr == nil:
		if existing.Fingerprint != fingerprint {
			return Run{}, false, ErrConflict
		}
		if err := tx.Commit(); err != nil {
			return Run{}, false, fmt.Errorf("commit idempotent StartRun lookup: %w", err)
		}
		return existing, false, nil
	case !errors.Is(getErr, ErrNotFound):
		return Run{}, false, getErr
	}
	if err := requireTargetRevision(ctx, tx, request.TargetID, resolvedRevision); err != nil {
		return Run{}, false, err
	}
	now := nowMillis()
	if now <= 0 {
		return Run{}, false, fmt.Errorf("%w: session lifecycle clock must be after Unix epoch", ErrInvalidArgument)
	}

	turnNumber := int64(0)
	if sessionPolicy.Mode == targetmanifest.SessionOpaqueResume {
		turnNumber = 1
	}
	if request.SessionRef != nil {
		candidate, err := sessionForAdmission(ctx, tx, *request.SessionRef, request.TargetID,
			resolvedRevision, request.SessionScopeDigest)
		if err != nil {
			return Run{}, false, err
		}
		if now < candidate.CreatedAtUnixMS || now >= candidate.ExpiresAtUnixMS ||
			candidate.TurnNumber >= sessionPolicy.MaxTurns {
			return Run{}, false, ErrSessionScope
		}
		turnNumber = candidate.TurnNumber + 1
	}

	var active int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM runs
        WHERE target_id = ? AND target_revision = ? AND session_scope_digest = ?
          AND state IN ('accepted','running','cancelling') LIMIT 1`,
		request.TargetID, resolvedRevision, request.SessionScopeDigest).Scan(&active)
	switch {
	case err == nil:
		return Run{}, false, ErrSessionBusy
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return Run{}, false, fmt.Errorf("inspect active session-scope Run: %w", err)
	}

	insertResult, err := tx.ExecContext(ctx, `INSERT INTO runs(
	    run_id, request_fingerprint, target_id, target_revision, workspace_id, writable,
	    input_sha256, requested_session_ref, session_scope_digest,
	    session_mode, session_max_age_seconds, session_max_turns, session_turn_number,
	    deadline_unix_ms, state, last_event_seq, created_at_unix_ms, updated_at_unix_ms
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		request.RunID,
		fingerprint,
		request.TargetID,
		resolvedRevision,
		workspaceID,
		writable,
		hex.EncodeToString(inputDigest[:]),
		nullableString(request.SessionRef),
		request.SessionScopeDigest,
		sessionPolicy.Mode,
		sessionPolicy.MaxAgeSeconds,
		sessionPolicy.MaxTurns,
		turnNumber,
		request.Deadline.UTC().UnixMilli(),
		executionwire.RunStateAccepted,
		now,
		now,
	)
	if err != nil {
		return Run{}, false, fmt.Errorf("insert run: %w", err)
	}
	inserted, err := insertResult.RowsAffected()
	if err != nil {
		return Run{}, false, fmt.Errorf("inspect run insertion: %w", err)
	}
	if inserted != 1 {
		return Run{}, false, fmt.Errorf("insert run changed %d rows", inserted)
	}
	if writable {
		result, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO workspace_locks(workspace_id, run_id, acquired_at_unix_ms) VALUES (?, ?, ?)`,
			workspaceID, request.RunID, now)
		if err != nil {
			return Run{}, false, fmt.Errorf("acquire workspace writer lock: %w", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return Run{}, false, fmt.Errorf("inspect workspace lock result: %w", err)
		}
		if rows != 1 {
			return Run{}, false, ErrWorkspaceBusy
		}
	}
	if request.SessionRef != nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO session_uses(
            session_ref, run_id, used_at_unix_ms
        ) VALUES (?, ?, ?)`, *request.SessionRef, request.RunID, now); err != nil {
			var owner string
			lookupErr := tx.QueryRowContext(ctx,
				`SELECT run_id FROM session_uses WHERE session_ref = ?`, *request.SessionRef,
			).Scan(&owner)
			if lookupErr == nil {
				return Run{}, false, ErrSessionScope
			}
			if !errors.Is(lookupErr, sql.ErrNoRows) {
				return Run{}, false, fmt.Errorf("inspect failed session use: %w", lookupErr)
			}
			return Run{}, false, fmt.Errorf("consume sandbox session: %w", err)
		}
	}

	run, err = getRunQuerier(ctx, tx, request.RunID)
	if err != nil {
		return Run{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Run{}, false, fmt.Errorf("commit StartRun registration: %w", err)
	}
	return run, true, nil
}

func (s *Store) GetRun(ctx context.Context, runID string) (Run, error) {
	if err := s.ready(ctx); err != nil {
		return Run{}, err
	}
	if err := validateRunID(runID); err != nil {
		return Run{}, err
	}
	return getRunQuerier(ctx, s.db, runID)
}

// BeginRuntimeIntent durably records permission to invoke exactly the
// deterministic Create operation for this Run. It must commit before the
// Docker CLI is invoked. The boot ID freezes the host epoch in which that
// authority was granted. Repeating the same intent in the same boot is
// idempotent; a different or legacy unknown boot never grants new authority.
// A terminal Run or one that already owns a runtime reference cannot begin
// another Create intent.
func (s *Store) BeginRuntimeIntent(ctx context.Context, runID, bootID string) (run Run, created bool, err error) {
	if err := s.ready(ctx); err != nil {
		return Run{}, false, err
	}
	if err := validateRunID(runID); err != nil {
		return Run{}, false, err
	}
	if err := validateBootID(bootID); err != nil {
		return Run{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return Run{}, false, fmt.Errorf("begin runtime intent: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx, `UPDATE runs SET
        runtime_intent_pending = 1, runtime_intent_boot_id = ?, updated_at_unix_ms = ?
    WHERE run_id = ?
      AND runtime_intent_pending = 0
      AND runtime_ref IS NULL
      AND state = 'accepted'`,
		bootID, time.Now().UTC().UnixMilli(), runID)
	if err != nil {
		return Run{}, false, fmt.Errorf("record runtime intent: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Run{}, false, fmt.Errorf("inspect runtime intent update: %w", err)
	}
	run, err = getRunQuerier(ctx, tx, runID)
	if err != nil {
		return Run{}, false, err
	}
	switch {
	case rows == 1:
		created = true
	case rows != 0:
		return Run{}, false, errors.New("sandboxstore: runtime intent update affected multiple rows")
	case isTerminal(run.State), run.RuntimeRef != nil:
		return Run{}, false, ErrIllegalTransition
	case run.RuntimeIntentPending && run.RuntimeIntentBootID != nil && *run.RuntimeIntentBootID == bootID:
		// Idempotent replay of the same immutable Run intent in the same
		// host epoch.
	case run.RuntimeIntentPending:
		return Run{}, false, ErrConflict
	case run.State != executionwire.RunStateAccepted:
		return Run{}, false, ErrIllegalTransition
	default:
		return Run{}, false, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return Run{}, false, fmt.Errorf("commit runtime intent: %w", err)
	}
	return run, created, nil
}

// ClearRuntimeIntent is the explicit proof boundary for an unbound Create
// intent. Callers may use it only when local preflight proves Create was never
// invoked, after an exact matching runtime was removed, or when a changed host
// boot proves an earlier Create handler cannot still complete. It works in any
// Run state, is idempotent, and refuses to discard an intent once a runtime
// reference exists.
func (s *Store) ClearRuntimeIntent(ctx context.Context, runID string) (Run, error) {
	if err := s.ready(ctx); err != nil {
		return Run{}, err
	}
	if err := validateRunID(runID); err != nil {
		return Run{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return Run{}, fmt.Errorf("begin runtime intent clear: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx, `UPDATE runs SET
        runtime_intent_pending = 0, runtime_intent_boot_id = NULL, updated_at_unix_ms = ?
    WHERE run_id = ?
      AND runtime_intent_pending = 1
	  AND runtime_ref IS NULL`,
		time.Now().UTC().UnixMilli(), runID)
	if err != nil {
		return Run{}, fmt.Errorf("clear runtime intent: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Run{}, fmt.Errorf("inspect runtime intent clear: %w", err)
	}
	run, err := getRunQuerier(ctx, tx, runID)
	if err != nil {
		return Run{}, err
	}
	if rows > 1 {
		return Run{}, errors.New("sandboxstore: runtime intent clear affected multiple rows")
	}
	if rows == 0 && run.RuntimeRef != nil {
		return Run{}, ErrIllegalTransition
	}
	if run.RuntimeIntentPending {
		return Run{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return Run{}, fmt.Errorf("commit runtime intent clear: %w", err)
	}
	return run, nil
}

// SetRuntimeRef records an opaque runtime/container reference. Repeating the
// same value is idempotent; replacing it or setting one on a terminal run is
// rejected. A first binding requires a previously committed Create intent and
// clears that intent atomically with the reference assignment.
func (s *Store) SetRuntimeRef(ctx context.Context, runID, runtimeRef string) (Run, error) {
	if err := s.ready(ctx); err != nil {
		return Run{}, err
	}
	if err := validateRunID(runID); err != nil {
		return Run{}, err
	}
	if err := validateRuntimeRef(runtimeRef); err != nil {
		return Run{}, err
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return Run{}, fmt.Errorf("begin runtime reference update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE OR IGNORE runs SET
        runtime_ref = ?, runtime_intent_pending = 0,
		runtime_intent_boot_id = NULL, updated_at_unix_ms = ?
    WHERE run_id = ?
      AND state IN ('accepted','running','cancelling')
      AND (
          (runtime_ref IS NULL AND runtime_intent_pending = 1)
          OR (runtime_ref = ? AND runtime_intent_pending = 0)
      )`, runtimeRef, time.Now().UTC().UnixMilli(), runID, runtimeRef)
	if err != nil {
		return Run{}, fmt.Errorf("record runtime reference: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Run{}, fmt.Errorf("inspect runtime reference update: %w", err)
	}
	run, err := getRunQuerier(ctx, tx, runID)
	if err != nil {
		return Run{}, err
	}
	if rows > 1 {
		return Run{}, errors.New("sandboxstore: runtime reference update affected multiple rows")
	}
	if rows == 0 {
		switch {
		case isTerminal(run.State):
			return Run{}, ErrIllegalTransition
		case run.RuntimeRef != nil && *run.RuntimeRef != runtimeRef:
			return Run{}, ErrConflict
		}
		var owner string
		ownerErr := tx.QueryRowContext(ctx,
			`SELECT run_id FROM runs WHERE runtime_ref = ?`, runtimeRef).Scan(&owner)
		if ownerErr == nil && owner != runID {
			return Run{}, ErrConflict
		}
		if ownerErr != nil && !errors.Is(ownerErr, sql.ErrNoRows) {
			return Run{}, fmt.Errorf("check runtime reference ownership: %w", ownerErr)
		}
		return Run{}, ErrIllegalTransition
	}
	if err := tx.Commit(); err != nil {
		return Run{}, fmt.Errorf("commit runtime reference: %w", err)
	}
	return run, nil
}

// MarkCancelling records a cancellation request without inventing a runner
// event. An accepted or running Run can enter cancelling; repeated calls are
// idempotent.
func (s *Store) MarkCancelling(ctx context.Context, runID string) (Run, error) {
	if err := s.ready(ctx); err != nil {
		return Run{}, err
	}
	if err := validateRunID(runID); err != nil {
		return Run{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return Run{}, fmt.Errorf("begin cancellation update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	run, err := getRunQuerier(ctx, tx, runID)
	if err != nil {
		return Run{}, err
	}
	switch run.State {
	case executionwire.RunStateCancelling:
	case executionwire.RunStateAccepted, executionwire.RunStateRunning:
		if _, err := tx.ExecContext(ctx,
			`UPDATE runs SET state = ?, updated_at_unix_ms = ? WHERE run_id = ?`,
			executionwire.RunStateCancelling, time.Now().UTC().UnixMilli(), runID); err != nil {
			return Run{}, fmt.Errorf("mark run cancelling: %w", err)
		}
	default:
		return Run{}, ErrIllegalTransition
	}
	run, err = getRunQuerier(ctx, tx, runID)
	if err != nil {
		return Run{}, err
	}
	if err := tx.Commit(); err != nil {
		return Run{}, fmt.Errorf("commit cancellation update: %w", err)
	}
	return run, nil
}

// ConfirmRuntimeStopped releases a workspace writer lock only after the Run
// already has a terminal state and no Create intent remains pending. It is
// idempotent. A pending intent must first cross ClearRuntimeIntent after exact
// runtime cleanup or changed-boot absence; same-boot absence is insufficient.
func (s *Store) ConfirmRuntimeStopped(ctx context.Context, runID string) (Run, error) {
	if err := s.ready(ctx); err != nil {
		return Run{}, err
	}
	if err := validateRunID(runID); err != nil {
		return Run{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return Run{}, fmt.Errorf("begin runtime stop confirmation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	run, err := getRunQuerier(ctx, tx, runID)
	if err != nil {
		return Run{}, err
	}
	if !isTerminal(run.State) {
		return Run{}, ErrIllegalTransition
	}
	if run.RuntimeIntentPending {
		return Run{}, ErrIllegalTransition
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE runs SET runtime_ref = NULL, updated_at_unix_ms = ? WHERE run_id = ?`,
		time.Now().UTC().UnixMilli(), runID); err != nil {
		return Run{}, fmt.Errorf("clear runtime reference: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM workspace_locks WHERE run_id = ?`, runID); err != nil {
		return Run{}, fmt.Errorf("release workspace lock: %w", err)
	}
	run, err = getRunQuerier(ctx, tx, runID)
	if err != nil {
		return Run{}, err
	}
	if err := tx.Commit(); err != nil {
		return Run{}, fmt.Errorf("commit runtime stop confirmation: %w", err)
	}
	return run, nil
}

func (s *Store) ListNonTerminal(ctx context.Context) ([]Run, error) {
	return s.listRuns(ctx, `r.state IN ('accepted','running','cancelling')`)
}

// ListUnreconciled includes terminal rows that still retain a runtime
// reference, pending Create intent, or writer lock, in addition to every
// nonterminal Run.
func (s *Store) ListUnreconciled(ctx context.Context) ([]Run, error) {
	return s.listRuns(ctx, `r.state IN ('accepted','running','cancelling')
        OR r.runtime_ref IS NOT NULL
		OR r.runtime_intent_pending = 1
        OR EXISTS(SELECT 1 FROM workspace_locks pending WHERE pending.run_id = r.run_id)`)
}

func (s *Store) listRuns(ctx context.Context, predicate string) ([]Run, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	query := `SELECT ` + runSelectColumns + ` FROM runs r WHERE ` + predicate + ` ORDER BY r.created_at_unix_ms, r.run_id`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list sandbox runs: %w", err)
	}
	defer rows.Close()
	runs := make([]Run, 0)
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		if run.SessionScopeDigest == "" {
			return nil, ErrUnsafeLegacySessionState
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sandbox runs: %w", err)
	}
	return runs, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func getRunQuerier(ctx context.Context, querier queryRower, runID string) (Run, error) {
	run, err := getStoredRunQuerier(ctx, querier, runID)
	if err != nil {
		return Run{}, err
	}
	if run.SessionScopeDigest == "" {
		return Run{}, ErrUnsafeLegacySessionState
	}
	return run, nil
}

func getStoredRunQuerier(ctx context.Context, querier queryRower, runID string) (Run, error) {
	row := querier.QueryRowContext(ctx,
		`SELECT `+runSelectColumns+` FROM runs r WHERE r.run_id = ?`, runID)
	run, err := scanRun(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	return run, err
}

func scanRun(scanner rowScanner) (Run, error) {
	var (
		run                  Run
		requestedSessionRef  sql.NullString
		sessionScopeDigest   sql.NullString
		sessionMode          sql.NullString
		sessionMaxAgeSeconds sql.NullInt64
		sessionMaxTurns      sql.NullInt64
		sessionTurnNumber    sql.NullInt64
		deadlineMS           int64
		state                string
		lastEventSeq         int64
		runtimeRef           sql.NullString
		runtimeIntentPending int
		runtimeIntentBootID  sql.NullString
		outputMediaType      sql.NullString
		outputText           sql.NullString
		resultSessionRef     sql.NullString
		failureCode          sql.NullString
		failureMessage       sql.NullString
		createdMS            int64
		updatedMS            int64
		terminalMS           sql.NullInt64
		workspaceLockHeld    int
		writable             int
	)
	if err := scanner.Scan(
		&run.RunID,
		&run.Fingerprint,
		&run.TargetID,
		&run.TargetRevision,
		&run.WorkspaceID,
		&writable,
		&run.InputSHA256,
		&requestedSessionRef,
		&sessionScopeDigest,
		&sessionMode,
		&sessionMaxAgeSeconds,
		&sessionMaxTurns,
		&sessionTurnNumber,
		&deadlineMS,
		&state,
		&lastEventSeq,
		&runtimeRef,
		&runtimeIntentPending,
		&runtimeIntentBootID,
		&outputMediaType,
		&outputText,
		&resultSessionRef,
		&failureCode,
		&failureMessage,
		&createdMS,
		&updatedMS,
		&terminalMS,
		&workspaceLockHeld,
	); err != nil {
		return Run{}, err
	}
	if lastEventSeq < 0 {
		return Run{}, errors.New("sandboxstore: database contains a negative event sequence")
	}
	run.State = executionwire.RunState(state)
	run.LastEventSeq = uint64(lastEventSeq)
	run.Deadline = time.UnixMilli(deadlineMS).UTC()
	run.CreatedAt = time.UnixMilli(createdMS).UTC()
	run.UpdatedAt = time.UnixMilli(updatedMS).UTC()
	run.RequestedSessionRef = stringPointer(requestedSessionRef)
	if sessionScopeDigest.Valid {
		run.SessionScopeDigest = sessionScopeDigest.String
	}
	if sessionMode.Valid {
		run.SessionMode = targetmanifest.SessionMode(sessionMode.String)
	}
	if sessionMaxAgeSeconds.Valid {
		run.SessionMaxAgeSeconds = sessionMaxAgeSeconds.Int64
	}
	if sessionMaxTurns.Valid {
		run.SessionMaxTurns = sessionMaxTurns.Int64
	}
	if sessionTurnNumber.Valid {
		run.SessionTurnNumber = sessionTurnNumber.Int64
	}
	run.RuntimeRef = stringPointer(runtimeRef)
	run.RuntimeIntentPending = runtimeIntentPending != 0
	run.RuntimeIntentBootID = stringPointer(runtimeIntentBootID)
	if run.RuntimeIntentPending {
		if run.RuntimeIntentBootID != nil {
			if err := validateBootID(*run.RuntimeIntentBootID); err != nil {
				return Run{}, errors.New("sandboxstore: database contains an invalid runtime intent boot identifier")
			}
		}
	} else if run.RuntimeIntentBootID != nil {
		return Run{}, errors.New("sandboxstore: database contains a boot identifier without a runtime intent")
	}
	run.ResultSessionRef = stringPointer(resultSessionRef)
	run.WorkspaceLockHeld = workspaceLockHeld != 0
	run.Writable = writable != 0
	if terminalMS.Valid {
		value := time.UnixMilli(terminalMS.Int64).UTC()
		run.TerminalAt = &value
	}
	if outputMediaType.Valid || outputText.Valid {
		if !outputMediaType.Valid || !outputText.Valid {
			return Run{}, errors.New("sandboxstore: database contains a partial output")
		}
		run.Output = &executionwire.TextOutput{
			MediaType: executionwire.MediaType(outputMediaType.String),
			Text:      outputText.String,
		}
	}
	if failureCode.Valid || failureMessage.Valid {
		if !failureCode.Valid || !failureMessage.Valid {
			return Run{}, errors.New("sandboxstore: database contains a partial failure")
		}
		run.Failure = &executionwire.RunFailure{
			Code:    executionwire.FailureCode(failureCode.String),
			Message: failureMessage.String,
		}
	}
	return run, nil
}

func validateSessionPolicy(policy SessionPolicy) error {
	switch policy.Mode {
	case targetmanifest.SessionNewOnly:
		if policy.MaxAgeSeconds != 0 || policy.MaxTurns != 0 {
			return fmt.Errorf("%w: new_only session policy must have zero lifecycle limits", ErrInvalidArgument)
		}
	case targetmanifest.SessionOpaqueResume:
		if policy.MaxAgeSeconds <= 0 || policy.MaxTurns <= 0 ||
			policy.MaxAgeSeconds > targetmanifest.MaxSessionAgeSeconds ||
			policy.MaxTurns > int64(targetmanifest.MaxSessionTurns) {
			return fmt.Errorf("%w: opaque_resume session policy has invalid lifecycle limits", ErrInvalidArgument)
		}
	default:
		return fmt.Errorf("%w: unsupported session mode", ErrInvalidArgument)
	}
	return nil
}

func (s *Store) ready(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sandboxstore: store is not open")
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidArgument)
	}
	return nil
}

func validateRunID(runID string) error {
	request := executionwire.GetRunRequest{RunID: runID}
	if err := request.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return nil
}

func validateLogicalID(field, value string, maxBytes int) error {
	if len(value) == 0 || len(value) > maxBytes || !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s has invalid length or encoding", ErrInvalidArgument, field)
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if isASCIIAlphaNumeric(char) || char == '-' || char == '_' || char == '.' || char == ':' || char == '@' {
			continue
		}
		return fmt.Errorf("%w: %s contains unsupported characters", ErrInvalidArgument, field)
	}
	return nil
}

func validateRuntimeRef(value string) error {
	if len(value) == 0 || len(value) > MaxRuntimeRefBytes || !utf8.ValidString(value) {
		return fmt.Errorf("%w: runtime reference has invalid length or encoding", ErrInvalidArgument)
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if isASCIIAlphaNumeric(char) || char == '-' || char == '_' || char == '.' || char == ':' || char == '@' {
			continue
		}
		return fmt.Errorf("%w: runtime reference contains unsupported characters", ErrInvalidArgument)
	}
	return nil
}

func validateSessionMapping(mapping SessionMapping) error {
	request := executionwire.StartRunRequest{
		RunID:              "validation",
		TargetID:           "validation",
		ExpectedRevision:   "validation",
		SessionScopeDigest: "0000000000000000000000000000000000000000000000000000000000000000",
		SessionRef:         &mapping.Ref,
		Input: executionwire.TextInput{
			MediaType: executionwire.MediaTypeTextPlain,
			Text:      "validation",
		},
		Deadline: time.Unix(1, 0).UTC(),
	}
	if err := request.Validate(); err != nil {
		return fmt.Errorf("%w: invalid session mapping reference: %v", ErrInvalidArgument, err)
	}
	if len(mapping.VendorToken) == 0 || len(mapping.VendorToken) > runnerwire.MaxSessionTokenBytes {
		return fmt.Errorf("%w: vendor session token exceeds byte limit", ErrInvalidArgument)
	}
	for index := 0; index < len(mapping.VendorToken); index++ {
		char := mapping.VendorToken[index]
		if isASCIIAlphaNumeric(char) || char == '-' || char == '.' || char == '_' || char == '~' ||
			char == ':' || char == '/' || char == '@' || char == '+' || char == '=' {
			continue
		}
		return fmt.Errorf("%w: vendor session token contains unsafe characters", ErrInvalidArgument)
	}
	return nil
}

func isTerminal(state executionwire.RunState) bool {
	switch state {
	case executionwire.RunStateCompleted, executionwire.RunStateFailed,
		executionwire.RunStateCancelled, executionwire.RunStateInterrupted:
		return true
	default:
		return false
	}
}

func isASCIIAlphaNumeric(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
}

func nullableString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func stringPointer(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	result := value.String
	return &result
}
