package corestore

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const runColumns = `
id, connector_id, event_id, actor_ref, conversation_ref, message_ref,
target_id, target_revision, COALESCE(binding_fingerprint, ''), COALESCE(policy_revision, ''),
input_text, state, output_text, failure_code, result_session_ref,
COALESCE(dispatch_token, ''), COALESCE(dispatch_expires_at_ms, 0), dispatch_attempt_count,
start_prepared, start_session_ref, COALESCE(start_deadline_ms, 0),
created_at_ms, updated_at_ms`

func (s *Store) IngestTextRun(
	ctx context.Context,
	input IngestTextRunInput,
	authorize TextRunAuthorizer,
	newRunID RunIDSource,
) (IngestResult, error) {
	if err := validateIngest(input); err != nil {
		return IngestResult{}, err
	}
	if authorize == nil || newRunID == nil {
		return IngestResult{}, fmt.Errorf("%w: nil inbound admission callback", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IngestResult{}, fmt.Errorf("begin inbound ingest: %w", err)
	}
	defer tx.Rollback()

	// _txlock=immediate means BeginTx acquires serialized writer authority.
	// Sample the clock exactly once after that boundary so a waiting writer can
	// never admit using a time older than a horizon another writer advanced.
	now, err := s.nowMillis()
	if err != nil {
		return IngestResult{}, err
	}
	horizon, err := s.evictInboundReceipts(ctx, tx, input.ConnectorID, now)
	if err != nil {
		return IngestResult{}, err
	}
	var existingHash []byte
	var existingHashVersion int
	var existingRunID string
	err = tx.QueryRowContext(ctx,
		"SELECT payload_hash, payload_hash_version, run_id FROM inbound_events WHERE connector_id = ? AND event_id = ?",
		input.ConnectorID, input.EventID,
	).Scan(&existingHash, &existingHashVersion, &existingRunID)
	switch {
	case err == nil:
		expectedHash := input.PayloadHash
		switch existingHashVersion {
		case 1:
			expectedHash = input.LegacyPayloadHash
		case 2:
		default:
			return IngestResult{}, errors.New("corestore: inbound receipt has an unsupported hash version")
		}
		if len(existingHash) != len(expectedHash) || subtle.ConstantTimeCompare(existingHash, expectedHash[:]) != 1 {
			return IngestResult{}, commitRejectedIngest(
				tx, fmt.Errorf("%w: inbound event payload hash changed", ErrConflict),
			)
		}
		run, err := getRunTx(ctx, tx, existingRunID)
		if err != nil {
			return IngestResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return IngestResult{}, fmt.Errorf("commit duplicate inbound read: %w", err)
		}
		return IngestResult{Run: run, Duplicate: true}, nil
	case errors.Is(err, sql.ErrNoRows):
		// Continue with one transactional Run and inbox insertion.
	case err != nil:
		return IngestResult{}, fmt.Errorf("read inbound deduplication key: %w", err)
	}

	// Eviction above removed every logically expired receipt. Therefore any
	// key found by the lookup was retained and took precedence over current
	// time, policy, and quota. Only a genuinely new key reaches these checks.
	if input.OccurredAtUnixMS > timeFromMillis(now).Add(s.admission.FutureSkew).UnixMilli() {
		return IngestResult{}, commitRejectedIngest(tx, ErrEventExpired)
	}
	if input.OccurredAtUnixMS <= horizon {
		return IngestResult{}, commitRejectedIngest(tx, ErrEventExpired)
	}
	acceptCutoff := timeFromMillis(now).Add(-s.admission.AcceptWindow).UnixMilli()
	if input.OccurredAtUnixMS < acceptCutoff {
		return IngestResult{}, commitRejectedIngest(tx, ErrEventExpired)
	}
	authorization, err := authorize()
	if err != nil {
		return IngestResult{}, commitRejectedIngest(tx, err)
	}
	if err := validateTextRunAuthorization(authorization); err != nil {
		return IngestResult{}, err
	}
	busy, err := sessionScopeBusy(ctx, tx, input, authorization)
	if err != nil {
		return IngestResult{}, err
	}
	if busy {
		return IngestResult{}, commitRejectedIngest(tx, ErrSessionScopeBusy)
	}
	if err := s.checkInboundCapacity(ctx, tx, input.ConnectorID, len([]byte(input.Text))); err != nil {
		return IngestResult{}, commitRejectedIngest(tx, err)
	}
	runID, err := newRunID()
	if err != nil {
		return IngestResult{}, commitRejectedIngest(tx, fmt.Errorf("generate Run ID: %w", err))
	}
	if err := validateIdentifier("run_id", runID, MaxIDBytes); err != nil {
		return IngestResult{}, err
	}

	var collision int
	err = tx.QueryRowContext(ctx, "SELECT 1 FROM runs WHERE id = ?", runID).Scan(&collision)
	if err == nil {
		return IngestResult{}, fmt.Errorf("%w: run ID already exists", ErrConflict)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return IngestResult{}, fmt.Errorf("check run ID: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO runs(
    id, connector_id, event_id, actor_ref, conversation_ref, message_ref,
    target_id, target_revision, binding_fingerprint, policy_revision,
    input_text, state, created_at_ms, updated_at_ms
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)`,
		runID, input.ConnectorID, input.EventID, input.ActorRef,
		input.ConversationRef, input.MessageRef, authorization.TargetID,
		authorization.TargetRevision, authorization.BindingFingerprint,
		authorization.PolicyRevision, input.Text, now, now,
	); err != nil {
		if isUniqueConstraint(err) {
			busy, inspectErr := sessionScopeBusy(ctx, tx, input, authorization)
			if inspectErr != nil {
				return IngestResult{}, inspectErr
			}
			if busy {
				return IngestResult{}, commitRejectedIngest(tx, ErrSessionScopeBusy)
			}
		}
		return IngestResult{}, ingestMutationError("insert queued run", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO inbound_events(
	connector_id, event_id, payload_hash, payload_hash_version,
	run_id, occurred_at_ms, received_at_ms
	) VALUES (?, ?, ?, 2, ?, ?, ?)`, input.ConnectorID, input.EventID, input.PayloadHash[:],
		runID, input.OccurredAtUnixMS, now); err != nil {
		return IngestResult{}, ingestMutationError("insert inbound deduplication record", err)
	}
	run, err := getRunTx(ctx, tx, runID)
	if err != nil {
		return IngestResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return IngestResult{}, ingestMutationError("commit inbound ingest", err)
	}
	return IngestResult{Run: run}, nil
}

func sessionScopeBusy(ctx context.Context, tx *sql.Tx, input IngestTextRunInput, authorization TextRunAuthorization) (bool, error) {
	var exists int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM runs
        WHERE binding_fingerprint = ? AND connector_id = ? AND actor_ref = ?
          AND conversation_ref = ? AND target_id = ? AND target_revision = ?
          AND state IN ('queued', 'dispatching', 'running')
        LIMIT 1`, authorization.BindingFingerprint, input.ConnectorID, input.ActorRef,
		input.ConversationRef, authorization.TargetID, authorization.TargetRevision).Scan(&exists)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	default:
		return false, fmt.Errorf("inspect nonterminal session scope: %w", err)
	}
}

func isUniqueConstraint(err error) bool {
	var sqliteError *sqlite.Error
	return errors.As(err, &sqliteError) && sqliteError.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE
}

func (s *Store) evictInboundReceipts(
	ctx context.Context,
	tx *sql.Tx,
	connectorID string,
	now int64,
) (int64, error) {
	cutoff := timeFromMillis(now).Add(-s.admission.ReceiptWindow).UnixMilli()
	if cutoff < 0 {
		cutoff = 0
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO inbound_event_horizons(connector_id, evicted_through_ms)
        VALUES (?, ?)
        ON CONFLICT(connector_id) DO UPDATE SET evicted_through_ms = excluded.evicted_through_ms
        WHERE excluded.evicted_through_ms > inbound_event_horizons.evicted_through_ms`,
		connectorID, cutoff); err != nil {
		return 0, ingestMutationError("advance inbound eviction horizon", err)
	}
	var horizon int64
	if err := tx.QueryRowContext(ctx,
		`SELECT evicted_through_ms FROM inbound_event_horizons WHERE connector_id = ?`,
		connectorID).Scan(&horizon); err != nil {
		return 0, fmt.Errorf("read inbound eviction horizon: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM inbound_events WHERE connector_id = ? AND occurred_at_ms <= ?`,
		connectorID, horizon); err != nil {
		return 0, ingestMutationError("evict inbound receipts", err)
	}
	// Once a receipt is gone, a terminal Run is no longer part of replay
	// authority. Remove its finished delivery and Run so retained input remains
	// bounded by the configured receipt/nonterminal pools.
	if _, err := tx.ExecContext(ctx, `DELETE FROM text_deliveries
        WHERE state IN ('delivered','permanent_failed')
          AND run_id IN (
              SELECT r.id FROM runs r
              WHERE r.connector_id = ?
                AND r.state IN ('completed','failed','cancelled','interrupted')
                AND NOT EXISTS (SELECT 1 FROM inbound_events i WHERE i.run_id = r.id)
          )`, connectorID); err != nil {
		return 0, ingestMutationError("compact terminal deliveries", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM runs
        WHERE connector_id = ?
          AND state IN ('completed','failed','cancelled','interrupted')
          AND NOT EXISTS (SELECT 1 FROM inbound_events i WHERE i.run_id = runs.id)
          AND NOT EXISTS (SELECT 1 FROM text_deliveries d WHERE d.run_id = runs.id)`,
		connectorID); err != nil {
		return 0, ingestMutationError("compact terminal runs", err)
	}
	return horizon, nil
}

func (s *Store) checkInboundCapacity(
	ctx context.Context,
	tx *sql.Tx,
	connectorID string,
	newInputBytes int,
) error {
	checks := []struct {
		name  string
		query string
		limit int64
	}{
		{"retained receipts", `SELECT COUNT(*) FROM inbound_events WHERE connector_id = ?`, s.admission.MaxReceiptsPerConnector},
		{"queued runs", `SELECT COUNT(*) FROM runs WHERE connector_id = ? AND state = 'queued'`, s.admission.MaxQueuedRunsPerConnector},
		{"nonterminal runs", `SELECT COUNT(*) FROM runs WHERE connector_id = ? AND state IN ('queued','dispatching','running')`, s.admission.MaxNonTerminalRunsPerConnector},
		{"pending deliveries", `SELECT COUNT(*) FROM text_deliveries AS d
            JOIN runs AS r ON r.id = d.run_id
            WHERE r.connector_id = ? AND d.state IN ('pending','leased')`, s.admission.MaxPendingDeliveriesPerConnector},
	}
	for _, check := range checks {
		var count int64
		if err := tx.QueryRowContext(ctx, check.query, connectorID).Scan(&count); err != nil {
			return fmt.Errorf("count %s: %w", check.name, err)
		}
		if count >= check.limit {
			return fmt.Errorf("%w: %s", ErrQuotaExceeded, check.name)
		}
	}
	var retainedInputBytes int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(length(CAST(input_text AS BLOB))), 0)
        FROM runs WHERE connector_id = ?`, connectorID).Scan(&retainedInputBytes); err != nil {
		return fmt.Errorf("count retained input bytes: %w", err)
	}
	if retainedInputBytes > s.admission.MaxRetainedInputBytesPerConnector-int64(newInputBytes) {
		return fmt.Errorf("%w: retained input bytes", ErrQuotaExceeded)
	}
	var pageCount, freePages int64
	if err := tx.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
		return fmt.Errorf("read admission page count: %w", err)
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&freePages); err != nil {
		return fmt.Errorf("read admission free page count: %w", err)
	}
	if pageCount >= s.admission.MaxDatabasePages && freePages == 0 {
		return fmt.Errorf("%w: database pages", ErrQuotaExceeded)
	}
	return nil
}

func commitRejectedIngest(tx *sql.Tx, decision error) error {
	if err := tx.Commit(); err != nil {
		return ingestMutationError("commit rejected inbound maintenance", err)
	}
	return decision
}

func ingestMutationError(operation string, err error) error {
	var sqliteError *sqlite.Error
	if errors.As(err, &sqliteError) && sqliteError.Code()&0xff == sqlite3.SQLITE_FULL {
		return fmt.Errorf("%w: database pages", ErrQuotaExceeded)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func (s *Store) GetRun(ctx context.Context, runID string) (Run, error) {
	if err := validateIdentifier("run_id", runID, MaxIDBytes); err != nil {
		return Run{}, err
	}
	run, err := scanRun(s.db.QueryRowContext(ctx, "SELECT "+runColumns+" FROM runs WHERE id = ?", runID))
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	if err != nil {
		return Run{}, fmt.Errorf("get run: %w", err)
	}
	return run, nil
}

// ListRunningRuns returns only Runs which have crossed the durable
// MarkRunRunning boundary. agentd uses this bounded list after restart to poll
// sandboxd and reconcile a result which may already be terminal there.
func (s *Store) ListRunningRuns(ctx context.Context, limit int) ([]Run, error) {
	if limit < 1 || limit > MaxReconcileRuns {
		return nil, invalidInput("limit", fmt.Sprintf("must be between 1 and %d", MaxReconcileRuns))
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+runColumns+" FROM runs WHERE state = 'running' ORDER BY created_at_ms, id LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list running runs: %w", err)
	}
	defer rows.Close()
	runs := make([]Run, 0)
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return nil, fmt.Errorf("scan running run: %w", err)
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate running runs: %w", err)
	}
	return runs, nil
}

func (s *Store) ClaimQueuedRun(ctx context.Context, lease time.Duration) (Run, bool, error) {
	if lease < time.Second || lease > 10*time.Minute {
		return Run{}, false, invalidInput("lease", "must be between one second and ten minutes")
	}
	now, err := s.nowMillis()
	if err != nil {
		return Run{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Run{}, false, fmt.Errorf("begin queued run claim: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
UPDATE runs
SET state = 'queued', dispatch_token = NULL, dispatch_expires_at_ms = NULL, updated_at_ms = ?
WHERE state = 'dispatching' AND dispatch_expires_at_ms <= ?`, now, now); err != nil {
		return Run{}, false, fmt.Errorf("release expired run dispatches: %w", err)
	}
	// A dispatching Run may still be in use by the pre-crash worker, and a
	// running Run is durably owned by sandboxd even though its dispatch lease has
	// been cleared. Either state gates the queue so the store, not an in-memory
	// supervisor, enforces the MVP's global-one execution invariant. Once a
	// dispatch lease expires, the update above safely requeues that Run and
	// deterministic queue order selects the original Run first.
	var activeRun int
	err = tx.QueryRowContext(ctx,
		"SELECT 1 FROM runs WHERE state IN ('dispatching', 'running') LIMIT 1",
	).Scan(&activeRun)
	switch {
	case err == nil:
		if err := tx.Commit(); err != nil {
			return Run{}, false, fmt.Errorf("commit gated queued run claim: %w", err)
		}
		return Run{}, false, nil
	case errors.Is(err, sql.ErrNoRows):
		// No active execution gates the queue.
	case err != nil:
		return Run{}, false, fmt.Errorf("check active run execution: %w", err)
	}
	run, err := scanRun(tx.QueryRowContext(ctx,
		"SELECT "+runColumns+" FROM runs WHERE state = 'queued' ORDER BY created_at_ms, id LIMIT 1"))
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return Run{}, false, fmt.Errorf("commit empty queued run claim: %w", err)
		}
		return Run{}, false, nil
	}
	if err != nil {
		return Run{}, false, fmt.Errorf("select queued run: %w", err)
	}
	token, err := s.newLeaseToken()
	if err != nil {
		return Run{}, false, fmt.Errorf("create run dispatch token: %w", err)
	}
	if err := validateIdentifier("generated dispatch_token", token, MaxIDBytes); err != nil {
		return Run{}, false, err
	}
	leaseMillis := lease.Milliseconds()
	if leaseMillis <= 0 || now > int64(^uint64(0)>>1)-leaseMillis {
		return Run{}, false, invalidInput("lease", "expires outside the supported timestamp range")
	}
	expires := now + leaseMillis
	result, err := tx.ExecContext(ctx,
		`UPDATE runs
SET state = 'dispatching', dispatch_token = ?, dispatch_expires_at_ms = ?,
    dispatch_attempt_count = dispatch_attempt_count + 1, updated_at_ms = ?
WHERE id = ? AND state = 'queued'`, token, expires, now, run.ID,
	)
	if err != nil {
		return Run{}, false, fmt.Errorf("claim queued run: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return Run{}, false, fmt.Errorf("claim queued run changed %d rows: %w", affected, err)
	}
	run.State = RunDispatching
	run.DispatchToken = token
	run.DispatchExpiresAt = timeFromMillis(expires)
	run.DispatchAttemptCount++
	run.UpdatedAt = timeFromMillis(now)
	if err := tx.Commit(); err != nil {
		return Run{}, false, fmt.Errorf("commit queued run claim: %w", err)
	}
	return run, true, nil
}

// PrepareRunStart persists the two StartRun fingerprint fields which are not
// otherwise immutable on Run. A valid current dispatch capability is required
// even when reading an already prepared value, so a stale worker cannot use
// this method as a session-reference oracle.
func (s *Store) PrepareRunStart(ctx context.Context, input PrepareRunStartInput) (PreparedRunStart, error) {
	now, err := s.nowMillis()
	if err != nil {
		return PreparedRunStart{}, err
	}
	if err := validatePrepareRunStart(input, now); err != nil {
		return PreparedRunStart{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PreparedRunStart{}, fmt.Errorf("begin run start preparation: %w", err)
	}
	defer tx.Rollback()
	run, err := getRunTx(ctx, tx, input.RunID)
	if errors.Is(err, sql.ErrNoRows) {
		return PreparedRunStart{}, ErrNotFound
	}
	if err != nil {
		return PreparedRunStart{}, fmt.Errorf("read run for start preparation: %w", err)
	}
	if run.State != RunDispatching || run.DispatchToken != input.DispatchToken ||
		run.DispatchExpiresAt.IsZero() || run.DispatchExpiresAt.UnixMilli() <= now {
		return PreparedRunStart{}, ErrDispatchLost
	}
	if run.StartPrepared {
		result := preparedStartFromRun(run)
		if err := tx.Commit(); err != nil {
			return PreparedRunStart{}, fmt.Errorf("commit prepared run start read: %w", err)
		}
		return result, nil
	}

	var currentRef string
	err = tx.QueryRowContext(ctx, `
SELECT session_ref FROM sessions
WHERE binding_fingerprint = ? AND connector_id = ? AND actor_ref = ?
  AND conversation_ref = ? AND target_id = ? AND target_revision = ?`,
		run.BindingFingerprint, run.ConnectorID, run.ActorRef,
		run.ConversationRef, run.TargetID, run.TargetRevision,
	).Scan(&currentRef)
	switch {
	case input.SessionRef == nil && err == nil:
		return PreparedRunStart{}, fmt.Errorf("%w: fresh start requires no current session for run scope", ErrConflict)
	case input.SessionRef == nil && errors.Is(err, sql.ErrNoRows):
	case input.SessionRef == nil && err != nil:
		return PreparedRunStart{}, fmt.Errorf("read current scoped session: %w", err)
	case input.SessionRef != nil:
		if errors.Is(err, sql.ErrNoRows) {
			return PreparedRunStart{}, fmt.Errorf("%w: requested start session is not current for run scope", ErrConflict)
		}
		if err != nil {
			return PreparedRunStart{}, fmt.Errorf("read current scoped session: %w", err)
		}
		if currentRef != *input.SessionRef {
			return PreparedRunStart{}, fmt.Errorf("%w: requested start session is not current for run scope", ErrConflict)
		}
	}

	deadlineMillis := input.Deadline.UTC().UnixMilli()
	var sessionRef any
	if input.SessionRef != nil {
		sessionRef = *input.SessionRef
	}
	result, err := tx.ExecContext(ctx, `
UPDATE runs
SET start_prepared = 1, start_session_ref = ?, start_deadline_ms = ?, updated_at_ms = ?
WHERE id = ? AND state = 'dispatching' AND dispatch_token = ? AND start_prepared = 0`,
		sessionRef, deadlineMillis, now, run.ID, input.DispatchToken,
	)
	if err != nil {
		return PreparedRunStart{}, fmt.Errorf("persist prepared run start: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return PreparedRunStart{}, fmt.Errorf("prepare run start changed %d rows: %w", affected, err)
	}
	run.StartPrepared = true
	if input.SessionRef != nil {
		copy := *input.SessionRef
		run.StartSessionRef = &copy
	}
	run.StartDeadline = timeFromMillis(deadlineMillis)
	if err := tx.Commit(); err != nil {
		return PreparedRunStart{}, fmt.Errorf("commit run start preparation: %w", err)
	}
	return preparedStartFromRun(run), nil
}

func preparedStartFromRun(run Run) PreparedRunStart {
	result := PreparedRunStart{Deadline: run.StartDeadline}
	if run.StartSessionRef != nil {
		copy := *run.StartSessionRef
		result.SessionRef = &copy
	}
	return result
}

func (s *Store) MarkRunRunning(ctx context.Context, runID, dispatchToken string) error {
	if err := validateIdentifier("run_id", runID, MaxIDBytes); err != nil {
		return err
	}
	if err := validateIdentifier("dispatch_token", dispatchToken, MaxIDBytes); err != nil {
		return err
	}
	now, err := s.nowMillis()
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin running transition: %w", err)
	}
	defer tx.Rollback()
	var state RunState
	var storedToken string
	var expires sql.NullInt64
	var startPrepared bool
	if err := tx.QueryRowContext(ctx,
		"SELECT state, COALESCE(dispatch_token, ''), dispatch_expires_at_ms, start_prepared FROM runs WHERE id = ?", runID,
	).Scan(&state, &storedToken, &expires, &startPrepared); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("read run state: %w", err)
	}
	if storedToken != dispatchToken {
		return ErrDispatchLost
	}
	if state == RunRunning {
		return tx.Commit()
	}
	if state != RunDispatching {
		return fmt.Errorf("%w: %s to running", ErrInvalidTransition, state)
	}
	if !expires.Valid || expires.Int64 <= now {
		return ErrDispatchLost
	}
	if !startPrepared {
		return ErrStartUnprepared
	}
	if _, err := tx.ExecContext(ctx,
		"UPDATE runs SET state = 'running', dispatch_expires_at_ms = NULL, updated_at_ms = ? WHERE id = ?", now, runID,
	); err != nil {
		return fmt.Errorf("mark run running: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit running transition: %w", err)
	}
	return nil
}

func (s *Store) FinishRun(ctx context.Context, input FinishRunInput, reply *TextDeliveryInput) error {
	if err := validateFinish(input); err != nil {
		return err
	}
	now, err := s.nowMillis()
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin run finish: %w", err)
	}
	defer tx.Rollback()
	run, err := getRunTx(ctx, tx, input.RunID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if run.DispatchToken != input.DispatchToken {
		return ErrDispatchLost
	}
	if !run.StartPrepared {
		return ErrStartUnprepared
	}

	var normalizedReply *TextDeliveryInput
	if reply != nil {
		copy := *reply
		if err := validateDelivery(copy); err != nil {
			return err
		}
		normalizedReply = &copy
	}

	newlyFinished := false
	if run.State == RunCompleted || run.State == RunFailed || run.State == RunCancelled || run.State == RunInterrupted {
		if !sameFinish(run, input) {
			return fmt.Errorf("%w: terminal run result changed", ErrConflict)
		}
	} else {
		if run.State != RunDispatching && run.State != RunRunning {
			return fmt.Errorf("%w: %s to %s", ErrInvalidTransition, run.State, input.State)
		}
		if run.State == RunDispatching && (run.DispatchExpiresAt.IsZero() || run.DispatchExpiresAt.UnixMilli() <= now) {
			return ErrDispatchLost
		}
		var output any
		if input.State == RunCompleted {
			output = input.OutputText
		}
		var failure any
		if input.FailureCode != "" {
			failure = string(input.FailureCode)
		}
		var sessionRef any
		if input.ResultSessionRef != "" {
			sessionRef = input.ResultSessionRef
		}
		if _, err := tx.ExecContext(ctx,
			"UPDATE runs SET state = ?, dispatch_expires_at_ms = NULL, output_text = ?, failure_code = ?, result_session_ref = ?, updated_at_ms = ? WHERE id = ?",
			string(input.State), output, failure, sessionRef, now, input.RunID,
		); err != nil {
			return fmt.Errorf("finish run: %w", err)
		}
		newlyFinished = true
	}

	if newlyFinished && input.ResultSessionRef != "" {
		session := Session{
			SessionKey: SessionKey{
				BindingFingerprint: run.BindingFingerprint,
				ConnectorID:        run.ConnectorID, ActorRef: run.ActorRef,
				ConversationRef: run.ConversationRef,
				TargetID:        run.TargetID, TargetRevision: run.TargetRevision,
			},
			Ref: input.ResultSessionRef,
		}
		if err := putSessionTx(ctx, tx, session, now); err != nil {
			return err
		}
	}
	if normalizedReply != nil {
		if err := s.insertDeliveryTx(ctx, tx, run, *normalizedReply, now); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit run finish: %w", err)
	}
	return nil
}

func sameFinish(run Run, input FinishRunInput) bool {
	if run.State != input.State {
		return false
	}
	switch input.State {
	case RunCompleted:
		return run.OutputText != nil && *run.OutputText == input.OutputText && run.FailureCode == nil &&
			sameOptionalString(run.ResultSessionRef, input.ResultSessionRef)
	case RunFailed, RunInterrupted:
		return run.OutputText == nil && run.FailureCode != nil && *run.FailureCode == input.FailureCode
	case RunCancelled:
		return run.OutputText == nil && run.FailureCode == nil
	default:
		return false
	}
}

func sameOptionalString(stored *string, supplied string) bool {
	if supplied == "" {
		return stored == nil
	}
	return stored != nil && *stored == supplied
}

type rowScanner interface {
	Scan(...any) error
}

func getRunTx(ctx context.Context, tx *sql.Tx, runID string) (Run, error) {
	return scanRun(tx.QueryRowContext(ctx, "SELECT "+runColumns+" FROM runs WHERE id = ?", runID))
}

func scanRun(row rowScanner) (Run, error) {
	var run Run
	var output sql.NullString
	var failure sql.NullString
	var resultSessionRef sql.NullString
	var startSessionRef sql.NullString
	var startPrepared bool
	var dispatchExpires, startDeadline, createdAt, updatedAt int64
	if err := row.Scan(
		&run.ID, &run.ConnectorID, &run.EventID, &run.ActorRef,
		&run.ConversationRef, &run.MessageRef, &run.TargetID,
		&run.TargetRevision, &run.BindingFingerprint, &run.PolicyRevision,
		&run.InputText, &run.State, &output, &failure, &resultSessionRef,
		&run.DispatchToken, &dispatchExpires, &run.DispatchAttemptCount,
		&startPrepared, &startSessionRef, &startDeadline,
		&createdAt, &updatedAt,
	); err != nil {
		return Run{}, err
	}
	if output.Valid {
		run.OutputText = &output.String
	}
	if failure.Valid {
		code := RunFailureCode(failure.String)
		run.FailureCode = &code
	}
	if resultSessionRef.Valid {
		run.ResultSessionRef = &resultSessionRef.String
	}
	run.StartPrepared = startPrepared
	if startSessionRef.Valid {
		run.StartSessionRef = &startSessionRef.String
	}
	if startDeadline > 0 {
		run.StartDeadline = timeFromMillis(startDeadline)
	}
	if dispatchExpires > 0 {
		run.DispatchExpiresAt = timeFromMillis(dispatchExpires)
	}
	run.CreatedAt = timeFromMillis(createdAt)
	run.UpdatedAt = timeFromMillis(updatedAt)
	return run, nil
}
