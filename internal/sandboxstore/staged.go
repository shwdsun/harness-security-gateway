package sandboxstore

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
)

// StageTerminal freezes one outcome without publishing an event, advancing the
// public Run state, binding its successor session, or releasing any authority.
// Exact retry is idempotent while the candidate exists; a different candidate
// conflicts. Only ConfirmRuntimeStopped may publish it after trusted cleanup.
func (s *Store) StageTerminal(ctx context.Context, event executionwire.RunEvent, mapping *SessionMapping) (Run, error) {
	if err := s.ready(ctx); err != nil {
		return Run{}, err
	}
	if err := event.Validate(); err != nil {
		return Run{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	switch event.Type {
	case executionwire.RunEventCompleted, executionwire.RunEventFailed,
		executionwire.RunEventCancelled, executionwire.RunEventInterrupted:
	default:
		return Run{}, ErrInvalidArgument
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return Run{}, fmt.Errorf("begin terminal staging: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	run, err := getRunQuerier(ctx, tx, event.RunID)
	if err != nil {
		return Run{}, err
	}
	if run.TerminalPending {
		candidate, err := stagedTerminal(ctx, tx, event.RunID)
		if err != nil {
			return Run{}, err
		}
		if !reflect.DeepEqual(candidate.event, event) || !reflect.DeepEqual(candidate.mapping, mapping) {
			return Run{}, ErrConflict
		}
		return run, nil
	}
	if _, err := validateRunEvent(run, event, mapping); err != nil {
		return Run{}, err
	}
	var token any
	if mapping != nil {
		var used bool
		if err := tx.QueryRowContext(ctx, `SELECT
            EXISTS(SELECT 1 FROM sessions WHERE session_ref = ?)
            OR EXISTS(SELECT 1 FROM staged_terminals WHERE result_session_ref = ?)`,
			mapping.Ref, mapping.Ref).Scan(&used); err != nil {
			return Run{}, fmt.Errorf("check staged session namespace: %w", err)
		}
		if used {
			return Run{}, ErrSessionScope
		}
		token = mapping.VendorToken
	}
	now := time.Now().UTC().UnixMilli()
	if now < run.CreatedAt.UnixMilli() {
		return Run{}, ErrIllegalTransition
	}
	columns := eventColumns(event)
	if _, err := tx.ExecContext(ctx, `INSERT INTO staged_terminals(
        run_id, seq, event_type, message_text, output_media_type,
        result_session_ref, vendor_token, failure_code, staged_at_unix_ms
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, event.RunID, event.Seq, event.Type,
		columns.message, columns.outputMediaType, columns.resultSessionRef, token,
		columns.failureCode, now); err != nil {
		return Run{}, fmt.Errorf("stage terminal: %w", err)
	}
	run.TerminalPending = true
	if err := tx.Commit(); err != nil {
		return Run{}, fmt.Errorf("commit terminal staging: %w", err)
	}
	return run, nil
}

type terminalCandidate struct {
	event    executionwire.RunEvent
	mapping  *SessionMapping
	stagedAt int64
}

func stagedTerminal(ctx context.Context, tx *sql.Tx, runID string) (terminalCandidate, error) {
	var candidate terminalCandidate
	var text, media, ref, token, code sql.NullString
	candidate.event.RunID = runID
	if err := tx.QueryRowContext(ctx, `SELECT seq, event_type, message_text,
        output_media_type, result_session_ref, vendor_token, failure_code,
        staged_at_unix_ms FROM staged_terminals WHERE run_id = ?`, runID).Scan(
		&candidate.event.Seq, &candidate.event.Type, &text, &media, &ref, &token,
		&code, &candidate.stagedAt); err != nil {
		return terminalCandidate{}, fmt.Errorf("read terminal candidate: %w", err)
	}
	switch candidate.event.Type {
	case executionwire.RunEventCompleted:
		candidate.event.Result = &executionwire.RunResult{
			Output:     executionwire.TextOutput{MediaType: executionwire.MediaType(media.String), Text: text.String},
			SessionRef: stringPointer(ref),
		}
		if ref.Valid {
			candidate.mapping = &SessionMapping{Ref: ref.String, VendorToken: token.String}
		}
	case executionwire.RunEventFailed, executionwire.RunEventInterrupted:
		candidate.event.Failure = &executionwire.RunFailure{Code: executionwire.FailureCode(code.String), Message: text.String}
	case executionwire.RunEventCancelled:
	default:
		return terminalCandidate{}, ErrIllegalTransition
	}
	if err := candidate.event.Validate(); err != nil {
		return terminalCandidate{}, fmt.Errorf("validate terminal candidate: %w", err)
	}
	return candidate, nil
}
