package sandboxstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// AppendEvent records the next contiguous typed event and performs its
// legal state transition. A terminal event deliberately retains the workspace
// lock and runtime reference; ConfirmRuntimeStopped must follow only after the
// runtime is known to be gone.
//
// mapping is required exactly when a completed event contains SessionRef, and
// is forbidden otherwise.
func (s *Store) AppendEvent(
	ctx context.Context,
	event executionwire.RunEvent,
	mapping *SessionMapping,
) (Run, error) {
	if err := s.ready(ctx); err != nil {
		return Run{}, err
	}
	if err := event.Validate(); err != nil {
		return Run{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return Run{}, fmt.Errorf("begin event append: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	run, err := getRunQuerier(ctx, tx, event.RunID)
	if err != nil {
		return Run{}, err
	}
	if event.Seq != run.LastEventSeq+1 {
		return Run{}, ErrEventSequence
	}
	if event.Type != executionwire.RunEventCompleted && mapping != nil {
		return Run{}, fmt.Errorf("%w: session mapping is allowed only on completion", ErrInvalidArgument)
	}
	if (event.Type == executionwire.RunEventStarted || event.Type == executionwire.RunEventProgress) && event.Seq >= executionwire.MaxEvents {
		return Run{}, fmt.Errorf("%w: terminal event capacity must be reserved", ErrEventSequence)
	}

	nextState, err := transition(run.State, event.Type)
	if err != nil {
		return Run{}, err
	}
	if run.RuntimeIntentPending && isTerminal(nextState) && nextState != executionwire.RunStateInterrupted {
		return Run{}, ErrIllegalTransition
	}
	now := time.Now().UTC().UnixMilli()

	if event.Type == executionwire.RunEventCompleted {
		hasRef := event.Result != nil && event.Result.SessionRef != nil
		if hasRef != (mapping != nil) {
			return Run{}, fmt.Errorf("%w: result session reference and mapping must appear together", ErrInvalidArgument)
		}
		switch run.SessionMode {
		case targetmanifest.SessionNewOnly:
			if hasRef {
				return Run{}, fmt.Errorf("%w: new_only completion cannot publish a session", ErrInvalidArgument)
			}
		case targetmanifest.SessionOpaqueResume:
			if !hasRef {
				return Run{}, fmt.Errorf("%w: opaque_resume completion requires a successor session", ErrInvalidArgument)
			}
		default:
			return Run{}, fmt.Errorf("%w: Run lacks session lifecycle authority", ErrInvalidArgument)
		}
		if mapping != nil {
			if mapping.Ref != *event.Result.SessionRef {
				return Run{}, fmt.Errorf("%w: result session reference does not match mapping", ErrInvalidArgument)
			}
			if err := bindSession(ctx, tx, run, *mapping, now); err != nil {
				return Run{}, err
			}
		}
	}

	columns := eventColumns(event)
	if _, err := tx.ExecContext(ctx, `INSERT INTO run_events(
        run_id, seq, event_type, progress_kind, message_text,
        output_media_type, result_session_ref, failure_code, created_at_unix_ms
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.RunID,
		event.Seq,
		event.Type,
		columns.progressKind,
		columns.message,
		columns.outputMediaType,
		columns.resultSessionRef,
		columns.failureCode,
		now,
	); err != nil {
		return Run{}, fmt.Errorf("insert run event: %w", err)
	}

	terminalAt := any(nil)
	if isTerminal(nextState) {
		terminalAt = now
	}
	if _, err := tx.ExecContext(ctx, `UPDATE runs SET
        state = ?,
        last_event_seq = ?,
        output_media_type = ?,
        output_text = ?,
        result_session_ref = ?,
        failure_code = ?,
        failure_message = ?,
        updated_at_unix_ms = ?,
        terminal_at_unix_ms = ?
    WHERE run_id = ?`,
		nextState,
		event.Seq,
		columns.outputMediaType,
		columns.output,
		columns.resultSessionRef,
		columns.failureCode,
		columns.failure,
		now,
		terminalAt,
		event.RunID,
	); err != nil {
		return Run{}, fmt.Errorf("advance run state: %w", err)
	}

	run, err = getRunQuerier(ctx, tx, event.RunID)
	if err != nil {
		return Run{}, err
	}
	if err := tx.Commit(); err != nil {
		return Run{}, fmt.Errorf("commit run event: %w", err)
	}
	return run, nil
}

// ReconcileInterrupted atomically marks a nonterminal Run interrupted and
// releases its writer lock. Calling it for an already terminal Run simply
// confirms the runtime stopped and releases any retained lock.
func (s *Store) ReconcileInterrupted(ctx context.Context, runID, message string) (Run, error) {
	if err := s.ready(ctx); err != nil {
		return Run{}, err
	}
	if err := validateRunID(runID); err != nil {
		return Run{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return Run{}, fmt.Errorf("begin interrupted reconciliation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	run, err := getRunQuerier(ctx, tx, runID)
	if err != nil {
		return Run{}, err
	}
	// ReconcileInterrupted is a legacy convenience for Runs that provably
	// never acquired runtime authority. Runtime-bearing or pending-intent Runs
	// must first record a terminal event and then cross the explicit
	// ConfirmRuntimeStopped proof boundary after deterministic cleanup.
	if run.RuntimeRef != nil || run.RuntimeIntentPending {
		return Run{}, ErrIllegalTransition
	}
	now := time.Now().UTC().UnixMilli()

	if !isTerminal(run.State) {
		seq := run.LastEventSeq + 1
		failure := executionwire.RunFailure{
			Code:    executionwire.FailureRuntimeInterrupted,
			Message: message,
		}
		event := executionwire.RunEvent{
			RunID:   runID,
			Seq:     seq,
			Type:    executionwire.RunEventInterrupted,
			Failure: &failure,
		}
		if err := event.Validate(); err != nil {
			return Run{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO run_events(
            run_id, seq, event_type, message_text, failure_code, created_at_unix_ms
        ) VALUES (?, ?, ?, ?, ?, ?)`,
			runID, seq, event.Type, failure.Message, failure.Code, now); err != nil {
			return Run{}, fmt.Errorf("record interrupted event: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE runs SET
            state = ?, last_event_seq = ?, failure_code = ?, failure_message = ?,
            runtime_ref = NULL, runtime_intent_pending = 0,
			runtime_intent_boot_id = NULL,
            updated_at_unix_ms = ?, terminal_at_unix_ms = ?
        WHERE run_id = ?`,
			executionwire.RunStateInterrupted,
			seq,
			failure.Code,
			failure.Message,
			now,
			now,
			runID,
		); err != nil {
			return Run{}, fmt.Errorf("mark run interrupted: %w", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx,
			`UPDATE runs SET runtime_ref = NULL, runtime_intent_pending = 0,
			 runtime_intent_boot_id = NULL,
             updated_at_unix_ms = ? WHERE run_id = ?`,
			now, runID); err != nil {
			return Run{}, fmt.Errorf("clear reconciled runtime reference: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM workspace_locks WHERE run_id = ?`, runID); err != nil {
		return Run{}, fmt.Errorf("release reconciled workspace lock: %w", err)
	}
	run, err = getRunQuerier(ctx, tx, runID)
	if err != nil {
		return Run{}, err
	}
	if err := tx.Commit(); err != nil {
		return Run{}, fmt.Errorf("commit interrupted reconciliation: %w", err)
	}
	return run, nil
}

// GetSnapshot returns the bounded executionwire status and typed event history
// expected by agentd.
func (s *Store) GetSnapshot(ctx context.Context, runID string) (executionwire.GetRunResponse, error) {
	if err := s.ready(ctx); err != nil {
		return executionwire.GetRunResponse{}, err
	}
	if err := validateRunID(runID); err != nil {
		return executionwire.GetRunResponse{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return executionwire.GetRunResponse{}, fmt.Errorf("begin run snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	run, err := getRunQuerier(ctx, tx, runID)
	if err != nil {
		return executionwire.GetRunResponse{}, err
	}
	events, err := listEventsQuerier(ctx, tx, runID)
	if err != nil {
		return executionwire.GetRunResponse{}, err
	}
	response := executionwire.GetRunResponse{
		Status: executionwire.RunStatus{
			RunID:        run.RunID,
			State:        run.State,
			LastEventSeq: run.LastEventSeq,
		},
		Events: events,
	}
	if err := response.Validate(); err != nil {
		return executionwire.GetRunResponse{}, fmt.Errorf("validate stored run snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return executionwire.GetRunResponse{}, fmt.Errorf("commit run snapshot: %w", err)
	}
	return response, nil
}

func (s *Store) listEvents(ctx context.Context, runID string) ([]executionwire.RunEvent, error) {
	return listEventsQuerier(ctx, s.db, runID)
}

type rowsQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func listEventsQuerier(ctx context.Context, querier rowsQuerier, runID string) ([]executionwire.RunEvent, error) {
	rows, err := querier.QueryContext(ctx, `SELECT
        seq, event_type, progress_kind, message_text,
        output_media_type, result_session_ref, failure_code
    FROM run_events WHERE run_id = ? ORDER BY seq`, runID)
	if err != nil {
		return nil, fmt.Errorf("list run events: %w", err)
	}
	defer rows.Close()
	events := make([]executionwire.RunEvent, 0)
	for rows.Next() {
		var (
			seq              uint64
			eventType        string
			progressKind     sql.NullString
			message          sql.NullString
			outputMediaType  sql.NullString
			resultSessionRef sql.NullString
			failureCode      sql.NullString
		)
		if err := rows.Scan(
			&seq,
			&eventType,
			&progressKind,
			&message,
			&outputMediaType,
			&resultSessionRef,
			&failureCode,
		); err != nil {
			return nil, fmt.Errorf("scan run event: %w", err)
		}
		event := executionwire.RunEvent{RunID: runID, Seq: seq, Type: executionwire.RunEventType(eventType)}
		switch event.Type {
		case executionwire.RunEventProgress:
			event.Progress = &executionwire.RunProgress{
				Kind: executionwire.ProgressKind(progressKind.String),
				Text: message.String,
			}
		case executionwire.RunEventCompleted:
			event.Result = &executionwire.RunResult{
				Output: executionwire.TextOutput{
					MediaType: executionwire.MediaType(outputMediaType.String),
					Text:      message.String,
				},
				SessionRef: stringPointer(resultSessionRef),
			}
		case executionwire.RunEventFailed, executionwire.RunEventInterrupted:
			event.Failure = &executionwire.RunFailure{
				Code:    executionwire.FailureCode(failureCode.String),
				Message: message.String,
			}
		}
		if err := event.Validate(); err != nil {
			return nil, fmt.Errorf("validate stored event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate run events: %w", err)
	}
	return events, nil
}

type eventData struct {
	progressKind     any
	message          any
	outputMediaType  any
	output           any
	resultSessionRef any
	failureCode      any
	failure          any
}

func eventColumns(event executionwire.RunEvent) eventData {
	var data eventData
	switch event.Type {
	case executionwire.RunEventProgress:
		data.progressKind = event.Progress.Kind
		data.message = event.Progress.Text
	case executionwire.RunEventCompleted:
		data.message = event.Result.Output.Text
		data.output = event.Result.Output.Text
		data.outputMediaType = event.Result.Output.MediaType
		data.resultSessionRef = nullableString(event.Result.SessionRef)
	case executionwire.RunEventFailed, executionwire.RunEventInterrupted:
		data.message = event.Failure.Message
		data.failure = event.Failure.Message
		data.failureCode = event.Failure.Code
	}
	return data
}

func transition(state executionwire.RunState, eventType executionwire.RunEventType) (executionwire.RunState, error) {
	if isTerminal(state) {
		return "", ErrIllegalTransition
	}
	switch eventType {
	case executionwire.RunEventStarted:
		if state == executionwire.RunStateAccepted {
			return executionwire.RunStateRunning, nil
		}
	case executionwire.RunEventProgress:
		if state == executionwire.RunStateRunning || state == executionwire.RunStateCancelling {
			return state, nil
		}
	case executionwire.RunEventCompleted:
		if state == executionwire.RunStateRunning || state == executionwire.RunStateCancelling {
			return executionwire.RunStateCompleted, nil
		}
	case executionwire.RunEventFailed:
		if state == executionwire.RunStateAccepted || state == executionwire.RunStateRunning || state == executionwire.RunStateCancelling {
			return executionwire.RunStateFailed, nil
		}
	case executionwire.RunEventCancelled:
		if state == executionwire.RunStateAccepted || state == executionwire.RunStateRunning || state == executionwire.RunStateCancelling {
			return executionwire.RunStateCancelled, nil
		}
	case executionwire.RunEventInterrupted:
		if state == executionwire.RunStateAccepted || state == executionwire.RunStateRunning || state == executionwire.RunStateCancelling {
			return executionwire.RunStateInterrupted, nil
		}
	}
	return "", ErrIllegalTransition
}
