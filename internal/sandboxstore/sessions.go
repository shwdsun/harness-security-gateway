package sandboxstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// ResolveSessionForRun returns a sandbox-private vendor token only to the
// exact durable Run which atomically consumed that one-use opaque reference.
func (s *Store) ResolveSessionForRun(
	ctx context.Context,
	runID string,
	sessionRef string,
	targetID string,
	targetRevision string,
	sessionScopeDigest string,
) (string, error) {
	if err := s.ready(ctx); err != nil {
		return "", err
	}
	if err := validateRunID(runID); err != nil {
		return "", err
	}
	if err := validateSessionLookup(sessionRef, targetID, targetRevision, sessionScopeDigest); err != nil {
		return "", err
	}
	var vendorToken string
	err := s.db.QueryRowContext(ctx, `SELECT s.vendor_token
        FROM sessions AS s
        JOIN session_uses AS u ON u.session_ref = s.session_ref
        JOIN runs AS r ON r.run_id = u.run_id
        WHERE s.session_ref = ? AND u.run_id = ?
          AND r.state = 'accepted'
          AND r.session_mode = 'opaque_resume'
          AND r.requested_session_ref = s.session_ref
          AND s.target_id = ? AND s.target_revision = ?
          AND s.session_scope_digest = ?
          AND r.target_id = s.target_id
          AND r.target_revision = s.target_revision
          AND r.session_scope_digest = s.session_scope_digest`,
		sessionRef, runID, targetID, targetRevision, sessionScopeDigest,
	).Scan(&vendorToken)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrSessionScope
	}
	if err != nil {
		return "", fmt.Errorf("resolve consumed sandbox session: %w", err)
	}
	return vendorToken, nil
}

type admissionSession struct {
	CreatedAtUnixMS int64
	ExpiresAtUnixMS int64
	TurnNumber      int64
}

func sessionForAdmission(
	ctx context.Context,
	querier queryRower,
	sessionRef string,
	targetID string,
	targetRevision string,
	sessionScopeDigest string,
) (admissionSession, error) {
	if err := validateSessionLookup(sessionRef, targetID, targetRevision, sessionScopeDigest); err != nil {
		return admissionSession{}, err
	}

	var storedTarget, storedRevision, storedDigest string
	var candidate admissionSession
	var used bool
	err := querier.QueryRowContext(ctx,
		`SELECT target_id, target_revision, session_scope_digest,
                created_at_unix_ms, expires_at_unix_ms, turn_number,
                EXISTS(SELECT 1 FROM session_uses u WHERE u.session_ref = sessions.session_ref)
         FROM sessions WHERE session_ref = ?`,
		sessionRef).Scan(&storedTarget, &storedRevision, &storedDigest,
		&candidate.CreatedAtUnixMS, &candidate.ExpiresAtUnixMS, &candidate.TurnNumber, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return admissionSession{}, ErrSessionScope
	}
	if err != nil {
		return admissionSession{}, fmt.Errorf("inspect sandbox session for admission: %w", err)
	}
	if used || storedTarget != targetID || storedRevision != targetRevision || storedDigest != sessionScopeDigest {
		return admissionSession{}, ErrSessionScope
	}
	return candidate, nil
}

func bindSession(
	ctx context.Context,
	tx *sql.Tx,
	run Run,
	mapping SessionMapping,
	nowMS int64,
) error {
	if err := validateSessionMapping(mapping); err != nil {
		return err
	}
	if run.SessionMode != targetmanifest.SessionOpaqueResume || run.SessionMaxAgeSeconds <= 0 ||
		run.SessionMaxTurns <= 0 || run.SessionTurnNumber < 1 ||
		run.SessionTurnNumber > run.SessionMaxTurns {
		return fmt.Errorf("%w: Run lacks resumable session lifecycle authority", ErrInvalidArgument)
	}
	// A completion observed before this Run's durable admission time is a clock
	// rollback. Refusing it keeps each successor's created-at watermark
	// monotonic; otherwise a child could lower the rollback floor inherited by
	// the next resume.
	if nowMS < run.CreatedAt.UnixMilli() {
		return ErrSessionScope
	}
	var parent any
	lineageStarted := run.CreatedAt.UnixMilli()
	expiresAt := lineageStarted + run.SessionMaxAgeSeconds*1000
	turnNumber := int64(1)
	if run.RequestedSessionRef != nil {
		parent = *run.RequestedSessionRef
		var parentTurn int64
		if err := tx.QueryRowContext(ctx, `SELECT
                parent.lineage_started_at_unix_ms,
                parent.expires_at_unix_ms,
                parent.turn_number
            FROM sessions AS parent
            JOIN session_uses AS used ON used.session_ref = parent.session_ref
            WHERE parent.session_ref = ? AND used.run_id = ?
              AND parent.target_id = ? AND parent.target_revision = ?
              AND parent.session_scope_digest = ?`,
			*run.RequestedSessionRef, run.RunID, run.TargetID, run.TargetRevision,
			run.SessionScopeDigest,
		).Scan(&lineageStarted, &expiresAt, &parentTurn); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSessionScope
			}
			return fmt.Errorf("read parent session lineage: %w", err)
		}
		turnNumber = parentTurn + 1
	}
	if turnNumber != run.SessionTurnNumber || expiresAt <= lineageStarted {
		return ErrSessionScope
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO sessions(
        session_ref, target_id, target_revision, session_scope_digest,
		vendor_token, parent_session_ref, created_by_run_id,
		lineage_started_at_unix_ms, expires_at_unix_ms, turn_number,
		created_at_unix_ms
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		mapping.Ref, run.TargetID, run.TargetRevision, run.SessionScopeDigest,
		mapping.VendorToken, parent, run.RunID, lineageStarted, expiresAt, turnNumber, nowMS)
	if err != nil {
		var storedTarget, storedRevision, storedDigest, storedToken, storedRun string
		var storedParent sql.NullString
		var storedStarted, storedExpires, storedTurn int64
		lookupErr := tx.QueryRowContext(ctx,
			`SELECT target_id, target_revision, session_scope_digest, vendor_token,
			        parent_session_ref, created_by_run_id,
			        lineage_started_at_unix_ms, expires_at_unix_ms, turn_number
             FROM sessions WHERE session_ref = ?`, mapping.Ref,
		).Scan(&storedTarget, &storedRevision, &storedDigest, &storedToken,
			&storedParent, &storedRun, &storedStarted, &storedExpires, &storedTurn)
		if errors.Is(lookupErr, sql.ErrNoRows) {
			return fmt.Errorf("bind sandbox session: %w", err)
		}
		if lookupErr != nil {
			return fmt.Errorf("inspect failed sandbox session binding: %w", lookupErr)
		}
		if storedTarget != run.TargetID || storedRevision != run.TargetRevision ||
			storedDigest != run.SessionScopeDigest || storedToken != mapping.VendorToken ||
			!sameNullableParent(storedParent, run.RequestedSessionRef) || storedRun != run.RunID ||
			storedStarted != lineageStarted || storedExpires != expiresAt || storedTurn != turnNumber {
			return ErrConflict
		}
		return nil
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect sandbox session binding: %w", err)
	}
	if rows != 1 {
		return fmt.Errorf("bind sandbox session changed %d rows", rows)
	}
	return nil
}

func validateSessionLookup(sessionRef, targetID, targetRevision, sessionScopeDigest string) error {
	if err := validateSessionRef(sessionRef); err != nil {
		return err
	}
	if err := validateLogicalID("target_id", targetID, 128); err != nil {
		return err
	}
	if err := validateLogicalID("target_revision", targetRevision, 160); err != nil {
		return err
	}
	if err := sessionauth.ValidateDigest(sessionScopeDigest); err != nil {
		return fmt.Errorf("%w: invalid session scope digest", ErrInvalidArgument)
	}
	return nil
}

func sameNullableParent(stored sql.NullString, expected *string) bool {
	if expected == nil {
		return !stored.Valid
	}
	return stored.Valid && stored.String == *expected
}

func validateSessionRef(sessionRef string) error {
	mapping := SessionMapping{Ref: sessionRef, VendorToken: "validation"}
	return validateSessionMapping(mapping)
}
