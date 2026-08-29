package corestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func (s *Store) GetSession(ctx context.Context, key SessionKey) (Session, bool, error) {
	if err := validateSessionKey(key); err != nil {
		return Session{}, false, err
	}
	var session Session
	var updatedAt int64
	err := s.db.QueryRowContext(ctx, `
SELECT binding_fingerprint, connector_id, actor_ref, conversation_ref,
       target_id, target_revision, session_ref, updated_at_ms
FROM sessions
WHERE binding_fingerprint = ? AND connector_id = ? AND actor_ref = ?
  AND conversation_ref = ? AND target_id = ? AND target_revision = ?`,
		key.BindingFingerprint, key.ConnectorID, key.ActorRef,
		key.ConversationRef, key.TargetID, key.TargetRevision,
	).Scan(
		&session.BindingFingerprint, &session.ConnectorID, &session.ActorRef,
		&session.ConversationRef, &session.TargetID, &session.TargetRevision,
		&session.Ref, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, fmt.Errorf("get session: %w", err)
	}
	session.UpdatedAt = timeFromMillis(updatedAt)
	return session, true, nil
}

func putSessionTx(ctx context.Context, tx *sql.Tx, session Session, now int64) error {
	if _, err := tx.ExecContext(ctx, `
INSERT INTO sessions(
    binding_fingerprint, connector_id, actor_ref, conversation_ref,
    target_id, target_revision, session_ref, updated_at_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(binding_fingerprint, connector_id, actor_ref, conversation_ref,
            target_id, target_revision)
DO UPDATE SET session_ref = excluded.session_ref, updated_at_ms = excluded.updated_at_ms`,
		session.BindingFingerprint, session.ConnectorID, session.ActorRef,
		session.ConversationRef, session.TargetID, session.TargetRevision,
		session.Ref, now,
	); err != nil {
		return fmt.Errorf("put session: %w", err)
	}
	return nil
}
