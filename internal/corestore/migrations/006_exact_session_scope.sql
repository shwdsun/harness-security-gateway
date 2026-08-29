DROP TABLE sessions;

CREATE TABLE sessions (
    binding_fingerprint TEXT NOT NULL CHECK (
        length(binding_fingerprint) = 64
        AND binding_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    connector_id       TEXT NOT NULL,
    actor_ref          TEXT NOT NULL,
    conversation_ref   TEXT NOT NULL,
    target_id          TEXT NOT NULL,
    target_revision    TEXT NOT NULL,
    session_ref        TEXT NOT NULL,
    updated_at_ms      INTEGER NOT NULL CHECK (updated_at_ms > 0),
    PRIMARY KEY (
        binding_fingerprint, connector_id, actor_ref, conversation_ref,
        target_id, target_revision
    )
) STRICT, WITHOUT ROWID;

CREATE TRIGGER runs_session_scope_immutable
BEFORE UPDATE OF actor_ref, target_id, target_revision ON runs
WHEN NEW.actor_ref IS NOT OLD.actor_ref
  OR NEW.target_id IS NOT OLD.target_id
  OR NEW.target_revision IS NOT OLD.target_revision
BEGIN
    SELECT RAISE(ABORT, 'Run session scope is immutable');
END;

CREATE TRIGGER sessions_scope_key_immutable
BEFORE UPDATE OF binding_fingerprint, connector_id, actor_ref,
                 conversation_ref, target_id, target_revision ON sessions
WHEN NEW.binding_fingerprint IS NOT OLD.binding_fingerprint
  OR NEW.connector_id IS NOT OLD.connector_id
  OR NEW.actor_ref IS NOT OLD.actor_ref
  OR NEW.conversation_ref IS NOT OLD.conversation_ref
  OR NEW.target_id IS NOT OLD.target_id
  OR NEW.target_revision IS NOT OLD.target_revision
BEGIN
    SELECT RAISE(ABORT, 'session scope key is immutable');
END;
