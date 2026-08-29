CREATE TABLE text_deliveries_v5 (
    id                      TEXT PRIMARY KEY,
    run_id                  TEXT NOT NULL UNIQUE REFERENCES runs(id) ON DELETE RESTRICT,
    media_type              TEXT NOT NULL DEFAULT 'text/plain' CHECK (media_type = 'text/plain'),
    text                    TEXT NOT NULL,
    state                   TEXT NOT NULL CHECK (state IN (
                                'pending', 'leased', 'delivered', 'permanent_failed'
                            )),
    lease_token             TEXT,
    lease_expires_at_ms     INTEGER,
    attempt_count           INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at_ms         INTEGER NOT NULL CHECK (available_at_ms > 0),
    provider_message_ref    TEXT,
    failure_code            TEXT CHECK (failure_code IS NULL OR failure_code IN (
                                'temporary_failure', 'rate_limited',
                                'recipient_unavailable', 'content_rejected',
                                'not_authorized', 'connector_internal'
                            )),
    created_at_ms           INTEGER NOT NULL CHECK (created_at_ms > 0),
    updated_at_ms           INTEGER NOT NULL CHECK (updated_at_ms > 0),
    CHECK (
        (state = 'pending' AND lease_expires_at_ms IS NULL
            AND provider_message_ref IS NULL)
        OR
        (state = 'leased' AND lease_token IS NOT NULL AND lease_expires_at_ms IS NOT NULL
            AND provider_message_ref IS NULL)
        OR
        (state = 'delivered' AND lease_token IS NOT NULL AND lease_expires_at_ms IS NULL
            AND provider_message_ref IS NOT NULL AND failure_code IS NULL)
        OR
        (state = 'permanent_failed' AND lease_token IS NOT NULL AND lease_expires_at_ms IS NULL
            AND provider_message_ref IS NULL AND failure_code IS NOT NULL)
    ),
    CHECK (state NOT IN ('pending', 'leased') OR failure_code IS NULL OR failure_code IN (
        'temporary_failure', 'rate_limited', 'connector_internal'
    )),
    CHECK (state != 'permanent_failed' OR failure_code IN (
        'recipient_unavailable', 'content_rejected', 'not_authorized', 'connector_internal'
    ))
) STRICT;

INSERT INTO text_deliveries_v5(
    id, run_id, media_type, text, state, lease_token, lease_expires_at_ms,
    attempt_count, available_at_ms, provider_message_ref, failure_code,
    created_at_ms, updated_at_ms
)
SELECT
    id, run_id, media_type, text, state, lease_token, lease_expires_at_ms,
    attempt_count, available_at_ms, provider_message_ref, failure_code,
    created_at_ms, updated_at_ms
FROM text_deliveries;

DROP TABLE text_deliveries;
ALTER TABLE text_deliveries_v5 RENAME TO text_deliveries;

CREATE INDEX text_deliveries_claim
    ON text_deliveries(state, available_at_ms, created_at_ms, id);
CREATE UNIQUE INDEX text_deliveries_lease_token
    ON text_deliveries(lease_token) WHERE lease_token IS NOT NULL;

CREATE TRIGGER runs_disclosure_scope_immutable
BEFORE UPDATE OF connector_id, conversation_ref, message_ref ON runs
WHEN NEW.connector_id IS NOT OLD.connector_id
  OR NEW.conversation_ref IS NOT OLD.conversation_ref
  OR NEW.message_ref IS NOT OLD.message_ref
BEGIN
    SELECT RAISE(ABORT, 'Run disclosure scope is immutable');
END;

CREATE TRIGGER text_deliveries_run_immutable
BEFORE UPDATE OF run_id ON text_deliveries
WHEN NEW.run_id IS NOT OLD.run_id
BEGIN
    SELECT RAISE(ABORT, 'delivery parent Run is immutable');
END;
