CREATE TABLE runs (
    id                  TEXT PRIMARY KEY,
    connector_id        TEXT NOT NULL,
    event_id            TEXT NOT NULL,
    actor_ref           TEXT NOT NULL,
    conversation_ref    TEXT NOT NULL,
    message_ref         TEXT NOT NULL,
    target_id           TEXT NOT NULL,
    target_revision     TEXT NOT NULL,
    input_text          TEXT NOT NULL,
    state               TEXT NOT NULL CHECK (state IN (
                            'queued', 'dispatching', 'running', 'completed',
                            'failed', 'cancelled', 'interrupted'
                        )),
    dispatch_token      TEXT,
    dispatch_expires_at_ms INTEGER,
    dispatch_attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (dispatch_attempt_count >= 0),
    start_prepared      INTEGER NOT NULL DEFAULT 0 CHECK (start_prepared IN (0, 1)),
    start_session_ref   TEXT,
    start_deadline_ms   INTEGER,
    output_text         TEXT,
    failure_code        TEXT CHECK (failure_code IS NULL OR failure_code IN (
                            'target_unavailable', 'revision_mismatch',
                            'invalid_session', 'policy_denied',
                            'deadline_exceeded', 'output_limit_exceeded',
                            'runner_failed', 'protocol_violation',
                            'runtime_interrupted', 'internal'
                        )),
    result_session_ref  TEXT,
    created_at_ms       INTEGER NOT NULL CHECK (created_at_ms > 0),
    updated_at_ms       INTEGER NOT NULL CHECK (updated_at_ms > 0),
    CHECK (output_text IS NULL OR state = 'completed'),
    CHECK (failure_code IS NULL OR state IN ('failed', 'interrupted')),
    CHECK (result_session_ref IS NULL OR state = 'completed'),
    CHECK (state != 'completed' OR output_text IS NOT NULL),
    CHECK (state != 'failed' OR failure_code IS NOT NULL),
    CHECK (state != 'failed' OR failure_code != 'runtime_interrupted'),
    CHECK (state != 'interrupted' OR failure_code = 'runtime_interrupted'),
    CHECK (
        (start_prepared = 0 AND start_session_ref IS NULL AND start_deadline_ms IS NULL)
        OR
        (start_prepared = 1 AND start_deadline_ms IS NOT NULL
            AND start_deadline_ms > 0 AND start_deadline_ms <= 253402300799999)
    ),
    CHECK (start_session_ref IS NULL OR
        length(CAST(start_session_ref AS BLOB)) BETWEEN 1 AND 512),
    CHECK (state NOT IN ('running', 'completed', 'failed', 'cancelled', 'interrupted')
        OR start_prepared = 1),
    CHECK (
        (state = 'queued' AND dispatch_token IS NULL AND dispatch_expires_at_ms IS NULL)
        OR
        (state = 'dispatching' AND dispatch_token IS NOT NULL AND dispatch_expires_at_ms IS NOT NULL)
        OR
        (state IN ('running', 'completed', 'failed', 'cancelled', 'interrupted')
            AND dispatch_token IS NOT NULL AND dispatch_expires_at_ms IS NULL)
    )
) STRICT;

CREATE TABLE inbound_events (
    connector_id       TEXT NOT NULL,
    event_id           TEXT NOT NULL,
    payload_hash       BLOB NOT NULL CHECK (length(payload_hash) = 32),
    run_id             TEXT NOT NULL UNIQUE REFERENCES runs(id) ON DELETE RESTRICT,
    occurred_at_ms     INTEGER NOT NULL CHECK (occurred_at_ms > 0),
    received_at_ms     INTEGER NOT NULL CHECK (received_at_ms > 0),
    PRIMARY KEY (connector_id, event_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX runs_queue_order ON runs(state, created_at_ms, id);
CREATE UNIQUE INDEX runs_dispatch_token
    ON runs(dispatch_token) WHERE dispatch_token IS NOT NULL;

CREATE TABLE sessions (
    connector_id       TEXT NOT NULL,
    conversation_ref   TEXT NOT NULL,
    target_id          TEXT NOT NULL,
    target_revision    TEXT NOT NULL,
    session_ref        TEXT NOT NULL,
    updated_at_ms      INTEGER NOT NULL CHECK (updated_at_ms > 0),
    PRIMARY KEY (connector_id, conversation_ref, target_id, target_revision)
) STRICT, WITHOUT ROWID;

CREATE TABLE text_deliveries (
    id                      TEXT PRIMARY KEY,
    run_id                  TEXT REFERENCES runs(id) ON DELETE RESTRICT,
    connector_id            TEXT NOT NULL,
    conversation_ref        TEXT NOT NULL,
    reply_to_ref            TEXT,
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

CREATE INDEX text_deliveries_claim
    ON text_deliveries(connector_id, state, available_at_ms, created_at_ms, id);
CREATE UNIQUE INDEX text_deliveries_run_reply
    ON text_deliveries(run_id) WHERE run_id IS NOT NULL;
CREATE UNIQUE INDEX text_deliveries_lease_token
    ON text_deliveries(lease_token) WHERE lease_token IS NOT NULL;
