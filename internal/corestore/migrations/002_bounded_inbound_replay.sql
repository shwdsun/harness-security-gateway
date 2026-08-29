CREATE TABLE inbound_event_horizons (
    connector_id      TEXT PRIMARY KEY,
    evicted_through_ms INTEGER NOT NULL CHECK (evicted_through_ms >= 0)
) STRICT, WITHOUT ROWID;

CREATE INDEX inbound_events_eviction
    ON inbound_events(connector_id, occurred_at_ms, event_id);
