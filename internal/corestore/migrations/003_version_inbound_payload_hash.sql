ALTER TABLE inbound_events ADD COLUMN payload_hash_version INTEGER NOT NULL DEFAULT 1
    CHECK (payload_hash_version IN (1, 2));
