package sandboxstore

// Append-only schema 10. Earlier migration bytes remain unchanged. Existing
// targets are explicitly credential-free; no historical credential is inferred.
const credentialMigration = `
ALTER TABLE target_revisions ADD COLUMN credential_kind TEXT NOT NULL DEFAULT 'none'
CHECK(credential_kind IN ('none','bound'));
CREATE TRIGGER target_credential_kind_immutable BEFORE UPDATE OF credential_kind ON target_revisions
WHEN NEW.credential_kind IS NOT OLD.credential_kind
BEGIN SELECT RAISE(ABORT,'credential kind is immutable'); END;

CREATE TABLE credential_sources (
 source_digest TEXT PRIMARY KEY CHECK(length(source_digest)=64),
 slot_ref TEXT NOT NULL CHECK(length(slot_ref) BETWEEN 1 AND 128),
 UNIQUE(source_digest,slot_ref)
) STRICT;
CREATE TABLE credential_generations (
 slot_ref TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>0),
 source_digest TEXT NOT NULL,
 workspace_ref TEXT NOT NULL CHECK(length(workspace_ref) BETWEEN 1 AND 128),
 auth_profile_ref TEXT NOT NULL CHECK(length(auth_profile_ref) BETWEEN 1 AND 128),
 scope_digest TEXT NOT NULL CHECK(length(scope_digest)=64),
 PRIMARY KEY(slot_ref,generation),
 FOREIGN KEY(source_digest,slot_ref) REFERENCES credential_sources(source_digest,slot_ref) ON DELETE RESTRICT
) STRICT;
CREATE TABLE credential_revocations (
 slot_ref TEXT NOT NULL, generation INTEGER NOT NULL,
 PRIMARY KEY(slot_ref,generation),
 FOREIGN KEY(slot_ref,generation) REFERENCES credential_generations(slot_ref,generation) ON DELETE RESTRICT
) STRICT;
CREATE TABLE target_credentials (
 target_id TEXT NOT NULL, target_revision TEXT NOT NULL,
 slot_ref TEXT NOT NULL, generation INTEGER NOT NULL,
 PRIMARY KEY(target_id,target_revision),
 FOREIGN KEY(target_id,target_revision) REFERENCES target_revisions(target_id,revision) ON DELETE RESTRICT,
 FOREIGN KEY(slot_ref,generation) REFERENCES credential_generations(slot_ref,generation) ON DELETE RESTRICT
) STRICT;
CREATE TABLE credential_occupancy (
 source_digest TEXT PRIMARY KEY,
 slot_ref TEXT NOT NULL UNIQUE, generation INTEGER NOT NULL,
 run_id TEXT NOT NULL UNIQUE REFERENCES runs(run_id) ON DELETE RESTRICT,
 acquired_at_unix_ms INTEGER NOT NULL,
 FOREIGN KEY(source_digest,slot_ref) REFERENCES credential_sources(source_digest,slot_ref) ON DELETE RESTRICT,
 FOREIGN KEY(slot_ref,generation) REFERENCES credential_generations(slot_ref,generation) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER credential_source_immutable BEFORE UPDATE ON credential_sources
BEGIN SELECT RAISE(ABORT,'credential source owner is immutable'); END;
CREATE TRIGGER credential_source_retained BEFORE DELETE ON credential_sources
BEGIN SELECT RAISE(ABORT,'credential source owner is retained'); END;
CREATE TRIGGER credential_generation_immutable BEFORE UPDATE ON credential_generations
BEGIN SELECT RAISE(ABORT,'credential generation is immutable'); END;
CREATE TRIGGER credential_generation_retained BEFORE DELETE ON credential_generations
BEGIN SELECT RAISE(ABORT,'credential generation is retained'); END;
CREATE TRIGGER credential_revocation_immutable BEFORE UPDATE ON credential_revocations
BEGIN SELECT RAISE(ABORT,'credential revocation is immutable'); END;
CREATE TRIGGER credential_revocation_retained BEFORE DELETE ON credential_revocations
BEGIN SELECT RAISE(ABORT,'credential revocation is retained'); END;
CREATE TRIGGER target_credential_immutable BEFORE UPDATE ON target_credentials
BEGIN SELECT RAISE(ABORT,'target credential binding is immutable'); END;
CREATE TRIGGER target_credential_retained BEFORE DELETE ON target_credentials
BEGIN SELECT RAISE(ABORT,'target credential binding is retained'); END;
CREATE TRIGGER credential_occupancy_immutable BEFORE UPDATE ON credential_occupancy
BEGIN SELECT RAISE(ABORT,'credential occupant is immutable'); END;

CREATE TRIGGER credential_generation_monotone BEFORE INSERT ON credential_generations
WHEN NEW.generation <= COALESCE((SELECT MAX(generation) FROM credential_generations WHERE slot_ref=NEW.slot_ref),0)
 OR EXISTS(SELECT 1 FROM credential_generations g WHERE g.slot_ref=NEW.slot_ref
 AND NOT EXISTS(SELECT 1 FROM credential_revocations v WHERE v.slot_ref=g.slot_ref AND v.generation=g.generation))
 OR EXISTS(SELECT 1 FROM credential_occupancy o WHERE o.slot_ref=NEW.slot_ref)
BEGIN SELECT RAISE(ABORT,'credential generation requires retired unoccupied history'); END;

CREATE TRIGGER target_credential_insert_guard BEFORE INSERT ON target_credentials
WHEN NOT EXISTS(SELECT 1 FROM target_revisions t WHERE t.target_id=NEW.target_id AND t.revision=NEW.target_revision AND t.credential_kind='bound')
 OR EXISTS(SELECT 1 FROM runs r WHERE r.target_id=NEW.target_id AND r.target_revision=NEW.target_revision)
BEGIN SELECT RAISE(ABORT,'credential binding requires a new bound target'); END;

CREATE TRIGGER credential_occupancy_insert_guard BEFORE INSERT ON credential_occupancy
WHEN NOT EXISTS(SELECT 1 FROM runs r
 JOIN target_credentials t ON t.target_id=r.target_id AND t.target_revision=r.target_revision
 JOIN credential_generations g ON g.slot_ref=t.slot_ref AND g.generation=t.generation
 WHERE r.run_id=NEW.run_id AND r.state='accepted' AND r.runtime_ref IS NULL AND r.runtime_intent_pending=0
 AND NEW.slot_ref=g.slot_ref AND NEW.generation=g.generation AND NEW.source_digest=g.source_digest
 AND r.workspace_id=g.workspace_ref AND r.session_scope_digest=g.scope_digest
 AND NOT EXISTS(SELECT 1 FROM credential_revocations v WHERE v.slot_ref=g.slot_ref AND v.generation=g.generation)
 AND NOT EXISTS(SELECT 1 FROM staged_terminals st WHERE st.run_id=r.run_id))
BEGIN SELECT RAISE(ABORT,'credential occupancy does not match admission'); END;

CREATE TRIGGER credential_create_guard BEFORE UPDATE OF runtime_intent_pending ON runs
WHEN OLD.runtime_intent_pending=0 AND NEW.runtime_intent_pending=1
 AND EXISTS(SELECT 1 FROM target_revisions t WHERE t.target_id=NEW.target_id AND t.revision=NEW.target_revision AND t.credential_kind='bound')
 AND NOT EXISTS(SELECT 1 FROM credential_occupancy o JOIN target_credentials t
 ON t.target_id=NEW.target_id AND t.target_revision=NEW.target_revision AND t.slot_ref=o.slot_ref AND t.generation=o.generation
 WHERE o.run_id=NEW.run_id AND NOT EXISTS(SELECT 1 FROM credential_revocations v WHERE v.slot_ref=o.slot_ref AND v.generation=o.generation))
BEGIN SELECT RAISE(ABORT,'Create requires current credential occupancy'); END;

CREATE TRIGGER credential_terminal_requires_candidate BEFORE UPDATE OF state ON runs
WHEN OLD.state!=NEW.state AND NEW.state IN ('completed','failed','cancelled','interrupted')
 AND EXISTS(SELECT 1 FROM target_revisions t WHERE t.target_id=NEW.target_id AND t.revision=NEW.target_revision AND t.credential_kind='bound')
 AND (NOT EXISTS(SELECT 1 FROM staged_terminals st WHERE st.run_id=NEW.run_id)
 OR NOT EXISTS(SELECT 1 FROM credential_occupancy o WHERE o.run_id=NEW.run_id))
BEGIN SELECT RAISE(ABORT,'credential terminal requires staged cleanup publication'); END;

CREATE TRIGGER credential_release_guard BEFORE DELETE ON credential_occupancy
WHEN NOT EXISTS(SELECT 1 FROM runs r WHERE r.run_id=OLD.run_id
 AND r.state IN ('completed','failed','cancelled','interrupted') AND r.runtime_ref IS NULL AND r.runtime_intent_pending=0
 AND NOT EXISTS(SELECT 1 FROM workspace_locks w WHERE w.run_id=r.run_id))
BEGIN SELECT RAISE(ABORT,'credential release requires cleanup publication'); END;
CREATE TRIGGER credential_candidate_retirement_guard BEFORE DELETE ON staged_terminals
WHEN EXISTS(SELECT 1 FROM credential_occupancy o WHERE o.run_id=OLD.run_id)
BEGIN SELECT RAISE(ABORT,'candidate retirement requires credential release'); END;
`
