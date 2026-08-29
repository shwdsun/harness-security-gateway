ALTER TABLE runs ADD COLUMN binding_fingerprint TEXT
    CHECK (binding_fingerprint IS NULL OR (
        length(binding_fingerprint) = 64
        AND binding_fingerprint NOT GLOB '*[^0-9a-f]*'
    ));

ALTER TABLE runs ADD COLUMN policy_revision TEXT
    CHECK (policy_revision IS NULL OR (
        length(policy_revision) = 64
        AND policy_revision NOT GLOB '*[^0-9a-f]*'
    ));

CREATE TRIGGER runs_require_exact_binding_evidence_insert
BEFORE INSERT ON runs
WHEN NEW.binding_fingerprint IS NULL OR NEW.policy_revision IS NULL
BEGIN
    SELECT RAISE(ABORT, 'new Run requires exact binding evidence');
END;

CREATE TRIGGER runs_exact_binding_evidence_immutable
BEFORE UPDATE OF binding_fingerprint, policy_revision ON runs
WHEN NEW.binding_fingerprint IS NOT OLD.binding_fingerprint
  OR NEW.policy_revision IS NOT OLD.policy_revision
BEGIN
    SELECT RAISE(ABORT, 'Run exact binding evidence is immutable');
END;
