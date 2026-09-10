package sandboxstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
)

var (
	ErrCredentialBusy      = errors.New("sandboxstore: credential source is occupied")
	ErrCredentialAuthority = errors.New("sandboxstore: credential authority unavailable")
)

// CredentialGeneration is a trusted local enrollment result, never wire input.
// SourceDigest must identify a canonical source supplied by a trusted resolver;
// a digest of token bytes, a caller-chosen ref, or a path alone is not proof.
// This store currently has synthetic callers only; it does not inspect sources.
type CredentialGeneration struct {
	SlotRef        string
	Generation     int64
	SourceDigest   string
	WorkspaceRef   string
	AuthProfileRef string
	ScopeDigest    string
}

// CredentialRef freezes an enrolled generation on a new TargetRevision.
// Nil on TargetAuthority explicitly means no credential, including old mocks.
type CredentialRef struct {
	SlotRef    string
	Generation int64
}

func validateCredentialRef(ref CredentialRef) error {
	if validateRunnerStateRef(ref.SlotRef) != nil || validateLogicalID("credential slot", ref.SlotRef, MaxWorkspaceIDBytes) != nil || ref.Generation <= 0 {
		return ErrInvalidArgument
	}
	return nil
}

func validateCredentialGeneration(g CredentialGeneration) error {
	if validateCredentialRef(CredentialRef{g.SlotRef, g.Generation}) != nil ||
		validateSHA256("source digest", g.SourceDigest) != nil || validateSHA256("scope digest", g.ScopeDigest) != nil ||
		validateLogicalID("workspace", g.WorkspaceRef, MaxWorkspaceIDBytes) != nil ||
		validateLogicalID("auth profile", g.AuthProfileRef, MaxWorkspaceIDBytes) != nil {
		return ErrInvalidArgument
	}
	return nil
}

// RegisterCredentialGeneration preserves proofless synthetic enrollment. It
// cannot replay or downgrade a generation registered with a proof. Production
// enrollment must use RegisterCredentialEnrollment after trusted resolution.
func (s *Store) RegisterCredentialGeneration(ctx context.Context, g CredentialGeneration) error {
	return s.registerCredentialGeneration(ctx, g, nil)
}

// registerCredentialGeneration keeps both entrypoints in the same transaction.
// New generations require retired, unoccupied history. Source ownership remains
// permanent within this non-rolled-back database lineage.
func (s *Store) registerCredentialGeneration(ctx context.Context, g CredentialGeneration, proof *credentialsource.Proof) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if err := validateCredentialGeneration(g); err != nil {
		return err
	}
	if proof != nil && proof.Validate() != nil {
		return ErrInvalidArgument
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	old, oldProof, err := loadCredentialGeneration(ctx, tx, CredentialRef{g.SlotRef, g.Generation})
	if err == nil {
		if old != g || (oldProof == nil) != (proof == nil) {
			return ErrConflict
		}
		if proof != nil && *oldProof != *proof {
			return ErrConflict
		}
		return tx.Commit() // Exact replay never removes a revocation.
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	var maximum int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(generation),0) FROM credential_generations WHERE slot_ref = ?`, g.SlotRef).Scan(&maximum); err != nil {
		return err
	}
	if g.Generation <= maximum {
		return ErrConflict
	}
	if maximum != 0 {
		var retired, occupied bool
		if err := tx.QueryRowContext(ctx, `SELECT
EXISTS(SELECT 1 FROM credential_revocations WHERE slot_ref = ? AND generation = ?),
EXISTS(SELECT 1 FROM credential_occupancy WHERE slot_ref = ?)`, g.SlotRef, maximum, g.SlotRef).Scan(&retired, &occupied); err != nil {
			return err
		}
		if occupied {
			return ErrCredentialBusy
		}
		if !retired {
			return ErrCredentialAuthority
		}
	}
	var owner string
	err = tx.QueryRowContext(ctx, `SELECT slot_ref FROM credential_sources WHERE source_digest = ?`, g.SourceDigest).Scan(&owner)
	if err == nil && owner != g.SlotRef {
		return ErrConflict
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO credential_sources(source_digest,slot_ref) VALUES (?,?)`, g.SourceDigest, g.SlotRef); err != nil {
			return err
		}
	}
	var pins [4]any // SQL NULL is the explicit proofless synthetic form.
	if proof != nil {
		pins = [4]any{proof.Scheme, proof.RootObjectDigest, proof.SlotObjectDigest, proof.LocatorDigest}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO credential_generations
(slot_ref,generation,source_digest,workspace_ref,auth_profile_ref,scope_digest,
 proof_scheme,root_object_digest,slot_object_digest,locator_digest) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		g.SlotRef, g.Generation, g.SourceDigest, g.WorkspaceRef, g.AuthProfileRef, g.ScopeDigest,
		pins[0], pins[1], pins[2], pins[3]); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeCredentialGeneration prevents new admission/Create intents. It does
// not revoke a provider token, roll back a refresh, cancel an already granted
// Create or running container, or release its durable occupancy.
func (s *Store) RevokeCredentialGeneration(ctx context.Context, ref CredentialRef) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if err := validateCredentialRef(ref); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO credential_revocations(slot_ref,generation)
SELECT slot_ref,generation FROM credential_generations WHERE slot_ref = ? AND generation = ?`, ref.SlotRef, ref.Generation)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	var found bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM credential_revocations WHERE slot_ref = ? AND generation = ?)`, ref.SlotRef, ref.Generation).Scan(&found); err != nil {
		return err
	}
	if !found {
		return ErrCredentialAuthority
	}
	return nil
}

// RevokeRunCredential retires only the generation joined to this Run's retained
// occupancy and immutable target. Failed admission, unrelated Runs and already
// released occupants cannot revoke another Run's source. It preserves occupancy
// and cleanup authority, and works for proofless history and repeated revocation.
func (s *Store) RevokeRunCredential(ctx context.Context, runID string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if err := validateRunID(runID); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	run, err := getRunQuerier(ctx, tx, runID)
	if err != nil {
		return err
	}
	if !run.CredentialRequired {
		return ErrCredentialAuthority
	}
	if err := requireRunCredential(ctx, tx, run, true); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO credential_revocations(slot_ref,generation)
SELECT slot_ref,generation FROM credential_occupancy WHERE run_id=?`, runID); err != nil {
		return err
	}
	return tx.Commit()
}

// RetireOccupiedCredentialGenerations revokes every generation referenced by
// retained Run occupancy in one transaction. The exclusive sandbox mutation
// owner calls this at startup, before permitting new credential work. It is
// idempotent and does not run implicitly in Open or ordinary reconciliation.
// Occupancy, enrollment and any granted runtime intent/reference remain intact
// for cleanup; idle generations and provider tokens are unaffected.
func (s *Store) RetireOccupiedCredentialGenerations(ctx context.Context) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin occupied credential retirement: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO credential_revocations(slot_ref,generation)
SELECT o.slot_ref,o.generation FROM credential_occupancy o
WHERE NOT EXISTS (SELECT 1 FROM credential_revocations v
                  WHERE v.slot_ref=o.slot_ref AND v.generation=o.generation)`); err != nil {
		return fmt.Errorf("retire occupied credential generations: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit occupied credential retirement: %w", err)
	}
	return nil
}

func registerTargetCredential(ctx context.Context, tx *sql.Tx, a TargetAuthority, existed bool) error {
	var ref CredentialRef
	err := tx.QueryRowContext(ctx, `SELECT slot_ref,generation FROM target_credentials WHERE target_id = ? AND target_revision = ?`, a.TargetID, a.TargetRevision).Scan(&ref.SlotRef, &ref.Generation)
	if a.Credential == nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return ErrConflict
	}
	if err == nil {
		if ref != *a.Credential {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if existed {
		return ErrCredentialAuthority
	}
	var valid bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM credential_generations g
WHERE slot_ref = ? AND generation = ? AND NOT EXISTS
(SELECT 1 FROM credential_revocations r WHERE r.slot_ref = g.slot_ref AND r.generation = g.generation))`, a.Credential.SlotRef, a.Credential.Generation).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return ErrCredentialAuthority
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO target_credentials(target_id,target_revision,slot_ref,generation) VALUES (?,?,?,?)`, a.TargetID, a.TargetRevision, a.Credential.SlotRef, a.Credential.Generation)
	return err
}

func acquireRunCredential(ctx context.Context, tx *sql.Tx, run Run) error {
	if !run.CredentialRequired {
		if run.CredentialLeaseHeld {
			return ErrCredentialAuthority
		}
		return nil
	}
	var g CredentialGeneration
	err := tx.QueryRowContext(ctx, `SELECT g.slot_ref,g.generation,g.source_digest,g.workspace_ref,g.auth_profile_ref,g.scope_digest
FROM target_credentials t JOIN credential_generations g USING(slot_ref,generation)
WHERE t.target_id = ? AND t.target_revision = ? AND NOT EXISTS
(SELECT 1 FROM credential_revocations v WHERE v.slot_ref = g.slot_ref AND v.generation = g.generation)`, run.TargetID, run.TargetRevision).
		Scan(&g.SlotRef, &g.Generation, &g.SourceDigest, &g.WorkspaceRef, &g.AuthProfileRef, &g.ScopeDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCredentialAuthority
	}
	if err != nil {
		return err
	}
	if g.ScopeDigest != run.SessionScopeDigest || g.WorkspaceRef != run.WorkspaceID {
		return ErrCredentialAuthority
	}
	var busy bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM credential_occupancy WHERE source_digest = ? OR slot_ref = ? OR run_id = ?)`, g.SourceDigest, g.SlotRef, run.RunID).Scan(&busy); err != nil {
		return err
	}
	if busy {
		return ErrCredentialBusy
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO credential_occupancy(source_digest,slot_ref,generation,run_id,acquired_at_unix_ms) VALUES (?,?,?,?,?)`, g.SourceDigest, g.SlotRef, g.Generation, run.RunID, time.Now().UTC().UnixMilli())
	return err
}

func requireRunCredential(ctx context.Context, q queryRower, run Run, allowRevoked bool) error {
	if !run.CredentialRequired {
		if run.CredentialLeaseHeld {
			return ErrCredentialAuthority
		}
		return nil
	}
	var valid bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM credential_occupancy o
JOIN target_credentials t ON t.target_id = ? AND t.target_revision = ? AND t.slot_ref = o.slot_ref AND t.generation = o.generation
JOIN credential_generations g ON g.slot_ref = o.slot_ref AND g.generation = o.generation AND g.source_digest = o.source_digest
WHERE o.run_id = ? AND g.workspace_ref = ? AND g.scope_digest = ? AND
(? OR NOT EXISTS(SELECT 1 FROM credential_revocations v WHERE v.slot_ref = g.slot_ref AND v.generation = g.generation)))`,
		run.TargetID, run.TargetRevision, run.RunID, run.WorkspaceID, run.SessionScopeDigest, allowRevoked).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrCredentialAuthority
	}
	return nil
}

func (s *Store) verifyCredentialIntegrity(ctx context.Context) error {
	var invalid bool
	err := s.db.QueryRowContext(ctx, `SELECT
EXISTS(SELECT 1 FROM target_revisions tr WHERE (tr.credential_kind = 'bound') !=
 EXISTS(SELECT 1 FROM target_credentials t WHERE t.target_id=tr.target_id AND t.target_revision=tr.revision))
OR EXISTS(SELECT 1 FROM credential_occupancy o WHERE NOT EXISTS
 (SELECT 1 FROM runs r JOIN target_credentials t ON t.target_id=r.target_id AND t.target_revision=r.target_revision
 JOIN credential_generations g ON g.slot_ref=t.slot_ref AND g.generation=t.generation
 WHERE r.run_id=o.run_id AND o.slot_ref=g.slot_ref AND o.generation=g.generation AND o.source_digest=g.source_digest
 AND r.workspace_id=g.workspace_ref AND r.session_scope_digest=g.scope_digest))
OR EXISTS(SELECT 1 FROM runs r JOIN target_revisions tr ON tr.target_id=r.target_id AND tr.revision=r.target_revision
 WHERE tr.credential_kind='bound' AND (r.state IN ('accepted','running','cancelling') OR r.runtime_ref IS NOT NULL OR r.runtime_intent_pending=1
 OR EXISTS(SELECT 1 FROM staged_terminals st WHERE st.run_id=r.run_id)
 OR EXISTS(SELECT 1 FROM workspace_locks w WHERE w.run_id=r.run_id))
 AND NOT EXISTS(SELECT 1 FROM credential_occupancy o WHERE o.run_id=r.run_id))`).Scan(&invalid)
	if err != nil {
		return fmt.Errorf("verify credential integrity: %w", err)
	}
	if invalid {
		return ErrCredentialAuthority
	}
	return s.verifyCredentialEnrollmentIntegrity(ctx)
}
