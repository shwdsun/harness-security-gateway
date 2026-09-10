package sandboxstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
)

// RegisterCredentialEnrollment atomically records supplied generation and proof
// under the caller's exclusive sandbox mutation ownership. The caller must
// already have resolved and checked the exact held source and approved scope.
// This store does not inspect a credential or grant a mount/Create. A constructed
// proof is not trusted evidence. All current callers are synthetic tests.
// Exact replay includes proof presence/content and never removes revocation.
func (s *Store) RegisterCredentialEnrollment(ctx context.Context, g CredentialGeneration, proof credentialsource.Proof) error {
	return s.registerCredentialGeneration(ctx, g, &proof)
}

// GetCredentialEnrollment reads one immutable historical generation/proof pair,
// including if revoked. Missing proof is rejected, never inferred or backfilled.
// This permits resolving an uncertain registration commit by exact comparison;
// success is not current authority, physical continuity or Run readiness.
func (s *Store) GetCredentialEnrollment(ctx context.Context, ref CredentialRef) (CredentialGeneration, credentialsource.Proof, error) {
	if err := s.ready(ctx); err != nil {
		return CredentialGeneration{}, credentialsource.Proof{}, err
	}
	if err := validateCredentialRef(ref); err != nil {
		return CredentialGeneration{}, credentialsource.Proof{}, err
	}
	g, proof, err := loadCredentialGeneration(ctx, s.db, ref)
	if err != nil {
		return CredentialGeneration{}, credentialsource.Proof{}, err
	}
	if proof == nil {
		return CredentialGeneration{}, credentialsource.Proof{}, ErrCredentialAuthority
	}
	return g, *proof, nil
}

// GetRunCredentialEnrollment reads only the enrollment owned by one accepted,
// occupied Run with no runtime intent/reference or staged outcome. The exact
// Run/target/source/workspace/scope join and revocation check share a snapshot.
// This does not acquire a file or cache readiness: BeginRuntimeIntent must
// still check current authority after the controller's physical comparison.
func (s *Store) GetRunCredentialEnrollment(ctx context.Context, runID string) (CredentialGeneration, credentialsource.Proof, error) {
	if err := s.ready(ctx); err != nil {
		return CredentialGeneration{}, credentialsource.Proof{}, err
	}
	if err := validateRunID(runID); err != nil {
		return CredentialGeneration{}, credentialsource.Proof{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CredentialGeneration{}, credentialsource.Proof{}, err
	}
	defer tx.Rollback()
	run, err := getRunQuerier(ctx, tx, runID)
	if err != nil {
		return CredentialGeneration{}, credentialsource.Proof{}, err
	}
	if !run.CredentialRequired || run.State != executionwire.RunStateAccepted ||
		run.RuntimeIntentPending || run.RuntimeRef != nil || run.TerminalPending {
		return CredentialGeneration{}, credentialsource.Proof{}, ErrCredentialAuthority
	}
	if err := requireRunCredential(ctx, tx, run, false); err != nil {
		return CredentialGeneration{}, credentialsource.Proof{}, err
	}
	var ref CredentialRef
	if err := tx.QueryRowContext(ctx, `SELECT slot_ref,generation FROM credential_occupancy WHERE run_id=?`, runID).
		Scan(&ref.SlotRef, &ref.Generation); err != nil {
		return CredentialGeneration{}, credentialsource.Proof{}, err
	}
	g, proof, err := loadCredentialGeneration(ctx, tx, ref)
	if err != nil {
		return CredentialGeneration{}, credentialsource.Proof{}, err
	}
	if proof == nil {
		return CredentialGeneration{}, credentialsource.Proof{}, ErrCredentialAuthority
	}
	if err := tx.Commit(); err != nil {
		return CredentialGeneration{}, credentialsource.Proof{}, err
	}
	return g, *proof, nil
}

const credentialGenerationColumns = `slot_ref,generation,source_digest,workspace_ref,auth_profile_ref,scope_digest,
proof_scheme,root_object_digest,slot_object_digest,locator_digest`

func loadCredentialGeneration(ctx context.Context, q queryRower, ref CredentialRef) (CredentialGeneration, *credentialsource.Proof, error) {
	return scanCredentialGeneration(q.QueryRowContext(ctx, `SELECT `+credentialGenerationColumns+`
FROM credential_generations WHERE slot_ref=? AND generation=?`, ref.SlotRef, ref.Generation))
}

func scanCredentialGeneration(row interface{ Scan(...any) error }) (CredentialGeneration, *credentialsource.Proof, error) {
	var g CredentialGeneration
	var pins [4]sql.NullString
	err := row.Scan(&g.SlotRef, &g.Generation, &g.SourceDigest, &g.WorkspaceRef, &g.AuthProfileRef, &g.ScopeDigest,
		&pins[0], &pins[1], &pins[2], &pins[3])
	if errors.Is(err, sql.ErrNoRows) {
		return CredentialGeneration{}, nil, ErrNotFound
	}
	if err != nil {
		return CredentialGeneration{}, nil, err
	}
	if validateCredentialGeneration(g) != nil {
		return CredentialGeneration{}, nil, ErrCredentialAuthority
	}
	var present int
	for _, pin := range pins {
		if pin.Valid {
			present++
		}
	}
	if present == 0 {
		return g, nil, nil
	}
	proof := credentialsource.Proof{Scheme: pins[0].String, RootObjectDigest: pins[1].String,
		SlotObjectDigest: pins[2].String, LocatorDigest: pins[3].String}
	if present != len(pins) || proof.Validate() != nil {
		return CredentialGeneration{}, nil, ErrCredentialAuthority
	}
	return g, &proof, nil
}

func (s *Store) verifyCredentialEnrollmentIntegrity(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT `+credentialGenerationColumns+` FROM credential_generations`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if _, _, err := scanCredentialGeneration(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}
