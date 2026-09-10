package sandboxstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// RegisterTargetAuthorities atomically pins the complete configured target
// batch and permanently assigns each runner-state ref and resolved-path digest
// to one exact TargetRevision. An exact retry is idempotent. A directory which
// has no exact durable owner may receive its first owner only when the trusted
// caller proves that the resolved path was absent before registration.
// Credential refs on this low-level path retain synthetic registration
// semantics: the supplied pin is not checked for credential proof/scope content.
// Real enrollment consumers must use RegisterEnrolledTargetAuthorities.
func (s *Store) RegisterTargetAuthorities(ctx context.Context, authorities []TargetAuthority) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if len(authorities) == 0 {
		return fmt.Errorf("%w: target authorities must not be empty", ErrInvalidArgument)
	}
	if err := validateTargetAuthorityBatch(authorities); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin target authority registration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, authority := range authorities {
		if err := registerTargetAuthority(ctx, tx, authority); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit target authority registration: %w", err)
	}
	return nil
}

func validateTargetAuthorityBatch(authorities []TargetAuthority) error {
	targets := make(map[string]struct{}, len(authorities))
	stateRefs := make(map[string]struct{}, len(authorities))
	pathDigests := make(map[string]struct{}, len(authorities))
	for index, authority := range authorities {
		if err := validateLogicalID("target_id", authority.TargetID, executionTargetIDMax); err != nil {
			return fmt.Errorf("target authority %d: %w", index, err)
		}
		if err := validateLogicalID("target_revision", authority.TargetRevision, executionRevisionMax); err != nil {
			return fmt.Errorf("target authority %d: %w", index, err)
		}
		if err := validateSHA256("revision pin", authority.RevisionPin); err != nil {
			return fmt.Errorf("target authority %d: %w", index, err)
		}
		if authority.Credential != nil {
			if err := validateCredentialRef(*authority.Credential); err != nil {
				return err
			}
		}
		targetKey := authority.TargetID + "\x00" + authority.TargetRevision
		if _, exists := targets[targetKey]; exists {
			return ErrConflict
		}
		targets[targetKey] = struct{}{}
		switch authority.RunnerStateKind {
		case targetmanifest.RunnerStateNone:
			if authority.RunnerStateRef != "" || authority.RunnerStatePathDigest != "" || authority.StatePathAbsent {
				return fmt.Errorf("%w: none cannot carry runner-state ownership evidence", ErrInvalidArgument)
			}
			continue
		case targetmanifest.RunnerStatePersistent:
		default:
			return fmt.Errorf("%w: runner-state kind must be explicit", ErrInvalidArgument)
		}
		if err := validateLogicalID("runner_state_ref", authority.RunnerStateRef, MaxWorkspaceIDBytes); err != nil {
			return fmt.Errorf("target authority %d: %w", index, err)
		}
		if err := validateRunnerStateRef(authority.RunnerStateRef); err != nil {
			return fmt.Errorf("target authority %d: %w", index, err)
		}
		if err := validateSHA256("runner-state path digest", authority.RunnerStatePathDigest); err != nil {
			return fmt.Errorf("target authority %d: %w", index, err)
		}

		if _, exists := stateRefs[authority.RunnerStateRef]; exists {
			return ErrConflict
		}
		if _, exists := pathDigests[authority.RunnerStatePathDigest]; exists {
			return ErrConflict
		}
		stateRefs[authority.RunnerStateRef] = struct{}{}
		pathDigests[authority.RunnerStatePathDigest] = struct{}{}
	}
	return nil
}

func validateRunnerStateRef(value string) error {
	if value == "." || value == ".." {
		return fmt.Errorf("%w: runner_state_ref must not be a path marker", ErrInvalidArgument)
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' ||
			char == '-' || char == '_' || char == '.' {
			continue
		}
		return fmt.Errorf("%w: runner_state_ref must use canonical lowercase ASCII", ErrInvalidArgument)
	}
	return nil
}

func registerTargetAuthority(ctx context.Context, tx *sql.Tx, authority TargetAuthority) error {
	var storedPin, storedKind, storedCredentialKind string
	credentialKind := "none"
	if authority.Credential != nil {
		credentialKind = "bound"
	}
	existingRevision := false
	err := tx.QueryRowContext(ctx, `SELECT semantic_fingerprint, runner_state_kind, credential_kind
        FROM target_revisions WHERE target_id = ? AND revision = ?`,
		authority.TargetID, authority.TargetRevision).Scan(&storedPin, &storedKind, &storedCredentialKind)
	switch {
	case err == nil:
		existingRevision = true
		if storedPin != authority.RevisionPin || storedKind != string(authority.RunnerStateKind) || storedCredentialKind != credentialKind {
			return ErrConflict
		}
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx, `INSERT INTO target_revisions(
            target_id, revision, semantic_fingerprint, registered_at_unix_ms, runner_state_kind, credential_kind
        ) VALUES (?, ?, ?, ?, ?, ?)`, authority.TargetID, authority.TargetRevision,
			authority.RevisionPin, time.Now().UTC().UnixMilli(), authority.RunnerStateKind, credentialKind); err != nil {
			return fmt.Errorf("register target revision: %w", err)
		}
	default:
		return fmt.Errorf("query target revision: %w", err)
	}

	if err := registerTargetCredential(ctx, tx, authority, existingRevision); err != nil {
		return err
	}
	var storedRef, storedDigest string
	err = tx.QueryRowContext(ctx, `SELECT runner_state_ref, runner_state_path_digest
        FROM runner_state_owners WHERE target_id = ? AND target_revision = ?`,
		authority.TargetID, authority.TargetRevision).Scan(&storedRef, &storedDigest)
	switch {
	case err == nil:
		if authority.RunnerStateKind != targetmanifest.RunnerStatePersistent {
			return ErrConflict
		}
		if storedRef != authority.RunnerStateRef || storedDigest != authority.RunnerStatePathDigest {
			return ErrConflict
		}
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("query runner-state owner: %w", err)
	}
	if authority.RunnerStateKind == targetmanifest.RunnerStateNone {
		return nil
	}
	if existingRevision {
		return ErrRunnerStateOwnershipUnknown
	}

	var conflictingTargetID string
	err = tx.QueryRowContext(ctx, `SELECT target_id FROM runner_state_owners
        WHERE runner_state_ref = ? OR runner_state_path_digest = ? LIMIT 1`,
		authority.RunnerStateRef, authority.RunnerStatePathDigest).Scan(&conflictingTargetID)
	if err == nil {
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("query runner-state namespace conflict: %w", err)
	}
	if !authority.StatePathAbsent {
		return ErrRunnerStateOwnershipUnknown
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO runner_state_owners(
        runner_state_path_digest, runner_state_ref, target_id, target_revision,
        registered_at_unix_ms
    ) VALUES (?, ?, ?, ?, ?)`, authority.RunnerStatePathDigest,
		authority.RunnerStateRef, authority.TargetID, authority.TargetRevision,
		time.Now().UTC().UnixMilli()); err != nil {
		return fmt.Errorf("register runner-state owner: %w", err)
	}
	return nil
}

// requireTargetRevision reads and verifies the explicit durable state kind in
// the same admission transaction. Missing ownership is never interpreted as none.
func requireTargetRevision(ctx context.Context, querier queryRower, targetID, revision string) (targetmanifest.RunnerStateKind, error) {
	var kind targetmanifest.RunnerStateKind
	var owner bool
	err := querier.QueryRowContext(ctx, `SELECT tr.runner_state_kind,
   EXISTS (SELECT 1 FROM runner_state_owners rso
     WHERE rso.target_id = tr.target_id AND rso.target_revision = tr.revision)
   FROM target_revisions tr WHERE tr.target_id = ? AND tr.revision = ?`,
		targetID, revision).Scan(&kind, &owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrTargetRevisionNotFound
	}
	if err != nil {
		return "", fmt.Errorf("verify target revision registration: %w", err)
	}
	if (kind == targetmanifest.RunnerStateNone && !owner) ||
		(kind == targetmanifest.RunnerStatePersistent && owner) {
		return kind, nil
	}
	return "", ErrRunnerStateOwnershipUnknown
}

func validateSHA256(field, value string) error {
	if len(value) != 64 {
		return fmt.Errorf("%w: %s must be 64 lowercase hexadecimal characters", ErrInvalidArgument, field)
	}
	for index := 0; index < len(value); index++ {
		if value[index] >= '0' && value[index] <= '9' || value[index] >= 'a' && value[index] <= 'f' {
			continue
		}
		return fmt.Errorf("%w: %s must be 64 lowercase hexadecimal characters", ErrInvalidArgument, field)
	}
	return nil
}

const (
	executionTargetIDMax = 128
	executionRevisionMax = 160
)
