package sandboxstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// RegisterTargetAuthorities atomically pins the complete configured target
// batch and permanently assigns each runner-state ref and resolved-path digest
// to one exact TargetRevision. An exact retry is idempotent. A directory which
// has no exact durable owner may receive its first owner only when the trusted
// caller proves that the resolved path was absent before registration.
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
		if err := validateLogicalID("runner_state_ref", authority.RunnerStateRef, MaxWorkspaceIDBytes); err != nil {
			return fmt.Errorf("target authority %d: %w", index, err)
		}
		if err := validateRunnerStateRef(authority.RunnerStateRef); err != nil {
			return fmt.Errorf("target authority %d: %w", index, err)
		}
		if err := validateSHA256("runner-state path digest", authority.RunnerStatePathDigest); err != nil {
			return fmt.Errorf("target authority %d: %w", index, err)
		}

		targetKey := authority.TargetID + "\x00" + authority.TargetRevision
		if _, exists := targets[targetKey]; exists {
			return ErrConflict
		}
		if _, exists := stateRefs[authority.RunnerStateRef]; exists {
			return ErrConflict
		}
		if _, exists := pathDigests[authority.RunnerStatePathDigest]; exists {
			return ErrConflict
		}
		targets[targetKey] = struct{}{}
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
	var storedPin string
	err := tx.QueryRowContext(ctx, `SELECT semantic_fingerprint
        FROM target_revisions WHERE target_id = ? AND revision = ?`,
		authority.TargetID, authority.TargetRevision).Scan(&storedPin)
	switch {
	case err == nil:
		if storedPin != authority.RevisionPin {
			return ErrConflict
		}
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx, `INSERT INTO target_revisions(
            target_id, revision, semantic_fingerprint, registered_at_unix_ms
        ) VALUES (?, ?, ?, ?)`, authority.TargetID, authority.TargetRevision,
			authority.RevisionPin, time.Now().UTC().UnixMilli()); err != nil {
			return fmt.Errorf("register target revision: %w", err)
		}
	default:
		return fmt.Errorf("query target revision: %w", err)
	}

	var storedRef, storedDigest string
	err = tx.QueryRowContext(ctx, `SELECT runner_state_ref, runner_state_path_digest
        FROM runner_state_owners WHERE target_id = ? AND target_revision = ?`,
		authority.TargetID, authority.TargetRevision).Scan(&storedRef, &storedDigest)
	switch {
	case err == nil:
		if storedRef != authority.RunnerStateRef || storedDigest != authority.RunnerStatePathDigest {
			return ErrConflict
		}
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("query runner-state owner: %w", err)
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

func requireTargetRevision(ctx context.Context, querier queryRower, targetID, revision string) error {
	var exists int
	err := querier.QueryRowContext(ctx, `SELECT 1
        FROM target_revisions tr
        JOIN runner_state_owners rso
          ON rso.target_id = tr.target_id AND rso.target_revision = tr.revision
        WHERE tr.target_id = ? AND tr.revision = ?`, targetID, revision).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTargetRevisionNotFound
	}
	if err != nil {
		return fmt.Errorf("verify target revision registration: %w", err)
	}
	return nil
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
