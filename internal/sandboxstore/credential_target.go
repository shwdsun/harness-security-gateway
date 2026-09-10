package sandboxstore

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
)

const credentialTargetFingerprintDomain = "harness-security-gateway.sandboxstore.credential-target/v1"

// CredentialTargetScope is the exact scope approved by the trusted local
// target resolver. It is never taken from a remote request or inferred from
// the enrollment being checked. ScopeDigest binds the Core disclosure scope.
type CredentialTargetScope struct {
	WorkspaceRef   string
	AuthProfileRef string
	ScopeDigest    string
}

// EnrolledTargetAuthority supplies the non-credential authority pin in Target
// and, for a credential-bearing target, its independently resolved exact scope.
// The store derives credential identity/proof from Target.Credential itself.
// A credential-free target must have nil Scope and retains its original pin.
//
// The caller must bind all resolved non-credential authority into RevisionPin.
// A manifest, sealed profile or candidate digest alone is not sufficient for a
// real provider. This API neither resolves that authority nor enables a runtime.
type EnrolledTargetAuthority struct {
	Target TargetAuthority
	Scope  *CredentialTargetScope
}

// RegisterEnrolledTargetAuthorities atomically composes enrolled credential
// authority into each target's durable pin, then performs existing immutable
// registration for the whole batch. Missing proof/scope fails closed; nothing
// is backfilled. Exact replay may reference revoked history but cannot revive
// it or authorize a new target binding. sandboxservice uses this for every
// registry; executable configuration supplies only credential-free mocks.
// Credential-bearing callers still use constructed synthetic authority in tests.
func (s *Store) RegisterEnrolledTargetAuthorities(ctx context.Context, entries []EnrolledTargetAuthority) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if len(entries) == 0 {
		return ErrInvalidArgument
	}
	authorities := make([]TargetAuthority, len(entries))
	for i, entry := range entries {
		authorities[i] = entry.Target
		if (entry.Target.Credential == nil) != (entry.Scope == nil) {
			return ErrCredentialAuthority
		}
		if entry.Scope != nil && (validateLogicalID("workspace", entry.Scope.WorkspaceRef, MaxWorkspaceIDBytes) != nil ||
			validateLogicalID("auth profile", entry.Scope.AuthProfileRef, MaxWorkspaceIDBytes) != nil ||
			validateSHA256("scope digest", entry.Scope.ScopeDigest) != nil) {
			return ErrInvalidArgument
		}
	}
	if err := validateTargetAuthorityBatch(authorities); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i, authority := range authorities {
		if authority.Credential != nil {
			g, proof, err := loadCredentialGeneration(ctx, tx, *authority.Credential)
			if errors.Is(err, ErrNotFound) {
				return ErrCredentialAuthority
			}
			if err != nil {
				return err
			}
			scope := entries[i].Scope
			if proof == nil || g.WorkspaceRef != scope.WorkspaceRef ||
				g.AuthProfileRef != scope.AuthProfileRef || g.ScopeDigest != scope.ScopeDigest {
				return ErrCredentialAuthority
			}
			authority.RevisionPin = fingerprintEnrolledTarget(authority.RevisionPin, g, *proof)
		}
		if err := registerTargetAuthority(ctx, tx, authority); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Inputs have been validated and read from one registration transaction. Frame
// every string with its uint64 big-endian byte length; generation is positive
// canonical base-10. Token bytes and revocation/readiness never enter this hash.
func fingerprintEnrolledTarget(basePin string, g CredentialGeneration, proof credentialsource.Proof) string {
	digest := sha256.New()
	for _, value := range []string{
		credentialTargetFingerprintDomain, basePin,
		g.SlotRef, strconv.FormatInt(g.Generation, 10),
		proof.Scheme, g.SourceDigest, proof.RootObjectDigest, proof.SlotObjectDigest, proof.LocatorDigest,
		g.WorkspaceRef, g.AuthProfileRef, g.ScopeDigest,
	} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(value))
	}
	return hex.EncodeToString(digest.Sum(nil))
}
