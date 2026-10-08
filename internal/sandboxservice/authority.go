package sandboxservice

import (
	"errors"

	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// ResolvedAuthority is trusted local resolver output, never execution wire
// input. RevisionPin must bind the manifest and all resolved non-credential
// authority. A manifest or candidate digest cannot replace that resolution.
// Missing provider policy must return an error, not a placeholder pin.
type ResolvedAuthority struct {
	RevisionPin string
	RunnerState sandboxstore.RunnerStateOwnership
	Credential  *ResolvedCredential
}

// ResolvedCredential selects an enrolled generation and independently approved
// scope, for example from agentpolicy.Endpoint.SessionScope. The service checks
// its exact target/revision and derives workspace/auth from the manifest. The
// store then compares against the selected enrollment in the registration tx.
type ResolvedCredential struct {
	Ref   sandboxstore.CredentialRef
	Scope sessionauth.Scope
}

type AuthorityResolverFunc func(manifest targetmanifest.Definition, manifestFingerprint string) (ResolvedAuthority, error)

// WithAuthorityResolver supplies a single startup authority resolver. Pass nil
// as New's legacy runner-state callback and do not use WithRevisionPin together
// with it. Each entry is resolved exactly once before the one batch registration;
// the service never calls this function again while admitting or replaying Runs.
func WithAuthorityResolver(resolve AuthorityResolverFunc) Option {
	return func(config *options) error {
		if resolve == nil || config.authorityResolver != nil || config.revisionPin != nil {
			return errors.New("sandboxservice: missing or conflicting authority resolver")
		}
		config.authorityResolver = resolve
		return nil
	}
}

func (o options) resolveAuthority(manifest targetmanifest.Definition, fingerprint string, state RunnerStateOwnershipFunc) (ResolvedAuthority, error) {
	if o.authorityResolver != nil {
		return o.authorityResolver(manifest.Clone(), fingerprint)
	}
	// Existing hooks supply only credential-free authority. Preserve their
	// exact mock pin behavior while using the same strict registration path.
	pin := fingerprint
	if o.revisionPin != nil {
		var err error
		pin, err = o.revisionPin(manifest.Clone(), fingerprint)
		if err != nil {
			return ResolvedAuthority{}, err
		}
	}
	ownership, err := state(manifest.Clone())
	if err != nil {
		return ResolvedAuthority{}, err
	}
	return ResolvedAuthority{RevisionPin: pin, RunnerState: ownership}, nil
}

func bindResolvedCredential(manifest targetmanifest.Definition, credential *ResolvedCredential, target *sandboxstore.EnrolledTargetAuthority) error {
	if credential == nil {
		return nil
	}
	resolved := *credential // Copy before another resolver call can mutate it.
	if resolved.Scope.TargetID != manifest.ID() || resolved.Scope.TargetRevision != manifest.Revision() {
		return errors.New("sandboxservice: credential scope target mismatch")
	}
	digest, err := sessionauth.Digest(resolved.Scope)
	if err != nil {
		return errors.New("sandboxservice: invalid approved credential scope")
	}
	target.Target.Credential = &resolved.Ref
	target.Scope = &sandboxstore.CredentialTargetScope{
		WorkspaceRef: manifest.Common().WorkspaceRef, AuthProfileRef: manifest.Common().AuthProfileRef,
		ScopeDigest: digest,
	}
	return nil
}
