package sandboxcontroller

import (
	"context"
	"errors"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

var ErrCredentialUnavailable = errors.New("sandboxcontroller: credential authority unavailable")

// This narrow handle cannot disclose a credential, descriptor or mount path.
// The native opener is fixed; only package tests replace the private seam.
type credentialHandle interface {
	VerifyProof(string, credentialsource.Proof) error
	Validate() error
	Close() error
}

type credentialOpener func(root, directory string) (credentialHandle, error)

func makeCredentialHandoff(held credentialHandle, runID, fingerprint string, binding credentialsource.Binding, source string, proof credentialsource.Proof) (*credentialsource.Handoff, error) {
	provider, ok := held.(interface {
		Handoff(string, string, credentialsource.Binding, string, credentialsource.Proof) (*credentialsource.Handoff, error)
	})
	if !ok {
		return nil, ErrCredentialUnavailable
	}
	return provider.Handoff(runID, fingerprint, binding, source, proof)
}

// Per-Run execution/reconciliation ownership serializes these fields. c.mu
// protects map membership, not file or database I/O. A failed Close is sticky
// until process death; disappearance of descriptors is not cleanup evidence.
type runCredential struct {
	held        credentialHandle
	handoff     *credentialsource.Handoff
	invalid     bool
	retired     bool
	closeFailed bool
}

// WithCredentialBindings freezes trusted local locators by slot. It neither
// enrolls a source nor grants a target/runtime capability. The opt-in fixed
// Codex startup supplies it together with resolved pins and exact-object mount
// handoff. Remote requests never carry these values.
func WithCredentialBindings(bindings []credentialsource.Binding) Option {
	frozen := append([]credentialsource.Binding(nil), bindings...)
	return func(config *options) error {
		bySlot := make(map[string]credentialsource.Binding, len(frozen))
		for _, binding := range frozen {
			if binding.SlotRef == "" || binding.Generation == 0 {
				return ErrCredentialUnavailable
			}
			if _, exists := bySlot[binding.SlotRef]; exists {
				return ErrCredentialUnavailable
			}
			bySlot[binding.SlotRef] = binding
		}
		config.credentialBindings = bySlot
		return nil
	}
}

func (c *Controller) credentialForRun(runID string) *runCredential {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.credentials[runID]
}

func (c *Controller) hasRetainedCredentials() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.credentials) != 0
}

func (c *Controller) prepareCredential(run sandboxstore.Run, manifest targetmanifest.Definition) error {
	if !run.CredentialRequired {
		return nil
	}
	c.mu.Lock()
	if c.credentials == nil {
		c.credentials = make(map[string]*runCredential)
	}
	if c.credentials[run.RunID] != nil {
		c.mu.Unlock()
		return ErrCredentialUnavailable // Never reacquire an existing attempt.
	}
	state := &runCredential{}
	c.credentials[run.RunID] = state
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), c.cleanupTimeout)
	defer cancel()
	generation, proof, err := c.store.GetRunCredentialEnrollment(ctx, run.RunID)
	if err != nil {
		return c.invalidateCredential(ctx, run.RunID, state)
	}
	binding, exists := c.credentialBindings[generation.SlotRef]
	common := manifest.Common()
	if !exists || generation.Generation <= 0 || binding.Generation != uint64(generation.Generation) ||
		binding.SlotRef != generation.SlotRef || binding.WorkspaceRef != generation.WorkspaceRef ||
		binding.AuthProfileRef != generation.AuthProfileRef || generation.WorkspaceRef != run.WorkspaceID ||
		generation.ScopeDigest != run.SessionScopeDigest || common.WorkspaceRef != run.WorkspaceID ||
		common.AuthProfileRef != generation.AuthProfileRef || proof.Validate() != nil || c.openCredential == nil {
		return c.invalidateCredential(ctx, run.RunID, state)
	}
	held, err := c.openCredential(binding.Root, binding.Directory)
	if !nilInterface(held) {
		state.held = held // Even a partial acquisition must retain its cleanup owner.
	}
	if err != nil || state.held == nil || state.held.VerifyProof(generation.SourceDigest, proof) != nil ||
		state.held.Validate() != nil {
		return c.invalidateCredential(ctx, run.RunID, state)
	}
	fingerprint, err := manifest.Fingerprint()
	if err != nil {
		return c.invalidateCredential(ctx, run.RunID, state)
	}
	state.handoff, err = makeCredentialHandoff(held, run.RunID, fingerprint, binding, generation.SourceDigest, proof)
	if err != nil || state.handoff == nil {
		return c.invalidateCredential(ctx, run.RunID, state)
	}
	return nil
}

func (c *Controller) retireCredential(ctx context.Context, runID string, state *runCredential) error {
	if state.invalid && !state.retired {
		if err := c.store.RevokeRunCredential(ctx, runID); err != nil {
			return ErrCredentialUnavailable
		}
		state.retired = true
	}
	return nil
}

func (c *Controller) invalidateCredential(ctx context.Context, runID string, state *runCredential) error {
	state.invalid = true
	state.handoff.Close()
	_ = c.retireCredential(ctx, runID, state)
	return ErrCredentialUnavailable
}

// Called only for credential-required Runs while their lifecycle owner holds
// the execution/reconciliation claim. It is not cached cross-Run readiness.
func (c *Controller) validateCredential(ctx context.Context, runID string) error {
	state := c.credentialForRun(runID)
	if state == nil {
		return ErrCredentialUnavailable
	}
	if state.invalid || state.held == nil || state.held.Validate() != nil {
		return c.invalidateCredential(ctx, runID, state)
	}
	return nil
}

// Call only after exact runtime cleanup (or a trusted never-dispatched proof),
// immediately before durable publication/release. Startup has no old handles;
// its separate retirement transaction already fenced every retained occupant.
func (c *Controller) closeCredential(ctx context.Context, runID string) error {
	state := c.credentialForRun(runID)
	if state == nil {
		return nil
	}
	if !state.invalid && state.held != nil && state.held.Validate() != nil {
		state.invalid = true
	}
	if err := c.retireCredential(ctx, runID, state); err != nil {
		return err
	}
	if state.closeFailed {
		return ErrCredentialUnavailable
	}
	state.handoff.Close()
	if state.held != nil && state.held.Close() != nil {
		state.closeFailed = true
		return c.invalidateCredential(ctx, runID, state)
	}
	c.mu.Lock()
	delete(c.credentials, runID)
	c.mu.Unlock()
	// The durable candidate/occupancy still fences successors. Once Close has
	// succeeded no volatile entry is needed, even if publication later fails or
	// commits with a lost response; reconciliation must never reopen the file.
	return nil
}
