package sandboxcontroller

import (
	"context"
	"errors"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/hostepoch"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
)

// This proof is process-local: the sole execution worker knows no external
// Create was dispatched, either before calling Runtime.Create or after its
// certified non-uncertain failure. It is never inferred from LookupIntent,
// a lease, or an earlier process's pending intent.
type predispatchProof struct {
	initial sandboxstore.Run
	bootID  string
}

func (c *Controller) finishPredispatchFailure(initial sandboxstore.Run, request executionwire.StartRunRequest, spec terminalSpec) {
	if initial.State != executionwire.RunStateAccepted || initial.TerminalPending ||
		initial.RuntimeRef != nil || initial.RuntimeIntentPending || hostepoch.Validate(c.bootID) != nil {
		c.finishWithoutRuntime(request, spec)
		return
	}
	// Retain an immutable copy of the optional request identity.
	if initial.RequestedSessionRef != nil {
		ref := *initial.RequestedSessionRef
		initial.RequestedSessionRef = &ref
	}
	proof := predispatchProof{initial: initial, bootID: c.bootID}
	c.mu.Lock()
	if c.predispatch == nil {
		c.predispatch = make(map[string]predispatchProof)
	}
	c.predispatch[initial.RunID] = proof
	c.desired[initial.RunID] = spec
	delete(c.certainNoRuntime, initial.RunID)
	c.mu.Unlock()
	c.signalReconcile()
	// A fresh bounded control context is independent of the failed Begin/read
	// budget and the cancelled execution. Failure retains proof for the next
	// serialized reconciliation; it never dispatches Create or probes the runtime.
	ctx, cancel := context.WithTimeout(context.Background(), c.cleanupTimeout)
	defer cancel()
	_ = c.reconcilePredispatch(ctx, proof, spec)
}

func (c *Controller) predispatchProofFor(id string) (predispatchProof, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	proof, ok := c.predispatch[id]
	return proof, ok
}

func (c *Controller) reconcilePredispatch(ctx context.Context, proof predispatchProof, spec terminalSpec) error {
	if proof.bootID != c.bootID || hostepoch.Validate(proof.bootID) != nil {
		return errors.New("sandboxcontroller: pre-dispatch proof belongs to another boot")
	}
	// Re-read and verify exact identity, absent ref, and current known intent
	// boot before clearing authority. Persistent failures preserve the fence.
	if err := c.clearAmbiguousPredispatchIntent(ctx, proof.initial); err != nil {
		return err
	}
	// Authority is now durably clear; reuse the existing no-runtime terminal
	// retry path for staging, resource closure and publication.
	c.rememberCertainNoRuntimeTerminal(proof.initial.RunID, spec)
	if err := c.finalizeReconciled(ctx, proof.initial.RunID, spec); err != nil {
		return err
	}
	c.clearDesiredTerminal(proof.initial.RunID)
	return nil
}
