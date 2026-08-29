package sandboxcontroller

import (
	"context"
	"errors"
	"fmt"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/hostepoch"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func (c *Controller) reconcileManaged(ctx context.Context) error {
	refs, err := c.runtime.ListManaged(ctx)
	if err != nil {
		return fmt.Errorf("sandboxcontroller: list managed runtimes: %w", err)
	}
	var failures []error
	for _, ref := range refs {
		cleanupCtx, cancel := context.WithTimeout(ctx, c.cleanupTimeout)
		err := c.cleanupRuntimeContext(cleanupCtx, ref)
		cancel()
		if err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) != 0 {
		return fmt.Errorf("sandboxcontroller: managed runtime reconciliation failed: %w", errors.Join(failures...))
	}
	return nil
}

func (c *Controller) reconcile(ctx context.Context) error {
	runs, err := c.store.ListUnreconciled(ctx)
	if err != nil {
		return fmt.Errorf("sandboxcontroller: list unreconciled runs: %w", err)
	}
	var failures []error
	for _, run := range runs {
		runCtx, cancel := context.WithTimeout(ctx, c.cleanupTimeout)
		spec, certainNoRuntime, desired := c.desiredTerminal(run.RunID)
		var err error
		if desired {
			err = c.reconcileDesired(runCtx, run, spec, certainNoRuntime)
		} else {
			err = c.reconcileRun(runCtx, run)
		}
		cancel()
		if err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("sandboxcontroller: startup reconciliation failed: %w", errors.Join(failures...))
	}
	return nil
}

func (c *Controller) reconcileDesired(
	ctx context.Context,
	run sandboxstore.Run,
	spec terminalSpec,
	certainNoRuntime bool,
) error {
	if certainNoRuntime {
		// The memo can outlive the control context that proved Create was never
		// called. Re-read after acquiring reconciliation ownership; if runtime
		// authority or a different lifecycle state appeared, discard the shortcut
		// and use the ordinary cleanup path.
		latest, err := c.store.GetRun(ctx, run.RunID)
		if err != nil {
			return err
		}
		run = latest
		if run.RuntimeRef != nil || run.RuntimeIntentPending ||
			(run.State != executionwire.RunStateAccepted && run.State != executionwire.RunStateCancelling &&
				!terminalState(run.State)) {
			certainNoRuntime = false
		}
	}
	if run.RuntimeRef != nil || run.RuntimeIntentPending {
		if !terminalState(run.State) {
			terminalRun, err := c.commitReconciledTerminal(ctx, run.RunID, spec)
			if err != nil {
				return err
			}
			run = terminalRun
		}
		c.clearDesiredTerminal(run.RunID)
		if run.RuntimeRef != nil {
			if err := c.cleanupRuntimeContext(ctx, *run.RuntimeRef); err != nil {
				return err
			}
		} else {
			manifest, err := c.manifestForRun(run)
			if err != nil {
				return err
			}
			if err := c.cleanupNoRefIntent(ctx, run, manifest); err != nil {
				return err
			}
		}
		return c.confirmStoppedContext(ctx, run.RunID)
	}
	if certainNoRuntime {
		if err := c.finalizeReconciled(ctx, run.RunID, spec); err != nil {
			return err
		}
		c.clearDesiredTerminal(run.RunID)
		return nil
	}

	manifest, err := c.manifestForRun(run)
	if err != nil {
		return err
	}
	if err := c.cleanupNoRefIntent(ctx, run, manifest); err != nil {
		return err
	}
	if err := c.finalizeReconciled(ctx, run.RunID, spec); err != nil {
		return err
	}
	c.clearDesiredTerminal(run.RunID)
	return nil
}

func (c *Controller) reconcileRun(ctx context.Context, run sandboxstore.Run) error {
	if terminalState(run.State) {
		if run.RuntimeRef != nil {
			if err := c.cleanupRuntimeContext(ctx, *run.RuntimeRef); err != nil {
				return err
			}
		} else if run.WorkspaceLockHeld || run.RuntimeIntentPending {
			// A crash can occur after Docker accepted Create but before
			// SetRuntimeRef committed. Only identity-verified LookupIntent plus the
			// boot epoch may prove it gone; reconciliation never issues Create.
			manifest, err := c.manifestForRun(run)
			if err != nil {
				return err
			}
			if err := c.cleanupNoRefIntent(ctx, run, manifest); err != nil {
				return err
			}
		}
		return c.confirmStoppedContext(ctx, run.RunID)
	}

	if run.RuntimeRef != nil {
		spec := terminalInterrupted
		if run.State == executionwire.RunStateCancelling {
			spec = terminalCancelled
		}
		terminalRun, err := c.commitReconciledTerminal(ctx, run.RunID, spec)
		if err != nil {
			return err
		}
		if terminalRun.RuntimeRef == nil {
			return errors.New("sandboxcontroller: runtime reference disappeared during reconciliation")
		}
		if err := c.cleanupRuntimeContext(ctx, *terminalRun.RuntimeRef); err != nil {
			return err
		}
		return c.confirmStoppedContext(ctx, run.RunID)
	}

	switch run.State {
	case executionwire.RunStateAccepted:
		if !run.RuntimeIntentPending && run.Deadline.After(c.clock().UTC()) {
			// The prompt was intentionally not persisted. Agentd must re-offer
			// this accepted request after observing its durable status.
			return nil
		}
		spec := terminalInterrupted
		if !run.Deadline.After(c.clock().UTC()) {
			spec = terminalDeadline
		}
		if run.RuntimeIntentPending {
			return c.terminalizePendingIntent(ctx, run, spec)
		}
		return c.recoverThenTerminal(ctx, run, spec)
	case executionwire.RunStateCancelling:
		if run.RuntimeIntentPending {
			return c.terminalizePendingIntent(ctx, run, terminalCancelled)
		}
		return c.recoverThenTerminal(ctx, run, terminalCancelled)
	case executionwire.RunStateRunning:
		if run.RuntimeIntentPending {
			return c.terminalizePendingIntent(ctx, run, terminalInterrupted)
		}
		return c.recoverThenTerminal(ctx, run, terminalInterrupted)
	default:
		return errors.New("sandboxcontroller: unreconciled run has an invalid state")
	}
}

func (c *Controller) terminalizePendingIntent(
	ctx context.Context,
	run sandboxstore.Run,
	spec terminalSpec,
) error {
	terminalRun, err := c.commitReconciledTerminal(ctx, run.RunID, spec)
	if err != nil {
		return err
	}
	manifest, err := c.manifestForRun(terminalRun)
	if err != nil {
		return err
	}
	if err := c.cleanupNoRefIntent(ctx, terminalRun, manifest); err != nil {
		return err
	}
	return c.confirmStoppedContext(ctx, run.RunID)
}

func (c *Controller) commitReconciledTerminal(
	ctx context.Context,
	runID string,
	proposed terminalSpec,
) (sandboxstore.Run, error) {
	return c.commitTerminal(ctx, runID, proposed)
}

func (c *Controller) recoverThenTerminal(ctx context.Context, run sandboxstore.Run, spec terminalSpec) error {
	manifest, err := c.manifestForRun(run)
	if err != nil {
		return err
	}
	if err := c.cleanupNoRefIntent(ctx, run, manifest); err != nil {
		return err
	}
	return c.finalizeReconciled(ctx, run.RunID, spec)
}

func (c *Controller) cleanupNoRefIntent(
	ctx context.Context,
	run sandboxstore.Run,
	manifest targetmanifest.Manifest,
) error {
	if run.RuntimeIntentPending {
		return c.reconcilePendingIntent(ctx, run, manifest)
	}
	return c.lookupAndCleanupIntent(ctx, run, manifest)
}

// reconcilePendingIntent never issues Create. A strict identity lookup either
// yields the one authorized container, which is removed before the intent is
// cleared, or proves it absent at that instant. Absence is a fence only after
// the host boot changes; in the same/unknown boot an earlier Docker handler
// may still complete after the lookup, so durable authority must be retained.
func (c *Controller) reconcilePendingIntent(
	ctx context.Context,
	run sandboxstore.Run,
	manifest targetmanifest.Manifest,
) error {
	if err := hostepoch.Validate(c.bootID); err != nil {
		return errors.New("sandboxcontroller: current host boot identifier is invalid")
	}
	ref, found, err := c.runtime.LookupIntent(ctx, run.RunID, manifest)
	if err != nil {
		return fmt.Errorf("sandboxcontroller: lookup pending runtime intent: %w", err)
	}
	if found {
		if err := c.cleanupRuntimeContext(ctx, ref); err != nil {
			return err
		}
		if run.RuntimeIntentBootID == nil {
			// Legacy v2 recovery may have dispatched more than one Create while
			// retrying an uncertain outcome. Removing the currently visible ref
			// therefore cannot prove that no older handler will create later.
			return fmt.Errorf("%w: legacy intent has no host boot identifier", ErrRuntimeIntentUnresolved)
		}
		return c.clearIntentAfterKnownCleanup(ctx, run.RunID, ref)
	}
	if run.RuntimeIntentBootID == nil {
		return fmt.Errorf("%w: legacy intent has no host boot identifier", ErrRuntimeIntentUnresolved)
	}
	if err := hostepoch.Validate(*run.RuntimeIntentBootID); err != nil {
		return fmt.Errorf("%w: stored host boot identifier is invalid", ErrRuntimeIntentUnresolved)
	}
	if *run.RuntimeIntentBootID == c.bootID {
		return fmt.Errorf("%w: Create may still complete in the current host boot", ErrRuntimeIntentUnresolved)
	}
	// A different boot proves every handler from the intent's boot is dead.
	return c.clearCertainRuntimeIntent(ctx, run.RunID)
}

// clearIntentAfterKnownCleanup crosses the proof boundary after Create has
// returned a concrete ref and that exact runtime has been removed, or after a
// strict pending-intent lookup found and removed it. A response-lost
// SetRuntimeRef may already have bound the same ref; leave that durable ref for
// terminalization and ConfirmRuntimeStopped instead of clearing it.
func (c *Controller) clearIntentAfterKnownCleanup(ctx context.Context, runID, recoveredRef string) error {
	latest, err := c.store.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	if latest.RuntimeRef != nil {
		if *latest.RuntimeRef == recoveredRef && !latest.RuntimeIntentPending {
			return nil
		}
		return errors.New("sandboxcontroller: recovered runtime reference conflicts with durable state")
	}
	if !latest.RuntimeIntentPending {
		return nil
	}
	if _, err := c.store.ClearRuntimeIntent(ctx, runID); err == nil {
		return nil
	} else {
		latest, getErr := c.store.GetRun(ctx, runID)
		if getErr == nil && latest.RuntimeRef == nil && !latest.RuntimeIntentPending {
			return nil
		}
		return fmt.Errorf("sandboxcontroller: clear cleaned runtime intent: %w", err)
	}
}

// lookupAndCleanupIntent closes the Create -> SetRuntimeRef crash window
// without using a mutating Create as a probe. LookupIntent returns absent only
// after a strict deterministic-name absence proof, and otherwise returns a
// fully identity-verified container reference.
func (c *Controller) lookupAndCleanupIntent(
	ctx context.Context,
	run sandboxstore.Run,
	manifest targetmanifest.Manifest,
) error {
	ref, found, lookupErr := c.runtime.LookupIntent(ctx, run.RunID, manifest)
	if lookupErr != nil {
		return fmt.Errorf("sandboxcontroller: lookup runtime intent: %w", lookupErr)
	}
	if !found {
		return nil
	}

	// Legacy schema-v1 rows have no pending intent marker. Lookup's complete
	// identity verification grants cleanup authority, but must not mint fresh
	// Create authority merely to satisfy SetRuntimeRef's v2 precondition.
	return c.cleanupRuntimeContext(ctx, ref)
}

// finalizeReconciled re-reads after runtime cleanup through commitTerminal,
// which centrally applies pending-intent and cancellation precedence.
func (c *Controller) finalizeReconciled(ctx context.Context, runID string, proposed terminalSpec) error {
	if _, err := c.commitTerminal(ctx, runID, proposed); err != nil {
		return err
	}
	return c.confirmStoppedContext(ctx, runID)
}

func (c *Controller) manifestForRun(run sandboxstore.Run) (targetmanifest.Manifest, error) {
	entry, err := c.registry.Resolve(run.TargetID, run.TargetRevision)
	if err != nil {
		return targetmanifest.Manifest{}, fmt.Errorf("sandboxcontroller: resolve runtime intent: %w", err)
	}
	if entry.Manifest.ID != run.TargetID || entry.Manifest.Revision != run.TargetRevision {
		return targetmanifest.Manifest{}, errors.New("sandboxcontroller: registry returned mismatched runtime intent")
	}
	if err := entry.Manifest.Validate(); err != nil {
		return targetmanifest.Manifest{}, errors.New("sandboxcontroller: registry returned invalid runtime intent")
	}
	return entry.Manifest, nil
}

func (c *Controller) commitTerminalContext(runID string, spec terminalSpec) (sandboxstore.Run, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.cleanupTimeout)
	defer cancel()
	return c.commitTerminal(ctx, runID, spec)
}

func (c *Controller) confirmStopped(runID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.cleanupTimeout)
	defer cancel()
	return c.confirmStoppedContext(ctx, runID)
}

func (c *Controller) confirmStoppedContext(ctx context.Context, runID string) error {
	_, err := c.store.ConfirmRuntimeStopped(ctx, runID)
	return err
}
