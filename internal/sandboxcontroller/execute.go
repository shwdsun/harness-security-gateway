package sandboxcontroller

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/runnerbridge"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func (c *Controller) execute(
	runCtx context.Context,
	runCancel context.CancelFunc,
	request executionwire.StartRunRequest,
) {
	run, err := c.getRunControl(request.RunID)
	if err != nil {
		return
	}
	fingerprint, err := executionwire.StartRunFingerprint(request)
	if err != nil || run.Fingerprint != fingerprint ||
		run.TargetID != request.TargetID || run.TargetRevision != request.ExpectedRevision {
		// A mismatched volatile offer has no authority to terminalize the
		// durable request. Leave it accepted so the exact request can be re-offered.
		return
	}
	if terminalState(run.State) {
		return
	}
	if run.State == executionwire.RunStateCancelling {
		c.finishWithoutRuntime(request, terminalCancelled)
		return
	}
	if !request.Deadline.After(c.clock().UTC()) {
		c.finishWithoutRuntime(request, terminalDeadline)
		return
	}

	entry, err := c.registry.Resolve(request.TargetID, request.ExpectedRevision)
	if err != nil || entry.Manifest.ID != request.TargetID || entry.Manifest.Revision != request.ExpectedRevision {
		c.finishWithoutRuntime(request, c.classifyFailure(request, err))
		return
	}
	executionCtx, executionCancel := context.WithTimeout(
		runCtx,
		time.Duration(entry.Manifest.Limits.TimeoutSeconds)*time.Second,
	)
	defer executionCancel()

	var vendorToken *string
	if request.SessionRef != nil {
		value, resolveErr := c.resolveVendorSession(request)
		if resolveErr != nil {
			c.finishWithoutRuntime(request, c.classifyFailure(request, resolveErr))
			return
		}
		vendorToken = &value
		defer func() { value = "" }()
	}

	// Intent persistence is control-plane work. A caller cancellation or Run
	// deadline must not make the Begin result ambiguous merely because the
	// execution context expired while SQLite was committing it.
	intentCtx, intentCancel := context.WithTimeout(context.Background(), c.cleanupTimeout)
	_, intentCreated, err := c.store.BeginRuntimeIntent(intentCtx, request.RunID, c.bootID)
	if err != nil {
		spec := c.classifyFailure(request, err)
		if c.clearAmbiguousPredispatchIntent(intentCtx, run) == nil {
			c.finishCertainNoRuntime(intentCtx, request, spec)
		} else {
			c.finishWithoutRuntime(request, spec)
		}
		intentCancel()
		return
	}
	if !intentCreated {
		intentCancel()
		// An existing intent is recovery authority, not permission to dispatch a
		// second Create. Lookup plus the boot epoch is the only safe boundary.
		c.finishCreateFailure(
			request,
			entry.Manifest,
			false,
			c.classifyFailure(request, dockerruntime.ErrCreateUncertain),
			dockerruntime.ErrCreateUncertain,
		)
		return
	}

	// Begin may have committed after the execution context was cancelled, and
	// cancellation may race its response. Re-read durable state before the sole
	// Create call. Because Create has not yet been invoked, a verified clear
	// permits an exact cancellation/deadline result without any runtime lookup.
	latest, getErr := c.store.GetRun(intentCtx, request.RunID)
	if getErr != nil || !sameRunIdentity(run, latest) || latest.RuntimeRef != nil ||
		!latest.RuntimeIntentPending || latest.RuntimeIntentBootID == nil ||
		*latest.RuntimeIntentBootID != c.bootID {
		intentCancel()
		c.finishCreateFailure(
			request,
			entry.Manifest,
			false,
			terminalInterrupted,
			dockerruntime.ErrCreateUncertain,
		)
		return
	}
	if latest.State == executionwire.RunStateCancelling || executionCtx.Err() != nil {
		spec := c.classifyFailure(request, executionCtx.Err())
		if latest.State == executionwire.RunStateCancelling {
			spec = terminalCancelled
		}
		if clearErr := c.clearCertainRuntimeIntent(intentCtx, request.RunID); clearErr == nil {
			c.finishCertainNoRuntime(intentCtx, request, spec)
		} else {
			c.finishWithoutRuntime(request, spec)
		}
		intentCancel()
		return
	}
	intentCancel()

	ref, err := c.runtime.Create(executionCtx, request.RunID, entry.Manifest)
	if err != nil {
		c.finishCreateFailure(
			request,
			entry.Manifest,
			intentCreated,
			c.classifyFailure(request, err),
			err,
		)
		return
	}

	boundRun, err := c.setRuntimeRefControl(request.RunID, ref)
	if err != nil {
		// The reference is known in memory even if the durable update had an
		// ambiguous result. Never release the lock unless cleanup proves it gone.
		if cleanupErr := c.cleanupRuntime(ref); cleanupErr != nil {
			return
		}
		clearCtx, clearCancel := context.WithTimeout(context.Background(), c.cleanupTimeout)
		clearErr := c.clearIntentAfterKnownCleanup(clearCtx, request.RunID, ref)
		clearCancel()
		if clearErr != nil {
			return
		}
		c.finishWithoutRuntime(request, c.classifyFailure(request, err))
		return
	}
	if boundRun.State == executionwire.RunStateCancelling {
		c.finishWithRuntime(request, ref, terminalCancelled)
		return
	}

	process, err := c.runtime.AttachStart(executionCtx, ref)
	if err != nil {
		c.finishWithRuntime(request, ref, c.classifyFailure(request, err))
		return
	}
	if process == nil {
		runCancel()
		c.finishWithRuntime(request, ref, terminalInternal)
		return
	}
	input, output, diagnostics := process.Input(), process.Output(), process.Diagnostics()
	if input == nil || output == nil || diagnostics == nil {
		runCancel()
		c.finishWithRuntime(request, ref, terminalInternal)
		return
	}

	bridgeCtx, bridgeCancel := context.WithCancel(executionCtx)
	waitResult := make(chan error, 1)
	go func() { waitResult <- process.Wait() }()
	diagnosticResult := make(chan error, 1)
	go func() {
		_, drainErr := io.Copy(io.Discard, diagnostics)
		diagnosticResult <- drainErr
		if drainErr != nil {
			bridgeCancel()
		}
	}()

	sink := c.eventSink()
	runnerInput := newFrameClosingWriter(input)
	bridgeErr := c.bridge(
		bridgeCtx,
		request,
		entry.Manifest,
		vendorToken,
		output,
		runnerInput,
		sink,
	)
	bridgeCancel()
	executionCancel()
	runCancel() // kill a stuck attach CLI; runtime cleanup owns the container.
	_ = runnerInput.Close()
	_ = output.Close()
	_ = diagnostics.Close()

	var diagnosticErr error
	select {
	case diagnosticErr = <-diagnosticResult:
	default:
	}
	var waitErr error
	waitReceived := false
	select {
	case waitErr = <-waitResult:
		waitReceived = true
	default:
	}

	current, getErr := c.getRunControl(request.RunID)
	if getErr == nil && !terminalState(current.State) {
		cause := bridgeErr
		if diagnosticErr != nil {
			cause = diagnosticErr
		} else if cause == nil && waitErr != nil {
			cause = waitErr
		}
		if cause == nil {
			cause = errors.New("bridge returned without a terminal event")
		}
		spec := c.classifyFailure(request, cause)
		c.rememberDesiredTerminal(request.RunID, spec)
		if _, err := c.commitTerminalContext(request.RunID, spec); err == nil {
			c.clearDesiredTerminal(request.RunID)
		}
	} else if getErr == nil {
		c.clearDesiredTerminal(request.RunID)
	}

	cleanupErr := c.cleanupRuntime(ref)
	if !waitReceived {
		_ = waitBriefly(waitResult, c.waitGrace)
	}
	if cleanupErr != nil {
		return
	}
	current, err = c.getRunControl(request.RunID)
	if err == nil && terminalState(current.State) {
		_ = c.confirmStopped(request.RunID)
	}
}

func (c *Controller) eventSink() runnerbridge.Sink {
	return func(ctx context.Context, emission runnerbridge.Emission) error {
		var mapping *sandboxstore.SessionMapping
		if emission.VendorSessionToken != nil {
			if emission.Event.Type != executionwire.RunEventCompleted ||
				emission.Event.Result == nil || emission.Event.Result.SessionRef != nil {
				return errors.New("sandboxcontroller: invalid session-bearing bridge emission")
			}
			ref, err := c.sessionRef()
			if err != nil {
				return errors.New("sandboxcontroller: session ref generation failed")
			}
			emission.Event.Result.SessionRef = &ref
			mapping = &sandboxstore.SessionMapping{
				Ref:         ref,
				VendorToken: *emission.VendorSessionToken,
			}
		}
		_, err := c.store.AppendEvent(ctx, emission.Event, mapping)
		return err
	}
}

func (c *Controller) finishWithoutRuntime(request executionwire.StartRunRequest, spec terminalSpec) {
	c.rememberDesiredTerminal(request.RunID, spec)
	ctx, cancel := context.WithTimeout(context.Background(), c.cleanupTimeout)
	defer cancel()
	run, err := c.store.GetRun(ctx, request.RunID)
	if err != nil {
		return
	}
	if run.RuntimeRef != nil || run.RuntimeIntentPending {
		// Durable runtime authority keeps a terminal row discoverable. Commit
		// the caller-visible outcome first, then attempt cleanup; any lookup or
		// runtime failure retains the ref/intent and workspace lock for retry.
		if !terminalState(run.State) {
			run, err = c.commitTerminal(ctx, request.RunID, spec)
			if err != nil {
				return
			}
		}
		c.clearDesiredTerminal(request.RunID)
		if run.RuntimeRef != nil {
			if err := c.cleanupRuntimeContext(ctx, *run.RuntimeRef); err != nil {
				return
			}
		} else {
			manifest, manifestErr := c.manifestForRun(run)
			if manifestErr != nil {
				return
			}
			if err := c.cleanupNoRefIntent(ctx, run, manifest); err != nil {
				return
			}
		}
		_ = c.confirmStoppedContext(ctx, request.RunID)
		return
	}
	if terminalState(run.State) {
		c.clearDesiredTerminal(request.RunID)
		return
	}

	// A legacy row with neither a durable ref nor an intent marker is not
	// guaranteed to remain discoverable after terminalization (especially for
	// a read-only workspace), so close its identity-verified lookup window
	// before committing the terminal event.
	manifest, err := c.manifestForRun(run)
	if err != nil {
		return
	}
	if err := c.cleanupNoRefIntent(ctx, run, manifest); err != nil {
		return
	}
	if _, err := c.commitTerminal(ctx, request.RunID, spec); err != nil {
		return
	}
	c.clearDesiredTerminal(request.RunID)
	_ = c.confirmStoppedContext(ctx, request.RunID)
}

func (c *Controller) finishWithRuntime(request executionwire.StartRunRequest, ref string, spec terminalSpec) {
	c.rememberDesiredTerminal(request.RunID, spec)
	_, terminalErr := c.commitTerminalContext(request.RunID, spec)
	if terminalErr == nil {
		c.clearDesiredTerminal(request.RunID)
	}
	cleanupErr := c.cleanupRuntime(ref)
	if terminalErr == nil && cleanupErr == nil {
		_ = c.confirmStopped(request.RunID)
	}
}

// finishCertainNoRuntime is used only after a fresh durable proof that this
// worker never called Runtime.Create and no runtime authority remains. Unlike
// finishWithoutRuntime it deliberately performs no LookupIntent probe.
func (c *Controller) finishCertainNoRuntime(
	ctx context.Context,
	request executionwire.StartRunRequest,
	spec terminalSpec,
) {
	c.rememberCertainNoRuntimeTerminal(request.RunID, spec)
	run, err := c.store.GetRun(ctx, request.RunID)
	if err != nil || run.RuntimeRef != nil || run.RuntimeIntentPending {
		return
	}
	if !terminalState(run.State) {
		if _, err := c.commitTerminal(ctx, request.RunID, spec); err != nil {
			return
		}
	}
	c.clearDesiredTerminal(request.RunID)
	_ = c.confirmStoppedContext(ctx, request.RunID)
}

// finishCreateFailure handles the only lifecycle window where a container may
// exist without a durable reference. A certain pre-dispatch failure can clear
// a newly-created intent directly. Every other case must cross the boot-aware
// LookupIntent boundary; it never dispatches Create again.
func (c *Controller) finishCreateFailure(
	request executionwire.StartRunRequest,
	manifest targetmanifest.Manifest,
	intentCreated bool,
	spec terminalSpec,
	cause error,
) {
	c.rememberDesiredTerminal(request.RunID, spec)
	ctx, cancel := context.WithTimeout(context.Background(), c.cleanupTimeout)
	defer cancel()
	run, err := c.store.GetRun(ctx, request.RunID)
	if err != nil {
		return
	}
	if intentCreated && !errors.Is(cause, dockerruntime.ErrCreateUncertain) {
		clearErr := c.clearCertainRuntimeIntent(ctx, request.RunID)
		if !terminalState(run.State) {
			run, err = c.commitTerminal(ctx, request.RunID, spec)
			if err != nil {
				return
			}
		}
		c.clearDesiredTerminal(request.RunID)
		// A failed clear leaves the terminal intent (or an unexpected durable
		// ref) visible to ListUnreconciled. Never Confirm across that boundary.
		if clearErr == nil {
			_ = c.confirmStoppedContext(ctx, request.RunID)
		}
		return
	}

	// Uncertain Create (including replay of an existing intent) becomes a
	// closed terminal outcome immediately. RuntimeIntentPending is retained
	// until boot-aware lookup proves cleanup, so both RW and RO rows stay in
	// ListUnreconciled without blocking agentd on an Accepted run.
	if !terminalState(run.State) {
		run, err = c.commitTerminal(ctx, request.RunID, spec)
		if err != nil {
			return
		}
	}
	c.clearDesiredTerminal(request.RunID)
	if run.RuntimeRef != nil {
		if err := c.cleanupRuntimeContext(ctx, *run.RuntimeRef); err != nil {
			return
		}
	} else if err := c.cleanupNoRefIntent(ctx, run, manifest); err != nil {
		return
	}
	_ = c.confirmStoppedContext(ctx, request.RunID)
}

func (c *Controller) clearCertainRuntimeIntent(ctx context.Context, runID string) error {
	baseline, err := c.store.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	if baseline.RuntimeRef != nil {
		return sandboxstore.ErrIllegalTransition
	}
	if !baseline.RuntimeIntentPending {
		return nil
	}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := c.store.ClearRuntimeIntent(ctx, runID); err == nil {
			return nil
		} else {
			lastErr = err
		}
		latest, getErr := c.store.GetRun(ctx, runID)
		if getErr != nil {
			return errors.Join(lastErr, getErr)
		}
		if !sameRunIdentity(baseline, latest) || latest.RuntimeRef != nil {
			return errors.Join(lastErr, errors.New("sandboxcontroller: runtime intent ownership changed while clearing"))
		}
		if !latest.RuntimeIntentPending {
			return nil
		}
		if latest.RuntimeIntentBootID == nil || baseline.RuntimeIntentBootID == nil ||
			*latest.RuntimeIntentBootID != *baseline.RuntimeIntentBootID {
			return errors.Join(lastErr, errors.New("sandboxcontroller: runtime intent ownership changed while clearing"))
		}
	}
	return lastErr
}

// clearAmbiguousPredispatchIntent proves that a failed Begin call did not
// leave runtime authority behind. The initial snapshot and the fresh row must
// describe the same immutable Run, and any committed intent must belong to the
// current boot. This relies on sandboxd's single execution worker.
func (c *Controller) clearAmbiguousPredispatchIntent(ctx context.Context, initial sandboxstore.Run) error {
	if initial.State != executionwire.RunStateAccepted || initial.RuntimeRef != nil || initial.RuntimeIntentPending {
		return errors.New("sandboxcontroller: invalid initial pre-dispatch state")
	}
	latest, err := c.store.GetRun(ctx, initial.RunID)
	if err != nil {
		return err
	}
	if !sameRunIdentity(initial, latest) || latest.RuntimeRef != nil ||
		(latest.State != executionwire.RunStateAccepted && latest.State != executionwire.RunStateCancelling) {
		return errors.New("sandboxcontroller: pre-dispatch state changed ambiguously")
	}
	if !latest.RuntimeIntentPending {
		return nil
	}
	if latest.RuntimeIntentBootID == nil || *latest.RuntimeIntentBootID != c.bootID {
		return errors.New("sandboxcontroller: ambiguous runtime intent belongs to another boot")
	}
	return c.clearCertainRuntimeIntent(ctx, initial.RunID)
}

func sameRunIdentity(first, second sandboxstore.Run) bool {
	if first.RunID != second.RunID || first.Fingerprint != second.Fingerprint ||
		first.TargetID != second.TargetID || first.TargetRevision != second.TargetRevision ||
		first.WorkspaceID != second.WorkspaceID || first.Writable != second.Writable ||
		first.InputSHA256 != second.InputSHA256 || !first.Deadline.Equal(second.Deadline) {
		return false
	}
	switch {
	case first.RequestedSessionRef == nil && second.RequestedSessionRef == nil:
		return true
	case first.RequestedSessionRef == nil || second.RequestedSessionRef == nil:
		return false
	default:
		return *first.RequestedSessionRef == *second.RequestedSessionRef
	}
}

func (c *Controller) classifyFailure(request executionwire.StartRunRequest, cause error) terminalSpec {
	if errors.Is(cause, dockerruntime.ErrCreateUncertain) {
		return terminalInterrupted
	}
	if run, err := c.getRunControl(request.RunID); err == nil && run.State == executionwire.RunStateCancelling {
		return terminalCancelled
	}
	if c.rootCtx.Err() != nil {
		return terminalInterrupted
	}
	if !request.Deadline.After(c.clock().UTC()) || errors.Is(cause, context.DeadlineExceeded) {
		return terminalDeadline
	}
	if errors.Is(cause, sandboxstore.ErrSessionNotFound) || errors.Is(cause, sandboxstore.ErrSessionScope) {
		return terminalInvalidSession
	}
	if errors.Is(cause, dockerruntime.ErrOutputLimit) {
		return terminalOutputLimit
	}
	var bridgeError *runnerbridge.BridgeError
	if errors.As(cause, &bridgeError) && bridgeError != nil {
		switch bridgeError.Class {
		case runnerbridge.ErrorProtocolViolation:
			return terminalProtocol
		case runnerbridge.ErrorRunnerFailed:
			return terminalRunnerFailed
		case runnerbridge.ErrorInvalidSession:
			return terminalInvalidSession
		case runnerbridge.ErrorPolicyDenied:
			return terminalPolicyDenied
		case runnerbridge.ErrorDeadline:
			return terminalDeadline
		case runnerbridge.ErrorOutputLimit:
			return terminalOutputLimit
		case runnerbridge.ErrorCancelled:
			return terminalInterrupted
		default:
			return terminalInternal
		}
	}
	if errors.Is(cause, context.Canceled) {
		return terminalInterrupted
	}
	return terminalInternal
}

func (c *Controller) resolveVendorSession(request executionwire.StartRunRequest) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.cleanupTimeout)
	defer cancel()
	return c.store.ResolveSessionForRun(ctx, request.RunID, *request.SessionRef, request.TargetID,
		request.ExpectedRevision, request.SessionScopeDigest)
}

func (c *Controller) getRunControl(runID string) (sandboxstore.Run, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.cleanupTimeout)
	defer cancel()
	return c.store.GetRun(ctx, runID)
}

func (c *Controller) setRuntimeRefControl(runID, ref string) (sandboxstore.Run, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.cleanupTimeout)
	defer cancel()
	return c.store.SetRuntimeRef(ctx, runID, ref)
}
