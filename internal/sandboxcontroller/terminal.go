package sandboxcontroller

import (
	"context"
	"errors"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
)

const (
	messageCancelled         = "run cancelled"
	messageDeadline          = "run deadline exceeded"
	messageInterrupted       = "sandbox runtime execution was interrupted"
	messageProtocolViolation = "runner protocol violation"
	messageRunnerFailed      = "runner execution failed"
	messageInvalidSession    = "runner session is invalid"
	messagePolicyDenied      = "runner policy denied execution"
	messageOutputLimit       = "runner output limit exceeded"
	messageInternal          = "sandbox runtime failure"
)

type terminalSpec struct {
	eventType executionwire.RunEventType
	code      executionwire.FailureCode
	message   string
}

var (
	terminalCancelled = terminalSpec{eventType: executionwire.RunEventCancelled, message: messageCancelled}
	terminalDeadline  = terminalSpec{
		eventType: executionwire.RunEventFailed,
		code:      executionwire.FailureDeadlineExceeded,
		message:   messageDeadline,
	}
	terminalInterrupted = terminalSpec{
		eventType: executionwire.RunEventInterrupted,
		code:      executionwire.FailureRuntimeInterrupted,
		message:   messageInterrupted,
	}
	terminalProtocol = terminalSpec{
		eventType: executionwire.RunEventFailed,
		code:      executionwire.FailureProtocolViolation,
		message:   messageProtocolViolation,
	}
	terminalRunnerFailed = terminalSpec{
		eventType: executionwire.RunEventFailed,
		code:      executionwire.FailureRunnerFailed,
		message:   messageRunnerFailed,
	}
	terminalInvalidSession = terminalSpec{
		eventType: executionwire.RunEventFailed,
		code:      executionwire.FailureInvalidSession,
		message:   messageInvalidSession,
	}
	terminalPolicyDenied = terminalSpec{
		eventType: executionwire.RunEventFailed,
		code:      executionwire.FailurePolicyDenied,
		message:   messagePolicyDenied,
	}
	terminalOutputLimit = terminalSpec{
		eventType: executionwire.RunEventFailed,
		code:      executionwire.FailureOutputLimit,
		message:   messageOutputLimit,
	}
	terminalInternal = terminalSpec{
		eventType: executionwire.RunEventFailed,
		code:      executionwire.FailureInternal,
		message:   messageInternal,
	}
)

func (c *Controller) commitTerminal(ctx context.Context, runID string, spec terminalSpec) (sandboxstore.Run, error) {
	for attempt := 0; attempt < 4; attempt++ {
		run, err := c.store.GetRun(ctx, runID)
		if err != nil {
			return sandboxstore.Run{}, err
		}
		if terminalState(run.State) {
			return run, nil
		}
		// This is the final typed guard before the Store transaction. A pending
		// Create may still complete, so cancellation, deadline, and all other
		// causes are secondary until that authority is definitively cleared.
		if run.RuntimeIntentPending {
			spec = terminalInterrupted
		} else if run.State == executionwire.RunStateCancelling {
			spec = terminalCancelled
		}
		event := executionwire.RunEvent{
			RunID: runID,
			Seq:   run.LastEventSeq + 1,
			Type:  spec.eventType,
		}
		if spec.eventType == executionwire.RunEventFailed || spec.eventType == executionwire.RunEventInterrupted {
			event.Failure = &executionwire.RunFailure{Code: spec.code, Message: spec.message}
		}
		run, err = c.store.AppendEvent(ctx, event, nil)
		if err == nil {
			return run, nil
		}
		if !errors.Is(err, sandboxstore.ErrEventSequence) && !errors.Is(err, sandboxstore.ErrIllegalTransition) {
			return sandboxstore.Run{}, err
		}
	}
	run, err := c.store.GetRun(ctx, runID)
	if err == nil && terminalState(run.State) {
		return run, nil
	}
	if err != nil {
		return sandboxstore.Run{}, err
	}
	return sandboxstore.Run{}, sandboxstore.ErrIllegalTransition
}

func terminalState(state executionwire.RunState) bool {
	switch state {
	case executionwire.RunStateCompleted, executionwire.RunStateFailed,
		executionwire.RunStateCancelled, executionwire.RunStateInterrupted:
		return true
	default:
		return false
	}
}

func (c *Controller) rememberDesiredTerminal(runID string, spec terminalSpec) {
	c.mu.Lock()
	if c.desired != nil {
		c.desired[runID] = spec
		delete(c.certainNoRuntime, runID)
	}
	c.mu.Unlock()
	c.signalReconcile()
}

func (c *Controller) rememberCertainNoRuntimeTerminal(runID string, spec terminalSpec) {
	c.mu.Lock()
	if c.desired != nil {
		c.desired[runID] = spec
		c.certainNoRuntime[runID] = true
	}
	c.mu.Unlock()
	c.signalReconcile()
}

func (c *Controller) desiredTerminal(runID string) (terminalSpec, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	spec, exists := c.desired[runID]
	return spec, c.certainNoRuntime[runID], exists
}

func (c *Controller) clearDesiredTerminal(runID string) {
	c.mu.Lock()
	delete(c.desired, runID)
	delete(c.certainNoRuntime, runID)
	c.mu.Unlock()
}
