package sandboxcontroller

import (
	"context"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
)

func (c *Controller) signalReconcile() {
	if c == nil || c.reconcileWake == nil {
		return
	}
	select {
	case c.reconcileWake <- struct{}{}:
	default:
	}
}

func (c *Controller) reconcileLoop() {
	defer close(c.reconcileDone)
	ticker := time.NewTicker(c.reconcileEvery)
	defer ticker.Stop()
	for {
		select {
		case <-c.rootCtx.Done():
			return
		case <-ticker.C:
		case <-c.reconcileWake:
		}
		c.reconcileOnline()
	}
}

func (c *Controller) reconcileOnline() {
	ctx, cancel := context.WithTimeout(c.rootCtx, c.cleanupTimeout)
	runs, err := c.store.ListUnreconciled(ctx)
	cancel()
	if err != nil {
		return
	}
	for _, run := range runs {
		if c.rootCtx.Err() != nil {
			return
		}
		if !c.claimReconciliation(run) {
			continue
		}
		runCtx, cancel := context.WithTimeout(c.rootCtx, c.cleanupTimeout)
		spec, certainNoRuntime, desired := c.desiredTerminal(run.RunID)
		if desired {
			_ = c.reconcileDesired(runCtx, run, spec, certainNoRuntime)
		} else {
			_ = c.reconcileRun(runCtx, run)
		}
		cancel()
		c.releaseReconciliation(run.RunID)
	}
}

func (c *Controller) claimReconciliation(run sandboxstore.Run) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, desired := c.desired[run.RunID]
	if run.State == executionwire.RunStateAccepted && run.RuntimeRef == nil &&
		!run.RuntimeIntentPending && !desired && run.Deadline.After(c.clock().UTC()) {
		return false
	}
	offered := c.offered[run.RunID]
	if offered == nil {
		c.offered[run.RunID] = &offeredRun{
			fingerprint: run.Fingerprint,
			phase:       phaseReconciling,
		}
		return true
	}
	if offered.phase == phaseActive || offered.phase == phaseReconciling {
		return false
	}
	offered.phase = phaseReconciling
	offered.cancel = nil
	return true
}

func (c *Controller) releaseReconciliation(runID string) {
	c.mu.Lock()
	if offered := c.offered[runID]; offered != nil && offered.phase == phaseReconciling {
		delete(c.offered, runID)
	}
	c.mu.Unlock()
}
