package sandboxcontroller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
)

const (
	cleanupPollInterval = 10 * time.Millisecond
	cleanupSignalGrace  = 50 * time.Millisecond
)

func (c *Controller) cleanupRuntime(ref string) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.cleanupTimeout)
	defer cancel()
	return c.cleanupRuntimeContext(ctx, ref)
}

func (c *Controller) cleanupRuntimeContext(ctx context.Context, ref string) error {
	inspection, err := c.inspectAfterSignal(ctx, ref, 0)
	if errors.Is(err, dockerruntime.ErrNotFound) {
		return nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return cleanupCause("inspect", ctx.Err())
		}
		return cleanupCause("inspect", err)
	}

	if runtimeActive(inspection.State) {
		stopErr := c.runtime.Stop(ctx, ref)
		if errors.Is(stopErr, dockerruntime.ErrNotFound) {
			return nil
		}
		inspection, err = c.inspectAfterSignal(ctx, ref, cleanupSignalGrace)
		if errors.Is(err, dockerruntime.ErrNotFound) {
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return cleanupCause("inspect-after-stop", ctx.Err())
			}
			if stopErr != nil {
				return cleanupCause("stop", stopErr)
			}
			return cleanupCause("inspect-after-stop", err)
		}
		if runtimeActive(inspection.State) {
			killErr := c.runtime.Kill(ctx, ref)
			if errors.Is(killErr, dockerruntime.ErrNotFound) {
				return nil
			}
			inspection, err = c.inspectAfterSignal(ctx, ref, cleanupSignalGrace)
			if errors.Is(err, dockerruntime.ErrNotFound) {
				return nil
			}
			if err != nil {
				if ctx.Err() != nil {
					return cleanupCause("inspect-after-kill", ctx.Err())
				}
				if killErr != nil {
					return cleanupCause("kill", killErr)
				}
				return cleanupCause("inspect-after-kill", err)
			}
			if runtimeActive(inspection.State) {
				return cleanupError("container-remained-active")
			}
		}
	}

	if !runtimeRemovable(inspection.State) {
		return cleanupError("container-not-removable")
	}
	removeErr := c.runtime.RemoveStopped(ctx, ref)
	if removeErr == nil || errors.Is(removeErr, dockerruntime.ErrNotFound) {
		return nil
	}
	// Remove can succeed at the daemon while its CLI response is lost. Only the
	// runtime's strict full-ID absence proof lets us treat that as success.
	_, inspectErr := c.inspectAfterSignal(ctx, ref, 0)
	if errors.Is(inspectErr, dockerruntime.ErrNotFound) {
		return nil
	}
	if inspectErr != nil {
		return cleanupCause("remove", errors.Join(removeErr, inspectErr))
	}
	return cleanupCause("remove", removeErr)
}

// inspectAfterSignal waits for Docker's asynchronous state convergence without
// ever extending ctx. StateRemoving has no safe signal to send, so it waits for
// absence or another closed state. An active state gets only grace before the
// caller escalates from Stop to Kill.
func (c *Controller) inspectAfterSignal(
	ctx context.Context,
	ref string,
	grace time.Duration,
) (dockerruntime.Inspection, error) {
	var graceTimer *time.Timer
	var graceDone <-chan time.Time
	if grace > 0 {
		graceTimer = time.NewTimer(grace)
		graceDone = graceTimer.C
		defer graceTimer.Stop()
	}
	for {
		inspection, err := c.runtime.Inspect(ctx, ref)
		if err != nil {
			return dockerruntime.Inspection{}, err
		}
		removing := inspection.State == dockerruntime.StateRemoving
		if !removing && (!runtimeActive(inspection.State) || grace == 0) {
			return inspection, nil
		}

		timer := time.NewTimer(cleanupPollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return dockerruntime.Inspection{}, ctx.Err()
		case <-graceDone:
			if !timer.Stop() {
				<-timer.C
			}
			if !removing {
				return inspection, nil
			}
			// Removing cannot be escalated. Continue under the original ctx.
			graceDone = nil
		case <-timer.C:
		}
	}
}

func runtimeActive(state dockerruntime.ContainerState) bool {
	switch state {
	case dockerruntime.StateRunning, dockerruntime.StatePaused, dockerruntime.StateRestarting:
		return true
	default:
		return false
	}
}

func runtimeRemovable(state dockerruntime.ContainerState) bool {
	switch state {
	case dockerruntime.StateCreated, dockerruntime.StateExited, dockerruntime.StateDead:
		return true
	default:
		return false
	}
}

func cleanupError(stage string) error {
	return fmt.Errorf("%w: %s", ErrCleanup, stage)
}

func cleanupCause(stage string, cause error) error {
	return fmt.Errorf("%w: %s: %w", ErrCleanup, stage, cause)
}

func waitBriefly(wait <-chan error, grace time.Duration) error {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-wait:
		return err
	case <-timer.C:
		return nil
	}
}
