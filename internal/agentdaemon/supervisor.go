// Package agentdaemon contains agentd's small process-level dispatch loop.
// Durable run semantics remain in corestore and agentdispatch; this package
// only decides when to ask that state machine for its next bounded step.
package agentdaemon

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentdispatch"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
)

// Engine is the complete scheduling surface used by the daemon loop.
type Engine interface {
	DispatchOne(context.Context) (agentdispatch.Result, bool, error)
	Advance(context.Context, string) (agentdispatch.Result, error)
	Reconcile(context.Context, int) ([]agentdispatch.ReconcileItem, error)
}

// Reporter receives only a closed error code. Causes can contain local paths
// or provider details and must not be written to normal daemon logs.
type Reporter func(agentdispatch.ErrorCode)

// Run executes a single-worker MVP scheduler until ctx ends. A Run that is
// still dispatching is remembered in memory and advanced before its lease can
// expire. A durably running Run always gates new dispatches and is reconciled
// without ever being started as a fresh execution.
func Run(ctx context.Context, engine Engine, interval time.Duration, report Reporter) error {
	if ctx == nil {
		return errors.New("agentdaemon: nil context")
	}
	if nilInterface(engine) {
		return errors.New("agentdaemon: nil dispatch engine")
	}
	if interval <= 0 || interval > time.Minute {
		return errors.New("agentdaemon: poll interval must be between zero and one minute")
	}
	if report == nil {
		report = func(agentdispatch.ErrorCode) {}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var activeDispatch string

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		hadDurableRunning := false
		items, err := engine.Reconcile(ctx, corestore.MaxReconcileRuns)
		if err != nil {
			if contextDone(ctx, err) {
				return nil
			}
			// Listing failure makes the existence of a running writer unknown.
			// Fail closed and do not claim new work in this cycle.
			hadDurableRunning = true
			report(errorCode(err))
		} else {
			hadDurableRunning = len(items) != 0
			for _, item := range items {
				if item.Err != nil {
					if contextDone(ctx, item.Err) {
						return nil
					}
					report(errorCode(item.Err))
				}
			}
		}

		// Do not dispatch a second Run in the same cycle in which an active
		// dispatch crossed into running or terminal state.
		hadActiveDispatch := activeDispatch != ""
		if activeDispatch != "" {
			result, advanceErr := engine.Advance(ctx, activeDispatch)
			if advanceErr != nil {
				if contextDone(ctx, advanceErr) {
					return nil
				}
				report(errorCode(advanceErr))
			}
			if result.Finished || result.CoreState == corestore.RunRunning || shouldForget(advanceErr) {
				activeDispatch = ""
			}
		}

		if !hadDurableRunning && !hadActiveDispatch && activeDispatch == "" {
			result, claimed, dispatchErr := engine.DispatchOne(ctx)
			if dispatchErr != nil {
				if contextDone(ctx, dispatchErr) {
					return nil
				}
				report(errorCode(dispatchErr))
			}
			if claimed && result.RunID == "" {
				report(agentdispatch.ErrorInvalidState)
			} else if claimed && !result.Finished && result.CoreState == corestore.RunDispatching && !shouldForget(dispatchErr) {
				activeDispatch = result.RunID
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func shouldForget(err error) bool {
	if err == nil {
		return false
	}
	switch errorCode(err) {
	case agentdispatch.ErrorDispatchLost,
		agentdispatch.ErrorConflict,
		agentdispatch.ErrorInvalidState,
		agentdispatch.ErrorProtocolViolation:
		return true
	default:
		return false
	}
}

func errorCode(err error) agentdispatch.ErrorCode {
	var dispatchError *agentdispatch.Error
	if errors.As(err, &dispatchError) && dispatchError != nil {
		return dispatchError.Code
	}
	return agentdispatch.ErrorInvalidState
}

func contextDone(ctx context.Context, err error) bool {
	// A lower layer may have its own request timeout while the daemon remains
	// healthy. Only the supervisor's parent context is a shutdown signal.
	return ctx.Err() != nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ Engine = (*agentdispatch.Engine)(nil)
