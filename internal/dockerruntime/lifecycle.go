package dockerruntime

import (
	"context"
	"strconv"
)

func (r *Runtime) Stop(ctx context.Context, ref ContainerRef) error {
	if _, _, err := r.inspectManaged(ctx, ref); err != nil {
		return err
	}
	_, err := r.run(ctx, "stop",
		"container", "stop", "--timeout", strconv.Itoa(stopGraceSeconds), string(ref))
	return err
}

func (r *Runtime) Kill(ctx context.Context, ref ContainerRef) error {
	if _, _, err := r.inspectManaged(ctx, ref); err != nil {
		return err
	}
	_, err := r.run(ctx, "kill",
		"container", "kill", "--signal", "KILL", string(ref))
	return err
}

func (r *Runtime) RemoveStopped(ctx context.Context, ref ContainerRef) error {
	record, spec, err := r.inspectManaged(ctx, ref)
	if err != nil {
		return err
	}
	switch record.State {
	case StateCreated, StateExited, StateDead:
	default:
		return ErrInvalidState
	}
	// The endpoint may otherwise outlive a removed container. Join it before
	// removal, and again through the controller's absence/publication boundary.
	if err := r.CloseRunResources(ctx, record.Labels[labelRunID]); err != nil {
		return err
	}
	_, err = r.run(ctx, "remove", "container", "rm", "--volumes", string(ref))
	if err == nil && spec.credential != nil {
		present, probeErr := r.probeFullRef(ctx, ref)
		if probeErr != nil {
			return probeErr
		}
		if present {
			return ErrInvalidState
		}
		r.forgetCredential(ref)
	}
	return err
}
