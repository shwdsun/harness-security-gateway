package dockerruntime

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidConfig       = errors.New("docker runtime: invalid configuration")
	ErrInvalidArgument     = errors.New("docker runtime: invalid argument")
	ErrInvalidRef          = errors.New("docker runtime: invalid container reference")
	ErrNotFound            = errors.New("docker runtime: container not found")
	ErrInvalidStorage      = errors.New("docker runtime: invalid storage directory")
	ErrUnsupportedProfile  = errors.New("docker runtime: unsupported security profile")
	ErrTargetNotConfigured = errors.New("docker runtime: target revision is not configured")
	ErrForeignContainer    = errors.New("docker runtime: refusing foreign container")
	ErrInvalidState        = errors.New("docker runtime: invalid container state")
	ErrInvalidResponse     = errors.New("docker runtime: invalid Docker response")
	ErrRootlessRequired    = errors.New("docker runtime: daemon is not attested rootless")
	ErrOutputLimit         = errors.New("docker runtime: command output limit exceeded")
	ErrCommandFailed       = errors.New("docker runtime: Docker CLI command failed")
	// ErrCreateUncertain means the Docker CLI process carrying a container
	// create request was started, but this call could not prove either the
	// exact managed container or a completed failure. Callers must preserve the
	// durable intent and reconcile by read-only lookup/host epoch; retrying
	// Create is forbidden.
	ErrCreateUncertain = errors.New("docker runtime: container create outcome uncertain")
)

// createUncertainError is deliberately closed: callers classify it with
// errors.Is and cannot attach unbounded daemon text. Its causes are already
// sanitized package errors, retained so context cancellation, output limits,
// invalid responses, and command failures remain machine-classifiable.
type createUncertainError struct {
	causes []error
}

func (e *createUncertainError) Error() string {
	return "docker runtime container create outcome uncertain"
}

func (e *createUncertainError) Unwrap() []error {
	result := make([]error, 0, len(e.causes)+1)
	result = append(result, ErrCreateUncertain)
	for _, cause := range e.causes {
		if cause != nil {
			result = append(result, cause)
		}
	}
	return result
}

func uncertainCreate(causes ...error) error {
	return &createUncertainError{causes: append([]error(nil), causes...)}
}

// CommandError is safe to return across internal boundaries. It retains an
// exit code and error identity but never includes Docker CLI stderr.
type CommandError struct {
	Operation string
	ExitCode  int
	Kind      error
	Cause     error
}

func (e *CommandError) Error() string {
	if e == nil {
		return "docker runtime command failed"
	}
	if e.Operation == "" {
		return "docker runtime command failed"
	}
	return fmt.Sprintf("docker runtime %s failed", e.Operation)
}

func (e *CommandError) Unwrap() []error {
	if e == nil {
		return nil
	}
	result := make([]error, 0, 2)
	if e.Kind != nil {
		result = append(result, e.Kind)
	}
	if e.Cause != nil {
		result = append(result, e.Cause)
	}
	return result
}
