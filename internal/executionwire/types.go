// Package executionwire defines the complete, vendor-neutral wire contract
// between agentd and sandboxd.
//
// The package intentionally has no fields for images, paths, commands,
// environments, mounts, network configuration, credentials, or container
// runtime options. Those are resolved exclusively by sandboxd from a trusted,
// immutable target manifest.
package executionwire

import "time"

const (
	// Request and response limits apply before JSON decoding.
	MaxRequestBytes  = 64 << 10
	MaxResponseBytes = 4 << 20
	MaxJSONDepth     = 10

	MaxRunIDBytes          = 64
	MaxTargetIDBytes       = 128
	MaxRevisionBytes       = 160
	MaxSessionRefBytes     = 512
	MaxInputTextBytes      = 32 << 10
	MaxOutputTextBytes     = 32 << 10
	MaxProgressTextBytes   = 8 << 10
	MaxFailureMessageBytes = 4 << 10
	MaxEvents              = 512
)

// MediaType is closed in v1. Attachments and structured input require a later
// protocol revision rather than an open-ended provider options object.
type MediaType string

const MediaTypeTextPlain MediaType = "text/plain"

type TextInput struct {
	MediaType MediaType `json:"media_type"`
	Text      string    `json:"text"`
}

// StartRunRequest is the sole operation that creates execution authority.
// SessionRef, when present, was previously minted by sandboxd and is opaque to
// agentd. It is never accepted directly from a chat user.
type StartRunRequest struct {
	RunID              string    `json:"run_id"`
	TargetID           string    `json:"target_id"`
	ExpectedRevision   string    `json:"expected_revision"`
	SessionScopeDigest string    `json:"session_scope_digest"`
	SessionRef         *string   `json:"session_ref,omitempty"`
	Input              TextInput `json:"input"`
	Deadline           time.Time `json:"deadline"`
}

type CancelRunRequest struct {
	RunID string `json:"run_id"`
}

type GetRunRequest struct {
	RunID string `json:"run_id"`
}

// RunState is a closed description of sandboxd's durable view of a Run.
type RunState string

const (
	RunStateAccepted    RunState = "accepted"
	RunStateRunning     RunState = "running"
	RunStateCancelling  RunState = "cancelling"
	RunStateCompleted   RunState = "completed"
	RunStateFailed      RunState = "failed"
	RunStateCancelled   RunState = "cancelled"
	RunStateInterrupted RunState = "interrupted"
)

type RunStatus struct {
	RunID        string   `json:"run_id"`
	State        RunState `json:"state"`
	LastEventSeq uint64   `json:"last_event_seq"`
}

// RunEventType is closed in v1. Event payloads are represented by the typed
// fields on RunEvent and validated as a discriminated union.
type RunEventType string

const (
	RunEventStarted     RunEventType = "started"
	RunEventProgress    RunEventType = "progress"
	RunEventCompleted   RunEventType = "completed"
	RunEventFailed      RunEventType = "failed"
	RunEventCancelled   RunEventType = "cancelled"
	RunEventInterrupted RunEventType = "interrupted"
)

type ProgressKind string

const (
	ProgressStatus      ProgressKind = "status"
	ProgressOutputDelta ProgressKind = "output_delta"
)

type RunProgress struct {
	Kind ProgressKind `json:"kind"`
	Text string       `json:"text"`
}

type TextOutput struct {
	MediaType MediaType `json:"media_type"`
	Text      string    `json:"text"`
}

type RunResult struct {
	Output     TextOutput `json:"output"`
	SessionRef *string    `json:"session_ref,omitempty"`
}

// FailureCode is deliberately closed. It describes a safe classification,
// not raw harness stderr or a provider-specific error.
type FailureCode string

const (
	FailureTargetUnavailable  FailureCode = "target_unavailable"
	FailureRevisionMismatch   FailureCode = "revision_mismatch"
	FailureInvalidSession     FailureCode = "invalid_session"
	FailurePolicyDenied       FailureCode = "policy_denied"
	FailureDeadlineExceeded   FailureCode = "deadline_exceeded"
	FailureOutputLimit        FailureCode = "output_limit_exceeded"
	FailureRunnerFailed       FailureCode = "runner_failed"
	FailureProtocolViolation  FailureCode = "protocol_violation"
	FailureRuntimeInterrupted FailureCode = "runtime_interrupted"
	FailureInternal           FailureCode = "internal"
)

type RunFailure struct {
	Code    FailureCode `json:"code"`
	Message string      `json:"message"`
}

// RunEvent is a strict discriminated union:
//
//   - started and cancelled have no payload;
//   - progress has Progress only;
//   - completed has Result only;
//   - failed and interrupted have Failure only.
type RunEvent struct {
	RunID    string       `json:"run_id"`
	Seq      uint64       `json:"seq"`
	Type     RunEventType `json:"type"`
	Progress *RunProgress `json:"progress,omitempty"`
	Result   *RunResult   `json:"result,omitempty"`
	Failure  *RunFailure  `json:"failure,omitempty"`
}

// GetRunResponse is a complete bounded event snapshot. V1 does not expose an
// open-ended cursor or metadata bag.
type GetRunResponse struct {
	Status RunStatus  `json:"status"`
	Events []RunEvent `json:"events"`
}
