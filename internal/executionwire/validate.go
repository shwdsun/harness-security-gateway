package executionwire

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
)

// ValidationError identifies one invalid wire field without echoing its
// potentially sensitive value.
type ValidationError struct {
	Field   string
	Problem string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid %s: %s", e.Field, e.Problem)
}

func invalid(field, problem string) error {
	return &ValidationError{Field: field, Problem: problem}
}

func (v MediaType) valid() bool {
	return v == MediaTypeTextPlain
}

func (s RunState) valid() bool {
	switch s {
	case RunStateAccepted, RunStateRunning, RunStateCancelling,
		RunStateCompleted, RunStateFailed, RunStateCancelled,
		RunStateInterrupted:
		return true
	default:
		return false
	}
}

func (t RunEventType) valid() bool {
	switch t {
	case RunEventStarted, RunEventProgress, RunEventCompleted, RunEventFailed,
		RunEventCancelled, RunEventInterrupted:
		return true
	default:
		return false
	}
}

func (k ProgressKind) valid() bool {
	return k == ProgressStatus || k == ProgressOutputDelta
}

func (c FailureCode) valid() bool {
	switch c {
	case FailureTargetUnavailable, FailureRevisionMismatch, FailureInvalidSession,
		FailurePolicyDenied, FailureDeadlineExceeded, FailureOutputLimit,
		FailureRunnerFailed, FailureProtocolViolation, FailureRuntimeInterrupted,
		FailureInternal:
		return true
	default:
		return false
	}
}

func (r StartRunRequest) Validate() error {
	if err := validateRunID("run_id", r.RunID); err != nil {
		return err
	}
	if err := validateName("target_id", r.TargetID, MaxTargetIDBytes); err != nil {
		return err
	}
	if err := validateName("expected_revision", r.ExpectedRevision, MaxRevisionBytes); err != nil {
		return err
	}
	if err := sessionauth.ValidateDigest(r.SessionScopeDigest); err != nil {
		return invalid("session_scope_digest", "must be a lowercase SHA-256 hex digest")
	}
	if r.SessionRef != nil {
		if err := validateOpaqueRef("session_ref", *r.SessionRef); err != nil {
			return err
		}
	}
	if err := r.Input.Validate(); err != nil {
		return err
	}
	if r.Deadline.IsZero() {
		return invalid("deadline", "must be set")
	}
	if _, err := r.Deadline.MarshalText(); err != nil {
		return invalid("deadline", "must be representable as RFC 3339")
	}
	return nil
}

func (i TextInput) Validate() error {
	if !i.MediaType.valid() {
		return invalid("input.media_type", "unsupported value")
	}
	if !utf8.ValidString(i.Text) {
		return invalid("input.text", "must be valid UTF-8")
	}
	if strings.TrimSpace(i.Text) == "" {
		return invalid("input.text", "must not be empty")
	}
	if strings.ContainsRune(i.Text, '\x00') {
		return invalid("input.text", "must not contain NUL")
	}
	if len(i.Text) > MaxInputTextBytes {
		return invalid("input.text", "exceeds byte limit")
	}
	return nil
}

func (r CancelRunRequest) Validate() error {
	return validateRunID("run_id", r.RunID)
}

func (r GetRunRequest) Validate() error {
	return validateRunID("run_id", r.RunID)
}

func (s RunStatus) Validate() error {
	if err := validateRunID("status.run_id", s.RunID); err != nil {
		return err
	}
	if !s.State.valid() {
		return invalid("status.state", "unsupported value")
	}
	if s.LastEventSeq > MaxEvents {
		return invalid("status.last_event_seq", "exceeds event limit")
	}
	if s.State == RunStateAccepted && s.LastEventSeq != 0 {
		return invalid("status.last_event_seq", "accepted run must not have events")
	}
	// Cancellation authority can arrive after StartRun is durably accepted but
	// before the runner emits run.started. That brief state is observable and
	// has no invented event; the eventual cancelled/interrupted event starts at
	// sequence one.
	if s.State != RunStateAccepted && s.State != RunStateCancelling && s.LastEventSeq == 0 {
		return invalid("status.last_event_seq", "non-accepted run must have an event")
	}
	return nil
}

func (p RunProgress) Validate() error {
	if !p.Kind.valid() {
		return invalid("event.progress.kind", "unsupported value")
	}
	if !utf8.ValidString(p.Text) {
		return invalid("event.progress.text", "must be valid UTF-8")
	}
	if strings.TrimSpace(p.Text) == "" {
		return invalid("event.progress.text", "must not be empty")
	}
	if strings.ContainsRune(p.Text, '\x00') {
		return invalid("event.progress.text", "must not contain NUL")
	}
	if len(p.Text) > MaxProgressTextBytes {
		return invalid("event.progress.text", "exceeds byte limit")
	}
	return nil
}

func (o TextOutput) Validate() error {
	if !o.MediaType.valid() {
		return invalid("event.result.output.media_type", "unsupported value")
	}
	if !utf8.ValidString(o.Text) {
		return invalid("event.result.output.text", "must be valid UTF-8")
	}
	if strings.ContainsRune(o.Text, '\x00') {
		return invalid("event.result.output.text", "must not contain NUL")
	}
	if len(o.Text) > MaxOutputTextBytes {
		return invalid("event.result.output.text", "exceeds byte limit")
	}
	return nil
}

func (r RunResult) Validate() error {
	if err := r.Output.Validate(); err != nil {
		return err
	}
	if r.SessionRef != nil {
		if err := validateOpaqueRef("event.result.session_ref", *r.SessionRef); err != nil {
			return err
		}
	}
	return nil
}

func (f RunFailure) Validate() error {
	if !f.Code.valid() {
		return invalid("event.failure.code", "unsupported value")
	}
	if !utf8.ValidString(f.Message) {
		return invalid("event.failure.message", "must be valid UTF-8")
	}
	if strings.TrimSpace(f.Message) == "" {
		return invalid("event.failure.message", "must not be empty")
	}
	if strings.ContainsRune(f.Message, '\x00') {
		return invalid("event.failure.message", "must not contain NUL")
	}
	if len(f.Message) > MaxFailureMessageBytes {
		return invalid("event.failure.message", "exceeds byte limit")
	}
	return nil
}

func (e RunEvent) Validate() error {
	if err := validateRunID("event.run_id", e.RunID); err != nil {
		return err
	}
	if e.Seq == 0 || e.Seq > MaxEvents {
		return invalid("event.seq", "must be within the event limit")
	}
	if !e.Type.valid() {
		return invalid("event.type", "unsupported value")
	}

	switch e.Type {
	case RunEventStarted, RunEventCancelled:
		if e.Progress != nil || e.Result != nil || e.Failure != nil {
			return invalid("event", "event type must not have a payload")
		}
	case RunEventProgress:
		if e.Progress == nil || e.Result != nil || e.Failure != nil {
			return invalid("event", "progress event must have only a progress payload")
		}
		return e.Progress.Validate()
	case RunEventCompleted:
		if e.Progress != nil || e.Result == nil || e.Failure != nil {
			return invalid("event", "completed event must have only a result payload")
		}
		return e.Result.Validate()
	case RunEventFailed, RunEventInterrupted:
		if e.Progress != nil || e.Result != nil || e.Failure == nil {
			return invalid("event", "failure event must have only a failure payload")
		}
		if e.Type == RunEventInterrupted && e.Failure.Code != FailureRuntimeInterrupted {
			return invalid("event.failure.code", "interrupted event requires runtime_interrupted")
		}
		if e.Type == RunEventFailed && e.Failure.Code == FailureRuntimeInterrupted {
			return invalid("event.failure.code", "runtime_interrupted requires interrupted event")
		}
		return e.Failure.Validate()
	}
	return nil
}

func (r GetRunResponse) Validate() error {
	if err := r.Status.Validate(); err != nil {
		return err
	}
	if len(r.Events) > MaxEvents {
		return invalid("events", "exceeds event limit")
	}
	if len(r.Events) == 0 {
		if (r.Status.State != RunStateAccepted && r.Status.State != RunStateCancelling) || r.Status.LastEventSeq != 0 {
			return invalid("events", "missing events for a state that requires runner events")
		}
		return nil
	}

	for index := range r.Events {
		event := r.Events[index]
		if err := event.Validate(); err != nil {
			return fmt.Errorf("events[%d]: %w", index, err)
		}
		if event.RunID != r.Status.RunID {
			return invalid(fmt.Sprintf("events[%d].run_id", index), "does not match status")
		}
		expected := uint64(index + 1)
		if event.Seq != expected {
			return invalid(fmt.Sprintf("events[%d].seq", index), "must be contiguous and begin at one")
		}
	}
	if uint64(len(r.Events)) != r.Status.LastEventSeq {
		return invalid("status.last_event_seq", "does not match the final event")
	}
	return validateStateAgainstFinalEvent(r.Status.State, r.Events[len(r.Events)-1].Type)
}

func validateStateAgainstFinalEvent(state RunState, eventType RunEventType) error {
	valid := false
	switch state {
	case RunStateRunning, RunStateCancelling:
		valid = eventType == RunEventStarted || eventType == RunEventProgress
	case RunStateCompleted:
		valid = eventType == RunEventCompleted
	case RunStateFailed:
		valid = eventType == RunEventFailed
	case RunStateCancelled:
		valid = eventType == RunEventCancelled
	case RunStateInterrupted:
		valid = eventType == RunEventInterrupted
	}
	if !valid {
		return invalid("status.state", "does not match the final event")
	}
	return nil
}

func validateRunID(field, value string) error {
	if len(value) == 0 || len(value) > MaxRunIDBytes {
		return invalid(field, "has invalid byte length")
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if isASCIIAlphaNumeric(char) || char == '-' || char == '_' {
			continue
		}
		return invalid(field, "contains unsupported characters")
	}
	return nil
}

func validateName(field, value string, maxBytes int) error {
	if len(value) == 0 || len(value) > maxBytes {
		return invalid(field, "has invalid byte length")
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if isASCIIAlphaNumeric(char) || char == '-' || char == '_' || char == '.' || char == ':' || char == '@' {
			continue
		}
		return invalid(field, "contains unsupported characters")
	}
	return nil
}

func validateOpaqueRef(field, value string) error {
	if len(value) == 0 || len(value) > MaxSessionRefBytes {
		return invalid(field, "has invalid byte length")
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if isASCIIAlphaNumeric(char) || char == '-' || char == '_' || char == '.' || char == '~' {
			continue
		}
		return invalid(field, "contains unsupported characters")
	}
	return nil
}

func isASCIIAlphaNumeric(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
}
