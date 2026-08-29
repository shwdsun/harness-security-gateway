package corestore

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

func validateIngest(input IngestTextRunInput) error {
	for _, item := range []struct {
		field string
		value string
		limit int
	}{
		{"connector_id", input.ConnectorID, MaxIDBytes},
		{"event_id", input.EventID, MaxIDBytes},
		{"actor_ref", input.ActorRef, MaxIDBytes},
		{"conversation_ref", input.ConversationRef, MaxIDBytes},
		{"message_ref", input.MessageRef, MaxIDBytes},
	} {
		if err := validateIdentifier(item.field, item.value, item.limit); err != nil {
			return err
		}
	}
	if input.OccurredAtUnixMS <= 0 {
		return invalidInput("occurred_at_unix_ms", "must be positive")
	}
	return validateText("text", input.Text, false)
}

func validateTextRunAuthorization(authorization TextRunAuthorization) error {
	for _, item := range []struct {
		field string
		value string
		limit int
	}{
		{"target_id", authorization.TargetID, MaxTargetIDBytes},
		{"target_revision", authorization.TargetRevision, MaxRevisionBytes},
	} {
		if err := validateIdentifier(item.field, item.value, item.limit); err != nil {
			return err
		}
	}
	if err := validateSHA256Hex("binding_fingerprint", authorization.BindingFingerprint); err != nil {
		return err
	}
	return validateSHA256Hex("policy_revision", authorization.PolicyRevision)
}

func validateSHA256Hex(field, value string) error {
	if len(value) != SHA256HexBytes {
		return invalidInput(field, "must be a lowercase SHA-256 hex digest")
	}
	for index := range value {
		character := value[index]
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return invalidInput(field, "must be a lowercase SHA-256 hex digest")
	}
	return nil
}

func validateSessionKey(key SessionKey) error {
	if err := validateSHA256Hex("binding_fingerprint", key.BindingFingerprint); err != nil {
		return err
	}
	for _, item := range []struct {
		field string
		value string
		limit int
	}{
		{"connector_id", key.ConnectorID, MaxIDBytes},
		{"actor_ref", key.ActorRef, MaxIDBytes},
		{"conversation_ref", key.ConversationRef, MaxIDBytes},
		{"target_id", key.TargetID, MaxTargetIDBytes},
		{"target_revision", key.TargetRevision, MaxRevisionBytes},
	} {
		if err := validateIdentifier(item.field, item.value, item.limit); err != nil {
			return err
		}
	}
	return nil
}

func validateSessionRef(value string) error {
	if len(value) == 0 || len(value) > MaxSessionRefBytes {
		return invalidInput("session_ref", fmt.Sprintf("must contain 1 to %d bytes", MaxSessionRefBytes))
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if isASCIIAlphaNumeric(char) || char == '-' || char == '_' || char == '.' || char == '~' {
			continue
		}
		return invalidInput("session_ref", "contains unsupported characters")
	}
	return nil
}

func validateFinish(input FinishRunInput) error {
	if err := validateIdentifier("run_id", input.RunID, MaxIDBytes); err != nil {
		return err
	}
	if err := validateIdentifier("dispatch_token", input.DispatchToken, MaxIDBytes); err != nil {
		return err
	}
	switch input.State {
	case RunCompleted:
		if input.FailureCode != "" {
			return invalidInput("failure_code", "must be empty for a completed run")
		}
		if err := validateText("output_text", input.OutputText, true); err != nil {
			return err
		}
		if input.ResultSessionRef != "" {
			return validateSessionRef(input.ResultSessionRef)
		}
		return nil
	case RunFailed:
		if input.OutputText != "" || input.ResultSessionRef != "" {
			return invalidInput("finish", "failed run cannot contain output or a session ref")
		}
		if !input.FailureCode.valid() || input.FailureCode == RunFailureRuntimeInterrupted {
			return invalidInput("failure_code", "unsupported for a failed run")
		}
		return nil
	case RunCancelled:
		if input.OutputText != "" || input.FailureCode != "" || input.ResultSessionRef != "" {
			return invalidInput("finish", "cancelled run cannot contain output, failure, or session ref")
		}
		return nil
	case RunInterrupted:
		if input.OutputText != "" || input.ResultSessionRef != "" || input.FailureCode != RunFailureRuntimeInterrupted {
			return invalidInput("finish", "interrupted run requires only runtime_interrupted")
		}
		return nil
	default:
		return invalidInput("state", "must be a terminal run state")
	}
}

func validatePrepareRunStart(input PrepareRunStartInput, nowMillis int64) error {
	if err := validateIdentifier("run_id", input.RunID, MaxIDBytes); err != nil {
		return err
	}
	if err := validateIdentifier("dispatch_token", input.DispatchToken, MaxIDBytes); err != nil {
		return err
	}
	if input.SessionRef != nil {
		if err := validateSessionRef(*input.SessionRef); err != nil {
			return err
		}
	}
	if input.Deadline.IsZero() {
		return invalidInput("deadline", "must be set")
	}
	deadline := input.Deadline.UTC()
	if deadline.Year() < 1970 || deadline.Year() > 9999 {
		return invalidInput("deadline", "must be between 1970 and 9999")
	}
	if _, err := deadline.MarshalText(); err != nil {
		return invalidInput("deadline", "must be representable as RFC 3339")
	}
	if deadline.UnixMilli() <= nowMillis {
		return invalidInput("deadline", "must be after the current store time")
	}
	return nil
}

func (code RunFailureCode) valid() bool {
	switch code {
	case RunFailureTargetUnavailable, RunFailureRevisionMismatch,
		RunFailureInvalidSession, RunFailurePolicyDenied,
		RunFailureDeadlineExceeded, RunFailureOutputLimit,
		RunFailureRunnerFailed, RunFailureProtocolViolation,
		RunFailureRuntimeInterrupted, RunFailureInternal:
		return true
	default:
		return false
	}
}

func validateDelivery(input TextDeliveryInput) error {
	if err := validateIdentifier("delivery_id", input.ID, MaxIDBytes); err != nil {
		return err
	}
	return validateText("text", input.Text, false)
}

func validateCompletion(input CompleteDeliveryInput) error {
	for _, item := range []struct {
		field string
		value string
	}{
		{"connector_id", input.ConnectorID},
		{"delivery_id", input.DeliveryID},
		{"lease_token", input.LeaseToken},
	} {
		if err := validateIdentifier(item.field, item.value, MaxIDBytes); err != nil {
			return err
		}
	}
	switch input.Outcome {
	case DeliveryOutcomeDelivered:
		if err := validateIdentifier("provider_message_ref", input.ProviderMessageRef, MaxIDBytes); err != nil {
			return err
		}
		if input.FailureCode != "" {
			return invalidInput("completion", "delivered outcome forbids a failure code")
		}
	case DeliveryOutcomeRetry:
		if input.ProviderMessageRef != "" {
			return invalidInput("provider_message_ref", "must be empty for retry")
		}
		if !input.FailureCode.retryable() {
			return invalidInput("failure_code", "must be a retryable closed code")
		}
	case DeliveryOutcomePermanentFailure:
		if input.ProviderMessageRef != "" {
			return invalidInput("completion", "permanent failure forbids a provider ref")
		}
		if !input.FailureCode.permanent() {
			return invalidInput("failure_code", "must be a permanent closed code")
		}
	default:
		return invalidInput("outcome", "unsupported value")
	}
	return nil
}

func (code DeliveryFailureCode) retryable() bool {
	switch code {
	case DeliveryFailureTemporary, DeliveryFailureRateLimited, DeliveryFailureConnectorInternal:
		return true
	default:
		return false
	}
}

func (code DeliveryFailureCode) permanent() bool {
	switch code {
	case DeliveryFailureRecipientUnavailable, DeliveryFailureContentRejected,
		DeliveryFailureNotAuthorized, DeliveryFailureConnectorInternal:
		return true
	default:
		return false
	}
}

func validateIdentifier(field, value string, maxBytes int) error {
	if value == "" || len(value) > maxBytes {
		return invalidInput(field, fmt.Sprintf("must contain 1 to %d bytes", maxBytes))
	}
	if !utf8.ValidString(value) {
		return invalidInput(field, "must be valid UTF-8")
	}
	for _, char := range value {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return invalidInput(field, "must not contain whitespace or control characters")
		}
	}
	return nil
}

func validateText(field, value string, allowEmpty bool) error {
	if !utf8.ValidString(value) {
		return invalidInput(field, "must be valid UTF-8")
	}
	if len(value) > MaxTextBytes {
		return invalidInput(field, fmt.Sprintf("must be at most %d bytes", MaxTextBytes))
	}
	if !allowEmpty && strings.TrimSpace(value) == "" {
		return invalidInput(field, "must not be empty")
	}
	if strings.IndexByte(value, 0) >= 0 {
		return invalidInput(field, "must not contain NUL")
	}
	return nil
}

func isASCIIAlphaNumeric(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
}

func invalidInput(field, problem string) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalid, field, problem)
}
