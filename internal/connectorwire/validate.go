package connectorwire

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

var ErrInvalid = errors.New("invalid connector v1 document")

// ValidationError identifies a schema field without echoing its untrusted
// value into logs or HTTP responses.
type ValidationError struct {
	Field   string
	Problem string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s: %s", ErrInvalid, e.Field, e.Problem)
}

func (e *ValidationError) Unwrap() error { return ErrInvalid }

type validator interface {
	Validate() error
}

// DecodeStrict decodes exactly one bounded JSON value, rejects duplicate keys
// and unknown fields, and applies the selected v1 DTO's semantic validation.
// maxBytes must be positive and may be lower than MaxPayloadBytes; the protocol
// hard cap is always enforced even if a caller supplies a larger limit.
func DecodeStrict(data []byte, maxBytes int, dst validator) error {
	if dst == nil {
		return errors.New("connectorwire: nil destination")
	}
	if maxBytes <= 0 {
		return errors.New("connectorwire: maxBytes must be positive")
	}
	if maxBytes > MaxPayloadBytes {
		maxBytes = MaxPayloadBytes
	}
	if err := strictjson.Decode(data, maxBytes, MaxJSONDepth, dst); err != nil {
		return err
	}
	return dst.Validate()
}

func (v *InboundEventV1) Validate() error {
	if v == nil {
		return invalid("event", "must not be null")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"event_id", v.EventID},
		{"actor_ref", v.ActorRef},
		{"conversation_ref", v.ConversationRef},
		{"message_ref", v.MessageRef},
	} {
		if err := validateID(field.name, field.value, MaxIDBytes); err != nil {
			return err
		}
	}
	if v.OccurredAtUnixMS <= 0 {
		return invalid("occurred_at_unix_ms", "must be positive")
	}
	return v.Content.validate("content")
}

func (v *InboundReceiptV1) Validate() error {
	if v == nil {
		return invalid("receipt", "must not be null")
	}
	if err := validateID("event_id", v.EventID, MaxIDBytes); err != nil {
		return err
	}
	if v.Disposition != InboundAccepted && v.Disposition != InboundDuplicate {
		return invalid("disposition", "must be accepted or duplicate")
	}
	if v.RunID != "" {
		return validateID("run_id", v.RunID, MaxIDBytes)
	}
	return nil
}

func (v *InboundContentV1) Validate() error {
	if v == nil {
		return invalid("content", "must not be null")
	}
	return v.validate("content")
}

func (v InboundContentV1) validate(field string) error {
	switch v.Type {
	case ContentTypeText:
		if v.Action != nil {
			return invalid(field+".action", "is forbidden for text content")
		}
		return validateText(field+".text", v.Text)
	case ContentTypeAction:
		if v.Text != "" {
			return invalid(field+".text", "is forbidden for action content")
		}
		if v.Action == nil {
			return invalid(field+".action", "is required for action content")
		}
		return v.Action.validate(field + ".action")
	default:
		return invalid(field+".type", "must be text or action")
	}
}

func (v *InboundActionV1) Validate() error {
	if v == nil {
		return invalid("action", "must not be null")
	}
	return v.validate("action")
}

func (v InboundActionV1) validate(field string) error {
	switch v.Type {
	case ActionStatus, ActionCancel:
		if v.TargetAlias != "" {
			return invalid(field+".target_alias", "is allowed only for select_target")
		}
		return nil
	case ActionSelectTarget:
		return validateAlias(field+".target_alias", v.TargetAlias)
	default:
		return invalid(field+".type", "must be status, cancel, or select_target")
	}
}

func (v *DeliveryClaimV1) Validate() error {
	if v == nil {
		return invalid("claim", "must not be null")
	}
	if v.Limit < 1 || v.Limit > MaxClaimDeliveries {
		return invalid("limit", fmt.Sprintf("must be between 1 and %d", MaxClaimDeliveries))
	}
	return nil
}

func (v *DeliveryClaimResultV1) Validate() error {
	if v == nil {
		return invalid("claim_result", "must not be null")
	}
	if v.Deliveries == nil {
		return invalid("deliveries", "must be an array")
	}
	if len(v.Deliveries) > MaxClaimDeliveries {
		return invalid("deliveries", fmt.Sprintf("must contain at most %d items", MaxClaimDeliveries))
	}
	for i := range v.Deliveries {
		if err := v.Deliveries[i].validate(fmt.Sprintf("deliveries[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

func (v *OutboundTextV1) Validate() error {
	if v == nil {
		return invalid("delivery", "must not be null")
	}
	return v.validate("delivery")
}

func (v OutboundTextV1) validate(field string) error {
	for _, id := range []struct {
		name  string
		value string
	}{
		{field + ".delivery_id", v.DeliveryID},
		{field + ".lease_token", v.LeaseToken},
		{field + ".conversation_ref", v.ConversationRef},
	} {
		if err := validateID(id.name, id.value, MaxIDBytes); err != nil {
			return err
		}
	}
	if v.LeaseExpiresUnixMS <= 0 {
		return invalid(field+".lease_expires_unix_ms", "must be positive")
	}
	if v.ReplyToRef != "" {
		if err := validateID(field+".reply_to_ref", v.ReplyToRef, MaxIDBytes); err != nil {
			return err
		}
	}
	return v.Content.validate(field + ".content")
}

func (v *PlainTextV1) Validate() error {
	if v == nil {
		return invalid("content", "must not be null")
	}
	return v.validate("content")
}

func (v PlainTextV1) validate(field string) error {
	if v.MediaType != "text/plain" {
		return invalid(field+".media_type", "must be text/plain")
	}
	return validateText(field+".text", v.Text)
}

func (v *DeliveryCompleteV1) Validate() error {
	if v == nil {
		return invalid("completion", "must not be null")
	}
	if err := validateID("delivery_id", v.DeliveryID, MaxIDBytes); err != nil {
		return err
	}
	if err := validateID("lease_token", v.LeaseToken, MaxIDBytes); err != nil {
		return err
	}
	switch v.Outcome {
	case DeliveryDelivered:
		if err := validateID("provider_message_ref", v.ProviderMessageRef, MaxIDBytes); err != nil {
			return err
		}
		if v.FailureClass != "" {
			return invalid("failure_class", "is forbidden for delivered outcome")
		}
		return nil
	case DeliveryRetry:
		if v.ProviderMessageRef != "" {
			return invalid("provider_message_ref", "is allowed only for delivered outcome")
		}
		if !v.FailureClass.retryable() {
			return invalid("failure_class", "must be temporary_failure, rate_limited, or connector_internal for retry")
		}
		return nil
	case DeliveryPermanentFailure:
		if v.ProviderMessageRef != "" {
			return invalid("provider_message_ref", "is allowed only for delivered outcome")
		}
		if !v.FailureClass.permanent() {
			return invalid("failure_class", "must be recipient_unavailable, content_rejected, not_authorized, or connector_internal for permanent_failure")
		}
		return nil
	default:
		return invalid("outcome", "must be delivered, retry, or permanent_failure")
	}
}

func (value DeliveryFailureClass) retryable() bool {
	switch value {
	case FailureTemporary, FailureRateLimited, FailureConnectorInternal:
		return true
	default:
		return false
	}
}

func (value DeliveryFailureClass) permanent() bool {
	switch value {
	case FailureRecipientUnavailable, FailureContentRejected,
		FailureNotAuthorized, FailureConnectorInternal:
		return true
	default:
		return false
	}
}

func validateID(field, value string, maxBytes int) error {
	if value == "" {
		return invalid(field, "is required")
	}
	if !utf8.ValidString(value) {
		return invalid(field, "must be valid UTF-8")
	}
	if len(value) > maxBytes {
		return invalid(field, fmt.Sprintf("must be at most %d bytes", maxBytes))
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return invalid(field, "must not contain whitespace or control characters")
		}
	}
	return nil
}

func validateAlias(field, value string) error {
	if value == "" {
		return invalid(field, "is required")
	}
	if !utf8.ValidString(value) || len(value) > MaxAliasBytes {
		return invalid(field, fmt.Sprintf("must be valid UTF-8 and at most %d bytes", MaxAliasBytes))
	}
	for i, r := range value {
		alphaNumeric := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		internalSeparator := i > 0 && i < len(value)-1 && (r == '.' || r == '_' || r == '-')
		if !alphaNumeric && !internalSeparator {
			return invalid(field, "must use letters or digits, with internal '.', '_', or '-'")
		}
	}
	return nil
}

func validateText(field, value string) error {
	if value == "" {
		return invalid(field, "is required")
	}
	if !utf8.ValidString(value) {
		return invalid(field, "must be valid UTF-8")
	}
	if len(value) > MaxTextBytes {
		return invalid(field, fmt.Sprintf("must be at most %d bytes", MaxTextBytes))
	}
	if strings.ContainsRune(value, '\x00') {
		return invalid(field, "must not contain NUL")
	}
	return nil
}

func invalid(field, problem string) error {
	return &ValidationError{Field: field, Problem: problem}
}
