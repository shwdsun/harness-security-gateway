package connectorwire

const (
	MaxIDBytes         = 256
	MaxAliasBytes      = 64
	MaxTextBytes       = 32 * 1024
	MaxClaimDeliveries = 20

	// MaxPayloadBytes is the hard upper bound for one connector JSON document.
	// It accommodates a maximum-size claimed delivery batch; HTTP handlers
	// should normally apply smaller, endpoint-specific request limits.
	MaxPayloadBytes = 1024 * 1024
	MaxJSONDepth    = 8
)

type ContentType string

const (
	ContentTypeText   ContentType = "text"
	ContentTypeAction ContentType = "action"
)

type ActionType string

const (
	ActionStatus       ActionType = "status"
	ActionCancel       ActionType = "cancel"
	ActionSelectTarget ActionType = "select_target"
)

// InboundEventV1 contains only stable platform facts and normalized content.
// The connector instance, routing target, runtime policy, and raw provider
// payload are deliberately not representable.
type InboundEventV1 struct {
	EventID          string           `json:"event_id"`
	ActorRef         string           `json:"actor_ref"`
	ConversationRef  string           `json:"conversation_ref"`
	MessageRef       string           `json:"message_ref"`
	OccurredAtUnixMS int64            `json:"occurred_at_unix_ms"`
	Content          InboundContentV1 `json:"content"`
}

type InboundDisposition string

const (
	InboundAccepted  InboundDisposition = "accepted"
	InboundDuplicate InboundDisposition = "duplicate"
)

// InboundReceiptV1 confirms that agentd durably committed the event. RunID is
// present for text events that create a Run; bounded control actions may have
// no Run of their own.
type InboundReceiptV1 struct {
	EventID     string             `json:"event_id"`
	Disposition InboundDisposition `json:"disposition"`
	RunID       string             `json:"run_id,omitempty"`
}

// InboundContentV1 is a closed tagged union. Type text requires Text and
// forbids Action; type action requires Action and forbids Text.
type InboundContentV1 struct {
	Type   ContentType      `json:"type"`
	Text   string           `json:"text,omitempty"`
	Action *InboundActionV1 `json:"action,omitempty"`
}

// InboundActionV1 is a closed action union. TargetAlias is present only for a
// select_target action. Status and cancel operate on the current conversation.
type InboundActionV1 struct {
	Type        ActionType `json:"type"`
	TargetAlias string     `json:"target_alias,omitempty"`
}

// DeliveryClaimV1 asks for a small bounded batch. Lease duration and retry
// policy remain agentd configuration and cannot be selected by a connector.
type DeliveryClaimV1 struct {
	Limit int `json:"limit"`
}

type DeliveryClaimResultV1 struct {
	Deliveries []OutboundTextV1 `json:"deliveries"`
}

// OutboundTextV1 is the only outbound content type in v1. LeaseToken is a
// capability for completing this delivery and must not be reused for another
// delivery.
type OutboundTextV1 struct {
	DeliveryID         string      `json:"delivery_id"`
	LeaseToken         string      `json:"lease_token"`
	LeaseExpiresUnixMS int64       `json:"lease_expires_unix_ms"`
	ConversationRef    string      `json:"conversation_ref"`
	ReplyToRef         string      `json:"reply_to_ref,omitempty"`
	Content            PlainTextV1 `json:"content"`
}

type PlainTextV1 struct {
	MediaType string `json:"media_type"`
	Text      string `json:"text"`
}

type DeliveryOutcome string

const (
	DeliveryDelivered        DeliveryOutcome = "delivered"
	DeliveryRetry            DeliveryOutcome = "retry"
	DeliveryPermanentFailure DeliveryOutcome = "permanent_failure"
)

// DeliveryFailureClass is a safe platform-independent classification. It is
// deliberately less detailed than provider diagnostics, which stay inside the
// connector's bounded local logs.
type DeliveryFailureClass string

const (
	FailureTemporary            DeliveryFailureClass = "temporary_failure"
	FailureRateLimited          DeliveryFailureClass = "rate_limited"
	FailureRecipientUnavailable DeliveryFailureClass = "recipient_unavailable"
	FailureContentRejected      DeliveryFailureClass = "content_rejected"
	FailureNotAuthorized        DeliveryFailureClass = "not_authorized"
	FailureConnectorInternal    DeliveryFailureClass = "connector_internal"
)

// DeliveryCompleteV1 resolves one leased provider attempt. It deliberately
// carries no provider error text or retry delay: the connector classifies the
// result, while agentd owns bounded retry policy and diagnostics stay local.
type DeliveryCompleteV1 struct {
	DeliveryID         string               `json:"delivery_id"`
	LeaseToken         string               `json:"lease_token"`
	Outcome            DeliveryOutcome      `json:"outcome"`
	ProviderMessageRef string               `json:"provider_message_ref,omitempty"`
	FailureClass       DeliveryFailureClass `json:"failure_class,omitempty"`
}
