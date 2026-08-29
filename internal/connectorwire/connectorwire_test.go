package connectorwire

import (
	"errors"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

func validTextEventJSON() string {
	return `{"event_id":"evt/1","actor_ref":"user/demo","conversation_ref":"dm/demo","message_ref":"msg/1","occurred_at_unix_ms":1786900000000,"content":{"type":"text","text":"hello\nworld"}}`
}

func TestDecodeStrictInboundText(t *testing.T) {
	var got InboundEventV1
	if err := DecodeStrict([]byte(validTextEventJSON()), MaxPayloadBytes, &got); err != nil {
		t.Fatalf("DecodeStrict() error = %v", err)
	}
	if got.Content.Type != ContentTypeText || got.Content.Text != "hello\nworld" {
		t.Fatalf("decoded content = %#v", got.Content)
	}
}

func TestInboundReceiptValidation(t *testing.T) {
	receipt := InboundReceiptV1{EventID: "event/1", Disposition: InboundAccepted, RunID: "run_1"}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("valid receipt error = %v", err)
	}
	receipt.Disposition = "invented"
	if err := receipt.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid disposition error = %v", err)
	}
	receipt = InboundReceiptV1{EventID: "event/1", Disposition: InboundDuplicate}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("action duplicate receipt error = %v", err)
	}
}

func TestDecodeStrictInboundActions(t *testing.T) {
	tests := []struct {
		name   string
		action string
	}{
		{"status", `{"type":"status"}`},
		{"cancel", `{"type":"cancel"}`},
		{"select target", `{"type":"select_target","target_alias":"claude"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := `{"event_id":"evt/1","actor_ref":"user/demo","conversation_ref":"dm/demo","message_ref":"msg/1","occurred_at_unix_ms":1786900000000,"content":{"type":"action","action":` + tt.action + `}}`
			var got InboundEventV1
			if err := DecodeStrict([]byte(doc), MaxPayloadBytes, &got); err != nil {
				t.Fatalf("DecodeStrict() error = %v", err)
			}
		})
	}
}

func TestInboundContentIsClosedUnion(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"unknown type", `{"type":"image","text":"x"}`},
		{"text with action", `{"type":"text","text":"x","action":{"type":"status"}}`},
		{"action with text", `{"type":"action","text":"x","action":{"type":"cancel"}}`},
		{"action missing body", `{"type":"action"}`},
		{"select missing alias", `{"type":"action","action":{"type":"select_target"}}`},
		{"status with alias", `{"type":"action","action":{"type":"status","target_alias":"codex"}}`},
		{"unknown action", `{"type":"action","action":{"type":"shell"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := `{"event_id":"evt/1","actor_ref":"user/demo","conversation_ref":"dm/demo","message_ref":"msg/1","occurred_at_unix_ms":1786900000000,"content":` + tt.content + `}`
			var got InboundEventV1
			if err := DecodeStrict([]byte(doc), MaxPayloadBytes, &got); !errors.Is(err, ErrInvalid) {
				t.Fatalf("DecodeStrict() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestDecodeStrictRejectsUnknownDuplicateAndMetadata(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want error
	}{
		{"unknown top level", strings.TrimSuffix(validTextEventJSON(), "}") + `,"raw_payload":{}}`, nil},
		{"metadata", strings.TrimSuffix(validTextEventJSON(), "}") + `,"metadata":{}}`, nil},
		{"unknown nested", strings.Replace(validTextEventJSON(), `"text":"hello\nworld"`, `"text":"hello\nworld","provider_options":{}`, 1), nil},
		{"duplicate nested", strings.Replace(validTextEventJSON(), `"text":"hello\nworld"`, `"text":"one","text":"two"`, 1), strictjson.ErrDuplicateKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got InboundEventV1
			err := DecodeStrict([]byte(tt.doc), MaxPayloadBytes, &got)
			if tt.want != nil {
				if !errors.Is(err, tt.want) {
					t.Fatalf("DecodeStrict() error = %v, want %v", err, tt.want)
				}
			} else if err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("DecodeStrict() error = %v, want unknown field", err)
			}
		})
	}
}

func TestDecodeStrictEnforcesFramingBoundsAndUTF8(t *testing.T) {
	valid := []byte(validTextEventJSON())
	var got InboundEventV1
	if err := DecodeStrict(valid, len(valid)-1, &got); !errors.Is(err, strictjson.ErrTooLarge) {
		t.Fatalf("byte limit error = %v", err)
	}

	badUTF8 := append([]byte(nil), valid...)
	badUTF8[len(badUTF8)-2] = 0xff
	if err := DecodeStrict(badUTF8, MaxPayloadBytes, &got); !errors.Is(err, strictjson.ErrInvalidUTF8) {
		t.Fatalf("UTF-8 error = %v", err)
	}

	oversized := `{"event_id":"evt/1","actor_ref":"user/demo","conversation_ref":"dm/demo","message_ref":"msg/1","occurred_at_unix_ms":1,"content":{"type":"text","text":"` + strings.Repeat("a", MaxTextBytes+1) + `"}}`
	if err := DecodeStrict([]byte(oversized), MaxPayloadBytes, &got); !errors.Is(err, ErrInvalid) {
		t.Fatalf("text bound error = %v, want ErrInvalid", err)
	}
}

func TestIdentifierAndAliasValidation(t *testing.T) {
	event := InboundEventV1{
		EventID:          "evt/1",
		ActorRef:         "user/demo",
		ConversationRef:  "dm/demo",
		MessageRef:       "msg/1",
		OccurredAtUnixMS: 1,
		Content:          InboundContentV1{Type: ContentTypeText, Text: "hello"},
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("valid event error = %v", err)
	}
	event.ActorRef = "user demo"
	if err := event.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("space in ID error = %v", err)
	}
	event.ActorRef = strings.Repeat("a", MaxIDBytes+1)
	if err := event.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("long ID error = %v", err)
	}

	action := InboundActionV1{Type: ActionSelectTarget, TargetAlias: "-unsafe"}
	if err := action.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid alias error = %v", err)
	}
	action.TargetAlias = "unsafe-"
	if err := action.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing separator error = %v", err)
	}
}

func TestDeliveryDTOs(t *testing.T) {
	claim := DeliveryClaimV1{Limit: MaxClaimDeliveries}
	if err := claim.Validate(); err != nil {
		t.Fatalf("valid claim error = %v", err)
	}
	claim.Limit++
	if err := claim.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("claim bound error = %v", err)
	}

	delivery := OutboundTextV1{
		DeliveryID:         "delivery/1",
		LeaseToken:         "lease/1",
		LeaseExpiresUnixMS: 1786900000000,
		ConversationRef:    "dm/demo",
		ReplyToRef:         "msg/1",
		Content:            PlainTextV1{MediaType: "text/plain", Text: "done"},
	}
	if err := delivery.Validate(); err != nil {
		t.Fatalf("valid delivery error = %v", err)
	}
	delivery.Content.MediaType = "text/markdown"
	if err := delivery.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("media type error = %v", err)
	}

	completion := DeliveryCompleteV1{DeliveryID: "delivery/1", LeaseToken: "lease/1", Outcome: DeliveryDelivered, ProviderMessageRef: "provider/1"}
	if err := completion.Validate(); err != nil {
		t.Fatalf("valid completion error = %v", err)
	}
	completion.ProviderMessageRef = ""
	if err := completion.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("completion error = %v", err)
	}
	completion.Outcome = DeliveryRetry
	completion.FailureClass = FailureTemporary
	if err := completion.Validate(); err != nil {
		t.Fatalf("valid retry completion error = %v", err)
	}
	completion.ProviderMessageRef = "provider/forbidden"
	if err := completion.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("retry provider ref error = %v", err)
	}
	completion.ProviderMessageRef = ""
	completion.FailureClass = ""
	completion.Outcome = "unknown"
	if err := completion.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown outcome error = %v", err)
	}
}

func TestDeliveryCompletionFailureClassesAreOutcomeSpecific(t *testing.T) {
	tests := []struct {
		name    string
		outcome DeliveryOutcome
		class   DeliveryFailureClass
		valid   bool
	}{
		{"retry temporary", DeliveryRetry, FailureTemporary, true},
		{"retry rate limit", DeliveryRetry, FailureRateLimited, true},
		{"retry internal", DeliveryRetry, FailureConnectorInternal, true},
		{"retry recipient", DeliveryRetry, FailureRecipientUnavailable, false},
		{"retry empty", DeliveryRetry, "", false},
		{"permanent recipient", DeliveryPermanentFailure, FailureRecipientUnavailable, true},
		{"permanent content", DeliveryPermanentFailure, FailureContentRejected, true},
		{"permanent auth", DeliveryPermanentFailure, FailureNotAuthorized, true},
		{"permanent internal", DeliveryPermanentFailure, FailureConnectorInternal, true},
		{"permanent temporary", DeliveryPermanentFailure, FailureTemporary, false},
		{"permanent unknown", DeliveryPermanentFailure, "provider_secret", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			completion := DeliveryCompleteV1{
				DeliveryID:   "delivery/1",
				LeaseToken:   "lease/1",
				Outcome:      test.outcome,
				FailureClass: test.class,
			}
			err := completion.Validate()
			if test.valid && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if !test.valid && !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate() error = %v, want ErrInvalid", err)
			}
		})
	}

	delivered := DeliveryCompleteV1{
		DeliveryID: "delivery/1", LeaseToken: "lease/1", Outcome: DeliveryDelivered,
		ProviderMessageRef: "provider/1", FailureClass: FailureTemporary,
	}
	if err := delivered.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("delivered failure class error = %v", err)
	}
}

func TestClaimResultValidatesEveryDelivery(t *testing.T) {
	result := DeliveryClaimResultV1{Deliveries: []OutboundTextV1{{
		DeliveryID:         "delivery/1",
		LeaseToken:         "lease/1",
		LeaseExpiresUnixMS: 1,
		ConversationRef:    "dm/demo",
		Content:            PlainTextV1{MediaType: "text/plain", Text: "done"},
	}}}
	if err := result.Validate(); err != nil {
		t.Fatalf("valid result error = %v", err)
	}
	result.Deliveries[0].Content.Text = ""
	if err := result.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nested delivery error = %v", err)
	}
	result.Deliveries = nil
	if err := result.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil deliveries error = %v", err)
	}
}
