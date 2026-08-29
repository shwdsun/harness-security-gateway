package agentservice

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/connectorhttp"
	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/secureid"
)

const (
	// These are frozen domain-separation labels persisted in event receipts.
	// They are not import paths and deliberately retain the prototype namespace.
	inboundEventHashDomain       = "harnessgateway.local/core/agentservice/inbound-event/v2"
	legacyInboundEventHashDomain = "harnessgateway.local/core/agentservice/inbound-event/v1"
)

// Store is the deliberately narrow durable operation set exposed to a
// connector-facing service. It cannot dispatch runs or alter sessions.
type Store interface {
	IngestTextRun(
		context.Context,
		corestore.IngestTextRunInput,
		corestore.TextRunAuthorizer,
		corestore.RunIDSource,
	) (corestore.IngestResult, error)
	ClaimTextDeliveries(context.Context, string, int, time.Duration) ([]corestore.TextDelivery, error)
	CompleteDelivery(context.Context, corestore.CompleteDeliveryInput) error
}

// RunIDSource generates a proposed persistent Run identifier. The store may
// return an older durable identifier when an event is a duplicate.
type RunIDSource func() (string, error)

// Service is one connector-bound implementation of connectorhttp.Service.
// Its maps are private copies, so mutating the source config after construction
// cannot change authorization or routing.
type Service struct {
	endpoint      agentpolicy.Endpoint
	connectorID   string
	deliveryLease time.Duration
	store         Store
	newRunID      RunIDSource
}

// New constructs a service using cryptographically random Run identifiers.
func New(endpoint agentpolicy.Endpoint, deliveryLease time.Duration, store Store) (*Service, error) {
	return newService(endpoint, deliveryLease, store, secureid.NewRunID)
}

// NewWithRunIDSource is New with an injectable identifier source for
// deterministic tests and controlled failure injection.
func NewWithRunIDSource(
	endpoint agentpolicy.Endpoint,
	deliveryLease time.Duration,
	store Store,
	newRunID RunIDSource,
) (*Service, error) {
	if newRunID == nil {
		return nil, errors.New("agentservice: nil Run ID source")
	}
	return newService(endpoint, deliveryLease, store, newRunID)
}

func newService(
	endpoint agentpolicy.Endpoint,
	deliveryLease time.Duration,
	store Store,
	newRunID RunIDSource,
) (*Service, error) {
	if isNil(store) {
		return nil, errors.New("agentservice: nil store")
	}
	if deliveryLease < time.Second || deliveryLease > 10*time.Minute {
		return nil, errors.New("agentservice: delivery lease must be between one second and ten minutes")
	}
	if endpoint.ConnectorID() == "" {
		return nil, errors.New("agentservice: invalid policy endpoint")
	}
	return &Service{
		endpoint:      endpoint,
		connectorID:   endpoint.ConnectorID(),
		deliveryLease: deliveryLease,
		store:         store,
		newRunID:      newRunID,
	}, nil
}

// Ingest authorizes and durably records one normalized text event. V1 control
// actions are closed but intentionally unsupported until their state-machine
// semantics are implemented.
func (s *Service) Ingest(ctx context.Context, event connectorwire.InboundEventV1) (connectorwire.InboundReceiptV1, error) {
	if s == nil || s.store == nil || s.newRunID == nil {
		return connectorwire.InboundReceiptV1{}, serviceError(connectorhttp.ErrorInternal, errors.New("agentservice: uninitialized service"))
	}
	if err := event.Validate(); err != nil {
		return connectorwire.InboundReceiptV1{}, serviceError(connectorhttp.ErrorInternal, err)
	}
	if event.Content.Type == connectorwire.ContentTypeAction {
		return connectorwire.InboundReceiptV1{}, serviceError(connectorhttp.ErrorActionUnsupported, errors.New("connector actions are not supported in v1"))
	}
	payloadHash := hashInboundEvent(s.connectorID, event)
	legacyPayloadHash := hashInboundEventV1(event)
	result, err := s.store.IngestTextRun(ctx, corestore.IngestTextRunInput{
		ConnectorID:       s.connectorID,
		EventID:           event.EventID,
		PayloadHash:       payloadHash,
		LegacyPayloadHash: legacyPayloadHash,
		ActorRef:          event.ActorRef,
		ConversationRef:   event.ConversationRef,
		MessageRef:        event.MessageRef,
		OccurredAtUnixMS:  event.OccurredAtUnixMS,
		Text:              event.Content.Text,
	}, func() (corestore.TextRunAuthorization, error) {
		decision, authorizeErr := s.endpoint.Authorize(event.ActorRef, event.ConversationRef)
		if errors.Is(authorizeErr, agentpolicy.ErrNoBinding) || errors.Is(authorizeErr, agentpolicy.ErrSelfEvent) {
			return corestore.TextRunAuthorization{}, serviceError(
				connectorhttp.ErrorForbidden, errors.New("no exact run.create binding"),
			)
		}
		if authorizeErr != nil {
			return corestore.TextRunAuthorization{}, serviceError(connectorhttp.ErrorInternal, authorizeErr)
		}
		return corestore.TextRunAuthorization{
			TargetID: decision.TargetID, TargetRevision: decision.TargetRevision,
			BindingFingerprint: decision.BindingFingerprint,
			PolicyRevision:     decision.PolicyRevision,
		}, nil
	}, corestore.RunIDSource(s.newRunID))
	if err != nil {
		return connectorwire.InboundReceiptV1{}, mapIngestError(err)
	}

	disposition := connectorwire.InboundAccepted
	if result.Duplicate {
		disposition = connectorwire.InboundDuplicate
	}
	receipt := connectorwire.InboundReceiptV1{
		EventID:     event.EventID,
		Disposition: disposition,
		RunID:       result.Run.ID,
	}
	if err := receipt.Validate(); err != nil {
		return connectorwire.InboundReceiptV1{}, serviceError(connectorhttp.ErrorInternal, fmt.Errorf("validate durable Run receipt: %w", err))
	}
	return receipt, nil
}

// Claim leases a connector-scoped batch using the operator-owned lease
// duration. The connector can select only its bounded batch size.
func (s *Service) Claim(ctx context.Context, claim connectorwire.DeliveryClaimV1) (connectorwire.DeliveryClaimResultV1, error) {
	if s == nil || s.store == nil {
		return connectorwire.DeliveryClaimResultV1{}, serviceError(connectorhttp.ErrorInternal, errors.New("agentservice: uninitialized service"))
	}
	if err := claim.Validate(); err != nil {
		return connectorwire.DeliveryClaimResultV1{}, serviceError(connectorhttp.ErrorInternal, err)
	}
	deliveries, err := s.store.ClaimTextDeliveries(ctx, s.connectorID, claim.Limit, s.deliveryLease)
	if err != nil {
		return connectorwire.DeliveryClaimResultV1{}, mapStoreError(err)
	}
	if len(deliveries) > claim.Limit {
		return connectorwire.DeliveryClaimResultV1{}, serviceError(connectorhttp.ErrorInternal, errors.New("store exceeded the requested delivery limit"))
	}

	result := connectorwire.DeliveryClaimResultV1{
		Deliveries: make([]connectorwire.OutboundTextV1, 0, len(deliveries)),
	}
	for _, delivery := range deliveries {
		if delivery.ConnectorID != s.connectorID || delivery.State != corestore.DeliveryLeased {
			return connectorwire.DeliveryClaimResultV1{}, serviceError(connectorhttp.ErrorInternal, errors.New("store returned a delivery outside the active connector lease"))
		}
		result.Deliveries = append(result.Deliveries, connectorwire.OutboundTextV1{
			DeliveryID:         delivery.ID,
			LeaseToken:         delivery.LeaseToken,
			LeaseExpiresUnixMS: delivery.LeaseExpiresAt.UnixMilli(),
			ConversationRef:    delivery.ConversationRef,
			ReplyToRef:         delivery.ReplyToRef,
			Content: connectorwire.PlainTextV1{
				MediaType: "text/plain",
				Text:      delivery.Text,
			},
		})
	}
	if err := result.Validate(); err != nil {
		return connectorwire.DeliveryClaimResultV1{}, serviceError(connectorhttp.ErrorInternal, fmt.Errorf("validate claimed delivery: %w", err))
	}
	return result, nil
}

// Complete resolves one connector-bound lease attempt. Retry scheduling stays
// entirely in corestore; the wire message carries only a closed failure class.
func (s *Service) Complete(ctx context.Context, completion connectorwire.DeliveryCompleteV1) error {
	if s == nil || s.store == nil {
		return serviceError(connectorhttp.ErrorInternal, errors.New("agentservice: uninitialized service"))
	}
	if err := completion.Validate(); err != nil {
		return serviceError(connectorhttp.ErrorInternal, err)
	}
	outcome, failureCode, ok := mapCompletion(completion)
	if !ok {
		return serviceError(connectorhttp.ErrorInternal, errors.New("unsupported delivery completion"))
	}
	err := s.store.CompleteDelivery(ctx, corestore.CompleteDeliveryInput{
		ConnectorID:        s.connectorID,
		DeliveryID:         completion.DeliveryID,
		LeaseToken:         completion.LeaseToken,
		Outcome:            outcome,
		ProviderMessageRef: completion.ProviderMessageRef,
		FailureCode:        failureCode,
	})
	if err != nil {
		return mapCompletionError(err)
	}
	return nil
}

func mapCompletion(completion connectorwire.DeliveryCompleteV1) (corestore.DeliveryOutcome, corestore.DeliveryFailureCode, bool) {
	var outcome corestore.DeliveryOutcome
	switch completion.Outcome {
	case connectorwire.DeliveryDelivered:
		outcome = corestore.DeliveryOutcomeDelivered
	case connectorwire.DeliveryRetry:
		outcome = corestore.DeliveryOutcomeRetry
	case connectorwire.DeliveryPermanentFailure:
		outcome = corestore.DeliveryOutcomePermanentFailure
	default:
		return "", "", false
	}

	var failure corestore.DeliveryFailureCode
	switch completion.FailureClass {
	case "":
	case connectorwire.FailureTemporary:
		failure = corestore.DeliveryFailureTemporary
	case connectorwire.FailureRateLimited:
		failure = corestore.DeliveryFailureRateLimited
	case connectorwire.FailureRecipientUnavailable:
		failure = corestore.DeliveryFailureRecipientUnavailable
	case connectorwire.FailureContentRejected:
		failure = corestore.DeliveryFailureContentRejected
	case connectorwire.FailureNotAuthorized:
		failure = corestore.DeliveryFailureNotAuthorized
	case connectorwire.FailureConnectorInternal:
		failure = corestore.DeliveryFailureConnectorInternal
	default:
		return "", "", false
	}
	return outcome, failure, true
}

func mapIngestError(err error) error {
	var publicError *connectorhttp.ServiceError
	if errors.As(err, &publicError) && publicError != nil {
		return err
	}
	switch {
	case errors.Is(err, corestore.ErrSessionScopeBusy):
		return serviceError(connectorhttp.ErrorRunInProgress, err)
	case errors.Is(err, corestore.ErrConflict):
		return serviceError(connectorhttp.ErrorEventConflict, err)
	case errors.Is(err, corestore.ErrEventExpired):
		return serviceError(connectorhttp.ErrorEventExpired, err)
	case errors.Is(err, corestore.ErrQuotaExceeded):
		return serviceError(connectorhttp.ErrorQuotaExceeded, err)
	}
	return mapStoreError(err)
}

func mapCompletionError(err error) error {
	switch {
	case errors.Is(err, corestore.ErrNotFound):
		return serviceError(connectorhttp.ErrorDeliveryNotFound, err)
	case errors.Is(err, corestore.ErrLeaseLost), errors.Is(err, corestore.ErrConflict):
		return serviceError(connectorhttp.ErrorLeaseLost, err)
	default:
		return mapStoreError(err)
	}
}

func mapStoreError(err error) error {
	switch {
	case errors.Is(err, corestore.ErrInvalid),
		errors.Is(err, corestore.ErrDispatchLost),
		errors.Is(err, corestore.ErrStartUnprepared),
		errors.Is(err, corestore.ErrInvalidTransition):
		return serviceError(connectorhttp.ErrorInternal, err)
	default:
		return serviceError(connectorhttp.ErrorUnavailable, err)
	}
}

func serviceError(code connectorhttp.ErrorCode, cause error) error {
	return connectorhttp.NewServiceError(code, cause)
}

// hashInboundEvent uses a fixed field order and length framing, rather than a
// map or raw JSON, so semantically identical typed events always hash alike.
// The domain prefix prevents reuse as a hash for another protocol object.
func hashInboundEvent(connectorID string, event connectorwire.InboundEventV1) corestore.PayloadHash {
	hasher := sha256.New()
	writeHashString(hasher, inboundEventHashDomain)
	writeHashString(hasher, connectorID)
	writeHashString(hasher, event.EventID)
	writeHashString(hasher, event.ActorRef)
	writeHashString(hasher, event.ConversationRef)
	writeHashString(hasher, event.MessageRef)
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], uint64(event.OccurredAtUnixMS))
	_, _ = hasher.Write(integer[:])
	writeHashString(hasher, string(event.Content.Type))
	writeHashString(hasher, event.Content.Text)
	if event.Content.Action == nil {
		_, _ = hasher.Write([]byte{0})
	} else {
		_, _ = hasher.Write([]byte{1})
		writeHashString(hasher, string(event.Content.Action.Type))
		writeHashString(hasher, event.Content.Action.TargetAlias)
	}
	var result corestore.PayloadHash
	copy(result[:], hasher.Sum(nil))
	return result
}

// hashInboundEventV1 is retained only to compare receipts written before the
// endpoint Connector became part of the hash domain. It never creates a new
// receipt and can be removed after every v1 receipt has aged past W_receipt.
func hashInboundEventV1(event connectorwire.InboundEventV1) corestore.PayloadHash {
	hasher := sha256.New()
	writeHashString(hasher, legacyInboundEventHashDomain)
	writeHashString(hasher, event.EventID)
	writeHashString(hasher, event.ActorRef)
	writeHashString(hasher, event.ConversationRef)
	writeHashString(hasher, event.MessageRef)
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], uint64(event.OccurredAtUnixMS))
	_, _ = hasher.Write(integer[:])
	writeHashString(hasher, string(event.Content.Type))
	writeHashString(hasher, event.Content.Text)
	if event.Content.Action == nil {
		_, _ = hasher.Write([]byte{0})
	} else {
		_, _ = hasher.Write([]byte{1})
		writeHashString(hasher, string(event.Content.Action.Type))
		writeHashString(hasher, event.Content.Action.TargetAlias)
	}
	var result corestore.PayloadHash
	copy(result[:], hasher.Sum(nil))
	return result
}

func writeHashString(hasher hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write([]byte(value))
}

func isNil(value any) bool {
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

var _ connectorhttp.Service = (*Service)(nil)
