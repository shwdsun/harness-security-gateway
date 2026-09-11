package discordconnector

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
)

// CoreClient is the agentd side of the Connector boundary. The Connector never
// reaches Core storage directly; these three operations are its whole authority.
type CoreClient interface {
	Ingest(context.Context, connectorwire.InboundEventV1) (connectorwire.InboundReceiptV1, error)
	Claim(context.Context, connectorwire.DeliveryClaimV1) (connectorwire.DeliveryClaimResultV1, error)
	Complete(context.Context, connectorwire.DeliveryCompleteV1) error
}

// Platform is the outbound-only Discord surface used by the service.
type Platform interface {
	FetchMessages(ctx context.Context, channelID, afterID string, limit int) ([]Message, error)
	LatestMessageID(ctx context.Context, channelID string) (string, error)
	SendMessage(ctx context.Context, channelID, replyToID, text string) (string, error)
}

// sentRetention bounds the local sent-delivery record. Core drops a delivery
// with its parent Run's receipt long before this.
const sentRetention = 7 * 24 * time.Hour

// Service owns one channel's ingress cursor and its outbound lease handling.
type Service struct {
	config   Config
	core     CoreClient
	platform Platform
	store    *Store
	now      func() time.Time
	skips    map[SkipReason]int
}

func NewService(config Config, core CoreClient, platform Platform, store *Store) (*Service, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if core == nil || platform == nil || store == nil {
		return nil, errors.New("discordconnector: service requires core, platform and state")
	}
	return &Service{config: config, core: core, platform: platform, store: store,
		now: time.Now, skips: make(map[SkipReason]int)}, nil
}

// Skips exposes bounded local counters for operational logging. They carry no
// message content, author or platform text.
func (s *Service) Skips() map[SkipReason]int {
	copied := make(map[SkipReason]int, len(s.skips))
	for reason, count := range s.skips {
		copied[reason] = count
	}
	return copied
}

// PollOnce performs one bounded catch-up window. It returns how many events
// Core accepted. The cursor advances only behind a durable acknowledgement.
func (s *Service) PollOnce(ctx context.Context) (int, error) {
	cursor, found, err := s.store.Cursor(ctx, s.config.ChannelID)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, s.adoptCursor(ctx)
	}
	messages, err := s.platform.FetchMessages(ctx, s.config.ChannelID, cursor, s.config.CatchUpLimit)
	if err != nil {
		return 0, err
	}
	admitted := 0
	for _, message := range messages {
		event, skip := s.config.Normalize(message)
		if skip != SkipNone {
			s.skips[skip]++
		} else {
			if _, err := s.core.Ingest(ctx, event); err != nil {
				// Stop before advancing: this message is presented again.
				return admitted, fmt.Errorf("ingest event: %w", err)
			}
			admitted++
		}
		if err := s.store.SetCursor(ctx, s.config.ChannelID, message.ID); err != nil {
			return admitted, err
		}
	}
	return admitted, nil
}

// adoptCursor takes the channel's current head on first start, so deploying the
// Connector never replays existing history. An empty channel starts from zero,
// so the operator's first message is still admitted.
func (s *Service) adoptCursor(ctx context.Context) error {
	latest, err := s.platform.LatestMessageID(ctx, s.config.ChannelID)
	if err != nil {
		return err
	}
	if latest == "" {
		latest = "0"
	}
	return s.store.SetCursor(ctx, s.config.ChannelID, latest)
}

// DeliverOnce claims one bounded batch and resolves every lease in it.
func (s *Service) DeliverOnce(ctx context.Context) (int, error) {
	result, err := s.core.Claim(ctx, connectorwire.DeliveryClaimV1{Limit: s.config.ClaimLimit})
	if err != nil {
		return 0, fmt.Errorf("claim deliveries: %w", err)
	}
	completed := 0
	for _, delivery := range result.Deliveries {
		if err := s.deliver(ctx, delivery); err != nil {
			return completed, err
		}
		completed++
	}
	return completed, nil
}

func (s *Service) deliver(ctx context.Context, delivery connectorwire.OutboundTextV1) error {
	completion := connectorwire.DeliveryCompleteV1{DeliveryID: delivery.DeliveryID, LeaseToken: delivery.LeaseToken}
	if ref, sent, err := s.store.SentDelivery(ctx, delivery.DeliveryID); err != nil {
		return err
	} else if sent {
		// Already on the platform: complete the re-leased attempt, never resend.
		completion.Outcome, completion.ProviderMessageRef = connectorwire.DeliveryDelivered, ref
		return s.complete(ctx, completion)
	}
	if delivery.ConversationRef != ConversationRef(s.config.ChannelID) {
		completion.Outcome = connectorwire.DeliveryPermanentFailure
		completion.FailureClass = connectorwire.FailureConnectorInternal
		return s.complete(ctx, completion)
	}
	chunks, ok := SplitReply(delivery.Content.Text, s.config.MaxReplyChunks)
	if !ok {
		completion.Outcome = connectorwire.DeliveryPermanentFailure
		completion.FailureClass = connectorwire.FailureContentRejected
		return s.complete(ctx, completion)
	}
	replyTo, _ := MessageIDFromRef(delivery.ReplyToRef)
	providerRef := ""
	for index, chunk := range chunks {
		reference := ""
		if index == 0 {
			reference = replyTo
		}
		id, err := s.platform.SendMessage(ctx, s.config.ChannelID, reference, chunk)
		if err != nil {
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				return err
			}
			if providerRef != "" {
				// Part of the reply is already posted; keep the durable record
				// so a retry cannot repeat the first chunks.
				break
			}
			completion.Outcome, completion.FailureClass = apiErr.Outcome()
			return s.complete(ctx, completion)
		}
		if index == 0 {
			providerRef = id
		}
	}
	if providerRef == "" {
		completion.Outcome = connectorwire.DeliveryPermanentFailure
		completion.FailureClass = connectorwire.FailureConnectorInternal
		return s.complete(ctx, completion)
	}
	if err := s.store.RecordSent(ctx, delivery.DeliveryID, providerRef, s.now().UTC().UnixMilli()); err != nil {
		return err
	}
	completion.Outcome, completion.ProviderMessageRef = connectorwire.DeliveryDelivered, providerRef
	return s.complete(ctx, completion)
}

func (s *Service) complete(ctx context.Context, completion connectorwire.DeliveryCompleteV1) error {
	if err := s.core.Complete(ctx, completion); err != nil {
		return fmt.Errorf("complete delivery: %w", err)
	}
	return nil
}

// Run alternates bounded ingress and delivery passes until the context ends.
// Platform and Core failures pause this cycle; they never drop the cursor.
func (s *Service) Run(ctx context.Context, onError func(error)) error {
	if ctx == nil {
		return errors.New("discordconnector: nil context")
	}
	interval := time.Duration(s.config.PollIntervalMS) * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	pruned := time.Time{}
	for {
		if _, err := s.PollOnce(ctx); err != nil && onError != nil && ctx.Err() == nil {
			onError(err)
		}
		if _, err := s.DeliverOnce(ctx); err != nil && onError != nil && ctx.Err() == nil {
			onError(err)
		}
		if now := s.now().UTC(); now.Sub(pruned) > time.Hour {
			if err := s.store.PruneSent(ctx, now.Add(-sentRetention).UnixMilli()); err != nil && onError != nil && ctx.Err() == nil {
				onError(err)
			}
			pruned = now
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
