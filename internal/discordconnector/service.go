package discordconnector

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/connectorhttp"
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

const (
	// maxCooldown bounds how long one platform response may pause the cycle.
	// Retry-After is untrusted platform data: it may delay our own requests,
	// but it must never be able to park an unattended Connector indefinitely.
	maxCooldown = 15 * time.Minute
	// maxBackoffSteps bounds the geometric growth of the failure backoff.
	maxBackoffSteps = 6
	// cycleReportInterval bounds how often the local counters are reported, so
	// the report cannot grow with traffic.
	cycleReportInterval = 5 * time.Minute
)

// Cycle is one bounded report of the Connector's running counters. Every field
// is cumulative since start, so one line cannot be read as a per-pass figure in
// one place and a total in another. It carries counters and closed skip labels
// only: never message content, author, identifier or platform text.
type Cycle struct {
	Admitted  int
	Delivered int
	Skips     map[SkipReason]int
}

// refusedForGood maps Core's event-specific refusals onto closed skip labels.
// Holding the cursor for a refusal that can never succeed wedges every later
// message behind it; holding it for a transient one is exactly what keeps a
// fenced message from being lost. Only refusals about this event qualify: a
// configuration refusal would otherwise silently discard every message.
func refusedForGood(err error) (SkipReason, bool) {
	var remote *connectorhttp.RemoteError
	if !errors.As(err, &remote) || remote == nil {
		return SkipNone, false
	}
	switch connectorhttp.ErrorCode(remote.Code) {
	case connectorhttp.ErrorEventExpired:
		return SkipExpiredEvent, true
	case connectorhttp.ErrorEventConflict:
		return SkipConflictingEvent, true
	default:
		return SkipNone, false
	}
}

// SkipSummary renders the counters in a fixed order for one log line.
func (c Cycle) SkipSummary() string {
	labels := make([]string, 0, len(c.Skips))
	for reason := range c.Skips {
		labels = append(labels, string(reason))
	}
	sort.Strings(labels)
	parts := make([]string, 0, len(labels))
	for _, label := range labels {
		parts = append(parts, label+"="+strconv.Itoa(c.Skips[SkipReason(label)]))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

// cooldownAfter returns how long the cycle pauses after the given number of
// consecutive failed passes. An unattended Connector must not hammer an
// unavailable or rate-limiting platform, so repeated failures back off
// geometrically from the configured interval, and a rate-limit response may
// extend but never shorten that wait.
func cooldownAfter(interval time.Duration, failures int, err error) time.Duration {
	if failures <= 0 {
		return 0
	}
	steps := failures - 1
	if steps > maxBackoffSteps {
		steps = maxBackoffSteps
	}
	wait := interval << steps
	if wait > maxCooldown {
		wait = maxCooldown
	}
	var api *APIError
	if errors.As(err, &api) && api.RetryAfterMS > 0 {
		requested := time.Duration(api.RetryAfterMS) * time.Millisecond
		if requested > maxCooldown {
			requested = maxCooldown
		}
		if requested > wait {
			wait = requested
		}
	}
	return wait
}

// sameCounts reports whether two bounded counter sets are equal.
func sameCounts(previous, current map[SkipReason]int) bool {
	if len(previous) != len(current) {
		return false
	}
	for reason, count := range current {
		if previous[reason] != count {
			return false
		}
	}
	return true
}

// waitTimer is the production pause between cycles.
func waitTimer(ctx context.Context, pause time.Duration) bool {
	timer := time.NewTimer(pause)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// Service owns one channel's ingress cursor and its outbound lease handling.
type Service struct {
	config    Config
	core      CoreClient
	platform  Platform
	store     *Store
	now       func() time.Time
	skips     map[SkipReason]int
	admitted  int
	delivered int
	wait      func(context.Context, time.Duration) bool
}

func NewService(config Config, core CoreClient, platform Platform, store *Store) (*Service, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if core == nil || platform == nil || store == nil {
		return nil, errors.New("discordconnector: service requires core, platform and state")
	}
	return &Service{config: config, core: core, platform: platform, store: store,
		now: time.Now, skips: make(map[SkipReason]int), wait: waitTimer}, nil
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
		} else if _, err := s.core.Ingest(ctx, event); err != nil {
			reason, permanent := refusedForGood(err)
			if !permanent {
				// Stop before advancing: this message is presented again.
				return admitted, fmt.Errorf("ingest event: %w", err)
			}
			// Refused for good, so count it like any other closed skip and move
			// past it. Retrying forever would stall every later message.
			s.skips[reason]++
		} else {
			admitted++
			s.admitted++
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
		s.delivered++
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
// Platform and Core failures pause this cycle; they never drop the cursor. The
// next pass is scheduled after the current one finishes rather than on a fixed
// tick, so a slow or failing platform cannot make passes overlap.
func (s *Service) Run(ctx context.Context, onError func(error), onCycle func(Cycle)) error {
	if ctx == nil {
		return errors.New("discordconnector: nil context")
	}
	interval := time.Duration(s.config.PollIntervalMS) * time.Millisecond
	pruned, reported := time.Time{}, time.Time{}
	var lastReport map[SkipReason]int
	lastTotals := [2]int{}
	failures := 0
	for {
		var failure error
		fail := func(err error) {
			failure = err
			if onError != nil && ctx.Err() == nil {
				onError(err)
			}
		}
		if _, err := s.PollOnce(ctx); err != nil {
			fail(err)
		}
		if _, err := s.DeliverOnce(ctx); err != nil {
			fail(err)
		}
		cycle := Cycle{Admitted: s.admitted, Delivered: s.delivered}
		if failure != nil {
			failures++
		} else {
			failures = 0
		}
		now := s.now().UTC()
		if now.Sub(pruned) > time.Hour {
			if err := s.store.PruneSent(ctx, now.Add(-sentRetention).UnixMilli()); err != nil && onError != nil && ctx.Err() == nil {
				onError(err)
			}
			pruned = now
		}
		// A Connector that looks healthy while admitting nothing is the shape
		// of a misconfigured platform application, so the closed counters must
		// reach the operator. Reporting only on change keeps that bounded, and
		// every reported field is a running total.
		if onCycle != nil && ctx.Err() == nil && now.Sub(reported) >= cycleReportInterval {
			cycle.Skips = s.Skips()
			if !sameCounts(lastReport, cycle.Skips) || lastTotals != [2]int{cycle.Admitted, cycle.Delivered} {
				lastReport, lastTotals, reported = cycle.Skips, [2]int{cycle.Admitted, cycle.Delivered}, now
				onCycle(cycle)
			}
		}
		pause := interval
		if cooldown := cooldownAfter(interval, failures, failure); cooldown > pause {
			pause = cooldown
		}
		if !s.wait(ctx, pause) {
			return nil
		}
	}
}
