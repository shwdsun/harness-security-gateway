package discordconnector

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
)

type interruptedPlatform struct {
	*fakePlatform
	failure error
}

func (p *interruptedPlatform) SendMessage(ctx context.Context, channel, reply, text string) (string, error) {
	if len(p.sent) == 1 && p.failure != nil {
		return "", p.failure
	}
	return p.fakePlatform.SendMessage(ctx, channel, reply, text)
}

func restartDeliveryService(t *testing.T, previous *Service) *Service {
	t.Helper()
	if err := previous.store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(context.Background(), previous.config.StateDatabase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	service, err := NewService(previous.config, previous.core, previous.platform, store)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestPartialReplyPreservesPrefixAndResumesAfterRestart(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusForbidden} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			service, core, platform, store := newTestService(t)
			failure := &APIError{Status: status}
			interrupted := &interruptedPlatform{fakePlatform: platform, failure: failure}
			service.platform = interrupted
			item := delivery("partial", ConversationRef(service.config.ChannelID), strings.Repeat("a", maxChunkText)+"tail")
			core.batches = [][]connectorwire.OutboundTextV1{{item}}
			if count, err := service.DeliverOnce(context.Background()); count != 0 || !errors.Is(err, failure) {
				t.Fatalf("partial send was accepted: count=%d error=%v", count, err)
			}
			outcome, class := failure.Outcome()
			if len(core.completed) != 1 || core.completed[0].Outcome != outcome || core.completed[0].FailureClass != class || core.completed[0].ProviderMessageRef != "" || service.delivered != 0 {
				t.Fatalf("partial reply reported as delivered: %#v count=%d", core.completed, service.delivered)
			}
			if _, sent, err := store.SentDelivery(context.Background(), item.DeliveryID); err != nil || sent {
				t.Fatalf("partial send acquired a full receipt: %v", err)
			}
			if len(platform.sent) != 1 || platform.sent[0].replyTo != "175928847299117063" {
				t.Fatalf("unexpected acknowledged prefix: %#v", platform.sent)
			}
			if outcome == connectorwire.DeliveryPermanentFailure {
				return // Core must not re-lease a permanent failure.
			}
			service = restartDeliveryService(t, service)
			interrupted.failure = nil
			item.LeaseToken = "new-lease"
			core.batches = [][]connectorwire.OutboundTextV1{{item}}
			if count, err := service.DeliverOnce(context.Background()); err != nil || count != 1 {
				t.Fatalf("tail retry failed: %d %v", count, err)
			}
			last := core.completed[len(core.completed)-1]
			if len(platform.sent) != 2 || platform.sent[1].text != "tail" || platform.sent[1].replyTo != "" || last.LeaseToken != item.LeaseToken || last.ProviderMessageRef != "900000000000000001" || last.Outcome != connectorwire.DeliveryDelivered {
				t.Fatalf("retry duplicated or rebound prefix: sent=%#v completion=%#v", platform.sent, last)
			}
		})
	}
}

type lostCompletionCore struct{ *fakeCore }

func (c lostCompletionCore) Complete(ctx context.Context, completion connectorwire.DeliveryCompleteV1) error {
	_ = c.fakeCore.Complete(ctx, completion)
	return errors.New("synthetic completion response lost")
}

func TestCompletedReplySurvivesLostCompletionAndRestart(t *testing.T) {
	service, core, platform, store := newTestService(t)
	service.core = lostCompletionCore{core}
	item := delivery("complete", ConversationRef(service.config.ChannelID), strings.Repeat("a", maxChunkText)+"tail")
	if err := service.deliver(context.Background(), item); err == nil || service.delivered != 0 {
		t.Fatal("lost completion was accepted")
	}
	first := platformRef(t, store, item.DeliveryID)
	service = restartDeliveryService(t, service)
	service.core = core
	item.LeaseToken = "new-lease"
	if err := service.deliver(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	last := core.completed[len(core.completed)-1]
	if len(platform.sent) != 2 || last.LeaseToken != item.LeaseToken || last.ProviderMessageRef != first || last.Outcome != connectorwire.DeliveryDelivered || service.delivered != 1 {
		t.Fatalf("completed reply resent or lost reference: %#v %#v", platform.sent, last)
	}
}

func TestPartialReplyRejectsChangedContentOrReplyDestination(t *testing.T) {
	for _, field := range []string{"content", "reply"} {
		t.Run(field, func(t *testing.T) {
			service, core, platform, _ := newTestService(t)
			interrupted := &interruptedPlatform{platform, &APIError{Status: 503}}
			service.platform = interrupted
			item := delivery("bound", ConversationRef(service.config.ChannelID), strings.Repeat("a", maxChunkText)+"tail")
			if err := service.deliver(context.Background(), item); err == nil {
				t.Fatal("fixture did not interrupt")
			}
			interrupted.failure = nil
			if field == "content" {
				item.Content.Text += "changed"
			} else {
				item.ReplyToRef = "discord:message:175928847299117064"
			}
			if err := service.deliver(context.Background(), item); err == nil || len(platform.sent) != 1 || len(core.completed) != 1 {
				t.Fatalf("changed reply consumed old progress: %v", err)
			}
		})
	}
}

func TestChunkReceiptsRejectConflictsAndPruneWholePrefixes(t *testing.T) {
	_, _, _, store := newTestService(t)
	ctx, digest := context.Background(), strings.Repeat("a", 64)
	for _, attempt := range []struct {
		index     int
		ref       string
		wantError bool
	}{
		{0, "900000000000000001", false}, {0, "900000000000000001", false},
		{0, "900000000000000002", true}, {2, "900000000000000003", true},
	} {
		if err := store.RecordChunk(ctx, "current", digest, attempt.index, attempt.ref, 10); (err != nil) != attempt.wantError {
			t.Fatalf("receipt index=%d conflict=%t: %v", attempt.index, attempt.wantError, err)
		}
	}
	if err := store.RecordChunk(ctx, "current", strings.Repeat("b", 64), 1, "900000000000000002", 30); err == nil {
		t.Fatal("changed digest accepted")
	}
	if err := store.RecordChunk(ctx, "current", digest, 1, "900000000000000002", 30); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordChunk(ctx, "old", digest, 0, "900000000000000003", 10); err != nil {
		t.Fatal(err)
	}
	if err := store.PruneSent(ctx, 20); err != nil {
		t.Fatal(err)
	}
	if refs, err := store.SentChunks(ctx, "current", digest); err != nil || len(refs) != 2 || refs[0] != "900000000000000001" {
		t.Fatalf("prune removed the older prefix: %v %v", refs, err)
	}
	if refs, err := store.SentChunks(ctx, "old", digest); err != nil || len(refs) != 0 {
		t.Fatalf("stale group retained: %v %v", refs, err)
	}
}

func TestStateMigrationPreservesLegacyReceiptsAndRejectsUnknownLineages(t *testing.T) {
	for _, versions := range []string{"1", "99", "1,1"} {
		t.Run(versions, func(t *testing.T) {
			service, _, _, store := newTestService(t)
			ctx := context.Background()
			if err := store.SetCursor(ctx, service.config.ChannelID, "175928847299117063"); err != nil {
				t.Fatal(err)
			}
			if err := store.RecordSent(ctx, "legacy", "900000000000000001", 10); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(`DROP TABLE sent_chunks; DELETE FROM schema_version`); err != nil {
				t.Fatal(err)
			}
			for _, version := range strings.Split(versions, ",") {
				if _, err := store.db.Exec(`INSERT INTO schema_version VALUES (?)`, version); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			upgraded, err := OpenStore(ctx, service.config.StateDatabase)
			if versions == "1" {
				if err != nil {
					t.Fatal(err)
				}
				defer upgraded.Close()
				var version int
				if err := upgraded.db.QueryRow(`SELECT version FROM schema_version`).Scan(&version); err != nil || version != 2 || cursorOf(t, upgraded) != "175928847299117063" || platformRef(t, upgraded, "legacy") != "900000000000000001" {
					t.Fatalf("legacy state not preserved: version=%d error=%v", version, err)
				}
				return
			}
			if err == nil || upgraded != nil {
				t.Fatal("unknown or multiple versions accepted")
			}
			db, err := sql.Open("sqlite", service.config.StateDatabase)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var tables int
			var retained string
			if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'sent_chunks'`).Scan(&tables); err != nil || tables != 0 {
				t.Fatalf("rejected migration committed its table: %d %v", tables, err)
			}
			if err := db.QueryRow(`SELECT group_concat(version, ',') FROM schema_version`).Scan(&retained); err != nil || retained != versions {
				t.Fatalf("rejected migration changed lineage: %q %v", retained, err)
			}
		})
	}
}

func TestOutboundRateLimitPacesCycleWithoutCountingDelivery(t *testing.T) {
	service, core, platform, _ := newTestService(t)
	platform.sendErr = &APIError{Status: 429, RetryAfterMS: 9000}
	core.batches = [][]connectorwire.OutboundTextV1{{delivery("limited", ConversationRef(service.config.ChannelID), "done")}}
	var pause time.Duration
	service.wait = func(_ context.Context, value time.Duration) bool { pause = value; return false }
	var failure error
	if err := service.Run(context.Background(), func(err error) { failure = err }, nil); err != nil {
		t.Fatal(err)
	}
	if pause != 9*time.Second || !errors.Is(failure, platform.sendErr) || service.delivered != 0 || len(core.completed) != 1 || core.completed[0].Outcome != connectorwire.DeliveryRetry {
		t.Fatalf("outbound cooldown/counter wrong: pause=%v delivered=%d error=%v", pause, service.delivered, failure)
	}
}

func TestReceiptWriteFailureStopsBeforeNextChunk(t *testing.T) {
	service, core, platform, store := newTestService(t)
	if _, err := store.db.Exec(`CREATE TRIGGER reject_receipt BEFORE INSERT ON sent_chunks BEGIN SELECT RAISE(ABORT, 'synthetic receipt failure'); END`); err != nil {
		t.Fatal(err)
	}
	item := delivery("receipt-failure", ConversationRef(service.config.ChannelID), strings.Repeat("a", maxChunkText)+"tail")
	if err := service.deliver(context.Background(), item); err == nil || len(platform.sent) != 1 || len(core.completed) != 0 {
		t.Fatalf("send continued beyond unpersisted acknowledgement: %v", err)
	}
	if _, sent, err := store.SentDelivery(context.Background(), item.DeliveryID); err != nil || sent {
		t.Fatalf("unpersisted reply marked delivered: %v", err)
	}
}
