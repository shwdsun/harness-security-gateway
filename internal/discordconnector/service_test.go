package discordconnector

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
)

type fakeCore struct {
	ingested    []connectorwire.InboundEventV1
	ingestFails int
	batches     [][]connectorwire.OutboundTextV1
	completed   []connectorwire.DeliveryCompleteV1
}

func (f *fakeCore) Ingest(_ context.Context, event connectorwire.InboundEventV1) (connectorwire.InboundReceiptV1, error) {
	if f.ingestFails > 0 && len(f.ingested) >= f.ingestFails {
		return connectorwire.InboundReceiptV1{}, errors.New("agentd unavailable")
	}
	f.ingested = append(f.ingested, event)
	return connectorwire.InboundReceiptV1{EventID: event.EventID, Disposition: connectorwire.InboundAccepted, RunID: "run_x"}, nil
}

func (f *fakeCore) Claim(_ context.Context, claim connectorwire.DeliveryClaimV1) (connectorwire.DeliveryClaimResultV1, error) {
	if len(f.batches) == 0 {
		return connectorwire.DeliveryClaimResultV1{Deliveries: []connectorwire.OutboundTextV1{}}, nil
	}
	batch := f.batches[0]
	f.batches = f.batches[1:]
	if len(batch) > claim.Limit {
		batch = batch[:claim.Limit]
	}
	return connectorwire.DeliveryClaimResultV1{Deliveries: batch}, nil
}

func (f *fakeCore) Complete(_ context.Context, completion connectorwire.DeliveryCompleteV1) error {
	f.completed = append(f.completed, completion)
	return nil
}

type sentMessage struct{ channel, replyTo, text string }

type fakePlatform struct {
	messages []Message
	latest   string
	sent     []sentMessage
	sendErr  error
	fetchErr error
	nextID   int
}

func (f *fakePlatform) FetchMessages(_ context.Context, channelID, afterID string, limit int) ([]Message, error) {
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	after := uint64(0)
	if afterID != "" {
		after, _ = strconv.ParseUint(afterID, 10, 64)
	}
	var selected []Message
	for _, message := range f.messages {
		id, err := strconv.ParseUint(message.ID, 10, 64)
		if err != nil || id <= after || message.ChannelID != channelID {
			continue
		}
		selected = append(selected, message)
		if len(selected) == limit {
			break
		}
	}
	return selected, nil
}

func (f *fakePlatform) LatestMessageID(context.Context, string) (string, error) { return f.latest, nil }

func (f *fakePlatform) SendMessage(_ context.Context, channelID, replyToID, text string) (string, error) {
	if f.sendErr != nil {
		return "", f.sendErr
	}
	f.sent = append(f.sent, sentMessage{channelID, replyToID, text})
	f.nextID++
	return strconv.Itoa(900000000000000000 + f.nextID), nil
}

func newTestService(t *testing.T) (*Service, *fakeCore, *fakePlatform, *Store) {
	t.Helper()
	config := validConfig()
	config.StateDatabase = filepath.Join(t.TempDir(), "state.sqlite3")
	config.TokenFile = filepath.Join(t.TempDir(), "bot-token")
	store, err := OpenStore(context.Background(), config.StateDatabase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	core, platform := &fakeCore{}, &fakePlatform{}
	service, err := NewService(config, core, platform, store)
	if err != nil {
		t.Fatal(err)
	}
	return service, core, platform, store
}

func message(id, author string) Message {
	value := Message{ID: id, ChannelID: "333333333333333333", Content: "inspect", Type: 0}
	value.Author.ID = author
	return value
}

func cursorOf(t *testing.T, store *Store) string {
	t.Helper()
	value, _, err := store.Cursor(context.Background(), "333333333333333333")
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestFirstPollAdoptsChannelHeadWithoutReplayingHistory(t *testing.T) {
	service, core, platform, store := newTestService(t)
	platform.latest = "175928847299117063"
	platform.messages = []Message{message("175928847299117000", "222222222222222222")}
	admitted, err := service.PollOnce(context.Background())
	if err != nil || admitted != 0 || len(core.ingested) != 0 {
		t.Fatalf("history was replayed: admitted=%d ingested=%d err=%v", admitted, len(core.ingested), err)
	}
	if cursorOf(t, store) != platform.latest {
		t.Fatalf("cursor did not adopt the channel head: %s", cursorOf(t, store))
	}
	platform.messages = append(platform.messages, message("175928847299117100", "222222222222222222"))
	if admitted, err = service.PollOnce(context.Background()); err != nil || admitted != 1 {
		t.Fatalf("new message not admitted: admitted=%d err=%v", admitted, err)
	}
	if cursorOf(t, store) != "175928847299117100" {
		t.Fatalf("cursor did not advance: %s", cursorOf(t, store))
	}
}

func TestEmptyChannelStartsFromZeroSoTheFirstMessageIsAdmitted(t *testing.T) {
	service, core, platform, store := newTestService(t)
	platform.latest = ""
	if _, err := service.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cursorOf(t, store) != "0" {
		t.Fatalf("empty channel cursor is %q", cursorOf(t, store))
	}
	platform.messages = []Message{message("175928847299117063", "222222222222222222")}
	if admitted, err := service.PollOnce(context.Background()); err != nil || admitted != 1 {
		t.Fatalf("first message not admitted: %d %v", admitted, err)
	}
	if len(core.ingested) != 1 {
		t.Fatalf("unexpected ingest count: %d", len(core.ingested))
	}
}

func TestCursorAdvancesOnlyBehindDurableAcknowledgement(t *testing.T) {
	service, core, platform, store := newTestService(t)
	if err := store.SetCursor(context.Background(), "333333333333333333", "100"); err != nil {
		t.Fatal(err)
	}
	platform.messages = []Message{message("175928847299117001", "222222222222222222"), message("175928847299117002", "222222222222222222")}
	core.ingestFails = 1
	admitted, err := service.PollOnce(context.Background())
	if err == nil || admitted != 1 {
		t.Fatalf("expected the second ingest to fail: admitted=%d err=%v", admitted, err)
	}
	if cursorOf(t, store) != "175928847299117001" {
		t.Fatalf("cursor passed an unacknowledged message: %s", cursorOf(t, store))
	}
	core.ingestFails = 0
	if admitted, err = service.PollOnce(context.Background()); err != nil || admitted != 1 {
		t.Fatalf("retry did not re-present the message: %d %v", admitted, err)
	}
	if len(core.ingested) != 2 || core.ingested[1].EventID != "discord:message:175928847299117002" {
		t.Fatalf("unexpected ingest sequence: %#v", core.ingested)
	}
}

func TestFilteredMessagesAdvanceTheCursorWithoutAdmission(t *testing.T) {
	service, core, platform, store := newTestService(t)
	if err := store.SetCursor(context.Background(), "333333333333333333", "100"); err != nil {
		t.Fatal(err)
	}
	platform.messages = []Message{message("175928847299117005", "555555555555555555")}
	admitted, err := service.PollOnce(context.Background())
	if err != nil || admitted != 0 || len(core.ingested) != 0 {
		t.Fatalf("unlisted author was admitted: %d %v", admitted, err)
	}
	if cursorOf(t, store) != "175928847299117005" {
		t.Fatal("filtered message did not advance the cursor")
	}
	if service.Skips()[SkipUnlistedAuthor] != 1 {
		t.Fatalf("skip counter not recorded: %#v", service.Skips())
	}
}

func delivery(id, conversation, text string) connectorwire.OutboundTextV1 {
	return connectorwire.OutboundTextV1{
		DeliveryID: id, LeaseToken: "lease_" + id, LeaseExpiresUnixMS: time.Now().Add(time.Minute).UnixMilli(),
		ConversationRef: conversation, ReplyToRef: "discord:message:175928847299117063",
		Content: connectorwire.PlainTextV1{MediaType: "text/plain", Text: text},
	}
}

func TestDeliverySendsOnceAndCompletesWithItsProviderReference(t *testing.T) {
	service, core, platform, store := newTestService(t)
	core.batches = [][]connectorwire.OutboundTextV1{{delivery("d1", "discord:channel:333333333333333333", "done")}}
	completed, err := service.DeliverOnce(context.Background())
	if err != nil || completed != 1 {
		t.Fatalf("delivery failed: %d %v", completed, err)
	}
	if len(platform.sent) != 1 || platform.sent[0].channel != "333333333333333333" ||
		platform.sent[0].replyTo != "175928847299117063" || platform.sent[0].text != "done" {
		t.Fatalf("unexpected platform send: %#v", platform.sent)
	}
	if len(core.completed) != 1 || core.completed[0].Outcome != connectorwire.DeliveryDelivered ||
		core.completed[0].ProviderMessageRef != platformRef(t, store, "d1") {
		t.Fatalf("unexpected completion: %#v", core.completed)
	}
}

func platformRef(t *testing.T, store *Store, deliveryID string) string {
	t.Helper()
	ref, sent, err := store.SentDelivery(context.Background(), deliveryID)
	if err != nil || !sent {
		t.Fatalf("delivery %s was not recorded: %v", deliveryID, err)
	}
	return ref
}

func TestReleasedDeliveryCompletesFromItsRecordWithoutResending(t *testing.T) {
	service, core, platform, store := newTestService(t)
	if err := store.RecordSent(context.Background(), "d1", "999999999999999999", time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	core.batches = [][]connectorwire.OutboundTextV1{{delivery("d1", "discord:channel:333333333333333333", "done")}}
	if _, err := service.DeliverOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(platform.sent) != 0 {
		t.Fatal("a re-leased delivery was sent twice")
	}
	if core.completed[0].Outcome != connectorwire.DeliveryDelivered ||
		core.completed[0].ProviderMessageRef != "999999999999999999" {
		t.Fatalf("unexpected completion: %#v", core.completed[0])
	}
}

func TestDeliveryFailsClosedOutsideItsConversationOrBudget(t *testing.T) {
	service, core, platform, _ := newTestService(t)
	long := ""
	for len(long) <= maxChunkText*validConfig().MaxReplyChunks {
		long += "abcdefghij"
	}
	core.batches = [][]connectorwire.OutboundTextV1{{
		delivery("foreign", "discord:channel:444444444444444444", "done"),
		delivery("oversize", "discord:channel:333333333333333333", long),
	}}
	if _, err := service.DeliverOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(platform.sent) != 0 {
		t.Fatal("a rejected delivery reached the platform")
	}
	if core.completed[0].FailureClass != connectorwire.FailureConnectorInternal ||
		core.completed[0].Outcome != connectorwire.DeliveryPermanentFailure {
		t.Fatalf("foreign conversation not failed closed: %#v", core.completed[0])
	}
	if core.completed[1].FailureClass != connectorwire.FailureContentRejected {
		t.Fatalf("oversize reply not rejected: %#v", core.completed[1])
	}
}

func TestPlatformRateLimitBecomesARetryWithoutASentRecord(t *testing.T) {
	service, core, platform, store := newTestService(t)
	platform.sendErr = &APIError{Status: http.StatusTooManyRequests, RetryAfterMS: 1500}
	core.batches = [][]connectorwire.OutboundTextV1{{delivery("d1", "discord:channel:333333333333333333", "done")}}
	if _, err := service.DeliverOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if core.completed[0].Outcome != connectorwire.DeliveryRetry ||
		core.completed[0].FailureClass != connectorwire.FailureRateLimited {
		t.Fatalf("unexpected completion: %#v", core.completed[0])
	}
	if _, sent, err := store.SentDelivery(context.Background(), "d1"); err != nil || sent {
		t.Fatal("a failed send was recorded as sent")
	}
}

func TestRunStopsWithItsContext(t *testing.T) {
	service, _, platform, _ := newTestService(t)
	platform.latest = "175928847299117063"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.Run(ctx, nil, nil); err != nil {
		t.Fatalf("run did not stop cleanly: %v", err)
	}
}

func TestStoreKeepsAPrivateMonotoneCursor(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.sqlite3")
	store, err := OpenStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file is not private: %v %v", err, info.Mode())
	}
	ctx := context.Background()
	if _, found, err := store.Cursor(ctx, "333333333333333333"); err != nil || found {
		t.Fatal("a fresh store reported a cursor")
	}
	if err := store.SetCursor(ctx, "333333333333333333", "175928847299117063"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetCursor(ctx, "333333333333333333", "100"); err != nil {
		t.Fatal(err)
	}
	value, found, err := store.Cursor(ctx, "333333333333333333")
	if err != nil || !found || value != "175928847299117063" {
		t.Fatalf("cursor moved backward: %q", value)
	}
	if err := store.SetCursor(ctx, "333333333333333333", "not-a-snowflake"); err == nil {
		t.Fatal("malformed cursor accepted")
	}
	if err := store.RecordSent(ctx, "d1", "999999999999999999", 1000); err != nil {
		t.Fatal(err)
	}
	if err := store.PruneSent(ctx, 2000); err != nil {
		t.Fatal(err)
	}
	if _, sent, err := store.SentDelivery(ctx, "d1"); err != nil || sent {
		t.Fatal("expired sent record was retained")
	}
}

func TestStoreRefusesAWorldReadableStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite3")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Set the mode explicitly: the process umask would otherwise mask it.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(context.Background(), path); err == nil {
		t.Fatal("group-readable state accepted")
	}
}
