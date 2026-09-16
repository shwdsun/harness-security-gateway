package discordconnector

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/connectorhttp"
)

func remote(status int, code string) error {
	return &connectorhttp.RemoteError{StatusCode: status, Code: code}
}

// Holding the ingress cursor for a refusal is what keeps a fenced message from
// being lost. Holding it for a refusal that can never succeed wedges every
// later message behind it, which is how one stale event stalled the live
// Connector on 2026-09-15.
func TestOnlyEventSpecificRefusalsMayAdvanceTheCursor(t *testing.T) {
	permanent := map[string]SkipReason{
		"event_expired":  SkipExpiredEvent,
		"event_conflict": SkipConflictingEvent,
	}
	for code, reason := range permanent {
		if got, ok := refusedForGood(remote(http.StatusGone, code)); !ok || got != reason {
			t.Fatalf("%s did not map to its closed label: %v %v", code, got, ok)
		}
	}
	// A configuration refusal is not about this event. Advancing past it would
	// discard every message instead of one.
	for _, code := range []string{"run_in_progress", "quota_exceeded", "unavailable", "internal",
		"forbidden", "action_unsupported", "invalid_error_response"} {
		if _, ok := refusedForGood(remote(http.StatusConflict, code)); ok {
			t.Fatalf("%s was treated as permanently refused", code)
		}
	}
	for _, err := range []error{nil, errors.New("agentd unavailable"),
		(*connectorhttp.RemoteError)(nil)} {
		if _, ok := refusedForGood(err); ok {
			t.Fatalf("a non-service error was treated as permanently refused: %v", err)
		}
	}
}

func TestAPermanentlyRefusedEventIsSkippedAndTheCursorMovesOn(t *testing.T) {
	service, core, platform, store := newTestService(t)
	ctx := context.Background()
	platform.latest = "175928847299117063"
	if _, err := service.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	stale := Message{ID: "175928847299117064", ChannelID: "333333333333333333",
		Content: "too old to admit", Type: 0}
	stale.Author.ID = "222222222222222222"
	platform.messages = []Message{stale}
	core.ingestErr = remote(http.StatusGone, "event_expired")
	admitted, err := service.PollOnce(ctx)
	if err != nil || admitted != 0 {
		t.Fatalf("a permanently refused event did not settle: %d %v", admitted, err)
	}
	if service.Skips()[SkipExpiredEvent] != 1 {
		t.Fatalf("the refusal was not counted under its closed label: %v", service.Skips())
	}
	cursor, found, err := store.Cursor(ctx, "333333333333333333")
	if err != nil || !found || cursor != stale.ID {
		t.Fatalf("the cursor did not move past the refused event: %q %v %v", cursor, found, err)
	}
}

func TestATransientRefusalStillHoldsTheCursor(t *testing.T) {
	service, core, platform, store := newTestService(t)
	ctx := context.Background()
	platform.latest = "175928847299117063"
	if _, err := service.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	fenced := Message{ID: "175928847299117064", ChannelID: "333333333333333333",
		Content: "arrives while a Run is live", Type: 0}
	fenced.Author.ID = "222222222222222222"
	platform.messages = []Message{fenced}
	core.ingestErr = remote(http.StatusConflict, "run_in_progress")
	if _, err := service.PollOnce(ctx); err == nil {
		t.Fatal("a fenced event was not reported as a cycle failure")
	}
	cursor, _, err := store.Cursor(ctx, "333333333333333333")
	if err != nil || cursor != platform.latest {
		t.Fatalf("a fenced event was skipped instead of retried: %q %v", cursor, err)
	}
	core.ingestErr = nil
	if admitted, err := service.PollOnce(ctx); err != nil || admitted != 1 {
		t.Fatalf("the retried event was not admitted: %d %v", admitted, err)
	}
}

func TestReportedCountersAreAllRunningTotals(t *testing.T) {
	service, core, platform, _ := newTestService(t)
	ctx := context.Background()
	platform.latest = "175928847299117063"
	if _, err := service.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	for index, id := range []string{"175928847299117064", "175928847299117065"} {
		message := Message{ID: id, ChannelID: "333333333333333333",
			Content: "request", Type: 0}
		message.Author.ID = "222222222222222222"
		platform.messages = append(platform.messages, message)
		if _, err := service.PollOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if service.admitted != index+1 {
			t.Fatalf("admitted is not cumulative: %d after %d messages", service.admitted, index+1)
		}
	}
	if len(core.ingested) != 2 {
		t.Fatalf("unexpected ingest count: %d", len(core.ingested))
	}
}
