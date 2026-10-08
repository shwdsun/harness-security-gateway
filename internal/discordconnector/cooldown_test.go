package discordconnector

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCooldownBacksOffAndBoundsPlatformRetryAfter(t *testing.T) {
	interval := 3 * time.Second
	cases := []struct {
		name     string
		failures int
		err      error
		want     time.Duration
	}{
		{"healthy pass has no cooldown", 0, nil, 0},
		{"first failure waits one interval", 1, errors.New("core unavailable"), interval},
		{"repeated failures grow geometrically", 3, errors.New("core unavailable"), 4 * interval},
		{"geometric growth stops at a fixed number of steps", 99,
			errors.New("core unavailable"), interval << maxBackoffSteps},
		{"a rate limit extends the wait", 1,
			&APIError{Status: http.StatusTooManyRequests, RetryAfterMS: 9000}, 9 * time.Second},
		{"a rate limit never shortens the wait", 4,
			&APIError{Status: http.StatusTooManyRequests, RetryAfterMS: 1000}, 8 * interval},
		{"a hostile Retry-After cannot park the Connector", 1,
			&APIError{Status: http.StatusTooManyRequests, RetryAfterMS: 24 * 60 * 60 * 1000}, maxCooldown},
		{"a transport failure still backs off", 2, &APIError{Transport: true}, 2 * interval},
	}
	// The two bounds are independent: with the largest configurable interval the
	// step cap alone would allow hours, so the absolute cap has to hold as well.
	if got := cooldownAfter(300*time.Second, 99, nil); got != maxCooldown {
		t.Fatalf("a long interval backed off to %v, want the %v cap", got, maxCooldown)
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := cooldownAfter(interval, testCase.failures, testCase.err); got != testCase.want {
				t.Fatalf("cooldown was %v, want %v", got, testCase.want)
			}
		})
	}
}

// The ingress path parses Retry-After but previously discarded it: the cycle
// ran on a fixed ticker, so a rate-limited Connector kept polling at its normal
// rate and would escalate its own limit.
func TestRunPausesForTheRateLimitTheIngressPathReceived(t *testing.T) {
	service, _, platform, _ := newTestService(t)
	platform.fetchErr = &APIError{Status: http.StatusTooManyRequests, RetryAfterMS: 9000}
	var pauses []time.Duration
	service.wait = func(_ context.Context, pause time.Duration) bool {
		pauses = append(pauses, pause)
		return len(pauses) < 3
	}
	failures := 0
	if err := service.Run(context.Background(), func(error) { failures++ }, nil); err != nil {
		t.Fatal(err)
	}
	interval := time.Duration(service.config.PollIntervalMS) * time.Millisecond
	// The first pass only adopts the channel head, so it never fetches.
	if len(pauses) != 3 || pauses[0] != interval {
		t.Fatalf("unexpected pauses: %v", pauses)
	}
	for _, pause := range pauses[1:] {
		if pause != 9*time.Second {
			t.Fatalf("a rate-limited pass waited %v, not the requested 9s", pause)
		}
	}
	if failures != 2 {
		t.Fatalf("expected both rate-limited passes to report, got %d", failures)
	}
}

// A platform application without the message-content intent delivers empty
// text, so every message is skipped and the Connector looks healthy while
// admitting nothing. The counters are the only signal that this is happening.
func TestRunReportsBoundedCountersWithoutContent(t *testing.T) {
	service, _, platform, _ := newTestService(t)
	platform.latest = "175928847299117063"
	skipped := Message{ID: "175928847299117064", ChannelID: "333333333333333333",
		Content: "secret-canary-text", Type: 0}
	skipped.Author.ID = "222222222222222222"
	skipped.Author.Bot = true
	platform.messages = []Message{skipped}
	clock := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	service.now = func() time.Time {
		clock = clock.Add(10 * time.Minute)
		return clock
	}
	var reports []Cycle
	service.wait = func(context.Context, time.Duration) bool { return len(reports) == 0 }
	if err := service.Run(context.Background(), nil, func(cycle Cycle) {
		reports = append(reports, cycle)
	}); err != nil {
		t.Fatal(err)
	}
	// The first pass adopts the cursor and skips nothing, so it stays silent.
	if len(reports) != 1 {
		t.Fatalf("expected exactly one report on change, got %d", len(reports))
	}
	report := reports[0]
	if report.Admitted != 0 || report.Skips[SkipAutomatedAuthor] != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
	summary := report.SkipSummary()
	if summary != "automated_author=1" {
		t.Fatalf("summary is not the closed label set: %q", summary)
	}
	if strings.Contains(summary, skipped.Content) || strings.Contains(summary, skipped.ID) ||
		strings.Contains(summary, skipped.Author.ID) {
		t.Fatal("the counter summary carried platform data")
	}
}

func TestSkipSummaryIsStableAndEmptyWhenNothingWasSkipped(t *testing.T) {
	if got := (Cycle{}).SkipSummary(); got != "none" {
		t.Fatalf("empty summary was %q", got)
	}
	cycle := Cycle{Skips: map[SkipReason]int{
		SkipUnlistedAuthor: 2, SkipEmptyContent: 7, SkipForeignChannel: 1}}
	want := "empty_content=7,foreign_channel=1,unlisted_author=2"
	for i := 0; i < 8; i++ {
		if got := cycle.SkipSummary(); got != want {
			t.Fatalf("summary was %q, want %q", got, want)
		}
	}
}
