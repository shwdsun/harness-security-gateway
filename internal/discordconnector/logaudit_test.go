package discordconnector

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// providerDiagnostic stands in for the platform's own error prose, which must
// stay inside the Connector and never reach a log line or agentd.
const providerDiagnostic = "PROVIDER-DIAGNOSTIC-4b19ae"

func TestPlatformFailuresHideTheTokenAndProviderText(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"` + providerDiagnostic + `","code":50013}`))
	}))
	defer server.Close()
	api, err := newAPI(server.URL, testToken, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = api.SendMessage(context.Background(), "333333333333333333", "", "reply"); err == nil {
		t.Fatal("expected a platform failure")
	}
	for label, text := range map[string]string{
		"Error()":   err.Error(),
		"%v":        fmt.Sprintf("%v", err),
		"cycle log": fmt.Sprintf("cycle error: %v", fmt.Errorf("deliver reply: %w", err)),
	} {
		if strings.Contains(text, testToken) {
			t.Fatalf("%s disclosed the bot token", label)
		}
		if strings.Contains(text, providerDiagnostic) {
			t.Fatalf("%s disclosed provider error text: %s", label, text)
		}
	}
}

func TestTokenFileFailuresNeverEchoTheSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot-token")
	short := "SHORTSECRET-9f2"
	if err := os.WriteFile(path, []byte(short), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadToken(path)
	if err == nil || strings.Contains(err.Error(), short) {
		t.Fatalf("implausible token accepted or echoed: %v", err)
	}
	if err := os.WriteFile(path, []byte(testToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = ReadToken(path)
	if err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("group-readable token accepted or echoed: %v", err)
	}
}

func TestSkipCountersCarryOnlyClosedLabels(t *testing.T) {
	service, _, platform, store := newTestService(t)
	if err := store.SetCursor(context.Background(), "333333333333333333", "1"); err != nil {
		t.Fatal(err)
	}
	hostile := message("175928847299117999", "555555555555555555")
	hostile.Content = "REDACTION-CANARY-8f3c1d hostile content"
	platform.messages = []Message{hostile}
	if _, err := service.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	closed := map[SkipReason]bool{
		SkipForeignChannel: true, SkipSelfAuthor: true, SkipAutomatedAuthor: true,
		SkipUnlistedAuthor: true, SkipUnsupportedType: true, SkipEmptyContent: true,
		SkipOversizeContent: true, SkipMalformed: true,
	}
	counters := service.Skips()
	if len(counters) == 0 {
		t.Fatal("the filtered message was not counted")
	}
	for reason := range counters {
		if !closed[reason] {
			t.Fatalf("skip counter carries an unreviewed label %q", reason)
		}
	}
}
