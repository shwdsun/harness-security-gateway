package discordconnector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
)

const testToken = "MTIzNDU2Nzg5MDEyMzQ1Njc4.Gabcde.fake-token-value"

func validConfig() Config {
	return Config{
		Schema:           Schema,
		AgentdSocket:     "/run/hgw/discord/agentd.sock",
		StateDatabase:    "/var/lib/hgw-connector-discord/state/connector.sqlite3",
		TokenFile:        "/var/lib/hgw-connector-discord/credentials/bot-token",
		APIBaseURL:       "https://discord.com/api/v10",
		SelfUserID:       "111111111111111111",
		ChannelID:        "333333333333333333",
		AllowedAuthorIDs: []string{"222222222222222222"},
		PollIntervalMS:   3000,
		CatchUpLimit:     20,
		ClaimLimit:       5,
		RequestTimeoutMS: 10000,
		MaxReplyChunks:   4,
	}
}

func TestConfigRejectsUnsafeAuthorityValues(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	cases := map[string]func(*Config){
		"schema":             func(c *Config) { c.Schema = "discord-connector/v2" },
		"relative path":      func(c *Config) { c.StateDatabase = "state/connector.sqlite3" },
		"token inside state": func(c *Config) { c.TokenFile = "/var/lib/hgw-connector-discord/state/bot-token" },
		"plaintext origin":   func(c *Config) { c.APIBaseURL = "http://discord.com/api/v10" },
		"foreign origin":     func(c *Config) { c.APIBaseURL = "https://discord.example.net/api/v10" },
		"origin with query":  func(c *Config) { c.APIBaseURL = "https://discord.com/api/v10?token=x" },
		"origin with userinfo": func(c *Config) {
			c.APIBaseURL = "https://user:pass@discord.com/api/v10"
		},
		"self in allowlist":  func(c *Config) { c.AllowedAuthorIDs = []string{c.SelfUserID} },
		"repeated author":    func(c *Config) { c.AllowedAuthorIDs = []string{"222222222222222222", "222222222222222222"} },
		"empty allowlist":    func(c *Config) { c.AllowedAuthorIDs = nil },
		"non numeric id":     func(c *Config) { c.ChannelID = "33333333333333333x" },
		"leading zero id":    func(c *Config) { c.ChannelID = "033333333333333333" },
		"fast poll":          func(c *Config) { c.PollIntervalMS = 10 },
		"unbounded catch up": func(c *Config) { c.CatchUpLimit = 500 },
		"claim above wire":   func(c *Config) { c.ClaimLimit = connectorwire.MaxClaimDeliveries + 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := validConfig()
			mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestLoadRequiresPrivateRegularFile(t *testing.T) {
	directory := t.TempDir()
	data, err := json.Marshal(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "connector.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded.ChannelID != validConfig().ChannelID {
		t.Fatal("loaded configuration differs")
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("world-writable configuration accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(directory, "unknown.json")
	if err := os.WriteFile(unknown, append(data[:len(data)-1], []byte(`,"gateway":true}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(unknown); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func testMessage() Message {
	message := Message{ID: "175928847299117063", ChannelID: "333333333333333333", Content: " inspect the project ", Type: 0}
	message.Author.ID = "222222222222222222"
	return message
}

func TestNormalizeProducesStablePlatformFacts(t *testing.T) {
	event, skip := validConfig().Normalize(testMessage())
	if skip != SkipNone {
		t.Fatalf("valid message skipped: %s", skip)
	}
	if event.EventID != "discord:message:175928847299117063" || event.MessageRef != event.EventID {
		t.Fatalf("unexpected event identity: %+v", event)
	}
	if event.ActorRef != "discord:user:222222222222222222" ||
		event.ConversationRef != "discord:channel:333333333333333333" {
		t.Fatalf("unexpected normalized refs: %+v", event)
	}
	// Documented snowflake example: the stable creation time, not a local clock.
	if event.OccurredAtUnixMS != 1462015105796 {
		t.Fatalf("unexpected occurred_at: %d", event.OccurredAtUnixMS)
	}
	if event.Content.Text != "inspect the project" || event.Content.Type != connectorwire.ContentTypeText {
		t.Fatalf("unexpected content: %+v", event.Content)
	}
	if event.Validate() != nil {
		t.Fatal("normalized event fails wire validation")
	}
}

func TestNormalizeSkipsEverythingOutsideTheAllowlistedShape(t *testing.T) {
	cases := map[SkipReason]func(*Message){
		SkipForeignChannel:  func(m *Message) { m.ChannelID = "444444444444444444" },
		SkipSelfAuthor:      func(m *Message) { m.Author.ID = "111111111111111111" },
		SkipAutomatedAuthor: func(m *Message) { m.Author.Bot = true },
		SkipUnlistedAuthor:  func(m *Message) { m.Author.ID = "555555555555555555" },
		SkipUnsupportedType: func(m *Message) { m.Type = 7 },
		SkipEmptyContent:    func(m *Message) { m.Content = "   " },
		SkipOversizeContent: func(m *Message) { m.Content = strings.Repeat("a", connectorwire.MaxTextBytes+1) },
		SkipMalformed:       func(m *Message) { m.ID = "not-a-snowflake" },
	}
	for reason, mutate := range cases {
		t.Run(string(reason), func(t *testing.T) {
			message := testMessage()
			mutate(&message)
			event, skip := validConfig().Normalize(message)
			if skip != reason {
				t.Fatalf("got skip %q, want %q", skip, reason)
			}
			if event.EventID != "" {
				t.Fatal("skipped message produced an event")
			}
		})
	}
	webhook := testMessage()
	webhook.WebhookID = "666666666666666666"
	if _, skip := validConfig().Normalize(webhook); skip != SkipAutomatedAuthor {
		t.Fatalf("webhook author not filtered: %s", skip)
	}
}

func TestMessageIDFromRefAcceptsOnlyItsOwnForm(t *testing.T) {
	id, ok := MessageIDFromRef("discord:message:175928847299117063")
	if !ok || id != "175928847299117063" {
		t.Fatal("valid reference rejected")
	}
	for _, ref := range []string{"", "175928847299117063", "discord:channel:175928847299117063", "discord:message:x"} {
		if _, ok := MessageIDFromRef(ref); ok {
			t.Fatalf("accepted foreign reference %q", ref)
		}
	}
}

func TestSplitReplyKeepsOrderedBoundedChunks(t *testing.T) {
	chunks, ok := SplitReply("short reply\n", 4)
	if !ok || len(chunks) != 1 || chunks[0] != "short reply" {
		t.Fatalf("unexpected single chunk: %#v", chunks)
	}
	long := strings.TrimSpace(strings.Repeat("word ", 1200))
	chunks, ok = SplitReply(long, 4)
	if !ok {
		t.Fatal("bounded reply rejected")
	}
	if len(chunks) < 2 {
		t.Fatal("long reply was not split")
	}
	for _, chunk := range chunks {
		if len(chunk) > maxChunkText {
			t.Fatalf("chunk exceeds the platform bound: %d", len(chunk))
		}
	}
	if strings.Join(strings.Fields(strings.Join(chunks, " ")), " ") != strings.Join(strings.Fields(long), " ") {
		t.Fatal("splitting lost or reordered text")
	}
	if _, ok := SplitReply(long, 1); ok {
		t.Fatal("reply exceeding the chunk budget was accepted")
	}
	if _, ok := SplitReply("   \n", 4); ok {
		t.Fatal("empty reply accepted")
	}
}

func TestReadTokenRequiresAPrivateOwnedFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "bot-token")
	if err := os.WriteFile(path, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := ReadToken(path)
	if err != nil || token != testToken {
		t.Fatalf("token not read: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadToken(path); err == nil {
		t.Fatal("group-readable token accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadToken(path); err == nil {
		t.Fatal("implausible token accepted")
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadToken(link); err == nil {
		t.Fatal("symlinked token accepted")
	}
}

func TestAPISendsTheTokenOnlyAsAHeaderAndNormalizesOrder(t *testing.T) {
	var seen struct {
		authorization, agent, query, body string
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.authorization = r.Header.Get("Authorization")
		seen.agent = r.Header.Get("User-Agent")
		seen.query = r.URL.RawQuery
		if r.Method == http.MethodPost {
			data := make([]byte, 4096)
			read, _ := r.Body.Read(data)
			seen.body = string(data[:read])
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"999999999999999999"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Discord returns newest first.
		_, _ = w.Write([]byte(`[{"id":"200","channel_id":"333333333333333333","content":"b","type":0,"author":{"id":"222222222222222222"}},
			{"id":"100","channel_id":"333333333333333333","content":"a","type":0,"author":{"id":"222222222222222222"}}]`))
	}))
	defer server.Close()

	api, err := newAPI(server.URL, testToken, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	messages, err := api.FetchMessages(context.Background(), "333333333333333333", "50", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].ID != "100" || messages[1].ID != "200" {
		t.Fatalf("messages are not oldest first: %#v", messages)
	}
	if seen.authorization != "Bot "+testToken || !strings.HasPrefix(seen.agent, "DiscordBot (") {
		t.Fatal("platform request headers are wrong")
	}
	if !strings.Contains(seen.query, "after=50") || !strings.Contains(seen.query, "limit=20") {
		t.Fatalf("unexpected catch-up query: %s", seen.query)
	}
	id, err := api.SendMessage(context.Background(), "333333333333333333", "175928847299117063", "reply")
	if err != nil || id != "999999999999999999" {
		t.Fatalf("send failed: %v", err)
	}
	if strings.Contains(seen.body, testToken) {
		t.Fatal("token appeared in a request body")
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(seen.body), &sent); err != nil {
		t.Fatalf("send body is not JSON: %v", err)
	}
	mentions, _ := sent["allowed_mentions"].(map[string]any)
	for _, field := range []string{"parse", "users", "roles"} {
		values, ok := mentions[field].([]any)
		if !ok || len(values) != 0 {
			t.Fatalf("allowed_mentions.%s does not suppress pings: %#v", field, mentions[field])
		}
	}
	if reference, ok := sent["message_reference"].(map[string]any); !ok || reference["message_id"] != "175928847299117063" {
		t.Fatalf("reply reference missing: %#v", sent["message_reference"])
	}
}

func TestAPIErrorsMapOntoClosedDeliveryClasses(t *testing.T) {
	cases := []struct {
		status  int
		retry   string
		outcome connectorwire.DeliveryOutcome
		class   connectorwire.DeliveryFailureClass
	}{
		{http.StatusTooManyRequests, "1.5", connectorwire.DeliveryRetry, connectorwire.FailureRateLimited},
		{http.StatusInternalServerError, "", connectorwire.DeliveryRetry, connectorwire.FailureTemporary},
		{http.StatusForbidden, "", connectorwire.DeliveryPermanentFailure, connectorwire.FailureNotAuthorized},
		{http.StatusNotFound, "", connectorwire.DeliveryPermanentFailure, connectorwire.FailureRecipientUnavailable},
		{http.StatusBadRequest, "", connectorwire.DeliveryPermanentFailure, connectorwire.FailureContentRejected},
		{http.StatusTeapot, "", connectorwire.DeliveryPermanentFailure, connectorwire.FailureConnectorInternal},
	}
	for _, testCase := range cases {
		t.Run(http.StatusText(testCase.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if testCase.retry != "" {
					w.Header().Set("Retry-After", testCase.retry)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(testCase.status)
				_, _ = w.Write([]byte(`{"message":"secret provider diagnostic","code":50001}`))
			}))
			defer server.Close()
			api, err := newAPI(server.URL, testToken, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = api.SendMessage(context.Background(), "333333333333333333", "", "reply")
			var apiErr *APIError
			if err == nil || !asAPIError(err, &apiErr) {
				t.Fatalf("expected a classified platform error, got %v", err)
			}
			outcome, class := apiErr.Outcome()
			if outcome != testCase.outcome || class != testCase.class {
				t.Fatalf("got %s/%s, want %s/%s", outcome, class, testCase.outcome, testCase.class)
			}
			if strings.Contains(apiErr.Error(), "secret provider diagnostic") {
				t.Fatal("provider diagnostic text crossed the boundary")
			}
			if testCase.retry != "" && apiErr.RetryAfterMS != 1500 {
				t.Fatalf("unexpected retry hint: %d", apiErr.RetryAfterMS)
			}
		})
	}
}

func TestNewAPIRejectsImplausibleTokenAndOrigin(t *testing.T) {
	if _, err := NewAPI("https://discord.com/api/v10", "short", time.Second); err == nil {
		t.Fatal("implausible token accepted")
	}
	if _, err := NewAPI("http://discord.com/api/v10", testToken, time.Second); err == nil {
		t.Fatal("plaintext origin accepted")
	}
}

func asAPIError(err error, target **APIError) bool {
	value, ok := err.(*APIError)
	if ok {
		*target = value
	}
	return ok
}
