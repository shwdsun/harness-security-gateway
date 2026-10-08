package discordconnector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
)

const (
	maxAPIResponseBytes = 1 << 20
	maxSendRequestBytes = 8 << 10
	userAgent           = "DiscordBot (https://github.com/shwdsun/harness-security-gateway, 1.0)"
)

// APIError is a bounded classification of one platform response. Provider
// error text is deliberately not retained: it never crosses to agentd and has
// no local use beyond this status.
type APIError struct {
	Status       int
	RetryAfterMS int64
	Transport    bool
}

func (e *APIError) Error() string {
	if e.Transport {
		return "discord request failed before a response"
	}
	return fmt.Sprintf("discord request failed: HTTP %d", e.Status)
}

// Outcome maps this failure onto the closed protocol classes. agentd owns the
// retry schedule; the Connector only classifies.
func (e *APIError) Outcome() (connectorwire.DeliveryOutcome, connectorwire.DeliveryFailureClass) {
	switch {
	case e.Transport:
		return connectorwire.DeliveryRetry, connectorwire.FailureTemporary
	case e.Status == http.StatusTooManyRequests:
		return connectorwire.DeliveryRetry, connectorwire.FailureRateLimited
	case e.Status >= 500 && e.Status <= 599:
		return connectorwire.DeliveryRetry, connectorwire.FailureTemporary
	case e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden:
		return connectorwire.DeliveryPermanentFailure, connectorwire.FailureNotAuthorized
	case e.Status == http.StatusNotFound || e.Status == http.StatusGone:
		return connectorwire.DeliveryPermanentFailure, connectorwire.FailureRecipientUnavailable
	case e.Status == http.StatusBadRequest || e.Status == http.StatusRequestEntityTooLarge:
		return connectorwire.DeliveryPermanentFailure, connectorwire.FailureContentRejected
	default:
		return connectorwire.DeliveryPermanentFailure, connectorwire.FailureConnectorInternal
	}
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// API is the outbound-only platform client. It holds the bot token in memory,
// sends it only to the configured origin, and never logs or returns it.
type API struct {
	baseURL string
	token   string
	http    httpDoer
}

func NewAPI(baseURL, token string, timeout time.Duration) (*API, error) {
	if err := validateAPIBaseURL(baseURL); err != nil {
		return nil, err
	}
	return newAPI(baseURL, token, &http.Client{
		Timeout: timeout,
		// Platform responses cannot select another credential recipient or
		// downgrade HTTPS. Classify the original 3xx without following it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	})
}

func newAPI(baseURL, token string, doer httpDoer) (*API, error) {
	if doer == nil {
		return nil, errors.New("discordconnector: nil HTTP client")
	}
	if err := validateToken(token); err != nil {
		return nil, err
	}
	return &API{baseURL: strings.TrimSuffix(baseURL, "/"), token: token, http: doer}, nil
}

// validateToken rejects a shape that cannot be a bot token before it is ever
// sent. The value itself is never included in an error.
func validateToken(token string) error {
	if len(token) < 16 || len(token) > 256 {
		return errors.New("discordconnector: bot token has an implausible length")
	}
	for index := 0; index < len(token); index++ {
		char := token[index]
		if char <= ' ' || char >= 0x7f {
			return errors.New("discordconnector: bot token contains unsupported bytes")
		}
	}
	return nil
}

// FetchMessages returns at most limit messages after the cursor, oldest first.
// Discord orders by snowflake, so this is the bounded catch-up window.
func (a *API) FetchMessages(ctx context.Context, channelID, afterID string, limit int) ([]Message, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	if afterID != "" {
		query.Set("after", afterID)
	}
	var messages []Message
	if err := a.call(ctx, http.MethodGet, "/channels/"+channelID+"/messages?"+query.Encode(), nil, &messages); err != nil {
		return nil, err
	}
	// Discord returns newest first for this query; the cursor advances forward.
	for left, right := 0, len(messages)-1; left < right; left, right = left+1, right-1 {
		messages[left], messages[right] = messages[right], messages[left]
	}
	return messages, nil
}

// LatestMessageID reports the channel's newest message, used once to adopt an
// initial cursor so deployment never replays existing history.
func (a *API) LatestMessageID(ctx context.Context, channelID string) (string, error) {
	messages, err := a.FetchMessages(ctx, channelID, "", 1)
	if err != nil || len(messages) == 0 {
		return "", err
	}
	id := messages[len(messages)-1].ID
	if validateSnowflake("id", id) != nil {
		return "", errors.New("discordconnector: channel returned a malformed message ID")
	}
	return id, nil
}

type sendRequest struct {
	Content         string           `json:"content"`
	AllowedMentions allowedMentions  `json:"allowed_mentions"`
	Reference       *messageRefrence `json:"message_reference,omitempty"`
}

// allowedMentions with empty parse arrays prevents any ping, whatever the
// reply text contains.
type allowedMentions struct {
	Parse       []string `json:"parse"`
	Users       []string `json:"users"`
	Roles       []string `json:"roles"`
	RepliedUser bool     `json:"replied_user"`
}

type messageRefrence struct {
	MessageID       string `json:"message_id"`
	ChannelID       string `json:"channel_id"`
	FailIfNotExists bool   `json:"fail_if_not_exists"`
}

// SendMessage posts one chunk to the fixed conversation. The recipient comes
// from the delivery, never from model output.
func (a *API) SendMessage(ctx context.Context, channelID, replyToID, text string) (string, error) {
	body := sendRequest{
		Content:         text,
		AllowedMentions: allowedMentions{Parse: []string{}, Users: []string{}, Roles: []string{}},
	}
	if replyToID != "" {
		body.Reference = &messageRefrence{MessageID: replyToID, ChannelID: channelID}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("encode message: %w", err)
	}
	if len(encoded) > maxSendRequestBytes {
		return "", &APIError{Status: http.StatusRequestEntityTooLarge}
	}
	var sent struct {
		ID string `json:"id"`
	}
	if err := a.call(ctx, http.MethodPost, "/channels/"+channelID+"/messages", encoded, &sent); err != nil {
		return "", err
	}
	if validateSnowflake("id", sent.ID) != nil {
		return "", errors.New("discordconnector: send response has no usable message ID")
	}
	return sent.ID, nil
}

func (a *API) call(ctx context.Context, method, path string, body []byte, out any) error {
	if a == nil || a.http == nil {
		return errors.New("discordconnector: API client is not initialized")
	}
	if ctx == nil {
		return errors.New("discordconnector: nil context")
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("build discord request: %w", err)
	}
	request.Header.Set("Authorization", "Bot "+a.token)
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := a.http.Do(request)
	if err != nil {
		return &APIError{Transport: true}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxAPIResponseBytes))
		_ = response.Body.Close()
	}()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return &APIError{Status: response.StatusCode, RetryAfterMS: retryAfterMS(response)}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxAPIResponseBytes+1))
	if err != nil {
		return &APIError{Transport: true}
	}
	if len(data) > maxAPIResponseBytes {
		return errors.New("discordconnector: platform response exceeds byte limit")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode discord response: %w", err)
	}
	return nil
}

func retryAfterMS(response *http.Response) int64 {
	value := strings.TrimSpace(response.Header.Get("Retry-After"))
	if value == "" {
		return 0
	}
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || seconds < 0 || seconds > 3600 {
		return 0
	}
	return int64(seconds * 1000)
}

// SplitReply divides one bounded reply into ordered platform-sized chunks. It
// never drops text silently: too many chunks is a rejected delivery.
func SplitReply(text string, maxChunks int) ([]string, bool) {
	if !utf8.ValidString(text) {
		return nil, false
	}
	// A whitespace-only reply has no postable content; the platform would
	// reject it, so it fails closed here instead.
	remaining := strings.TrimSpace(text)
	if remaining == "" || maxChunks < 1 {
		return nil, false
	}
	var chunks []string
	for len(remaining) > 0 {
		if len(chunks) == maxChunks {
			return nil, false
		}
		if len(remaining) <= maxChunkText {
			chunks = append(chunks, remaining)
			break
		}
		cut := strings.LastIndexAny(remaining[:maxChunkText], "\n ")
		if cut <= 0 {
			cut = maxChunkText
			for !utf8.RuneStart(remaining[cut]) {
				cut--
			}
		}
		chunks = append(chunks, strings.TrimRight(remaining[:cut], " "))
		remaining = strings.TrimLeft(remaining[cut:], " ")
	}
	return chunks, true
}
