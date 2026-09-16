package discordconnector

import (
	"strconv"
	"strings"

	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
)

// discordEpochMS is Discord's snowflake epoch: 2015-01-01T00:00:00Z.
const discordEpochMS = 1_420_070_400_000

// Message contains only the platform fields this Connector uses. Discord adds
// response fields over time, so unknown members are ignored here and every
// used value is validated before it can become an event.
type Message struct {
	ID        string `json:"id"`
	ChannelID string `json:"channel_id"`
	Content   string `json:"content"`
	Type      int    `json:"type"`
	WebhookID string `json:"webhook_id"`
	Author    struct {
		ID     string `json:"id"`
		Bot    bool   `json:"bot"`
		System bool   `json:"system"`
	} `json:"author"`
}

// SkipReason is a bounded local counter label. It never leaves the Connector
// and never carries message content.
type SkipReason string

const (
	SkipNone            SkipReason = ""
	SkipForeignChannel  SkipReason = "foreign_channel"
	SkipSelfAuthor      SkipReason = "self_author"
	SkipAutomatedAuthor SkipReason = "automated_author"
	SkipUnlistedAuthor  SkipReason = "unlisted_author"
	SkipUnsupportedType SkipReason = "unsupported_type"
	SkipEmptyContent    SkipReason = "empty_content"
	SkipOversizeContent SkipReason = "oversize_content"
	SkipMalformed       SkipReason = "malformed"
	// Core refused this exact event in a way that can never succeed.
	SkipExpiredEvent     SkipReason = "expired_event"
	SkipConflictingEvent SkipReason = "conflicting_event"
)

// Discord message types this Connector admits: a plain message and a reply.
const (
	messageTypeDefault = 0
	messageTypeReply   = 19
)

// Normalize converts one platform message into the closed wire event, or
// reports why it is not admissible. Filtering is deliberately positive: an
// unrecognized shape is skipped rather than interpreted.
func (c Config) Normalize(message Message) (connectorwire.InboundEventV1, SkipReason) {
	if validateSnowflake("id", message.ID) != nil || validateSnowflake("channel_id", message.ChannelID) != nil ||
		validateSnowflake("author.id", message.Author.ID) != nil {
		return connectorwire.InboundEventV1{}, SkipMalformed
	}
	if message.ChannelID != c.ChannelID {
		return connectorwire.InboundEventV1{}, SkipForeignChannel
	}
	if message.Author.ID == c.SelfUserID {
		return connectorwire.InboundEventV1{}, SkipSelfAuthor
	}
	if message.Author.Bot || message.Author.System || message.WebhookID != "" {
		return connectorwire.InboundEventV1{}, SkipAutomatedAuthor
	}
	if !c.allowsAuthor(message.Author.ID) {
		return connectorwire.InboundEventV1{}, SkipUnlistedAuthor
	}
	if message.Type != messageTypeDefault && message.Type != messageTypeReply {
		return connectorwire.InboundEventV1{}, SkipUnsupportedType
	}
	// An unprivileged bot also sees empty content, which is nothing to admit.
	text := strings.TrimSpace(message.Content)
	if text == "" {
		return connectorwire.InboundEventV1{}, SkipEmptyContent
	}
	if len(text) > connectorwire.MaxTextBytes {
		return connectorwire.InboundEventV1{}, SkipOversizeContent
	}
	occurred, ok := snowflakeUnixMS(message.ID)
	if !ok {
		return connectorwire.InboundEventV1{}, SkipMalformed
	}
	event := connectorwire.InboundEventV1{
		EventID:          MessageRef(message.ID),
		ActorRef:         ActorRef(message.Author.ID),
		ConversationRef:  ConversationRef(message.ChannelID),
		MessageRef:       MessageRef(message.ID),
		OccurredAtUnixMS: occurred,
		Content:          connectorwire.InboundContentV1{Type: connectorwire.ContentTypeText, Text: text},
	}
	if event.Validate() != nil {
		return connectorwire.InboundEventV1{}, SkipMalformed
	}
	return event, SkipNone
}

func (c Config) allowsAuthor(id string) bool {
	for _, allowed := range c.AllowedAuthorIDs {
		if allowed == id {
			return true
		}
	}
	return false
}

func ActorRef(userID string) string { return "discord:user:" + userID }

func ConversationRef(channelID string) string { return "discord:channel:" + channelID }

func MessageRef(messageID string) string { return "discord:message:" + messageID }

// MessageIDFromRef recovers the platform ID for a reply target. An unexpected
// shape yields no ID, and the reply is then sent without a reference rather
// than with a guessed one.
func MessageIDFromRef(ref string) (string, bool) {
	id, found := strings.CutPrefix(ref, "discord:message:")
	if !found || validateSnowflake("message_ref", id) != nil {
		return "", false
	}
	return id, true
}

// snowflakeUnixMS derives the stable platform event time. It does not change
// on retry, which the replay contract requires of occurred_at_unix_ms.
func snowflakeUnixMS(id string) (int64, bool) {
	value, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return 0, false
	}
	milliseconds := int64(value>>22) + discordEpochMS
	if milliseconds <= 0 {
		return 0, false
	}
	return milliseconds, true
}
