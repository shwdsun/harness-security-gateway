// Package discordconnector implements the private Discord Connector: one
// platform account, one allowlisted channel, one dedicated agentd socket, and
// no listening port. Platform data is normalized into connectorwire's closed
// contract; it never selects a target, path, runtime option or credential.
package discordconnector

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

const (
	Schema         = "discord-connector/v1"
	MaxConfigBytes = 1 << 16
	MaxJSONDepth   = 8

	// Discord's documented API origin. A different origin would receive the
	// bot token, so it is fixed here rather than being operator-selectable.
	APIHost      = "discord.com"
	APIPathPre   = "/api/v"
	MaxIDDigits  = 20
	maxChunkText = 1900
)

var ErrInvalid = errors.New("invalid discord connector configuration")

// Config is startup-only authority. No platform message can change any field.
type Config struct {
	Schema           string   `json:"schema"`
	AgentdSocket     string   `json:"agentd_socket"`
	StateDatabase    string   `json:"state_database"`
	TokenFile        string   `json:"token_file"`
	APIBaseURL       string   `json:"api_base_url"`
	SelfUserID       string   `json:"self_user_id"`
	ChannelID        string   `json:"channel_id"`
	AllowedAuthorIDs []string `json:"allowed_author_ids"`
	PollIntervalMS   int64    `json:"poll_interval_ms"`
	CatchUpLimit     int      `json:"catch_up_limit"`
	ClaimLimit       int      `json:"claim_limit"`
	RequestTimeoutMS int64    `json:"request_timeout_ms"`
	MaxReplyChunks   int      `json:"max_reply_chunks"`
}

func Load(path string) (Config, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("resolve connector config path: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return Config{}, fmt.Errorf("inspect connector config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return Config{}, fmt.Errorf("%w: config must be a regular non-symlink file not writable by group or others", ErrInvalid)
	}
	file, err := os.Open(absolute)
	if err != nil {
		return Config{}, fmt.Errorf("open connector config: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read connector config: %w", err)
	}
	if len(data) > MaxConfigBytes {
		return Config{}, fmt.Errorf("%w: file exceeds byte limit", ErrInvalid)
	}
	var config Config
	if err := strictjson.Decode(data, MaxConfigBytes, MaxJSONDepth, &config); err != nil {
		return Config{}, err
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	if c.Schema != Schema {
		return invalid("schema", "must be "+Schema)
	}
	for _, field := range []struct{ name, value string }{
		{"agentd_socket", c.AgentdSocket},
		{"state_database", c.StateDatabase},
		{"token_file", c.TokenFile},
	} {
		if !filepath.IsAbs(field.value) || filepath.Clean(field.value) != field.value ||
			strings.ContainsAny(field.value, "\x00\r\n") {
			return invalid(field.name, "must be a clean absolute path")
		}
	}
	// The credential must not sit inside mutable connector state.
	if pathWithin(c.TokenFile, filepath.Dir(c.StateDatabase)) {
		return invalid("token_file", "must not be inside the state directory")
	}
	if c.TokenFile == c.StateDatabase || c.AgentdSocket == c.StateDatabase || c.AgentdSocket == c.TokenFile {
		return invalid("paths", "must be distinct")
	}
	if err := validateAPIBaseURL(c.APIBaseURL); err != nil {
		return err
	}
	if err := validateSnowflake("self_user_id", c.SelfUserID); err != nil {
		return err
	}
	if err := validateSnowflake("channel_id", c.ChannelID); err != nil {
		return err
	}
	if len(c.AllowedAuthorIDs) == 0 {
		return invalid("allowed_author_ids", "must list at least one stable user ID")
	}
	seen := make(map[string]struct{}, len(c.AllowedAuthorIDs))
	for index, id := range c.AllowedAuthorIDs {
		if err := validateSnowflake(fmt.Sprintf("allowed_author_ids[%d]", index), id); err != nil {
			return err
		}
		if id == c.SelfUserID {
			return invalid("allowed_author_ids", "must not contain the connector's own account")
		}
		if _, exists := seen[id]; exists {
			return invalid("allowed_author_ids", "must not repeat an ID")
		}
		seen[id] = struct{}{}
	}
	for _, bound := range []struct {
		name            string
		value, min, max int64
	}{
		{"poll_interval_ms", c.PollIntervalMS, 500, 300_000},
		{"catch_up_limit", int64(c.CatchUpLimit), 1, 50},
		{"claim_limit", int64(c.ClaimLimit), 1, connectorwire.MaxClaimDeliveries},
		{"request_timeout_ms", c.RequestTimeoutMS, 1_000, 60_000},
		{"max_reply_chunks", int64(c.MaxReplyChunks), 1, 8},
	} {
		if bound.value < bound.min || bound.value > bound.max {
			return invalid(bound.name, fmt.Sprintf("must be between %d and %d", bound.min, bound.max))
		}
	}
	return nil
}

// validateAPIBaseURL fixes the origin that receives the bot token.
func validateAPIBaseURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host != APIHost ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return invalid("api_base_url", "must be an https URL at "+APIHost+" without query, fragment or userinfo")
	}
	if !strings.HasPrefix(parsed.Path, APIPathPre) || strings.HasSuffix(parsed.Path, "/") ||
		parsed.Path != filepath.Clean(parsed.Path) {
		return invalid("api_base_url", "must be a clean versioned API path such as "+APIPathPre+"10")
	}
	return nil
}

func validateSnowflake(field, value string) error {
	if value == "" || len(value) > MaxIDDigits {
		return invalid(field, "must be a Discord snowflake ID")
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return invalid(field, "must contain only decimal digits")
		}
	}
	if value[0] == '0' {
		return invalid(field, "must not have a leading zero")
	}
	return nil
}

func pathWithin(path, root string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return false
	}
	return relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func invalid(field, problem string) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalid, field, problem)
}
