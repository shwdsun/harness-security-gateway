package codexprovider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

const maxOwnerAuthBytes = 64 << 10

var ErrOwnerAuth = errors.New("codexprovider: owner auth state unavailable")

// OwnerAuth is parsed local storage, not evidence of OAuth success or freshness.
// Construction is only for an owner-held source or a separately verified native
// candidate; never use a Runner's file, JWT or account claim as authority.
// Its secret fields cannot be serialized or formatted through this type.
type OwnerAuth struct {
	encoded                  []byte
	access, account, subject string
	refresh, identity        string
	refreshed                time.Time
}

func (OwnerAuth) String() string               { return "codexprovider.OwnerAuth[redacted]" }
func (a OwnerAuth) GoString() string           { return a.String() }
func (v OwnerAuth) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, v.String()) }
func (OwnerAuth) MarshalJSON() ([]byte, error) { return nil, ErrOwnerAuth }
func (*OwnerAuth) UnmarshalJSON([]byte) error  { return ErrOwnerAuth }

// ParseOwnerAuth accepts the fixed managed-ChatGPT file shape only. Unknown,
// duplicate and differently cased keys fail closed. JWT claims are checked for
// storage consistency only; this function does not verify a JWT signature.
func ParseOwnerAuth(data []byte) (*OwnerAuth, error) {
	var root map[string]json.RawMessage
	if strictjson.Decode(data, maxOwnerAuthBytes, 8, &root) != nil || root == nil || len(root) < 3 || len(root) > 4 {
		return nil, ErrOwnerAuth
	}
	for k := range root {
		if k != "auth_mode" && k != "OPENAI_API_KEY" && k != "tokens" && k != "last_refresh" {
			return nil, ErrOwnerAuth
		}
	}
	var mode, timestamp string
	if json.Unmarshal(root["auth_mode"], &mode) != nil || mode != "chatgpt" ||
		json.Unmarshal(root["last_refresh"], &timestamp) != nil {
		return nil, ErrOwnerAuth
	}
	if key, exists := root["OPENAI_API_KEY"]; exists && !bytes.Equal(bytes.TrimSpace(key), []byte("null")) {
		return nil, ErrOwnerAuth
	}
	var tokens map[string]string
	if strictjson.Decode(root["tokens"], maxOwnerAuthBytes, 2, &tokens) != nil || len(tokens) != 4 {
		return nil, ErrOwnerAuth
	}
	for k, v := range tokens {
		limit := 8192
		switch k {
		case "account_id":
			limit = 256
		case "id_token":
			limit = 16 << 10
		case "access_token", "refresh_token":
		default:
			return nil, ErrOwnerAuth
		}
		if !opaqueValue(v, limit) {
			return nil, ErrOwnerAuth
		}
	}
	refreshed, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil || refreshed.IsZero() {
		return nil, ErrOwnerAuth
	}
	parts := strings.Split(tokens["id_token"], ".")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return nil, ErrOwnerAuth
	}
	claims, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return nil, ErrOwnerAuth
	}
	defer clear(claims)
	var fields map[string]json.RawMessage
	if strictjson.Decode(claims, 16<<10, 8, &fields) != nil {
		return nil, ErrOwnerAuth
	}
	var identity map[string]json.RawMessage
	var subject, account string
	if json.Unmarshal(fields["sub"], &subject) != nil || !opaqueValue(subject, 256) ||
		json.Unmarshal(fields["https://api.openai.com/auth"], &identity) != nil ||
		json.Unmarshal(identity["chatgpt_account_id"], &account) != nil || account != tokens["account_id"] {
		return nil, ErrOwnerAuth
	}
	return &OwnerAuth{encoded: bytes.Clone(data), access: tokens["access_token"], refresh: tokens["refresh_token"], identity: tokens["id_token"], account: account, subject: subject, refreshed: refreshed}, nil
}

// ValidateOwnerAuthUpdate prohibits account/subject drift and timestamp rollback.
// Identical token strings are allowed: a provider need not rotate each token.
// A successful result says nothing about whether a native refresh happened or
// whether the caller has persisted this candidate; those are separate proofs.
func ValidateOwnerAuthUpdate(before, candidate []byte) (*OwnerAuth, error) {
	old, err := ParseOwnerAuth(before)
	if err != nil {
		return nil, ErrOwnerAuth
	}
	next, err := ParseOwnerAuth(candidate)
	if err != nil || next.account != old.account || next.subject != old.subject || next.refreshed.Before(old.refreshed) {
		return nil, ErrOwnerAuth
	}
	return next, nil
}

// ProviderIdentity is for the fixed upstream transport inside the trusted
// owner. It excludes refresh/ID tokens. Possession does not authorize dispatch;
// the existing per-Run endpoint admission and lifecycle must still be checked.
func (a *OwnerAuth) ProviderIdentity() (access, account string, err error) {
	if a == nil || a.access == "" || a.account == "" {
		return "", "", ErrOwnerAuth
	}
	return a.access, a.account, nil
}

// NativeInput returns a private copy for the future trusted native consumer.
// It must never become Runner input, diagnostics or serialized public state.
func (a *OwnerAuth) NativeInput() ([]byte, error) {
	if a == nil || len(a.encoded) == 0 {
		return nil, ErrOwnerAuth
	}
	return bytes.Clone(a.encoded), nil
}
