//go:build codexintegration

// Package providerfixture contains only synthetic data for opt-in integration
// tests. It is excluded from normal builds and is not credential validation.
package providerfixture

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

const Nonce = "hsg-controller-synthetic"

type OperationProof struct {
	ToolNonce         string
	Counts            map[string]int
	Statuses          []int
	Refreshed, Closed bool
}

func jwt() string {
	payload, _ := json.Marshal(map[string]any{"sub": "hsg-synthetic-subject", "email": "probe@example.invalid", "exp": int64(4102444800),
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "hsg-synthetic-account", "chatgpt_plan_type": "pro"}})
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".synthetic"
}

func InitialAuth() []byte {
	data, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "OPENAI_API_KEY": nil, "last_refresh": "2000-01-01T00:00:00Z",
		"tokens": map[string]any{"id_token": jwt(), "access_token": Nonce, "refresh_token": Nonce + "-refresh", "account_id": "hsg-synthetic-account"}})
	return data
}

// AuthMatches accepts only this exact synthetic object (ignoring JSON layout),
// or the fixed responder's refresh of it. Real tokens and extra fields fail.
func AuthMatches(data []byte, refreshed bool) bool {
	var got, expected map[string]any
	if strictjson.Decode(data, 16<<10, 4, &got) != nil || json.Unmarshal(InitialAuth(), &expected) != nil {
		return false
	}
	if refreshed {
		stamp, ok := got["last_refresh"].(string)
		when, err := time.Parse(time.RFC3339, stamp)
		if !ok || err != nil || !when.After(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) || when.After(time.Now().Add(time.Minute)) {
			return false
		}
		expected["last_refresh"] = stamp
		tokens := expected["tokens"].(map[string]any)
		tokens["access_token"], tokens["refresh_token"] = Nonce+"-refreshed", Nonce+"-refresh-after"
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(expected)
	return bytes.Equal(a, b)
}
