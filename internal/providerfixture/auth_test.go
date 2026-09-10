//go:build codexintegration

package providerfixture

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSyntheticOnlyAuth(t *testing.T) {
	initial := InitialAuth()
	if !AuthMatches(initial, false) || AuthMatches(initial, true) {
		t.Fatal("initial/refresh states conflated")
	}
	var object map[string]any
	_ = json.Unmarshal(initial, &object)
	object["last_refresh"] = time.Now().UTC().Format(time.RFC3339)
	tokens := object["tokens"].(map[string]any)
	tokens["access_token"], tokens["refresh_token"] = Nonce+"-refreshed", Nonce+"-refresh-after"
	refreshed, _ := json.Marshal(object)
	if !AuthMatches(refreshed, true) || AuthMatches(refreshed, false) {
		t.Fatal("refresh did not bind all synthetic tokens")
	}
	for _, invalid := range []string{
		strings.Replace(string(initial), Nonce, "unrecognized-token", 1),
		strings.Replace(string(initial), "hsg-synthetic-account", "different-account", 1),
		strings.Replace(string(initial), `"tokens":`, `"Tokens":`, 1),
		strings.TrimSuffix(string(initial), "}") + `,"unexpected":"value"}`,
		strings.Replace(string(initial), `"auth_mode":`, `"auth_mode":"other","auth_mode":`, 1),
	} {
		if AuthMatches([]byte(invalid), false) {
			t.Fatal("noncanonical synthetic source accepted")
		}
	}
}
