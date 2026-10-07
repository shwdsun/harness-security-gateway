//go:build linux && amd64 && codexintegration

package codexprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// Run only by the privately frozen network-none container plan. This exercises
// the actual fixed native ELF through the new launcher and consumer; it does not
// assert a host service startup gate or real OAuth/provider compatibility.
func TestOwnerNativePinnedFilterCompatibility(t *testing.T) {
	if os.Getenv("HSG_OWNER_NATIVE_PROBE") != "synthetic-network-none-v1" {
		t.Skip("requires the frozen offline container plan")
	}
	files, err := openOwnerNativeFiles("/auth-launcher", "/codex", os.Getenv("HSG_OWNER_LAUNCHER_SHA256"))
	if err != nil {
		t.Fatal("pinned artifacts rejected")
	}
	defer files.launcher.Close()
	defer files.native.Close()
	claims, _ := json.Marshal(map[string]any{"sub": "subject-one", "email": "synthetic@example.invalid", "exp": 4102444800,
		"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": "account-one", "chatgpt_plan_type": "pro"}})
	identity := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims) + ".synthetic"
	for _, mode := range []string{"fresh", "stale"} {
		t.Run(mode, func(t *testing.T) {
			o, source := nativeTestConsumer(t, files, "")
			timestamp := time.Now().UTC().Format(time.RFC3339Nano)
			if mode == "stale" {
				timestamp = "2000-01-01T00:00:00Z"
			}
			data, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "OPENAI_API_KEY": nil, "last_refresh": timestamp,
				"tokens": map[string]string{"access_token": "SYNTHETIC_ACCESS_SECRET", "refresh_token": "SYNTHETIC_REFRESH_SECRET", "id_token": identity, "account_id": "account-one"}})
			source.data = data
			before, err := ParseOwnerAuth(data)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			o.send = func(ctx context.Context, r Request) (Response, error) {
				calls.Add(1)
				return Response{Status: 200, MediaType: "application/json", Body: io.NopCloser(bytes.NewReader(refreshData(t, before)))}, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			result, refreshed, err := o.resolve(ctx, true)
			if err != nil || result == nil || !refreshed || source.invalid || source.commits != 1 || calls.Load() != 1 || o.active != nil {
				t.Fatal("fixed native consumer/filter acceptance failed", err, "dispatches", calls.Load(), "commits", source.commits)
			}
			t.Log("one native refresh; matched complete unchanged-token response; joined process/readers/relay; persisted candidate; private home removed")
		})
	}
}
