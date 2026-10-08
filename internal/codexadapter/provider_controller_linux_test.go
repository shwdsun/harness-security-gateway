//go:build linux && codexintegration

package codexadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/providerfixture"
	"github.com/shwdsun/harness-security-gateway/internal/responsesgate"
)

// This constructor reuses the verified fixed HTTPS operation fixture. The
// auth file is the bootstrap-verified mount, not a new file or fallback copy.
func newProviderControllerConsumer(t *testing.T, ctx context.Context, home, workspace, toolNonce string, responder responsesgate.Responder) (*responsesgate.Gate, *providerObserver, string, func()) {
	t.Helper()
	authPath := filepath.Join(home, "auth.json")
	data, err := os.ReadFile(authPath)
	if err != nil || !providerfixture.AuthMatches(data, false) {
		t.Fatal("requires the exact mounted synthetic subscription object")
	}
	ops := newProviderCompositionOps(t, ctx, providerfixture.Nonce, responder)
	writeProof := func(closed bool) {
		ops.mu.Lock()
		defer ops.mu.Unlock()
		data, err := os.ReadFile(authPath)
		refreshed := err == nil && providerfixture.AuthMatches(data, true)
		proof, _ := json.Marshal(providerfixture.OperationProof{ToolNonce: toolNonce, Counts: ops.counts, Statuses: ops.statuses, Refreshed: refreshed, Closed: closed})
		if os.WriteFile(filepath.Join(workspace, "provider-operations-proof.json"), proof, 0o600) != nil {
			t.Error("cannot retain bounded provider witness")
		}
	}
	observer := newProviderObserverWithResponder(t, providerfixture.Nonce, func(w http.ResponseWriter, r *http.Request, body []byte) {
		ops.respond(w, r, body)
		writeProof(false)
	})
	ca := filepath.Join(t.TempDir(), "provider-ca.pem")
	if os.WriteFile(ca, observer.ca, 0o600) != nil {
		t.Fatal("synthetic CA write failed")
	}
	cleanup := func() {
		observer.close()
		ops.close() // Join before the wrapper releases its withheld HRP terminal.
		writeProof(true)
		ops.mu.Lock()
		defer ops.mu.Unlock()
		data, err := os.ReadFile(authPath)
		if err != nil || !providerfixture.AuthMatches(data, true) || ops.counts["refresh"] != 1 || ops.counts["inference"] != 2 {
			t.Error("mounted refresh/completion not established")
		}
		for _, status := range ops.statuses {
			if status != http.StatusOK && status != http.StatusNotFound {
				t.Error("unexpected fixed operation rejection")
			}
		}
	}
	return ops.gate, observer, ca, cleanup
}

func TestCodexControllerProviderRunner(t *testing.T) {
	if os.Getenv("HSG_CODEX_CONTROLLER_PROVIDER_RUNNER") != "1" {
		t.Skip("fixed offline HTTPS controller Runner")
	}
	mode := os.Getenv("HSG_CODEX_CONTROLLER_PROVIDER_MODE")
	if mode != "complete" && mode != "cancel" {
		t.Fatal("unknown fixed provider Runner")
	}
	controllerRunnerNamespace(t)
	stream := &controllerRunnerIO{input: os.Stdin, output: os.Stdout}
	tool := "command-exec"
	if mode == "cancel" {
		tool = "command-cancel"
	}
	toolsConfigurationProviderIO(t, codexprofile.CLIBinaryPathV3, tool, true, stream, true)
	if mode == "cancel" {
		t.Fatal("externally cancelled provider Runner survived teardown")
	}
	assertIntegrationQuiescence(t)
	if len(stream.buffer) != 0 || len(stream.pending) == 0 || len(stream.frames) != 3 || t.Failed() {
		t.Fatal("provider terminal did not pass independent checks")
	}
	if n, err := os.Stdout.Write(stream.pending); err != nil || n != len(stream.pending) {
		os.Exit(1)
	}
	os.Exit(0) // Testing output must never enter the HRP stream.
}
