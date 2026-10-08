//go:build linux && amd64 && codexintegration

package sandboxcontroller

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/codexprovider"
	"github.com/shwdsun/harness-security-gateway/internal/providerfixture"
)

type coreProviderConfig struct{ Root, OwnerSHA256 string }
type coreProviderFixture struct {
	mu       sync.Mutex
	config   coreNativeConfig
	nonce    string
	counts   map[string]int
	verified bool
}

func newCoreProviderFixture(t *testing.T, config coreNativeConfig) *coreProviderFixture {
	t.Helper()
	if !config.ProviderHTTPS || !strings.HasPrefix(config.Provider.Root, filepath.Dir(config.Runtime.WorkspaceRoot)+"/") {
		t.Fatal("invalid fixed provider fixture")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	p := &coreProviderFixture{config: config, nonce: hex.EncodeToString(nonce[:]), counts: map[string]int{"refresh": 0, "catalog": 0, "inference": 0}}
	if config.Case == "cancel-held-tool" || config.Case == "owner-running" {
		f, err := os.OpenFile(filepath.Join(config.Runtime.WorkspaceRoot, config.Runtime.WorkspaceDirectory, "probe.lock"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if f.Close() != nil {
			t.Fatal("lock close")
		}
	}
	return p
}

func (p *coreProviderFixture) proof(closed bool) error {
	data, err := os.ReadFile(nativeProviderAuthPath(p.config))
	proof := providerfixture.OperationProof{ToolNonce: p.nonce, Counts: p.counts, Refreshed: err == nil && providerfixture.AuthMatches(data, true), Closed: closed}
	encoded, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	workspace := filepath.Join(p.config.Runtime.WorkspaceRoot, p.config.Runtime.WorkspaceDirectory)
	f, err := os.CreateTemp(workspace, ".provider-proof-")
	if err != nil {
		return err
	}
	_, writeErr := f.Write(encoded)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("fixture proof write")
	}
	return os.Rename(f.Name(), filepath.Join(workspace, "provider-operations-proof.json"))
}

func (p *coreProviderFixture) respond(ctx context.Context, request codexprovider.Request) (codexprovider.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	bad := func() (codexprovider.Response, error) {
		return codexprovider.Response{}, errors.New("fixed synthetic operation mismatch")
	}
	jsonResponse := func(value any) (codexprovider.Response, error) {
		data, err := json.Marshal(value)
		return codexprovider.Response{Status: 200, MediaType: "application/json", Body: io.NopCloser(bytes.NewReader(data))}, err
	}
	if ctx.Err() != nil {
		return bad()
	}
	if request.Operation == codexprovider.Refresh {
		var token struct {
			Refresh string `json:"refresh_token"`
		}
		if json.Unmarshal(request.Body, &token) != nil || token.Refresh != providerfixture.Nonce+"-refresh" || p.counts["refresh"] != 0 {
			return bad()
		}
		p.counts["refresh"]++
		var auth struct {
			Tokens struct {
				ID string `json:"id_token"`
			}
		}
		_ = json.Unmarshal(providerfixture.InitialAuth(), &auth)
		return jsonResponse(map[string]any{"access_token": providerfixture.Nonce + "-refreshed", "id_token": auth.Tokens.ID, "refresh_token": providerfixture.Nonce + "-refresh-after", "expires_in": 3600, "token_type": "Bearer"})
	}
	if request.Header.Get("Authorization") != "Bearer "+providerfixture.Nonce+"-refreshed" || request.Header.Get("Chatgpt-Account-Id") != "hsg-synthetic-account" {
		return bad()
	}
	if request.Operation == codexprovider.Catalog {
		p.counts["catalog"]++
		return jsonResponse(map[string]any{"models": []any{}})
	}
	if request.Operation != codexprovider.Inference {
		return bad()
	}
	p.counts["inference"]++
	var item map[string]any
	switch p.counts["inference"] {
	case 1:
		command := "exec /hsg-canary '-test.run=^TestCodexToolsCommandProbe$' -- hsg-v3-command-probe /workspace " + p.nonce
		if p.config.Case == "cancel-held-tool" || p.config.Case == "owner-running" {
			command = "exec /hsg-canary '-test.run=^TestCodexExecIntegrationTool$' -- hsg-exec-probe cancel /workspace " + p.nonce + " http://127.0.0.1:1"
		}
		args, _ := json.Marshal(map[string]any{"cmd": command, "workdir": "/workspace", "yield_time_ms": 10000, "max_output_tokens": 1000})
		code := fmt.Sprintf(`text({command_marker:%q,result:await tools.exec_command(%s)});`, p.nonce, args)
		item = map[string]any{"type": "custom_tool_call", "id": "ct_" + p.nonce, "call_id": "call_" + p.nonce, "name": "exec", "namespace": "functions", "input": code, "status": "completed"}
	case 2:
		if p.config.Case != "replay-cleanup" {
			return bad()
		}
		data, err := os.ReadFile(filepath.Join(p.config.Runtime.WorkspaceRoot, p.config.Runtime.WorkspaceDirectory, "native-command-proof.json"))
		if err != nil || len(data) > 4096 {
			return bad()
		}
		var input struct {
			Input []struct {
				Type   string
				CallID string `json:"call_id"`
				Output []struct{ Type, Text string }
			}
		}
		if json.Unmarshal(request.Body, &input) != nil {
			return bad()
		}
		for _, entry := range input.Input {
			if entry.Type != "custom_tool_call_output" || entry.CallID != "call_"+p.nonce {
				continue
			}
			for _, chunk := range entry.Output {
				var output struct {
					Marker string `json:"command_marker"`
					Result struct {
						Exit   *int `json:"exit_code"`
						Output string
					}
				}
				if chunk.Type == "input_text" && json.Unmarshal([]byte(chunk.Text), &output) == nil && output.Marker == p.nonce && output.Result.Exit != nil && *output.Result.Exit == 17 && strings.Contains(output.Result.Output, string(data)) && strings.Contains(output.Result.Output, "COMMAND_STDERR_"+p.nonce) {
					p.verified = true
				}
			}
		}
		if !p.verified {
			return bad()
		}
		item = map[string]any{"type": "message", "id": "msg_" + p.nonce, "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": "HSG_DONE_" + p.nonce, "annotations": []any{}}}}
	default:
		return bad()
	}
	if err := p.proof(false); err != nil {
		return bad()
	}
	var stream bytes.Buffer
	for _, event := range []map[string]any{
		{"type": "response.output_item.done", "output_index": 0, "sequence_number": 0, "item": item},
		{"type": "response.completed", "sequence_number": 1, "response": map[string]any{"id": "resp_" + p.nonce, "status": "completed", "output": []any{item}}},
	} {
		data, _ := json.Marshal(event)
		fmt.Fprintf(&stream, "event: %s\ndata: %s\n\n", event["type"], data)
	}
	return codexprovider.Response{Status: 200, MediaType: "text/event-stream", Body: io.NopCloser(bytes.NewReader(stream.Bytes()))}, nil
}

func (r *coreNativeRuntime) CloseRunResources(ctx context.Context, runID string) error {
	if err := r.DockerRuntime.CloseRunResources(ctx, runID); err != nil {
		return err
	}
	if r.provider != nil {
		r.provider.mu.Lock()
		defer r.provider.mu.Unlock()
		if err := r.provider.proof(true); err != nil {
			return err
		}
		r.record("provider-joined-before-credential-release-and-publication")
	}
	return nil
}
