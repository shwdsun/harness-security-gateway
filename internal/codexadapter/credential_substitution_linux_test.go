//go:build linux && codexintegration

package codexadapter

// Offline compatibility experiment only. The owner below simulates an upstream
// and credential persistence; it is not a production credential broker.
import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/codexprovider"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

const substitutionWorkspace = "/tmp/hsg-substitution-workspace"
const substitutionHome = "/tmp/hgw-codex-home"
const substitutionMarker = "HSG_LOCAL_AUTH_TOOL_OK"

type substitutionTokens struct {
	Access, Refresh, Identity string
}

func substitutionSecret() string {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic("synthetic entropy unavailable")
	}
	return "owner-only-" + hex.EncodeToString(value[:])
}

func substitutionLocal(generation int) map[string]string {
	return map[string]string{"access_token": fmt.Sprintf("hsg-local-access-%d", generation),
		"refresh_token": fmt.Sprintf("hsg-local-refresh-%d", generation),
		"id_token":      providerSyntheticJWT(), "account_id": "hsg-synthetic-account"}
}

type substitutionOwner struct {
	mu                                                    sync.Mutex
	root, mode                                            string
	tokens                                                substitutionTokens
	secrets                                               []string
	generation, refreshes, attempts, inferences, catalogs int
	toolVerified                                          bool
	events                                                []string
}

func (o *substitutionOwner) rotate() error {
	next := substitutionTokens{substitutionSecret(), substitutionSecret(), substitutionSecret()}
	// Synthetic owner-only persistence. No real token endpoint or credential
	// store is used; crash-safe production refresh remains a separate gate.
	if err := nativeProviderWrite(filepath.Join(o.root, "owner-auth.json"), next); err != nil {
		return err
	}
	o.tokens = next
	o.secrets = append(o.secrets, next.Access, next.Refresh, next.Identity)
	return nil
}

func substitutionResponse(status int, media string, body []byte) codexprovider.Response {
	return codexprovider.Response{Status: status, MediaType: media, Body: io.NopCloser(bytes.NewReader(body))}
}

func (o *substitutionOwner) containsSecret(data []byte) bool {
	for _, secret := range o.secrets {
		if bytes.Contains(data, []byte(secret)) {
			return true
		}
	}
	return false
}

func (o *substitutionOwner) respond(_ context.Context, request codexprovider.Request) (codexprovider.Response, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.containsSecret(request.Body) {
		return codexprovider.Response{}, errors.New("owner secret returned by client")
	}
	local := substitutionLocal(o.generation)
	if request.Operation == codexprovider.Refresh {
		var fields map[string]string
		if o.mode == "fresh" || o.refreshes != 0 || strictjson.Decode(request.Body, 8192, 4, &fields) != nil ||
			fields["refresh_token"] != local["refresh_token"] {
			return codexprovider.Response{}, errors.New("local refresh mismatch")
		}
		// Simulated upstream accepts only the owner's current refresh token.
		upstream := map[string]string{"refresh_token": o.tokens.Refresh}
		if upstream["refresh_token"] == fields["refresh_token"] || upstream["refresh_token"] == "" {
			return codexprovider.Response{}, errors.New("upstream/local auth conflated")
		}
		if err := o.rotate(); err != nil {
			return codexprovider.Response{}, err
		}
		o.generation++
		o.refreshes++
		o.events = append(o.events, "refresh_persisted")
		body, _ := json.Marshal(substitutionLocal(o.generation))
		return substitutionResponse(200, "application/json", body), nil
	}
	if request.Header.Get("Authorization") != "Bearer "+local["access_token"] ||
		request.Header.Get("Chatgpt-Account-Id") != local["account_id"] {
		return codexprovider.Response{}, errors.New("local inference/catalog auth mismatch")
	}
	upstreamHeader := request.Header.Clone()
	upstreamHeader.Set("Authorization", "Bearer "+o.tokens.Access)
	upstreamHeader.Set("Chatgpt-Account-Id", "owner-only-account")
	if upstreamHeader.Get("Authorization") == request.Header.Get("Authorization") {
		return codexprovider.Response{}, errors.New("upstream auth was not substituted")
	}
	if request.Operation == codexprovider.Catalog {
		o.catalogs++
		o.events = append(o.events, "catalog")
		return substitutionResponse(200, "application/json", []byte(`{"models":[]}`)), nil
	}
	if request.Operation != codexprovider.Inference {
		return codexprovider.Response{}, errors.New("unexpected fixture operation")
	}
	o.attempts++
	if o.mode == "rejected" && o.generation == 0 {
		// One 401 is insufficient: the pinned client may reload its auth cache
		// before refreshing. Keep the old generation invalid rather than making
		// it magically usable on retry. Bound this diagnostic to two old attempts.
		if o.attempts > 2 {
			return codexprovider.Response{}, errors.New("old-auth diagnostic budget exceeded")
		}
		o.events = append(o.events, "inference_401")
		// Poison body: the production endpoint must replace non-200 bodies.
		return substitutionResponse(401, "application/json", []byte(o.tokens.Access)), nil
	}
	o.inferences++
	o.events = append(o.events, "inference_200")
	var input struct {
		Input []struct {
			Type   string
			CallID string `json:"call_id"`
			Output json.RawMessage
		}
	}
	if json.Unmarshal(request.Body, &input) != nil {
		return codexprovider.Response{}, errors.New("invalid native input")
	}
	recorder := httptest.NewRecorder()
	switch o.inferences {
	case 1:
		args, _ := json.Marshal(map[string]any{"cmd": "exec /probe.test -test.run=^TestCredentialSubstitutionTool$ -- hsg-local-auth-probe", "workdir": substitutionWorkspace, "yield_time_ms": 10000, "max_output_tokens": 1000})
		code := fmt.Sprintf(`text({command_marker:%q,result:await tools.exec_command(%s)});`, substitutionMarker, args)
		writeIntegrationResponse(recorder, "substitution", map[string]any{"type": "custom_tool_call", "id": "ct_substitution", "call_id": "call_substitution", "name": "exec", "namespace": "functions", "input": code, "status": "completed"})
	case 2:
		proof, err := os.ReadFile(filepath.Join(o.root, "workspace", "tool-proof.json"))
		if err != nil || string(proof) != substitutionMarker {
			return codexprovider.Response{}, errors.New("independent tool proof missing")
		}
		for _, item := range input.Input {
			if item.Type == "custom_tool_call_output" && item.CallID == "call_substitution" && verifyToolsExecOutput(item.Output, substitutionMarker, 0, substitutionMarker) {
				o.toolVerified = true
			}
		}
		if !o.toolVerified {
			return codexprovider.Response{}, errors.New("native tool output not correlated")
		}
		writeIntegrationResponse(recorder, "substitution", map[string]any{"type": "message", "id": "msg_substitution", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": substitutionMarker, "annotations": []any{}}}})
	default:
		return codexprovider.Response{}, errors.New("extra inference")
	}
	return substitutionResponse(200, "text/event-stream", recorder.Body.Bytes()), nil
}

// No symlink traversal or unbounded reads of tool-controlled fixture output.
func (o *substitutionOwner) scanClientFiles() error {
	var total int64
	for _, name := range []string{"home", "workspace", "capture"} {
		if err := filepath.WalkDir(filepath.Join(o.root, name), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 {
				return errors.New("unsafe fixture output")
			}
			total += info.Size()
			if total > 32<<20 {
				return errors.New("fixture output budget exceeded")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if o.containsSecret(data) {
				return errors.New("owner secret in client output")
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func TestCredentialSubstitutionOwner(t *testing.T) {
	root := os.Getenv("HSG_CREDENTIAL_SUBSTITUTION_OWNER")
	if root == "" {
		t.Skip("opt-in offline credential substitution owner")
	}
	var fixture struct{ Mode string }
	if os.Geteuid() != 1000 || nativeProviderRead(filepath.Join(root, "fixture.json"), &fixture) != nil ||
		(fixture.Mode != "fresh" && fixture.Mode != "stale" && fixture.Mode != "rejected") {
		t.Fatal("invalid fixed fixture")
	}
	o := &substitutionOwner{root: root, mode: fixture.Mode}
	if o.rotate() != nil {
		t.Fatal("synthetic owner seed failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	dir := filepath.Join(root, "endpoint")
	if os.Mkdir(dir, 0o700) != nil {
		t.Fatal("endpoint directory")
	}
	endpoint, err := codexprovider.NewSynthetic(ctx, dir, localidentity.UID(1000), o.respond)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		closeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if endpoint.Close(closeCtx) != nil {
			t.Error("endpoint join failed")
		}
	}()
	if endpoint.Open() != nil {
		t.Fatal("endpoint admission")
	}
	socket, ca := endpoint.Paths()
	if nativeProviderWrite(filepath.Join(root, "ready.json"), map[string]string{"socket": socket, "ca": ca}) != nil {
		t.Fatal("ready record")
	}
	done := make(chan struct{})
	go func() { var b [1]byte; _, _ = os.Stdin.Read(b[:]); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("owner deadline")
	}
	closeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if endpoint.Close(closeCtx) != nil {
		t.Fatal("endpoint close failed")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	wantRefresh, wantAttempts := 1, 2
	if fixture.Mode == "fresh" {
		wantRefresh = 0
	}
	if fixture.Mode == "rejected" {
		wantAttempts = 4
	}
	if o.refreshes != wantRefresh || o.attempts != wantAttempts || o.inferences != 2 || !o.toolVerified {
		t.Error("operation/completion counts mismatch")
	}
	var saved substitutionTokens
	if nativeProviderRead(filepath.Join(root, "owner-auth.json"), &saved) != nil || saved != o.tokens {
		t.Error("owner persistence mismatch")
	}
	if err := o.scanClientFiles(); err != nil {
		t.Error(err)
	}
	report := map[string]any{"passed": !t.Failed(), "mode": fixture.Mode, "generation": o.generation, "refreshes": o.refreshes, "inference_attempts": o.attempts, "inferences": o.inferences, "catalogs": o.catalogs, "tool_verified": o.toolVerified, "events": o.events, "endpoint_joined": true, "scanned_owner_canaries": len(o.secrets)}
	if nativeProviderWrite(filepath.Join(root, "owner-result.json"), report) != nil {
		t.Error("result write failed")
	}
}

func TestCredentialSubstitutionClient(t *testing.T) {
	if os.Getenv("HSG_CREDENTIAL_SUBSTITUTION_CLIENT") != "1" {
		t.Skip("opt-in offline native substitution client")
	}
	requireProviderInventoryNamespace(t)
	if os.Geteuid() != 1000 {
		t.Fatal("fixed native UID required")
	}
	config := MessagingToolsConfig(codexprofile.ModelNameV1)
	config.Workspace, config.CodexHome, config.OutputDirectory = substitutionWorkspace, substitutionHome, filepath.Join(t.TempDir(), "output")
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	var diagnostics integrationDiagnostics
	launcher := launcherFunc(func(ctx context.Context, inv Invocation) (Process, error) {
		inv.Stdout, inv.Stderr = io.MultiWriter(inv.Stdout, &diagnostics), io.MultiWriter(inv.Stderr, &diagnostics)
		return (ProviderCanaryLauncher{}).Start(ctx, inv)
	})
	start := testStart()
	start.Input.Text = "Execute the fixed offline local-auth probe and return its marker."
	frames, _, err := execute(t, ctx, start, config, launcher)
	// Synthetic-only bounded private diagnostics; never used by the real path.
	if os.WriteFile(filepath.Join(substitutionWorkspace, "native-diagnostics.txt"), []byte(diagnostics.String()), 0o600) != nil {
		t.Error("diagnostic capture failed")
	}
	if err != nil || len(frames) != 3 || ctx.Err() != nil {
		t.Fatal("native HRP/deadline failure")
	}
	complete, ok := frames[2].(*runnerwire.RunCompleted)
	if !ok || complete.Output.Text != substitutionMarker {
		t.Fatalf("native completion missing: %T", frames[2])
	}
	assertIntegrationQuiescence(t)
}

func TestCredentialSubstitutionTool(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "hsg-local-auth-probe" {
		return
	}
	data, err := os.ReadFile(filepath.Join(substitutionHome, "auth.json"))
	var auth struct {
		Tokens map[string]string `json:"tokens"`
	}
	var object map[string]json.RawMessage
	if err != nil || strictjson.Decode(data, 16<<10, 8, &object) != nil || json.Unmarshal(object["tokens"], &auth.Tokens) != nil {
		t.Fatal("local auth read failed")
	}
	if auth.Tokens["id_token"] != providerSyntheticJWT() || auth.Tokens["account_id"] != "hsg-synthetic-account" ||
		!strings.HasPrefix(auth.Tokens["access_token"], "hsg-local-access-") || !strings.HasPrefix(auth.Tokens["refresh_token"], "hsg-local-refresh-") {
		t.Fatal("unexpected client auth")
	}
	if os.WriteFile(filepath.Join(substitutionWorkspace, "tool-proof.json"), []byte(substitutionMarker), 0o600) != nil {
		t.Fatal("tool proof write")
	}
	fmt.Println(substitutionMarker)
}

func TestCredentialSubstitutionFixtureGuards(t *testing.T) {
	o := &substitutionOwner{root: t.TempDir(), mode: "stale"}
	if err := o.rotate(); err != nil {
		t.Fatal(err)
	}
	initial := o.tokens
	request := codexprovider.Request{Operation: codexprovider.Catalog, Header: make(http.Header)}
	request.Header.Set("Authorization", "Bearer "+initial.Access)
	request.Header.Set("Chatgpt-Account-Id", "hsg-synthetic-account")
	if _, err := o.respond(context.Background(), request); err == nil {
		t.Fatal("client-supplied owner auth was accepted")
	}
	request.Header.Set("Authorization", "Bearer hsg-local-access-0")
	response, err := o.respond(context.Background(), request)
	if err != nil || response.Status != 200 {
		t.Fatal("matching local positive control failed")
	}
	_ = response.Body.Close()
	refresh := codexprovider.Request{Operation: codexprovider.Refresh, Body: []byte(`{"refresh_token":"wrong"}`)}
	if _, err := o.respond(context.Background(), refresh); err == nil || o.tokens != initial {
		t.Fatal("mismatched refresh changed owner auth")
	}
	refresh.Body = []byte(`{"refresh_token":"hsg-local-refresh-0"}`)
	response, err = o.respond(context.Background(), refresh)
	if err != nil || response.Status != 200 {
		t.Fatal("matching refresh positive control failed")
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || o.containsSecret(body) || o.tokens == initial || o.generation != 1 {
		t.Fatal("local response or rotation incorrect")
	}
	if _, err := o.respond(context.Background(), request); err == nil {
		t.Fatal("old local representation survived rotation")
	}
	if _, err := o.respond(context.Background(), refresh); err == nil {
		t.Fatal("duplicate refresh accepted")
	}
	for _, name := range []string{"home", "workspace", "capture"} {
		if err := os.Mkdir(filepath.Join(o.root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.scanClientFiles(); err != nil {
		t.Fatal("clean scan positive control", err)
	}
	poison := filepath.Join(o.root, "capture", "poison")
	if err := os.WriteFile(poison, []byte(initial.Access), 0o600); err != nil {
		t.Fatal(err)
	}
	if o.scanClientFiles() == nil {
		t.Fatal("old owner token escaped detection")
	}
}
