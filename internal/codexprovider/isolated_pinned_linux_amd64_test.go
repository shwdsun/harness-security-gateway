//go:build linux && amd64 && codexintegration

package codexprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/providerrelay"
)

// Auth compatibility only, inside the frozen network-none container. Client,
// endpoint and owner share a fixture PID/mount domain; this cannot prove final
// Runner containment. Both upstream seams are synthetic. No real model request,
// native tool, actual HeldSource enrollment or host service gate is exercised.
func TestIsolatedPinnedRecovery(t *testing.T) {
	if os.Getenv("HSG_ISOLATED_NATIVE_PROBE") != "synthetic-network-none-v1" {
		t.Skip("requires the frozen offline container plan")
	}
	if os.Geteuid() != 1000 {
		t.Fatal("fixed unprivileged fixture identity required")
	}
	files, err := openOwnerNativeFiles("/auth-launcher", "/codex", os.Getenv("HSG_OWNER_LAUNCHER_SHA256"))
	if err != nil {
		t.Fatal("pinned artifacts rejected")
	}
	defer files.launcher.Close()
	defer files.native.Close()
	owner, storage := nativeTestConsumer(t, files, "")
	canary := func() string {
		v, err := localRandom()
		if err != nil {
			t.Fatal(err)
		}
		return "OWNER_CANARY_" + v
	}
	access, refresh, account, subject := canary(), canary(), canary(), canary()
	claims, _ := json.Marshal(map[string]any{"sub": subject, "email": "owner@example.invalid", "exp": 4102444800,
		"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": account, "chatgpt_plan_type": "pro"}})
	identity := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims) + ".synthetic"
	data, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "OPENAI_API_KEY": nil, "last_refresh": time.Now().UTC().Format(time.RFC3339Nano),
		"tokens": map[string]string{"access_token": access, "refresh_token": refresh, "id_token": identity, "account_id": account}})
	storage.data = data
	before, err := ParseOwnerAuth(data)
	if err != nil {
		t.Fatal("synthetic owner seed rejected")
	}
	var refreshes, inferences, catalogs atomic.Int32
	owner.send = func(context.Context, Request) (Response, error) {
		refreshes.Add(1)
		// The real provider is allowed to leave token strings unchanged.
		return Response{Status: 200, MediaType: "application/json", Body: io.NopCloser(bytes.NewReader(refreshData(t, before)))}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	root, err := os.MkdirTemp("", "hsg-pinned-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	for _, name := range []string{"endpoint", "client", "workspace", "output", "tmp"} {
		if os.Mkdir(filepath.Join(root, name), 0700) != nil {
			t.Fatal("fixture directories")
		}
	}
	const marker = "HSG_ISOLATED_RECOVERY_OK"
	p, err := makeIsolatedProvider(ctx, filepath.Join(root, "endpoint"), localidentity.UID(1000), owner, func(_ context.Context, request Request) (Response, error) {
		if request.Header.Get("Authorization") != "Bearer "+access || request.Header.Get("Chatgpt-Account-Id") != account {
			return Response{}, ErrOwnerAuth
		}
		switch request.Operation {
		case Catalog:
			catalogs.Add(1)
			return Response{Status: 200, MediaType: "application/json", Body: io.NopCloser(strings.NewReader(`{"models":[]}`))}, nil
		case Inference:
			switch inferences.Add(1) {
			case 1:
				return isolatedReply(401, string(data)), nil // Poison error must be replaced.
			case 2:
				item := map[string]any{"type": "message", "id": "msg_isolated", "role": "assistant", "status": "completed",
					"content": []any{map[string]any{"type": "output_text", "text": marker, "annotations": []any{}}}}
				var body bytes.Buffer
				for _, event := range []map[string]any{
					{"type": "response.output_item.done", "output_index": 0, "sequence_number": 0, "item": item},
					{"type": "response.completed", "sequence_number": 1, "response": map[string]any{"id": "resp_isolated", "status": "completed", "output": []any{item}}},
				} {
					encoded, _ := json.Marshal(event)
					fmt.Fprintf(&body, "event: %s\ndata: %s\n\n", event["type"], encoded)
				}
				return isolatedReply(200, body.String()), nil
			}
		}
		return Response{}, ErrDenied
	})
	if err != nil {
		t.Fatal("isolated provider construction")
	}
	t.Cleanup(func() {
		end, stop := context.WithTimeout(context.Background(), 12*time.Second)
		defer stop()
		if p.Close(end) != nil {
			t.Error("provider cleanup incomplete")
		}
	})
	seed, err := p.initialAuth()
	if err != nil || os.WriteFile(filepath.Join(root, "client", "auth.json"), seed, 0600) != nil {
		t.Fatal("exact production local representation unavailable")
	}
	if err := openIsolated(p); err != nil {
		t.Fatal("native owner readiness", err)
	}
	if storage.commits != 1 || refreshes.Load() != 0 {
		t.Fatal("cached readiness unnecessarily refreshed owner")
	}
	socket, ca := p.Paths()
	relay, err := providerrelay.Start(ctx, socket, localidentity.UID(1000))
	if err != nil {
		t.Fatal("client relay")
	}
	defer func() {
		if relay.Close() != nil {
			t.Error("client relay join")
		}
	}()
	// This uses the existing native HTTPS overlay, with no model tool responses
	// or external connection. Full HRP/tool/profile composition remains separate.
	args := []string{"exec", "--json", "--ephemeral", "--ignore-user-config", "--ignore-rules", "--strict-config", "--skip-git-repo-check",
		"--color", "never", "--sandbox", "workspace-write", "--model", codexprofile.ModelNameV1, "--cd", filepath.Join(root, "workspace"),
		"--output-last-message", filepath.Join(root, "output", "final.txt")}
	for _, config := range []string{
		`model_reasoning_effort="medium"`, `approval_policy="never"`, `forced_login_method="chatgpt"`, `cli_auth_credentials_store="file"`,
		`model_provider="hsg-subscription-https"`,
		`model_providers.hsg-subscription-https={name="HSG subscription HTTPS",base_url="https://chatgpt.com/backend-api/codex",wire_api="responses",requires_openai_auth=true,supports_websockets=false}`,
		`features.enable_request_compression=false`, `project_doc_max_bytes=0`, `check_for_update_on_startup=false`,
		`web_search="disabled"`, `features.code_mode.enabled=false`, `features.code_mode_host=false`, `features.plugins=false`, `features.apps=false`,
		`features.shell_snapshot=false`, `features.hooks=false`, `features.memories=false`, `features.multi_agent=false`, `features.auth_elicitation=false`,
		`features.remote_compaction_v2=false`, `features.remote_plugin=false`, `features.skill_mcp_dependency_install=false`, `history.persistence="none"`,
	} {
		args = append(args, "--config", config)
	}
	args = append(args, "-")
	command := exec.CommandContext(ctx, "/codex", args...)
	command.Dir = filepath.Join(root, "workspace")
	command.Env = []string{"HOME=" + filepath.Join(root, "client"), "CODEX_HOME=" + filepath.Join(root, "client"), "CODEX_SQLITE_HOME=" + filepath.Join(root, "output"),
		"TMPDIR=" + filepath.Join(root, "tmp"), "PATH=/nonexistent", "LANG=C.UTF-8", "TERM=dumb", "CODEX_CA_CERTIFICATE=" + ca,
		"HTTP_PROXY=http://" + relay.Address(), "HTTPS_PROXY=http://" + relay.Address()}
	command.Stdin = strings.NewReader("Return only the fixed synthetic observation marker; do not invoke tools.\n")
	stdout, stderr := &isolatedCapture{}, &isolatedCapture{}
	command.Stdout, command.Stderr, command.WaitDelay = stdout, stderr, 2*time.Second
	err = command.Run()
	if err != nil || ctx.Err() != nil {
		t.Logf("native client exit: %v; inference=%d catalog=%d owner-refresh=%d; endpoint=%+v", err, inferences.Load(), catalogs.Load(), refreshes.Load(), p.endpoint.Diagnostics())
		t.Fatal("native client did not complete within fixed bound")
	}
	if err := p.Close(ctx); err != nil {
		t.Fatal("provider/native join", err)
	}
	if relay.Close() != nil {
		t.Fatal("relay join")
	}
	final, err := os.ReadFile(filepath.Join(root, "output", "final.txt"))
	if err != nil || strings.TrimSpace(string(final)) != marker {
		t.Fatal("native final response did not match fixed synthetic marker")
	}
	if refreshes.Load() != 1 || inferences.Load() != 2 || storage.commits != 2 || storage.invalid || owner.active != nil {
		t.Fatal("native auth recovery count/persistence/cleanup mismatch", refreshes.Load(), inferences.Load(), storage.commits)
	}
	diagnostic := p.endpoint.Diagnostics()
	localDenied, localRefresh := 0, 0
	for _, exchange := range diagnostic.Exchanges {
		switch exchange.LocalAuth {
		case "denied":
			localDenied++
		case "refresh":
			localRefresh++
		}
		if exchange.LocalAuth != "" && (exchange.UpstreamAuthorized || exchange.UpstreamStatus != 0) {
			t.Fatal("local auth classified as external dispatch")
		}
	}
	if !diagnostic.Joined || localDenied != 1 || localRefresh != 1 {
		t.Fatal("expected exactly one local old-auth denial and one local refresh", localDenied, localRefresh)
	}
	secrets := []string{access, refresh, account, subject, identity}
	scan := func(data []byte) {
		for _, secret := range secrets {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatal("owner canary in client output/state")
			}
		}
	}
	scan(seed)
	scan(stdout.Bytes())
	scan(stderr.Bytes())
	diagnosticBytes, _ := json.Marshal(diagnostic)
	scan(diagnosticBytes)
	var total int64
	for _, name := range []string{"client", "workspace", "output", "tmp"} {
		if filepath.WalkDir(filepath.Join(root, name), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 {
				return ErrDenied
			}
			total += info.Size()
			if total > 32<<20 {
				return ErrDenied
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scan(data)
			return nil
		}) != nil {
			t.Fatal("unsafe/unbounded client fixture output")
		}
	}
	// Private namespace: no unaccounted child leader can survive the joined
	// client/helper. This is an observation for this fixture, not a host gate.
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err == nil && pid != os.Getpid() {
			t.Fatal("unexpected process left in fixture PID namespace", pid)
		}
	}
	t.Log("native isolated recovery passed: one upstream 401, one owner-native refresh/persistence, one local 401, one local refresh, one new inference; canaries absent; all joins complete")
}

type isolatedCapture struct{ bytes.Buffer }

func (b *isolatedCapture) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 64<<10 {
		return 0, ErrDenied
	}
	return b.Buffer.Write(p)
}
