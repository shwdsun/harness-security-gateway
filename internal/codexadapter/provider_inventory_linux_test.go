//go:build linux && codexintegration

package codexadapter

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
)

// These fixtures inventory the pinned built-in provider and a separate fixed
// HTTPS candidate with synthetic file authentication. The TLS peer is a local
// responder with no upstream/dialer.
// It is not an executable provider policy or evidence of real account access.
type providerObservation struct {
	Method, Authority, Path string
	QueryKeys, HeaderNames  []string
	Encoding, Upgrade       string
	SyntheticBearer         bool
	RefreshedBearer         bool
	SyntheticAccount        bool
	InferenceTupleMatched   bool
	BodyBytes, Status       int
}

type providerObserver struct {
	mu          sync.Mutex
	requests    []providerObservation
	connects    []string
	connections map[net.Conn]bool
	stages      map[string]int
	closed      bool
	wg          sync.WaitGroup
	server      *httptest.Server
	certificate tls.Certificate
	ca          []byte
	// Optional frozen offline responder; set before the listener starts.
	responder func(http.ResponseWriter, *http.Request, []byte)
	nonce     string
	refreshes int
	responses int
	// Optional synthetic inference body, read and installed under mu.
	inferenceReply func(http.ResponseWriter)
}

func newProviderObserver(t *testing.T, nonce string) *providerObserver {
	return newProviderObserverWithResponder(t, nonce, nil)
}

func newProviderObserverWithResponder(t *testing.T, nonce string, responder func(http.ResponseWriter, *http.Request, []byte)) *providerObserver {
	return newProviderObserverOnListener(t, nonce, responder, nil)
}

// A Unix listener keeps TLS/operation handling in the endpoint-owner process.
// The ordinary inventory still uses its original loopback listener.
func newProviderObserverOnListener(t *testing.T, nonce string, responder func(http.ResponseWriter, *http.Request, []byte), listener net.Listener) *providerObserver {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "HSG synthetic observer CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign,
		IsCA:     true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "HSG synthetic observer server"},
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		DNSNames: []string{"chatgpt.com", "auth.openai.com", "api.openai.com"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, cert, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	o := &providerObserver{nonce: nonce, connections: make(map[net.Conn]bool), stages: make(map[string]int),
		responder:   responder,
		certificate: tls.Certificate{Certificate: [][]byte{leafDER, der}, PrivateKey: leafKey},
		ca:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	o.server = httptest.NewUnstartedServer(http.HandlerFunc(o.connect))
	if listener != nil {
		_ = o.server.Listener.Close()
		o.server.Listener = listener
	}
	o.server.Config.ReadHeaderTimeout = 2 * time.Second
	o.server.Config.ReadTimeout = 5 * time.Second
	o.server.Config.WriteTimeout = 5 * time.Second
	o.server.Config.MaxHeaderBytes = 16 << 10
	o.server.Start()
	t.Cleanup(o.close)
	return o
}

func (o *providerObserver) note(stage string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.stages[stage]++
}

func (o *providerObserver) close() {
	o.mu.Lock()
	o.closed = true
	for conn := range o.connections {
		_ = conn.Close()
	}
	o.mu.Unlock()
	o.server.Close()
	o.wg.Wait()
}

func (o *providerObserver) connect(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	allowed := !o.closed && len(o.connects) < 16 && r.Method == http.MethodConnect &&
		(r.Host == "chatgpt.com:443" || r.Host == "auth.openai.com:443" || r.Host == "api.openai.com:443")
	if len(o.connects) < 16 && len(r.Host) <= 128 {
		o.connects = append(o.connects, r.Host)
	}
	if !allowed {
		o.mu.Unlock()
		http.Error(w, "synthetic observer rejects destination", http.StatusBadGateway)
		return
	}
	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		o.mu.Unlock()
		return
	}
	o.connections[conn] = true
	o.wg.Add(1)
	o.mu.Unlock()
	defer func() {
		_ = conn.Close()
		o.mu.Lock()
		delete(o.connections, conn)
		o.mu.Unlock()
		o.wg.Done()
	}()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if rw.Flush() != nil {
		o.note("connect_reply_failed")
		return
	}
	if rw.Reader.Buffered() != 0 {
		o.note("pipelined_tls_rejected")
		return
	}
	secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{o.certificate}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if secure.Handshake() != nil {
		o.note("tls_handshake_failed")
		return
	}
	o.note("tls_ready")
	// Bound all decoded request bytes on this connection, including headers.
	reader := bufio.NewReader(io.LimitReader(secure, 4<<20))
	for count := 0; count < 8; count++ {
		request, err := http.ReadRequest(reader)
		if err != nil {
			o.note("http_read_ended")
			return
		}
		if request.Host != strings.TrimSuffix(r.Host, ":443") {
			o.note("inner_authority_rejected")
			_ = request.Body.Close()
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, (2<<20)+1))
		_ = request.Body.Close()
		if err != nil || len(body) > 2<<20 || len(request.URL.Path) > 512 {
			o.note("body_or_path_rejected")
			return
		}
		recorder := httptest.NewRecorder()
		if o.responder != nil {
			o.responder(recorder, request, body)
		} else {
			o.respond(recorder, request, body)
		}
		response := recorder.Result()
		// All synthetic responses are finite and already buffered. Supply their
		// exact length: Response.Write otherwise selects close-delimited framing,
		// while this observer would keep the connection open for another request.
		response.ContentLength = int64(recorder.Body.Len())
		err = response.Write(secure)
		_ = response.Body.Close()
		if err != nil || request.Close {
			o.note("response_connection_ended")
			return
		}
	}
}

func (o *providerObserver) respond(w http.ResponseWriter, r *http.Request, body []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.requests) >= 16 {
		http.Error(w, "synthetic request budget", http.StatusTooManyRequests)
		return
	}
	query := r.URL.Query()
	metadataFits := len(r.Header) <= 64 && len(query) <= 32 && len(r.Header.Get("Content-Encoding")) <= 64 && len(r.Header.Get("Upgrade")) <= 64
	for key := range r.Header {
		metadataFits = metadataFits && len(key) <= 128
	}
	for key := range query {
		metadataFits = metadataFits && len(key) <= 128
	}
	if !metadataFits {
		o.stages["metadata_budget_rejected"]++
		http.Error(w, "synthetic metadata budget", http.StatusRequestHeaderFieldsTooLarge)
		return
	}
	observation := providerObservation{Method: r.Method, Authority: r.Host, Path: r.URL.Path,
		Encoding: r.Header.Get("Content-Encoding"), Upgrade: r.Header.Get("Upgrade"), BodyBytes: len(body),
		SyntheticBearer:  r.Header.Get("Authorization") == "Bearer "+o.nonce || r.Header.Get("Authorization") == "Bearer "+o.nonce+"-refreshed",
		RefreshedBearer:  r.Header.Get("Authorization") == "Bearer "+o.nonce+"-refreshed",
		SyntheticAccount: r.Header.Get("ChatGPT-Account-ID") == "hsg-synthetic-account", Status: http.StatusNotFound}
	for key := range query {
		observation.QueryKeys = append(observation.QueryKeys, key)
	}
	for key := range r.Header {
		observation.HeaderNames = append(observation.HeaderNames, key)
	}
	sort.Strings(observation.QueryKeys)
	sort.Strings(observation.HeaderNames)
	// Suffix classification is for this no-upstream observer only. The actual
	// observed full paths must be reviewed before any executable allowlist exists.
	switch {
	case r.Host == "auth.openai.com" && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/token"):
		var fields map[string]string
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			values, _ := url.ParseQuery(string(body))
			fields = map[string]string{"grant_type": values.Get("grant_type"), "refresh_token": values.Get("refresh_token")}
		} else {
			_ = json.Unmarshal(body, &fields)
		}
		if fields["grant_type"] == "refresh_token" && fields["refresh_token"] == o.nonce+"-refresh" && o.refreshes == 0 {
			o.refreshes++
			observation.Status = http.StatusOK
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": o.nonce + "-refreshed", "id_token": providerSyntheticJWT(),
				"refresh_token": o.nonce + "-refresh-after", "expires_in": 3600, "token_type": "Bearer"})
		} else {
			observation.Status = http.StatusBadRequest
			http.Error(w, "synthetic refresh rejected", observation.Status)
		}
	case r.Host == "chatgpt.com" && observation.SyntheticBearer && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/models"):
		observation.Status = http.StatusOK
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"models":[]}`)
	case r.Host == "chatgpt.com" && observation.SyntheticBearer && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/responses") && o.responses == 0:
		// A basic compatibility projection, not the consumer's strict JSON
		// authorization parser. Never retain the native body in observations.
		if observation.Encoding == "" {
			var request struct {
				Model     string
				Reasoning struct{ Effort string }
				Stream    bool
			}
			observation.InferenceTupleMatched = json.Unmarshal(body, &request) == nil &&
				request.Model == codexprofile.ModelNameV1 && request.Reasoning.Effort == codexprofile.ModelReasoningEffortV1 && request.Stream
		}
		o.responses++
		observation.Status = http.StatusOK
		if o.inferenceReply != nil {
			o.inferenceReply(w)
		} else {
			writeIntegrationResponse(w, o.nonce, map[string]any{"type": "message", "id": "msg_" + o.nonce, "role": "assistant", "status": "completed",
				"content": []any{map[string]any{"type": "output_text", "text": "HSG_PROVIDER_OBSERVED", "annotations": []any{}}}})
		}
	default:
		http.Error(w, "synthetic observer has no such operation", observation.Status)
	}
	o.requests = append(o.requests, observation)
}

func providerSyntheticJWT() string {
	payload, _ := json.Marshal(map[string]any{"sub": "hsg-synthetic-subject", "email": "probe@example.invalid", "exp": int64(4102444800),
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "hsg-synthetic-account", "chatgpt_plan_type": "pro"}})
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".synthetic"
}

func TestCodexProviderOperationInventory(t *testing.T) {
	if os.Getenv("HSG_CODEX_PROVIDER_INVENTORY") != "1" {
		t.Skip("opt-in offline native provider inventory")
	}
	requireProviderInventoryNamespace(t)
	for _, mode := range []string{"fresh", "refresh"} {
		if !t.Run(mode, func(t *testing.T) { providerInventoryCase(t, mode, false) }) {
			t.FailNow()
		}
	}
}

func TestCodexProviderHTTPCandidate(t *testing.T) {
	if os.Getenv("HSG_CODEX_PROVIDER_HTTP_CANDIDATE") != "1" {
		t.Skip("opt-in offline subscription HTTPS candidate")
	}
	requireProviderInventoryNamespace(t)
	for _, mode := range []string{"fresh", "refresh"} {
		if !t.Run(mode, func(t *testing.T) { providerInventoryCase(t, mode, true) }) {
			t.FailNow()
		}
	}
}

// The gateway supplies an SSE transport type on the fixed inference route;
// native Codex must still require provider stream completion. This fixture
// uses the same downstream type/bytes, not the live upstream parser or account.
func TestCodexProviderStreamCompletion(t *testing.T) {
	if os.Getenv("HSG_CODEX_PROVIDER_STREAM_COMPLETION") != "1" {
		t.Skip("opt-in offline native stream completion witness")
	}
	requireProviderInventoryNamespace(t)
	for _, mode := range []string{"stream-complete", "stream-json", "stream-incomplete"} {
		if !t.Run(mode, func(t *testing.T) { providerInventoryCase(t, mode, true) }) {
			t.FailNow()
		}
	}
}

func requireProviderInventoryNamespace(t *testing.T) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil || os.Getpid() != 1 || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagUp == 0 {
		t.Fatal("requires owned PID-1 namespace with only active loopback")
	}
	if err := verifyToolsPackage(codexprofile.CLIBinaryPathV3); err != nil {
		t.Fatal(err)
	}
}

func providerInventoryCase(t *testing.T, mode string, httpCandidate bool) {
	root := t.TempDir()
	config := MessagingToolsConfig(codexprofile.ModelNameV1)
	config.Workspace, config.CodexHome, config.OutputDirectory = filepath.Join(root, "workspace"), filepath.Join(root, "home"), filepath.Join(root, "output")
	for _, path := range []string{config.Workspace, config.CodexHome, filepath.Join(root, "tmp")} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	nonce := "hsg-synthetic-" + mode
	observer := newProviderObserver(t, nonce)
	invalidStream := mode == "stream-json" || mode == "stream-incomplete"
	if invalidStream {
		observer.mu.Lock()
		observer.inferenceReply = func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/event-stream")
			if mode == "stream-json" {
				_, _ = io.WriteString(w, `{"type":"response.completed","output_text":"HSG_PROVIDER_OBSERVED"}`)
			} else {
				_, _ = io.WriteString(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"HSG_PROVIDER_OBSERVED\"}\n\n")
			}
		}
		observer.mu.Unlock()
	}
	terminal := ""
	defer func() {
		observer.close()
		observer.mu.Lock()
		defer observer.mu.Unlock()
		record, _ := json.Marshal(map[string]any{"mode": mode, "http_candidate": httpCandidate, "utc": time.Now().UTC().Format(time.RFC3339Nano), "uid": os.Geteuid(),
			"connects": observer.connects, "stages": observer.stages, "requests": observer.requests, "refreshes": observer.refreshes, "responses": observer.responses, "terminal": terminal, "passed": !t.Failed()})
		t.Logf("HSG_PROVIDER_OBSERVATION %s", record)
	}()
	caPath := filepath.Join(root, "observer-ca.pem")
	if err := os.WriteFile(caPath, observer.ca, 0o600); err != nil {
		t.Fatal(err)
	}
	lastRefresh := time.Now().UTC().Format(time.RFC3339)
	if mode == "refresh" {
		lastRefresh = "2000-01-01T00:00:00Z"
	}
	credential, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "OPENAI_API_KEY": nil, "last_refresh": lastRefresh,
		"tokens": map[string]any{"id_token": providerSyntheticJWT(), "access_token": nonce, "refresh_token": nonce + "-refresh", "account_id": "hsg-synthetic-account"}})
	if err := os.WriteFile(filepath.Join(config.CodexHome, "auth.json"), credential, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	launcher := launcherFunc(func(ctx context.Context, inv Invocation) (Process, error) {
		inv.Args = append(inv.Args[:len(inv.Args)-1], "--skip-git-repo-check", "-")
		if httpCandidate {
			// Fixed experimental overlay only. Built-in provider IDs cannot be
			// overridden; no normal V3 invocation or TargetRevision is changed.
			inv.Args = append(inv.Args[:len(inv.Args)-1],
				"--config", `model_provider="hsg-subscription-https"`,
				"--config", `model_providers.hsg-subscription-https={name="HSG subscription HTTPS",base_url="https://chatgpt.com/backend-api/codex",wire_api="responses",requires_openai_auth=true,supports_websockets=false}`,
				"--config", `features.enable_request_compression=false`, "-")
			if strings.HasPrefix(mode, "stream-") {
				// Fixture-only bound, shared by positive and negative controls.
				// Production/native retry defaults remain unchanged.
				inv.Args = append(inv.Args[:len(inv.Args)-1], "--config", `model_providers.hsg-subscription-https.stream_max_retries=0`, "-")
			}
		}
		inv.Env = append(inv.Env, "HTTPS_PROXY="+observer.server.URL, "HTTP_PROXY="+observer.server.URL,
			"CODEX_CA_CERTIFICATE="+caPath, "TMPDIR="+filepath.Join(root, "tmp"))
		return (ExecLauncher{}).Start(ctx, inv)
	})
	start := testStart()
	start.Input.Text = "Return only the fixed synthetic observation marker."
	frames, _, err := execute(t, ctx, start, config, launcher)
	if err != nil || ctx.Err() != nil {
		t.Fatal("native HRP did not terminate successfully before its deadline")
	}
	if len(frames) != 3 {
		t.Fatalf("expected readiness/start/terminal, got %d frames", len(frames))
	}
	if invalidStream {
		failed, ok := frames[2].(*runnerwire.RunFailed)
		if !ok || failed.Error.Code != runnerwire.ErrorCodeHarnessError {
			t.Fatalf("invalid stream did not fail before deadline; terminal type %T", frames[2])
		}
		terminal = "harness_error"
	} else {
		completed, ok := frames[2].(*runnerwire.RunCompleted)
		if !ok || completed.Output.Text != "HSG_PROVIDER_OBSERVED" {
			t.Fatalf("native completion missing; terminal type %T", frames[2])
		}
		terminal = "complete"
	}
	observer.close()
	observer.mu.Lock()
	responses, refreshes := observer.responses, observer.refreshes
	observations := append([]providerObservation(nil), observer.requests...)
	connects := append([]string(nil), observer.connects...)
	observer.mu.Unlock()
	if responses != 1 || (mode != "refresh" && refreshes != 0) || (mode == "refresh" && refreshes != 1) {
		t.Fatalf("operation counts responses=%d refreshes=%d", responses, refreshes)
	}
	if mode == "refresh" {
		data, err := os.ReadFile(filepath.Join(config.CodexHome, "auth.json"))
		var saved struct {
			Tokens struct {
				AccessToken string `json:"access_token"`
			} `json:"tokens"`
		}
		if err != nil || json.Unmarshal(data, &saved) != nil || saved.Tokens.AccessToken != nonce+"-refreshed" {
			t.Fatal("synthetic refresh was not persisted")
		}
	}
	if httpCandidate {
		for _, authority := range connects {
			if authority != "chatgpt.com:443" && !(mode == "refresh" && authority == "auth.openai.com:443") {
				t.Fatal("HTTPS candidate attempted another CONNECT destination")
			}
		}
		for _, request := range observations {
			if request.Upgrade != "" || request.Encoding != "" {
				t.Fatal("HTTPS candidate attempted an upgrade or compressed request")
			}
			switch {
			case request.Authority == "chatgpt.com" && request.Method == http.MethodPost && request.Path == "/backend-api/codex/responses":
				if request.Status != http.StatusOK || !request.InferenceTupleMatched || !request.SyntheticAccount ||
					!request.SyntheticBearer || request.RefreshedBearer != (mode == "refresh") || len(request.QueryKeys) != 0 {
					t.Fatal("HTTPS candidate inference or refreshed authentication mismatch")
				}
			case request.Authority == "chatgpt.com" && request.Method == http.MethodGet && request.Path == "/backend-api/codex/models":
				if request.Status != http.StatusOK || !request.SyntheticBearer || !request.SyntheticAccount {
					t.Fatal("HTTPS candidate synthetic catalog mismatch")
				}
			case request.Authority == "chatgpt.com" && request.Method == http.MethodGet && request.Path == "/backend-api/wham/settings/user":
				if request.Status != http.StatusNotFound {
					t.Fatal("HTTPS candidate unexpectedly accepted settings")
				}
			case request.Authority == "auth.openai.com" && request.Method == http.MethodPost && request.Path == "/oauth/token":
				if mode != "refresh" || request.Status != http.StatusOK {
					t.Fatal("HTTPS candidate refresh mismatch")
				}
			default:
				t.Fatal("HTTPS candidate attempted an unclassified operation")
			}
		}
	}
	assertIntegrationQuiescence(t)
}

func TestProviderObserverTLSAndRejection(t *testing.T) {
	observer := newProviderObserver(t, "unit-synthetic")
	proxy, _ := url.Parse(observer.server.URL)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(observer.ca) {
		t.Fatal("fixture CA")
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get("https://chatgpt.com/not-an-operation?synthetic=discarded")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatalf("synthetic response did not finish: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatal("unknown operation was accepted")
	}
	response, err = client.Post("https://auth.openai.com/oauth/token", "application/json",
		strings.NewReader(`{"grant_type":"refresh_token","refresh_token":"unit-synthetic-refresh"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !json.Valid(body) {
		t.Fatalf("synthetic refresh response did not finish: status=%d error=%v", response.StatusCode, err)
	}
	if _, err := client.Get("https://destination.invalid/"); err == nil {
		t.Fatal("unknown CONNECT authority was accepted")
	}
	observer.close()
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if len(observer.connections) != 0 || len(observer.requests) != 2 || len(observer.requests[0].QueryKeys) != 1 || observer.requests[0].QueryKeys[0] != "synthetic" || observer.stages["tls_ready"] != 2 || observer.refreshes != 1 {
		t.Fatal("observer cleanup or bounded metadata mismatch")
	}
}
