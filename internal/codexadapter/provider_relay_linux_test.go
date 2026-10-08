//go:build linux && codexintegration

package codexadapter

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/providerfixture"
	"github.com/shwdsun/harness-security-gateway/internal/providerrelay"
	"github.com/shwdsun/harness-security-gateway/internal/responsesgate"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

const relayInference = `{"model":"gpt-5.6-sol","reasoning":{"effort":"medium"},"stream":true}`
const relayRefresh = `{"grant_type":"refresh_token","refresh_token":"hsg-controller-synthetic-refresh","client_id":"app_EMoamEEZ73f0CkXaXp7hrann"}`

func relayOwnerListener(t *testing.T, root string) net.Listener {
	t.Helper()
	uid := localidentity.UID(os.Geteuid())
	if uid.Validate() != nil {
		t.Skip("requires a concrete non-root Unix peer UID")
	}
	listener, err := localhttp.Listen(filepath.Join(root, "owner.sock"), uid)
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func relayTLSClient(t *testing.T, ctx context.Context, root string, ca []byte) (*http.Client, *providerrelay.Relay) {
	t.Helper()
	relay, err := providerrelay.Start(ctx, filepath.Join(root, "owner.sock"), localidentity.UID(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relay.Close() })
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("fixture CA invalid")
	}
	proxy, _ := url.Parse("http://" + relay.Address())
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		DisableCompression: true, TLSHandshakeTimeout: 2 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, relay
}

func relayRequest(ctx context.Context, client *http.Client, refresh bool, body string) (int, []byte, error) {
	endpoint := "https://chatgpt.com/backend-api/codex/responses"
	if refresh {
		endpoint = "https://auth.openai.com/oauth/token"
	}
	request, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if !refresh {
		request.Header.Set("Authorization", "Bearer "+providerfixture.Nonce+"-refreshed")
		request.Header.Set("ChatGPT-Account-ID", "hsg-synthetic-account")
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, responsesgate.MaxBodyBytes+1))
	if len(data) > responsesgate.MaxBodyBytes {
		return 0, nil, errors.New("fixture response exceeded bound")
	}
	return response.StatusCode, data, err
}

func TestProviderRelayHTTPS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	root := t.TempDir()
	dispatches := 0
	ops := newProviderCompositionOps(t, ctx, providerfixture.Nonce, func(_ context.Context, request responsesgate.Request) (responsesgate.Response, error) {
		dispatches++ // The Gate serializes dispatches; inspect only after joined close.
		if !bytes.Equal(request.Body, []byte(relayInference)) || len(request.Header) != 2 {
			return responsesgate.Response{}, errors.New("operation projection changed")
		}
		return responsesgate.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}},
			Body: io.NopCloser(strings.NewReader("data: fixed-owner-response\n\n"))}, nil
	})
	observer := newProviderObserverOnListener(t, providerfixture.Nonce, ops.respond, relayOwnerListener(t, root))
	client, relay := relayTLSClient(t, ctx, root, observer.ca)
	status, data, err := relayRequest(ctx, client, true, relayRefresh)
	var refreshed map[string]any
	if err != nil || status != 200 || json.Unmarshal(data, &refreshed) != nil || refreshed["access_token"] != providerfixture.Nonce+"-refreshed" {
		t.Fatal("synthetic refresh did not cross the fixed TLS channel")
	}
	status, data, err = relayRequest(ctx, client, false, relayInference)
	if err != nil || status != 200 || string(data) != "data: fixed-owner-response\n\n" {
		t.Fatal("inference did not reach the owner policy/consumer")
	}
	status, _, err = relayRequest(ctx, client, false, strings.Replace(relayInference, "medium", "high", 1))
	if err != nil || status == 200 {
		t.Fatal("relay bypassed the owner policy")
	}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	observer.close()
	ops.close()
	if dispatches != 1 {
		t.Fatal("invalid operation reached the responder")
	}
	t.Log("fixed Unix relay: TLS refresh/inference succeeded; changed effort rejected before dispatch; cleanup joined")
}

type relayOwnerWitness struct{ PID int }

func relayWriteWitness(t *testing.T, path string) {
	t.Helper()
	data, _ := json.Marshal(relayOwnerWitness{PID: os.Getpid()})
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal("fresh owner witness unavailable")
	}
	_, writeErr := file.Write(data)
	if closeErr := file.Close(); writeErr != nil || closeErr != nil {
		t.Fatal("owner witness write failed")
	}
}

// A separately owned synthetic process, never an external service or provider.
func TestProviderRelayOwnerProcess(t *testing.T) {
	root := os.Getenv("HSG_PROVIDER_RELAY_OWNER_ROOT")
	if root == "" {
		t.Skip("exact subprocess fixture only")
	}
	info, err := os.Lstat(root)
	if err != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatal("private owner root required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ops := newProviderCompositionOps(t, ctx, providerfixture.Nonce, func(ctx context.Context, _ responsesgate.Request) (responsesgate.Response, error) {
		relayWriteWitness(t, filepath.Join(root, "active.json"))
		<-ctx.Done()
		return responsesgate.Response{}, ctx.Err()
	})
	observer := newProviderObserverOnListener(t, providerfixture.Nonce, ops.respond, relayOwnerListener(t, root))
	if os.WriteFile(filepath.Join(root, "ca.pem"), observer.ca, 0o600) != nil {
		t.Fatal("fixture CA write failed")
	}
	relayWriteWitness(t, filepath.Join(root, "ready.json"))
	<-ctx.Done()
	t.Fatal("the parent did not reach its owned crash point")
}

func awaitRelayOwner(t *testing.T, ctx context.Context, path string, pid int, exited <-chan struct{}) {
	t.Helper()
	for {
		data, err := os.ReadFile(path)
		var witness relayOwnerWitness
		if err == nil && strictjson.Decode(data, 1024, 2, &witness) == nil {
			if witness.PID != pid {
				t.Fatal("witness did not identify the exact child")
			}
			return
		}
		select {
		case <-exited:
			t.Fatal("owner exited before its witness")
		case <-ctx.Done():
			t.Fatal("owner witness not reached")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestProviderRelayOwnerLoss(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	// testing.TempDir's numbered leaf follows umask; this owner fixture
	// deliberately requires a fresh 0700 root regardless of that setting.
	root, err := os.MkdirTemp(t.TempDir(), "owner-")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("owner-root mode=%04o", info.Mode().Perm())
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(root, "owner.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command := exec.Command(self, "-test.run=^TestProviderRelayOwnerProcess$", "-test.timeout=25s")
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C.UTF-8", "HSG_PROVIDER_RELAY_OWNER_ROOT=" + root}
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = command.Wait(); close(done) }()
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			_ = command.Process.Kill()
			<-done
		}
		if t.Failed() {
			if data, err := os.ReadFile(filepath.Join(root, "owner.log")); err == nil && len(data) < 8192 {
				t.Logf("synthetic owner diagnostic: %s", data)
			}
		}
	})
	awaitRelayOwner(t, ctx, filepath.Join(root, "ready.json"), command.Process.Pid, done)
	ca, err := os.ReadFile(filepath.Join(root, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	client, relay := relayTLSClient(t, ctx, root, ca)
	status, _, err := relayRequest(ctx, client, true, relayRefresh)
	if err != nil || status != 200 {
		t.Fatal("owner was not serving synthetic refresh")
	}
	requestDone := make(chan error, 1)
	go func() {
		_, _, err := relayRequest(ctx, client, false, relayInference)
		requestDone <- err
	}()
	awaitRelayOwner(t, ctx, filepath.Join(root, "active.json"), command.Process.Pid, done)
	// PID comes only from exec.Cmd, with a matching child witness, and is
	// unreaped at this live dispatch point. No PID/name search authorizes kill.
	started := time.Now()
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-done
	var exited *exec.ExitError
	if !errors.As(waitErr, &exited) || exited.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatal("owned process did not die from the injected signal")
	}
	select {
	case err := <-requestDone:
		var timeout net.Error
		if err == nil || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("owner loss fabricated completion or only hit a request timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active TLS exchange survived the endpoint owner")
	}
	if _, err := os.Lstat(filepath.Join(root, "owner.sock")); err != nil {
		t.Fatal("crash evidence socket unexpectedly replaced/removed")
	}
	// A new connection still targets the old pinned object and must fail;
	// neither a caller retry nor a stale pathname starts another owner.
	// The earlier refresh can leave a pooled TLS tunnel. Its EOF alone does
	// not exercise a new Unix dial or require the relay to stop with ErrEndpoint.
	client.CloseIdleConnections()
	_, _, err = relayRequest(ctx, client, true, relayRefresh)
	var timeout net.Error
	if err == nil || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatalf("new request to dead owner did not fail promptly: %v", err)
	}
	relayDone := make(chan error, 1)
	go func() { relayDone <- relay.Wait() }()
	select {
	case err := <-relayDone:
		if !errors.Is(err, providerrelay.ErrEndpoint) {
			t.Fatalf("new dial to dead owner lost endpoint failure: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not join after the failed new owner dial")
	}
	t.Logf("owned SIGKILL: active TLS request failed without timeout; fixed endpoint refused reuse; relay joined; elapsed=%s", time.Since(started))
}
