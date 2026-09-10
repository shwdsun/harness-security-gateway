package codexprovider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
)

func testEndpoint(t *testing.T, ctx context.Context, respond responder, cleanupError ...error) (*Endpoint, *http.Client) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("concrete non-root peer required")
	}
	dir, err := os.MkdirTemp(t.TempDir(), "owner-")
	if err != nil {
		t.Fatal(err)
	}
	e, err := newEndpoint(ctx, dir, localidentity.UID(os.Geteuid()), respond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var expected error
		if len(cleanupError) != 0 {
			expected = cleanupError[0]
		}
		if err := e.Close(c); !errors.Is(err, expected) {
			t.Error(err)
		}
	})
	ca, err := os.ReadFile(e.ca)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("CA")
	}
	proxy, _ := url.Parse("http://fixed.invalid")
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableCompression: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", e.socket)
		}}
	t.Cleanup(transport.CloseIdleConnections)
	return e, &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func testInference(ctx context.Context, client *http.Client) (int, []byte, error) {
	r, _ := http.NewRequestWithContext(ctx, "POST", "https://chatgpt.com/backend-api/codex/responses", strings.NewReader(inferenceBody))
	r.Header.Set("Authorization", "Bearer synthetic-only")
	r.Header.Set("Chatgpt-Account-Id", "synthetic-account")
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return response.StatusCode, body, err
}

func TestEndpointAdmissionAndTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var calls atomic.Int32
	e, client := testEndpoint(t, ctx, func(_ context.Context, r Request) (Response, error) {
		calls.Add(1)
		if r.Operation != Inference {
			return Response{}, ErrDenied
		}
		return Response{200, "text/event-stream", io.NopCloser(strings.NewReader("data: synthetic\n\n"))}, nil
	})
	if _, _, err := testInference(ctx, client); err == nil || calls.Load() != 0 {
		t.Fatal("closed endpoint dispatched")
	}
	if e.Open() != nil || e.Open() == nil {
		t.Fatal("one-use open")
	}
	status, body, err := testInference(ctx, client)
	if err != nil || status != 200 || string(body) != "data: synthetic\n\n" || calls.Load() != 1 {
		t.Fatalf("TLS progress status=%d calls=%d err=%v", status, calls.Load(), err)
	}
	if e.Close(ctx) != nil {
		t.Fatal("join")
	}
	if _, _, err := testInference(ctx, client); err == nil || e.Open() == nil || calls.Load() != 1 {
		t.Fatal("closed endpoint reused")
	}
}

type truncatedBody struct{ sent bool }

func (b *truncatedBody) Read(p []byte) (int, error) {
	if b.sent {
		return 0, io.ErrUnexpectedEOF
	}
	b.sent = true
	return copy(p, "partial"), nil
}
func (*truncatedBody) Close() error { return nil }

func TestEndpointStreamingBoundary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e, client := testEndpoint(t, ctx, func(context.Context, Request) (Response, error) {
		return Response{200, "text/event-stream", &truncatedBody{}}, nil
	})
	if e.Open() != nil {
		t.Fatal("open")
	}
	status, body, err := testInference(ctx, client)
	if status != 200 || string(body) != "partial" || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated producer became a complete HTTP response: %d %q %v", status, body, err)
	}
}

type heldBody struct {
	entered, closeEntered, release chan struct{}
	readOnce, closeOnce            sync.Once
}

func (b *heldBody) Read([]byte) (int, error) {
	b.readOnce.Do(func() { close(b.entered) })
	<-b.release
	return 0, io.EOF
}
func (b *heldBody) Close() error {
	b.closeOnce.Do(func() { close(b.closeEntered) })
	<-b.release
	return nil
}

func TestEndpointCloseWaitsForBodyOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body := &heldBody{make(chan struct{}), make(chan struct{}), make(chan struct{}), sync.Once{}, sync.Once{}}
	var release sync.Once
	defer release.Do(func() { close(body.release) })
	e, client := testEndpoint(t, ctx, func(context.Context, Request) (Response, error) { return Response{200, "text/event-stream", body}, nil })
	if e.Open() != nil {
		t.Fatal("open")
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _, _ = testInference(ctx, client) }()
	select {
	case <-body.entered:
	case <-ctx.Done():
		t.Fatal("no active body")
	}
	short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := e.Close(short)
	stop()
	if !errors.Is(err, ErrCleanup) {
		t.Fatal("unjoined close passed")
	}
	if d := e.Diagnostics(); d.Joined || !d.Stopped || len(d.Exchanges) != 1 || d.Exchanges[0].Finished {
		t.Fatal("diagnostics hid an unjoined body owner")
	}
	select {
	case <-e.Done():
		t.Fatal("producer still held")
	default:
	}
	select {
	case <-body.closeEntered:
	case <-ctx.Done():
		t.Fatal("Close did not cancel body")
	}
	release.Do(func() { close(body.release) })
	if e.Close(ctx) != nil {
		t.Fatal("joined retry failed")
	}
	<-done
	d := e.Diagnostics()
	if !d.Joined || !d.Exchanges[0].Finished || !d.Exchanges[0].Cancelled || d.Exchanges[0].Stage == "complete" {
		t.Fatal("cancelled exchange reported completion")
	}
}

func TestUpstreamHasNoRedirectOrRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cert, ca, err := newCertificate()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var calls atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Host != "chatgpt.com" || r.URL.RequestURI() != "/backend-api/codex/responses" {
			t.Error("upstream route changed")
		}
		w.Header().Set("Location", "https://elsewhere.invalid/")
		w.WriteHeader(302)
	}), ReadHeaderTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() { server.Close(); <-done }()
	var dials atomic.Int32
	response, err := upstreamResponse(ctx, Request{Inference, http.Header{"Content-Type": {"application/json"}}, []byte(inferenceBody)}, func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if network != "tcp" || address != "chatgpt.com:443" {
			t.Error("request-selected upstream")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}, roots)
	if response.Body != nil {
		response.Body.Close()
	}
	if !errors.Is(err, ErrUpstream) || calls.Load() != 1 || dials.Load() != 1 {
		t.Fatalf("redirect/retry: %v calls=%d dials=%d", err, calls.Load(), dials.Load())
	}
}
