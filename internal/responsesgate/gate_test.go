package responsesgate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
)

const testBody = `{"model":"gpt-5.6-sol","reasoning":{"effort":"medium"},"stream":true,"input":[]}`
const testSSE = "data: {\"type\":\"response.completed\"}\n\n"

type pipeListener struct {
	queue chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{queue: make(chan net.Conn), done: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.queue:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *pipeListener) Addr() net.Addr { return pipeAddress{} }

type pipeAddress struct{}

func (pipeAddress) Network() string { return "pipe" }
func (pipeAddress) String() string  { return "hsg-fixture.test" }

func (l *pipeListener) dial() (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.queue <- server:
		return client, nil
	case <-l.done:
		_ = client.Close()
		_ = server.Close()
		return nil, net.ErrClosed
	}
}

type fixture struct {
	gate     *Gate
	listener *pipeListener
	served   chan struct{}
	err      error // Read only after served closes.
	cancel   context.CancelFunc
}

func newFixture(t *testing.T, responder Responder) *fixture {
	t.Helper()
	return fixtureWithDeadline(t, responder, time.Minute)
}

func fixtureWithDeadline(t *testing.T, responder Responder, duration time.Duration) *fixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	g, err := NewSynthetic(ctx, "hsg-fixture.test", responder)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	f := &fixture{gate: g, listener: newPipeListener(), served: make(chan struct{}), cancel: cancel}
	go func() { f.err = g.Serve(f.listener); close(f.served) }()
	t.Cleanup(func() {
		g.Stop()
		cancel()
		select {
		case <-f.served:
			if f.err != nil && !errors.Is(f.err, ErrClosed) {
				t.Errorf("Serve: %v", f.err)
			}
		case <-time.After(10 * time.Second):
			t.Error("owned consumer did not finish")
		}
	})
	return f
}

func (f *fixture) open(t *testing.T) {
	t.Helper()
	if err := f.gate.Open(); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) request(body string) string {
	return fmt.Sprintf("POST /v1/responses HTTP/1.1\r\nHost: hsg-fixture.test\r\nAuthorization: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		f.gate.SyntheticAuthorization(), len(body), body)
}

type exchange struct {
	status int
	header http.Header
	body   string
	err    error
}

func (f *fixture) exchange(raw string) exchange {
	conn, err := f.listener.dial()
	if err != nil {
		return exchange{err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	writeDone := make(chan struct{})
	go func() { _, _ = io.WriteString(conn, raw); close(writeDone) }()
	defer func() { _ = conn.Close(); <-writeDone }()
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return exchange{err: err}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxBodyBytes+1))
	return exchange{status: response.StatusCode, header: response.Header, body: string(body), err: err}
}

func sseResponse(body string) Response {
	return Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}},
		Body: io.NopCloser(strings.NewReader(body))}
}

func TestClosedOpenExchangeAndInferenceBudget(t *testing.T) {
	v3 := codexprofile.V3().Model
	if v3.Name != "gpt-5.6-sol" || v3.ReasoningEffort != "medium" {
		t.Fatal("synthetic policy must be revisited when V3 changes")
	}
	var calls atomic.Int32
	inputs := make(chan Request, 2)
	f := newFixture(t, func(_ context.Context, r Request) (Response, error) {
		calls.Add(1)
		inputs <- r
		response := sseResponse(testSSE)
		response.Header.Set("Set-Cookie", "private-response-sentinel")
		response.Header.Set("X-Internal", "private-response-sentinel")
		return response, nil
	})
	if got := f.exchange(f.request(testBody)); got.status != 503 || calls.Load() != 0 {
		t.Fatalf("closed consumer dispatched: status=%d calls=%d", got.status, calls.Load())
	}
	f.open(t)
	if !errors.Is(f.gate.Open(), ErrClosed) {
		t.Fatal("a second Open succeeded")
	}
	for _, body := range []string{testBody, testBody + strings.Repeat(" ", MaxBodyBytes-len(testBody))} {
		raw := strings.Replace(f.request(body), "Content-Type:", "Cookie: private-request-sentinel\r\nX-API-Key: private-request-sentinel\r\nContent-Type:", 1)
		got := f.exchange(raw)
		if got.err != nil || got.status != 200 || got.body != testSSE || got.header.Get("Set-Cookie") != "" || got.header.Get("X-Internal") != "" {
			t.Fatalf("exchange failed: status=%d err=%v", got.status, got.err)
		}
		input := <-inputs
		if string(input.Body) != body || !reflect.DeepEqual(input.Header, http.Header{
			"Content-Type": {"application/json"}, "Authorization": {f.gate.SyntheticAuthorization()},
		}) {
			t.Fatal("upstream request was not constructed from the verified envelope")
		}
	}
	if got := f.exchange(f.request(testBody)); got.status != 503 || calls.Load() != 2 {
		t.Fatalf("inference budget escaped: status=%d calls=%d", got.status, calls.Load())
	}
	f.gate.Stop()
	<-f.served
	if !errors.Is(f.gate.Open(), ErrClosed) {
		t.Fatal("stopped Run reopened")
	}
	next := newPipeListener()
	if !errors.Is(f.gate.Serve(next), ErrClosed) {
		t.Fatal("stopped Run served again")
	}
	if _, err := next.dial(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("rejected listener remained open")
	}
}

func TestInvalidInputCannotReachResponder(t *testing.T) {
	// These test the consumer boundary, not another implementation of HTTP
	// or the existing strictjson parser. Every rejection has a positive control.
	cases := []struct {
		name string
		edit func(*fixture) string
	}{
		{"other-operation", func(f *fixture) string { return strings.Replace(f.request(testBody), "/v1/responses", "/token", 1) }},
		{"connect", func(f *fixture) string { return strings.Replace(f.request(testBody), "POST", "CONNECT", 1) }},
		{"empty-query", func(f *fixture) string {
			return strings.Replace(f.request(testBody), "/v1/responses", "/v1/responses?", 1)
		}},
		{"escaped-path", func(f *fixture) string {
			return strings.Replace(f.request(testBody), "/v1/responses", "/v1/%72esponses", 1)
		}},
		{"absolute-form", func(f *fixture) string {
			return strings.Replace(f.request(testBody), "/v1/responses", "http://hsg-fixture.test/v1/responses", 1)
		}},
		{"other-authority", func(f *fixture) string {
			return strings.Replace(f.request(testBody), "Host: hsg-fixture.test", "Host: elsewhere.invalid", 1)
		}},
		{"wrong-bearer", func(f *fixture) string {
			return strings.Replace(f.request(testBody), f.gate.SyntheticAuthorization(), "Bearer wrong", 1)
		}},
		{"duplicate-bearer", func(f *fixture) string {
			return strings.Replace(f.request(testBody), "Authorization:", "Authorization: wrong\r\nauthorization:", 1)
		}},
		{"routing-header", func(f *fixture) string {
			return strings.Replace(f.request(testBody), "Content-Type:", "Forwarded: host=elsewhere.invalid\r\nContent-Type:", 1)
		}},
		{"upgrade", func(f *fixture) string {
			return strings.Replace(f.request(testBody), "Content-Type:", "Connection: Upgrade\r\nUpgrade: websocket\r\nContent-Type:", 1)
		}},
		{"compressed", func(f *fixture) string {
			return strings.Replace(f.request(testBody), "Content-Type:", "Content-Encoding: gzip\r\nContent-Type:", 1)
		}},
		{"chunked", func(f *fixture) string {
			return strings.Replace(f.request(testBody), "Content-Length:", "Transfer-Encoding: chunked\r\nContent-Length:", 1)
		}},
		{"conflicting-length", func(f *fixture) string {
			return strings.Replace(f.request(testBody), "Content-Length:", "Content-Length: 1\r\nContent-Length:", 1)
		}},
		{"oversize-header", func(f *fixture) string {
			return strings.Replace(f.request(testBody), "Content-Type:", "X-Padding: "+strings.Repeat("x", MaxHeaderBytes)+"\r\nContent-Type:", 1)
		}},
		{"oversize-body", func(f *fixture) string {
			return f.request(testBody + strings.Repeat(" ", MaxBodyBytes+1-len(testBody)))
		}},
		{"wrong-model", func(f *fixture) string { return f.request(strings.Replace(testBody, "gpt-5.6-sol", "unapproved", 1)) }},
		{"wrong-effort", func(f *fixture) string { return f.request(strings.Replace(testBody, "medium", "high", 1)) }},
		{"duplicate-field", func(f *fixture) string {
			return f.request(strings.Replace(testBody, `"model":`, `"model":"unapproved","model":`, 1))
		}},
		{"case-alias", func(f *fixture) string {
			return f.request(strings.Replace(testBody, `"model":`, `"Model":"unapproved","model":`, 1))
		}},
		{"effort-alias", func(f *fixture) string {
			return f.request(strings.Replace(testBody, `"effort":`, `"Effort":"high","effort":`, 1))
		}},
		{"no-stream", func(f *fixture) string {
			return f.request(strings.Replace(testBody, `"stream":true`, `"stream":false`, 1))
		}},
		{"trailing-json", func(f *fixture) string { return f.request(testBody + `{}`) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			f := newFixture(t, func(context.Context, Request) (Response, error) { calls.Add(1); return sseResponse(testSSE), nil })
			f.open(t)
			got := f.exchange(tc.edit(f))
			if got.status == 200 || calls.Load() != 0 || strings.Contains(got.body, f.gate.SyntheticAuthorization()) {
				t.Fatalf("rejection escaped: status=%d calls=%d", got.status, calls.Load())
			}
			if got := f.exchange(f.request(testBody)); got.err != nil || got.status != 200 || calls.Load() != 1 {
				t.Fatalf("positive control failed: status=%d err=%v calls=%d", got.status, got.err, calls.Load())
			}
		})
	}
}

func TestConnectionBudgetAndNoPipelining(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("malformed-%v", malformed), func(t *testing.T) {
			var calls atomic.Int32
			f := newFixture(t, func(context.Context, Request) (Response, error) { calls.Add(1); return sseResponse(testSSE), nil })
			f.open(t)
			for range 8 {
				raw := strings.Replace(f.request(testBody), f.gate.SyntheticAuthorization(), "Bearer wrong", 1)
				if malformed {
					raw = "BROKEN\r\n\r\n"
				}
				if got := f.exchange(raw); got.status == 200 {
					t.Fatal("bad request succeeded")
				}
			}
			if _, err := f.listener.dial(); !errors.Is(err, net.ErrClosed) {
				t.Fatal("ninth connection accepted")
			}
			if calls.Load() != 0 {
				t.Fatal("bad traffic dispatched")
			}
		})
	}
	t.Run("one-exchange", func(t *testing.T) {
		var calls atomic.Int32
		f := newFixture(t, func(context.Context, Request) (Response, error) { calls.Add(1); return sseResponse(testSSE), nil })
		f.open(t)
		got := f.exchange(f.request(testBody) + f.request(testBody))
		if got.err != nil || got.status != 200 || calls.Load() != 1 {
			t.Fatal("pipelined request was dispatched or first exchange failed")
		}
	})
}

func TestConcurrentAdmissionAndBearerIsolation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	f := newFixture(t, func(ctx context.Context, _ Request) (Response, error) {
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return sseResponse(testSSE), nil
	})
	f.open(t)
	first := make(chan exchange, 1)
	go func() { first <- f.exchange(f.request(testBody)) }()
	<-started
	if got := f.exchange(f.request(testBody)); got.status != 503 || calls.Load() != 1 {
		t.Fatal("parallel dispatch admitted")
	}
	close(release)
	if got := <-first; got.err != nil || got.status != 200 {
		t.Fatal("first exchange failed")
	}
	if got := f.exchange(f.request(testBody)); got.status != 200 || calls.Load() != 2 {
		t.Fatal("active slot did not release")
	}
	other := newFixture(t, func(context.Context, Request) (Response, error) { return sseResponse(testSSE), nil })
	other.open(t)
	if other.gate.SyntheticAuthorization() == f.gate.SyntheticAuthorization() {
		t.Fatal("bearer reused")
	}
	if got := other.exchange(f.request(testBody)); got.status == 200 {
		t.Fatal("prior Run bearer admitted")
	}
}

func TestResponseEnvelopeAndStreamingBound(t *testing.T) {
	cases := []struct {
		name       string
		make       func() (Response, error)
		wantStatus int
		wantAbort  bool
	}{
		{"redirect", func() (Response, error) {
			r := sseResponse(testSSE)
			r.StatusCode = 302
			r.Header.Set("Location", "https://elsewhere.invalid/private")
			return r, nil
		}, 502, false},
		{"encoding", func() (Response, error) {
			r := sseResponse(testSSE)
			r.Header.Set("Content-Encoding", "gzip")
			return r, nil
		}, 502, false},
		{"upgrade", func() (Response, error) { r := sseResponse(testSSE); r.StatusCode = 101; return r, nil }, 502, false},
		{"type-alias", func() (Response, error) {
			r := sseResponse(testSSE)
			r.Header["content-type"] = []string{"application/json"}
			return r, nil
		}, 502, false},
		{"private-error", func() (Response, error) { return sseResponse("private-sentinel"), errors.New("private-sentinel") }, 502, false},
		{"exact-bound", func() (Response, error) { return sseResponse(strings.Repeat("x", MaxBodyBytes)), nil }, 200, false},
		{"over-bound", func() (Response, error) { return sseResponse(strings.Repeat("x", MaxBodyBytes+1)), nil }, 200, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			f := newFixture(t, func(context.Context, Request) (Response, error) { calls.Add(1); return tc.make() })
			f.open(t)
			got := f.exchange(f.request(testBody))
			if got.status != tc.wantStatus || (got.err != nil) != tc.wantAbort || len(got.body) > MaxBodyBytes || strings.Contains(got.body, "private-sentinel") || calls.Load() != 1 {
				t.Fatalf("response boundary: status=%d err=%v size=%d calls=%d", got.status, got.err, len(got.body), calls.Load())
			}
			if tc.name == "private-error" {
				if got := f.exchange(f.request(testBody)); got.status != 502 {
					t.Fatal("second failed dispatch changed behavior")
				}
				if got := f.exchange(f.request(testBody)); got.status != 503 || calls.Load() != 2 {
					t.Fatal("failed dispatch budget was refunded")
				}
			}
		})
	}
}
