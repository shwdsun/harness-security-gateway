package codexprovider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type probeDeadlineConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *probeDeadlineConn) SetReadDeadline(deadline time.Time) error {
	err := c.Conn.SetReadDeadline(deadline)
	c.once.Do(func() { close(c.started) })
	return err
}

func rawResponseEndpoint(t *testing.T, ctx context.Context, serve func(net.Conn)) (*Endpoint, *http.Client, *atomic.Int32, <-chan struct{}) {
	t.Helper()
	cert, ca, err := newCertificate()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	calls := new(atomic.Int32)
	probeStarted := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.Host != "chatgpt.com" || r.URL.RequestURI() != "/backend-api/codex/responses" {
			t.Error("unexpected upstream route")
		}
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(deadline(ctx, 4*time.Second))
		serve(conn)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	e, client := testEndpoint(t, ctx, func(ctx context.Context, request Request) (Response, error) {
		return upstreamResponse(ctx, request, func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "chatgpt.com:443" {
				t.Error("unexpected upstream dial")
			}
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			if err != nil {
				return nil, err
			}
			return &probeDeadlineConn{Conn: conn, started: probeStarted}, nil
		}, roots)
	})
	if e.Open() != nil {
		t.Fatal("open")
	}
	return e, client, calls, probeStarted
}

func TestRejectedResponseMetadataAndPrefix(t *testing.T) {
	wire := func(headers, body string) string {
		return fmt.Sprintf("HTTP/1.1 200 OK\r\n%sContent-Length: %d\r\n\r\n%s", headers, len(body), body)
	}
	for _, row := range []struct {
		name, wire, contentType, framing, length, prefix, end string
	}{
		{"empty-sse", wire("Content-Type:\r\n", "data: "+diagnosticSecret+"\n\n"), "empty", "fixed", "positive", "event_stream_like", "eof"},
		{"empty-json", wire("Content-Type: \t\r\n", `{"secret":"`+diagnosticSecret+`"}`), "empty", "fixed", "positive", "json_like", "eof"},
		{"multiple-first-empty", wire("Content-Type:\r\nContent-Type: text/event-stream\r\n", "data: x\n\n"), "multiple_first_empty", "fixed", "positive", "event_stream_like", "eof"},
		{"empty-body", wire("Content-Type:\r\n", ""), "empty", "fixed", "zero", "empty", "eof"},
		{"chunked", "HTTP/1.1 200 OK\r\nContent-Type:\r\nTransfer-Encoding: chunked\r\n\r\n8\r\ndata: x\n\r\n1\r\n\n\r\n0\r\n\r\n", "empty", "chunked", "unknown", "event_stream_like", "eof"},
		{"close-delimited", "HTTP/1.1 200 OK\r\nContent-Type:\r\nConnection: close\r\n\r\n<!DOCTYPE HTML>" + diagnosticSecret, "empty", "close_delimited", "unknown", "html_like", "eof"},
		{"bounded", wire("Content-Type: invalid; secret="+diagnosticSecret+"; broken\r\n", strings.Repeat("x", 1024)), "single", "fixed", "positive", "other", "limit"},
		{"wrong-media", wire("Content-Type: application/json\r\n", "\xef\xbb\xbf \n{}"), "single", "fixed", "positive", "json_like", "eof"},
		{"whitespace", wire("Content-Type:\r\n", " \t\n"), "empty", "fixed", "positive", "whitespace", "eof"},
		{"truncated", "HTTP/1.1 200 OK\r\nContent-Type:\r\nContent-Length: 100\r\n\r\ndata: short", "empty", "fixed", "positive", "event_stream_like", "read_error"},
		{"encoding-no-sample", wire("Content-Encoding: gzip\r\n", diagnosticSecret), "absent", "fixed", "positive", "", ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			e, client, calls, _ := rawResponseEndpoint(t, ctx, func(conn net.Conn) { _, _ = io.WriteString(conn, row.wire) })
			status, body, err := testInference(ctx, client)
			if err != nil || status != 502 || string(body) != "request denied\n" {
				t.Fatal("diagnostics changed response rejection")
			}
			waitEndpointExchanges(t, ctx, e, 1)
			d := e.Diagnostics().Exchanges[0]
			if d.ResponseProtocol != "http_1_1" || d.ContentTypeState != row.contentType || d.ResponseFraming != row.framing || d.DeclaredBody != row.length || d.BodyPrefix != row.prefix || d.BodyProbeEnd != row.end || d.Stage != "upstream_policy" || !d.Finished || d.Cancelled || calls.Load() != 1 {
				t.Fatalf("response evidence: %+v", d)
			}
			encoded, _ := json.Marshal(d)
			if strings.Contains(string(encoded), diagnosticSecret) {
				t.Fatal("response value escaped into diagnostics")
			}
			bounded := Diagnostics{Exchanges: make([]ExchangeDiagnostic, MaxConnections)}
			for i := range bounded.Exchanges {
				bounded.Exchanges[i] = d
			}
			encoded, _ = json.Marshal(bounded)
			if len(encoded) > 8<<10 {
				t.Fatal("response diagnostics exceeded the endpoint output budget")
			}
			status, _, err = testInference(ctx, client)
			if err != nil || status != 503 || calls.Load() != 1 {
				t.Fatal("diagnostic observation allowed a new upstream call")
			}
			waitEndpointExchanges(t, ctx, e, 2)
			checkLocalRejection(t, e.Diagnostics().Exchanges[1], d.Reason)
		})
	}
}

func TestRejectedBodyProbeIsBoundedAndJoined(t *testing.T) {
	for _, mode := range []string{"deadline", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			peerClosed := make(chan struct{})
			e, client, calls, probeStarted := rawResponseEndpoint(t, ctx, func(conn net.Conn) {
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type:\r\nContent-Length: 1024\r\n\r\ndata: "+diagnosticSecret)
				var buffer [1]byte
				_, _ = conn.Read(buffer[:])
				close(peerClosed)
			})
			finished := make(chan int, 1)
			started := time.Now()
			go func() { status, _, _ := testInference(ctx, client); finished <- status }()
			// Observe the real socket's diagnostic deadline, without substituting
			// a body reader. The first worker remains held in its short probe.
			select {
			case <-probeStarted:
			case <-ctx.Done():
				t.Fatal("probe did not start")
			}
			select {
			case <-finished:
				t.Fatal("stalled body was not observed before the next request")
			default:
			}
			status, _, err := testInference(ctx, client)
			if err != nil || status != 503 || calls.Load() != 1 {
				t.Fatal("stalled diagnostics delayed operation rejection")
			}
			for !e.Diagnostics().Exchanges[1].Finished {
				if ctx.Err() != nil {
					t.Fatal("local denial did not finish")
				}
				time.Sleep(time.Millisecond)
			}
			if mode == "cancel" {
				e.Stop()
			}
			select {
			case status := <-finished:
				if mode == "deadline" && status != 502 {
					t.Fatal("bounded probe changed rejection status")
				}
			case <-ctx.Done():
				t.Fatal("probe did not finish")
			}
			if time.Since(started) > 2*time.Second {
				t.Fatal("diagnostic exceeded its one-second bound plus test allowance")
			}
			waitEndpointExchanges(t, ctx, e, 2)
			if e.Close(ctx) != nil {
				t.Fatal("probe cleanup failed")
			}
			select {
			case <-peerClosed:
			case <-ctx.Done():
				t.Fatal("upstream socket survived joined cleanup")
			}
			d := e.Diagnostics()
			wantEnd := "timeout"
			if mode == "cancel" {
				wantEnd = "cancelled"
			}
			if !d.Joined || d.CleanupFailed || (mode == "deadline" && d.Exchanges[0].BodyPrefix != "event_stream_like") || d.Exchanges[0].BodyProbeEnd != wantEnd || d.Exchanges[0].Cancelled != (mode == "cancel") {
				t.Fatalf("probe completion: %+v", d)
			}
			checkLocalRejection(t, d.Exchanges[1], "content_type_missing")
		})
	}
}
