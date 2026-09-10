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
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the actual HTTP parser and TLS dialer through the endpoint. Raw
// responses avoid net/http silently adding Content-Type or changing framing.
func TestUpstreamResponsePolicyClassification(t *testing.T) {
	body := "data: " + diagnosticSecret + "\n\n"
	wire := func(status int, headers string) string {
		return fmt.Sprintf("HTTP/1.1 %d %s\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), headers, len(body), body)
	}
	for _, row := range []struct {
		name, response, stage, reason, media string
		operation                            Operation
		upstreamStatus, clientStatus         int
	}{
		{"upgrade", "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + diagnosticSecret + "\r\n\r\n", "upstream_policy", "protocol_upgrade", "", Inference, 101, 502},
		{"encoding", wire(200, "Content-Encoding: gzip\r\nContent-Type: text/event-stream\r\n"), "upstream_policy", "content_encoding", "", Inference, 200, 502},
		{"identity-encoding", wire(200, "Content-Encoding: identity\r\nContent-Type: text/event-stream\r\n"), "upstream_policy", "content_encoding", "", Inference, 200, 502},
		{"location-on-200", wire(200, "Location: https://"+diagnosticSecret+".invalid/\r\n"), "upstream_policy", "location", "", Inference, 200, 502},
		{"redirect", wire(302, "Location: https://"+diagnosticSecret+".invalid/\r\n"), "upstream_policy", "location", "", Inference, 302, 502},
		{"trailer", "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nTrailer: X-Result\r\n\r\n1\r\nx\r\n0\r\nX-Result: " + diagnosticSecret + "\r\n\r\n", "upstream_policy", "trailer", "", Inference, 200, 502},
		{"missing-type", wire(200, ""), "upstream_policy", "content_type_missing", "", Inference, 200, 502},
		{"invalid-type", wire(200, "Content-Type: text/plain; "+diagnosticSecret+"\r\n"), "upstream_policy", "content_type_invalid", "", Inference, 200, 502},
		{"inference-json", wire(200, "Content-Type: application/json\r\n"), "upstream_policy", "media_type_mismatch", "json", Inference, 200, 502},
		{"inference-html", wire(200, "Content-Type: text/html\r\n"), "upstream_policy", "media_type_mismatch", "html", Inference, 200, 502},
		{"unknown-type", wire(200, "Content-Type: application/x-"+diagnosticSecret+"\r\n"), "upstream_policy", "media_type_mismatch", "other", Inference, 200, 502},
		{"catalog-sse", wire(200, "Content-Type: text/event-stream\r\n"), "upstream_policy", "media_type_mismatch", "event_stream", Catalog, 200, 502},
		{"sse-parameters", wire(200, "Content-Type: Text/Event-Stream; note=\""+diagnosticSecret+"\"\r\n"), "complete", "", "event_stream", Inference, 200, 200},
		{"catalog-json", wire(200, "Content-Type: application/json\r\n"), "complete", "", "json", Catalog, 200, 200},
		{"unauthorized-missing-type", wire(401, ""), "upstream_status", "", "", Inference, 401, 401},
		{"limited-invalid-type", wire(429, "Content-Type: text/plain; "+diagnosticSecret+"\r\n"), "upstream_status", "", "", Inference, 429, 429},
		{"server-failure", wire(500, ""), "upstream_status", "", "", Inference, 500, 502},
		{"malformed-headers", diagnosticSecret + "\r\n\r\n", "upstream_headers", "", "", Inference, 0, 502},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cert, ca, err := newCertificate()
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(ca) {
				t.Fatal("CA")
			}
			var calls, dials atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				method, host, path := route(row.operation)
				if r.Method != method || r.Host != host || r.URL.RequestURI() != path {
					t.Error("fixed route changed")
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = io.WriteString(conn, row.response)
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			server.StartTLS()
			defer server.Close()
			e, client := testEndpoint(t, ctx, func(ctx context.Context, request Request) (Response, error) {
				return upstreamResponse(ctx, request, func(ctx context.Context, network, address string) (net.Conn, error) {
					dials.Add(1)
					if network != "tcp" || address != "chatgpt.com:443" {
						t.Error("unexpected destination")
					}
					return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
				}, roots)
			})
			if e.Open() != nil {
				t.Fatal("open")
			}
			method, host, path := route(row.operation)
			var input io.Reader
			if row.operation == Inference {
				input = strings.NewReader(inferenceBody)
			}
			r, err := http.NewRequestWithContext(ctx, method, "https://"+host+path, input)
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Authorization", "Bearer "+diagnosticSecret)
			r.Header.Set("Chatgpt-Account-Id", diagnosticSecret)
			if input != nil {
				r.Header.Set("Content-Type", "application/json")
			}
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			data, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != row.clientStatus || readErr != nil {
				t.Fatalf("client status=%d error=%v", response.StatusCode, readErr)
			}
			wantBody := "request denied\n"
			if row.clientStatus == 200 {
				wantBody = body
			}
			if string(data) != wantBody {
				t.Fatal("response content or fixed error changed")
			}
			waitEndpointExchanges(t, ctx, e, 1)
			if e.Close(ctx) != nil {
				t.Fatal("join")
			}
			d := e.Diagnostics()
			if len(d.Exchanges) != 1 || calls.Load() != 1 || dials.Load() != 1 || !d.Joined || d.CleanupFailed {
				t.Fatalf("unexpected exchange count/cleanup: %+v", d)
			}
			got := d.Exchanges[0]
			if got.Stage != row.stage || got.Reason != row.reason || got.MediaClass != row.media || got.UpstreamStatus != row.upstreamStatus || !got.UpstreamAuthorized || !got.Finished || got.Cancelled {
				t.Fatalf("response classification: %+v", got)
			}
			encoded, err := json.Marshal(d)
			if err != nil || len(encoded) > 8<<10 || strings.Contains(strings.ToLower(string(encoded)), strings.ToLower(diagnosticSecret)) {
				t.Fatal("unsafe/unbounded diagnostic")
			}
		})
	}
}
