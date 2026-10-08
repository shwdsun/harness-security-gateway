package codexprovider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const diagnosticSecret = "PRIVATE-SENTINEL-DO-NOT-EXPORT"

type diagnosticCloseFailure struct{ io.Reader }

func (diagnosticCloseFailure) Close() error { return errors.New(diagnosticSecret) }

func TestDiagnosticOutcomes(t *testing.T) {
	for _, row := range []struct {
		name, stage, reason, media string
		status                     int
	}{
		{"success", "complete", "", "event_stream", 200},
		{"unauthorized", "upstream_status", "", "", 401},
		{"forbidden", "upstream_status", "", "", 403},
		{"limited", "upstream_status", "", "", 429},
		{"transport", "upstream", "", "", 0},
		{"dial", "upstream_dial", "", "", 0},
		{"redirect", "upstream_policy", "location", "", 302},
		{"cleanup", "complete", "", "event_stream", 200},
		{"media", "upstream_policy", "media_type_mismatch", "other", 200},
		{"truncated", "response_read", "", "event_stream", 200},
		{"budget", "response_budget", "", "event_stream", 200},
		{"policy", "request_policy", "", "", 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var calls atomic.Int32
			var cleanupError error
			if row.name == "cleanup" {
				cleanupError = ErrCleanup
			}
			e, client := testEndpoint(t, ctx, func(context.Context, Request) (Response, error) {
				calls.Add(1)
				if row.name == "transport" {
					return Response{}, errors.New(diagnosticSecret)
				}
				if row.name == "dial" || row.name == "redirect" {
					failure := upstreamFailure{stage: row.stage, status: row.status}
					if row.name == "redirect" {
						failure.rejection = rejectionLocation
					}
					return Response{}, failure
				}
				response := Response{Status: row.status, MediaType: "text/event-stream", Body: io.NopCloser(strings.NewReader(diagnosticSecret))}
				switch row.name {
				case "media":
					response.MediaType = diagnosticSecret
				case "truncated":
					response.Body = &truncatedBody{}
				case "budget":
					response.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", MaxBodyBytes+1)))
				case "cleanup":
					response.Body = diagnosticCloseFailure{strings.NewReader(diagnosticSecret)}
				}
				return response, nil
			}, cleanupError)
			if e.Open() != nil {
				t.Fatal("open")
			}
			body := strings.TrimSuffix(inferenceBody, "}") + `,"input":"` + diagnosticSecret + `"}`
			r, _ := http.NewRequestWithContext(ctx, "POST", "https://chatgpt.com/backend-api/codex/responses", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+diagnosticSecret)
			r.Header.Set("Chatgpt-Account-Id", diagnosticSecret)
			r.Header.Set("Content-Type", "application/json")
			if row.name == "policy" {
				r.URL.RawQuery = "secret=" + diagnosticSecret
			}
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			_, readErr := io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if (row.name == "truncated" || row.name == "budget") && readErr == nil {
				t.Fatal("diagnostics changed truncation into success")
			}
			// Join completed exchanges before stopping admission: ordinary local
			// teardown must not label a successful exchange as cancelled.
			waitEndpointExchanges(t, ctx, e, 1)
			if !errors.Is(e.Close(ctx), cleanupError) {
				t.Fatal("close")
			}
			d := e.Diagnostics()
			if !d.Opened || !d.Stopped || !d.Joined || d.CleanupFailed != (cleanupError != nil) || len(d.Exchanges) != 1 {
				t.Fatalf("endpoint metadata: %+v", d)
			}
			got := d.Exchanges[0]
			op, wantCalls := "inference", int32(1)
			if row.name == "policy" {
				op, wantCalls = "unknown", 0
			}
			if got.Stage != row.stage || got.UpstreamStatus != row.status || got.Operation != op || !got.Finished || got.Cancelled || calls.Load() != wantCalls {
				t.Fatalf("outcome: %+v, calls=%d", got, calls.Load())
			}
			if got.Reason != row.reason || got.MediaClass != row.media || got.UpstreamAuthorized != (wantCalls == 1) {
				t.Fatalf("response classification/authorization: %+v", got)
			}
			data, err := json.Marshal(d)
			if err != nil || strings.Contains(string(data), diagnosticSecret) || strings.Contains(string(data), "chatgpt.com") || strings.Contains(string(data), "backend-api") || len(data) > 8<<10 {
				t.Fatal("unsafe or unbounded diagnostic")
			}
			d.Exchanges[0].Stage = diagnosticSecret
			if e.Diagnostics().Exchanges[0].Stage != row.stage {
				t.Fatal("snapshot aliases endpoint state")
			}
		})
	}
}

func TestDiagnosticBound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e, client := testEndpoint(t, ctx, func(context.Context, Request) (Response, error) {
		t.Error("local settings reached upstream")
		return Response{}, ErrDenied
	})
	if e.Open() != nil {
		t.Fatal("open")
	}
	for range MaxConnections {
		r, _ := http.NewRequestWithContext(ctx, "GET", "https://chatgpt.com/backend-api/wham/settings/user", nil)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatal("local settings changed")
		}
	}
	select {
	case <-e.Done():
	case <-ctx.Done():
		t.Fatal("connection budget did not join")
	}
	d := e.Diagnostics()
	if len(d.Exchanges) != MaxConnections || !d.Joined {
		t.Fatal("diagnostic count")
	}
	for _, exchange := range d.Exchanges {
		if !exchange.Finished || exchange.Operation != "settings" || exchange.Stage != "local_settings" || exchange.UpstreamStatus != 0 || exchange.UpstreamAuthorized || exchange.Reason != "" || exchange.MediaClass != "" {
			t.Fatal("local response presented as upstream evidence")
		}
	}
	data, _ := json.Marshal(d)
	if len(data) > 8<<10 {
		t.Fatal("diagnostic output budget")
	}
	if _, _, err := testInference(ctx, client); err == nil || len(e.Diagnostics().Exchanges) != MaxConnections {
		t.Fatal("diagnostic collection widened connection budget")
	}
}

func TestUpstreamDiagnostics(t *testing.T) {
	for _, mode := range []string{"dial", "tls", "headers", "redirect", "unauthorized"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cert, ca, err := newCertificate()
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(ca)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "headers" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					io.WriteString(conn, diagnosticSecret+"\r\n\r\n")
					return
				}
				if mode == "redirect" {
					w.Header().Set("Location", "https://"+diagnosticSecret+".invalid/")
					w.WriteHeader(302)
				} else {
					w.WriteHeader(401)
				}
				io.WriteString(w, diagnosticSecret)
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			server.StartTLS()
			defer server.Close()
			var calls int
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				calls++
				if network != "tcp" || address != "chatgpt.com:443" {
					t.Error("fixed route changed")
				}
				if mode == "dial" {
					return nil, errors.New(diagnosticSecret)
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}
			if mode == "tls" {
				roots = x509.NewCertPool()
			}
			response, err := upstreamResponse(ctx, Request{Operation: Inference}, dial, roots)
			if response.Body != nil {
				response.Body.Close()
			}
			if calls != 1 {
				t.Fatal("unexpected retry")
			}
			if mode == "unauthorized" {
				if err != nil || response.Status != 401 {
					t.Fatal("upstream status lost")
				}
				return
			}
			var failure upstreamFailure
			if !errors.Is(err, ErrUpstream) || !errors.As(err, &failure) || strings.Contains(err.Error(), diagnosticSecret) {
				t.Fatal("unsafe or incompatible upstream error")
			}
			stage, status := "upstream_"+mode, 0
			if mode == "redirect" {
				stage, status = "upstream_policy", 302
			}
			if failure.stage != stage || failure.status != status {
				t.Fatalf("failure: %+v", failure)
			}
		})
	}
}
