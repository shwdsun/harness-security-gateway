package codexprovider

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestInferenceAbsentTypeTransport(t *testing.T) {
	fixed := func(body string) string {
		return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}
	for _, row := range []struct {
		name, wire, body, framing, stage string
		incomplete                       bool
	}{
		{"sse", fixed("data: x\n\n"), "data: x\n\n", "fixed", "complete", false},
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\ndata: x\n\r\n1\r\n\n\r\n0\r\n\r\n", "data: x\n\n", "chunked", "complete", false},
		// No body sniffing: native Codex, not this transport, interprets these
		// bytes and decides whether a provider stream actually completed.
		{"json", fixed(`{"type":"response.completed"}`), `{"type":"response.completed"}`, "fixed", "complete", false},
		{"html-close-delimited", "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n<html>synthetic</html>", "<html>synthetic</html>", "close_delimited", "complete", false},
		{"empty", fixed(""), "", "fixed", "complete", false},
		{"body-limit", fixed(strings.Repeat("x", MaxBodyBytes)), strings.Repeat("x", MaxBodyBytes), "fixed", "complete", false},
		{"over-budget", fixed(strings.Repeat("x", MaxBodyBytes+1)), strings.Repeat("x", MaxBodyBytes+1), "fixed", "response_budget", true},
		{"truncated", "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\ndata: short", "data: short", "fixed", "response_read", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			e, client, calls, _ := rawResponseEndpoint(t, ctx, func(conn net.Conn) { _, _ = io.WriteString(conn, row.wire) })
			status, body, err := testInference(ctx, client)
			if status != 200 || (err != nil) != row.incomplete || len(body) > MaxBodyBytes {
				t.Fatalf("transport status=%d bytes=%d error=%v", status, len(body), err)
			}
			if (!row.incomplete && string(body) != row.body) || !strings.HasPrefix(row.body, string(body)) {
				t.Fatal("body bytes changed")
			}
			waitEndpointExchanges(t, ctx, e, 1)
			if e.Close(ctx) != nil {
				t.Fatal("join")
			}
			d := e.Diagnostics()
			got := d.Exchanges[0]
			if calls.Load() != 1 || !d.Joined || d.CleanupFailed || got.Stage != row.stage || got.MediaClass != "event_stream" || got.ContentTypeState != "absent" || got.ResponseFraming != row.framing || got.Reason != "" || got.BodyPrefix != "" || got.BodyProbeEnd != "" || !got.UpstreamAuthorized || !got.Finished || got.Cancelled {
				t.Fatalf("transport/observed metadata mismatch: %+v", d)
			}
		})
	}
}

func TestInferenceAbsentTypeCancellationJoinsSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peerClosed := make(chan struct{})
	e, client, calls, _ := rawResponseEndpoint(t, ctx, func(conn net.Conn) {
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\ndata: x\n\n")
		var buffer [1]byte
		_, _ = conn.Read(buffer[:])
		close(peerClosed)
	})
	r, err := http.NewRequestWithContext(ctx, "POST", "https://chatgpt.com/backend-api/codex/responses", strings.NewReader(inferenceBody))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer synthetic")
	r.Header.Set("Chatgpt-Account-Id", "synthetic-account")
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal("effective inference type was not forwarded")
	}
	first := make([]byte, len("data: x\n\n"))
	if _, err := io.ReadFull(response.Body, first); err != nil || string(first) != "data: x\n\n" {
		t.Fatal("stream did not deliver its first bytes")
	}
	e.Stop()
	if e.Close(ctx) != nil {
		t.Fatal("cancelled socket did not join")
	}
	if _, err := io.ReadAll(response.Body); err == nil {
		t.Fatal("cancelled producer gained a clean HTTP end")
	}
	select {
	case <-peerClosed:
	case <-ctx.Done():
		t.Fatal("upstream socket survived cancellation")
	}
	d := e.Diagnostics()
	got := d.Exchanges[0]
	if calls.Load() != 1 || !d.Joined || d.CleanupFailed || !got.Cancelled || !got.Finished || got.Stage == "complete" || got.ContentTypeState != "absent" || got.MediaClass != "event_stream" || got.BodyPrefix != "" || got.BodyProbeEnd != "" {
		t.Fatalf("cancelled response ownership: %+v", d)
	}
}
