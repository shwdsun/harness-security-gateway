package responsesgate

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

func (g *Gate) handle(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		// Close may still be reaching a concurrently accepted connection.
		// Never let an empty handler return become an implicit HTTP 200.
		deny(w, http.StatusServiceUnavailable)
		return
	}
	g.handlers.Add(1)
	g.attempts++
	allowed := g.opened && g.ctx.Err() == nil && g.attempts <= MaxAttempts && !g.active
	if allowed {
		g.active = true
	}
	g.mu.Unlock()
	defer g.handlers.Done()
	if !allowed {
		deny(w, http.StatusServiceUnavailable)
		return
	}
	defer func() { g.mu.Lock(); g.active = false; g.mu.Unlock() }()
	if !g.validRequest(r) {
		deny(w, http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil || len(body) > MaxBodyBytes || !validBody(body) {
		deny(w, http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	allowed = !g.closed && g.ctx.Err() == nil && r.Context().Err() == nil && g.dispatches < MaxInferences
	if allowed {
		g.dispatches++ // A failed or cancelled dispatch also consumes its slot.
	}
	g.mu.Unlock()
	if !allowed {
		deny(w, http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	// r.Context descends from the Run context through Server.BaseContext.
	// This timer also bounds an idle callback before it produces headers.
	idle := time.AfterFunc(IdleTimeout, cancel)
	defer idle.Stop()
	response, err := g.responder(ctx, Request{Body: body, Header: http.Header{
		"Content-Type": {"application/json"}, "Authorization": {g.bearer},
	}})
	if response.Body == nil {
		deny(w, http.StatusBadGateway)
		return
	}
	var once sync.Once
	closeBody := func() { once.Do(func() { g.recordCleanup(response.Body.Close()) }) }
	// Even normal EOF cancels the exchange before Close joins its producer.
	// Deferring cancel until after Close could stall cooperative cleanup.
	defer func() { cancel(); closeBody() }()
	stopClose := context.AfterFunc(ctx, closeBody)
	defer stopClose()
	if err != nil || ctx.Err() != nil || !validResponse(response) {
		deny(w, http.StatusBadGateway)
		return
	}
	idle.Reset(IdleTimeout)
	controller := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "close")
	// No application header from either peer, including cookies and error
	// detail, reaches the other side. net/http owns response framing.
	w.WriteHeader(http.StatusOK)
	remaining, emptyReads := MaxBodyBytes, 0
	var buffer [32 << 10]byte
	for {
		limit := min(len(buffer), remaining+1)
		n, readErr := response.Body.Read(buffer[:limit])
		if ctx.Err() != nil || n > remaining {
			panic(http.ErrAbortHandler) // An incomplete SSE must not look complete.
		}
		if n > 0 {
			emptyReads = 0
			idle.Reset(IdleTimeout)
			deadline := time.Now().Add(IdleTimeout)
			if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
				deadline = end
			}
			if controller.SetWriteDeadline(deadline) != nil {
				panic(http.ErrAbortHandler)
			}
			if _, err := w.Write(buffer[:n]); err != nil || controller.Flush() != nil {
				panic(http.ErrAbortHandler)
			}
			remaining -= n
		} else {
			emptyReads++
		}
		if readErr == io.EOF {
			return
		}
		if readErr != nil || emptyReads >= 3 {
			panic(http.ErrAbortHandler)
		}
	}
}

func (g *Gate) validRequest(r *http.Request) bool {
	if r.Method != http.MethodPost || r.ProtoMajor != 1 || r.ProtoMinor != 1 ||
		r.RequestURI != "/v1/responses" || r.Host != g.authority ||
		r.URL == nil || r.URL.IsAbs() || r.URL.Host != "" || r.URL.User != nil ||
		r.URL.Path != "/v1/responses" || r.URL.RawPath != "" || r.URL.RawQuery != "" ||
		r.URL.ForceQuery || r.URL.Fragment != "" || r.ContentLength <= 0 ||
		r.ContentLength > MaxBodyBytes || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		return false
	}
	if !oneHeader(r.Header, "Authorization", g.bearer) ||
		!oneHeader(r.Header, "Content-Type", "application/json") {
		return false
	}
	for key := range r.Header {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "proxy-") {
			return false
		}
		switch lower {
		case "content-encoding", "transfer-encoding", "trailer", "te", "upgrade", "expect",
			"forwarded", "x-original-url", "x-rewrite-url":
			return false
		case "connection":
			if !oneHeader(r.Header, key, "close") {
				return false
			}
		}
	}
	return true
}

func oneHeader(h http.Header, key, expected string) bool {
	count, matches := 0, false
	for name, values := range h {
		if !strings.EqualFold(name, key) {
			continue
		}
		count += len(values)
		if len(values) == 1 {
			matches = subtle.ConstantTimeCompare([]byte(values[0]), []byte(expected)) == 1
		}
	}
	return count == 1 && matches
}

func validBody(body []byte) bool {
	var fields map[string]json.RawMessage
	if strictjson.Decode(body, MaxBodyBytes, 32, &fields) != nil || fields == nil {
		return false
	}
	// Use case-sensitive map lookups rather than encoding/json's struct-field
	// matching. Reject case aliases too, before any downstream decoder sees them.
	for key := range fields {
		for _, name := range []string{"model", "reasoning", "stream"} {
			if key != name && strings.EqualFold(key, name) {
				return false
			}
		}
	}
	var model string
	var stream bool
	var reasoning map[string]json.RawMessage
	if json.Unmarshal(fields["model"], &model) != nil || model != codexprofile.ModelNameV1 ||
		json.Unmarshal(fields["stream"], &stream) != nil || !stream ||
		json.Unmarshal(fields["reasoning"], &reasoning) != nil || reasoning == nil {
		return false
	}
	for key := range reasoning {
		if key != "effort" && strings.EqualFold(key, "effort") {
			return false
		}
	}
	var effort string
	return json.Unmarshal(reasoning["effort"], &effort) == nil && effort == codexprofile.ModelReasoningEffortV1
}

func validResponse(r Response) bool {
	if r.StatusCode != http.StatusOK || !oneHeader(r.Header, "Content-Type", "text/event-stream") {
		return false
	}
	size := 0
	for key, values := range r.Header {
		for _, value := range values {
			size += len(key) + len(value) + 4
		}
		switch strings.ToLower(key) {
		case "content-encoding", "transfer-encoding", "trailer", "upgrade", "location", "connection", "content-length":
			return false
		}
	}
	return size <= MaxHeaderBytes
}

func deny(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "request denied\n")
}
