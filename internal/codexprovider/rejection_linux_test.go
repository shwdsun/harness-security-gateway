package codexprovider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func rejectionSuccess(media string) Response {
	return Response{Status: 200, MediaType: media, Body: io.NopCloser(strings.NewReader("synthetic"))}
}

func rejectionGet(ctx context.Context, client *http.Client, path string) (int, error) {
	r, err := http.NewRequestWithContext(ctx, "GET", "https://chatgpt.com"+path, nil)
	if err != nil {
		return 0, err
	}
	r.Header.Set("Authorization", "Bearer synthetic-only")
	r.Header.Set("Chatgpt-Account-Id", "synthetic-account")
	response, err := client.Do(r)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, response.Body)
	return response.StatusCode, err
}

func checkLocalRejection(t *testing.T, got ExchangeDiagnostic, reason string) {
	t.Helper()
	if got.Stage != "operation_rejected" || got.Reason != reason || got.UpstreamAuthorized || got.UpstreamStatus != 0 || got.MediaClass != "" || !got.Finished || got.Cancelled ||
		got.ResponseProtocol != "" || got.ContentTypeState != "" || got.ResponseFraming != "" || got.DeclaredBody != "" || got.BodyPrefix != "" || got.BodyProbeEnd != "" {
		t.Fatalf("local rejection presented as a new upstream exchange: %+v", got)
	}
}

func TestEndpointPolicyRejectionIsOperationScoped(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var inferenceCalls, catalogCalls atomic.Int32
	e, client := testEndpoint(t, ctx, func(_ context.Context, request Request) (Response, error) {
		switch request.Operation {
		case Inference:
			inferenceCalls.Add(1)
			return Response{}, upstreamFailure{stage: "upstream_policy", status: 200, rejection: rejectionContentEncoding}
		case Catalog:
			catalogCalls.Add(1)
			return rejectionSuccess("application/json"), nil
		default:
			t.Error("local settings reached upstream")
			return Response{}, ErrDenied
		}
	})
	if e.Open() != nil {
		t.Fatal("open")
	}
	for _, expected := range []int{502, 503, 503} {
		status, _, err := testInference(ctx, client)
		if err != nil || status != expected {
			t.Fatalf("inference status=%d want=%d err=%v", status, expected, err)
		}
	}
	// The unrelated operation retains both its progress and its existing budget.
	for _, expected := range []int{200, 200, 503} {
		status, err := rejectionGet(ctx, client, "/backend-api/codex/models?client_version=0.151.0")
		if err != nil || status != expected {
			t.Fatalf("catalog status=%d want=%d err=%v", status, expected, err)
		}
	}
	if status, err := rejectionGet(ctx, client, "/backend-api/wham/settings/user"); err != nil || status != 404 {
		t.Fatalf("local settings status=%d err=%v", status, err)
	}
	waitEndpointExchanges(t, ctx, e, 7)
	if inferenceCalls.Load() != 1 || catalogCalls.Load() != 2 {
		t.Fatalf("operation scope or budget changed: inference=%d catalog=%d", inferenceCalls.Load(), catalogCalls.Load())
	}
	d := e.Diagnostics()
	if len(d.Exchanges) != 7 {
		t.Fatalf("exchanges=%d", len(d.Exchanges))
	}
	first := d.Exchanges[0]
	if first.Stage != "upstream_policy" || first.Reason != "content_encoding" || first.UpstreamStatus != 200 || !first.UpstreamAuthorized || !first.Finished {
		t.Fatalf("first rejection lost its evidence: %+v", first)
	}
	for _, got := range d.Exchanges[1:3] {
		checkLocalRejection(t, got, "content_encoding")
	}
	for _, got := range d.Exchanges[3:5] {
		if got.Stage != "complete" || !got.UpstreamAuthorized || got.Reason != "" {
			t.Fatalf("other operation did not progress: %+v", got)
		}
	}
	if got := d.Exchanges[5]; got.Stage != "operation_budget" || got.UpstreamAuthorized || got.Reason != "" {
		t.Fatalf("catalog budget changed: %+v", got)
	}
	if got := d.Exchanges[6]; got.Stage != "local_settings" || got.UpstreamAuthorized || got.UpstreamStatus != 0 || got.Reason != "" {
		t.Fatalf("settings presented as upstream work: %+v", got)
	}
}

func TestEndpointNonPolicyFailureDoesNotRejectOperation(t *testing.T) {
	for _, row := range []struct {
		name     string
		status   int
		readFail bool
		first    func() (Response, error)
	}{
		{"ordinary", 502, false, func() (Response, error) { return Response{}, errors.New(diagnosticSecret) }},
		{"dial", 502, false, func() (Response, error) { return Response{}, upstreamFailure{stage: "upstream_dial"} }},
		{"tls", 502, false, func() (Response, error) { return Response{}, upstreamFailure{stage: "upstream_tls"} }},
		{"headers", 502, false, func() (Response, error) { return Response{}, upstreamFailure{stage: "upstream_headers"} }},
		// A diagnostic label is deliberately insufficient to change authority.
		{"policy_stage_only", 502, false, func() (Response, error) { return Response{}, upstreamFailure{stage: "upstream_policy", status: 200} }},
		{"unauthorized", 401, false, func() (Response, error) { return Response{401, "", io.NopCloser(strings.NewReader("denied"))}, nil }},
		{"forbidden", 403, false, func() (Response, error) { return Response{403, "", io.NopCloser(strings.NewReader("denied"))}, nil }},
		{"limited", 429, false, func() (Response, error) { return Response{429, "", io.NopCloser(strings.NewReader("denied"))}, nil }},
		{"server_error", 502, false, func() (Response, error) { return Response{500, "", io.NopCloser(strings.NewReader("denied"))}, nil }},
		{"unavailable", 502, false, func() (Response, error) { return Response{503, "", io.NopCloser(strings.NewReader("denied"))}, nil }},
		{"truncated", 200, true, func() (Response, error) { return Response{200, "text/event-stream", &truncatedBody{}}, nil }},
		{"body_budget", 200, true, func() (Response, error) {
			return Response{200, "text/event-stream", io.NopCloser(strings.NewReader(strings.Repeat("x", MaxBodyBytes+1)))}, nil
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var calls atomic.Int32
			e, client := testEndpoint(t, ctx, func(context.Context, Request) (Response, error) {
				if calls.Add(1) == 1 {
					return row.first()
				}
				return rejectionSuccess("text/event-stream"), nil
			})
			if e.Open() != nil {
				t.Fatal("open")
			}
			status, _, err := testInference(ctx, client)
			if status != row.status || (err != nil) != row.readFail {
				t.Fatalf("first status=%d want=%d err=%v readFail=%t", status, row.status, err, row.readFail)
			}
			status, body, err := testInference(ctx, client)
			if err != nil || status != 200 || string(body) != "synthetic" || calls.Load() != 2 {
				t.Fatalf("transient/status/body failure latched: status=%d calls=%d err=%v", status, calls.Load(), err)
			}
			waitEndpointExchanges(t, ctx, e, 2)
			d := e.Diagnostics()
			if len(d.Exchanges) != 2 {
				t.Fatalf("exchanges=%d", len(d.Exchanges))
			}
			for _, got := range d.Exchanges {
				if !got.UpstreamAuthorized || !got.Finished || got.Reason != "" {
					t.Fatalf("non-policy failure changed dispatch authority: %+v", got)
				}
			}
			if d.Exchanges[1].Stage != "complete" {
				t.Fatalf("later success: %+v", d.Exchanges[1])
			}
		})
	}
}

func TestEndpointRejectionAllowsPreviouslyAuthorizedConcurrentWork(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered := make(chan struct{}, MaxConcurrent)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var calls atomic.Int32
	e, client := testEndpoint(t, ctx, func(ctx context.Context, _ Request) (Response, error) {
		if calls.Add(1) <= 5 {
			return rejectionSuccess("text/event-stream"), nil
		}
		entered <- struct{}{}
		select {
		case <-release:
			return Response{}, upstreamFailure{stage: "upstream_policy", status: 200, rejection: rejectionLocation}
		case <-ctx.Done():
			return Response{}, ctx.Err()
		}
	})
	if e.Open() != nil {
		t.Fatal("open")
	}
	for range 5 {
		if status, _, err := testInference(ctx, client); err != nil || status != 200 {
			t.Fatalf("initial success status=%d err=%v", status, err)
		}
	}
	waitEndpointExchanges(t, ctx, e, 5)
	type result struct {
		status int
		err    error
	}
	results := make(chan result, MaxConcurrent)
	for range MaxConcurrent {
		go func() {
			status, _, err := testInference(ctx, client)
			results <- result{status, err}
		}()
	}
	for range MaxConcurrent {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("the failing batch was not concurrently authorized")
		}
	}
	releaseOnce.Do(func() { close(release) })
	for range MaxConcurrent {
		select {
		case got := <-results:
			if got.err != nil || got.status != 502 {
				t.Fatalf("previously authorized failure status=%d err=%v", got.status, got.err)
			}
		case <-ctx.Done():
			t.Fatal("authorized work did not finish")
		}
	}
	waitEndpointExchanges(t, ctx, e, 5+MaxConcurrent)
	for range 2 {
		if status, _, err := testInference(ctx, client); err != nil || status != 503 {
			t.Fatalf("post-rejection request status=%d err=%v", status, err)
		}
	}
	waitEndpointExchanges(t, ctx, e, 5+MaxConcurrent+2)
	// MaxConcurrent limits work active at the transition, not all work in a Run.
	if calls.Load() != 5+MaxConcurrent {
		t.Fatalf("dispatch count=%d want=%d", calls.Load(), 5+MaxConcurrent)
	}
	d := e.Diagnostics()
	if len(d.Exchanges) != 5+MaxConcurrent+2 {
		t.Fatalf("exchanges=%d", len(d.Exchanges))
	}
	for i, got := range d.Exchanges[:5+MaxConcurrent] {
		if !got.UpstreamAuthorized || !got.Finished {
			t.Fatalf("authorized exchange %d lost: %+v", i, got)
		}
		if i >= 5 && (got.Stage != "upstream_policy" || got.Reason != "location" || got.UpstreamStatus != 200) {
			t.Fatalf("concurrent rejection %d lost: %+v", i, got)
		}
	}
	for _, got := range d.Exchanges[5+MaxConcurrent:] {
		checkLocalRejection(t, got, "location")
	}
}

func TestEndpointCloseWaitsForActiveResponder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	e, client := testEndpoint(t, ctx, func(ctx context.Context, _ Request) (Response, error) {
		close(entered)
		select {
		case <-ctx.Done():
			close(cancelled)
		case <-release:
			return Response{}, ErrUpstream
		}
		<-release
		return Response{}, ctx.Err()
	})
	if e.Open() != nil {
		t.Fatal("open")
	}
	clientDone := make(chan struct{})
	go func() { defer close(clientDone); _, _, _ = testInference(ctx, client) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("responder did not enter")
	}
	short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	closeDone := make(chan error, 1)
	go func() { closeDone <- e.Close(short) }()
	select {
	case err := <-closeDone:
		if !errors.Is(err, ErrCleanup) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("active callback accepted as joined cleanup: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Close blocked behind an active callback")
	}
	select {
	case <-cancelled:
	case <-ctx.Done():
		t.Fatal("Close did not cancel the active responder")
	}
	if d := e.Diagnostics(); !d.Stopped || d.Joined || len(d.Exchanges) != 1 || d.Exchanges[0].Finished {
		t.Fatalf("held callback reported joined: %+v", d)
	}
	select {
	case <-e.Done():
		t.Fatal("Done closed while the callback was still held")
	default:
	}
	releaseOnce.Do(func() { close(release) })
	if err := e.Close(ctx); err != nil {
		t.Fatalf("released callback did not join: %v", err)
	}
	select {
	case <-clientDone:
	case <-ctx.Done():
		t.Fatal("client did not stop")
	}
	d := e.Diagnostics()
	if !d.Joined || !d.Exchanges[0].Finished || !d.Exchanges[0].Cancelled || !d.Exchanges[0].UpstreamAuthorized {
		t.Fatalf("joined cancellation evidence missing: %+v", d)
	}
}

type rejectionHeldCloseBody struct {
	entered, release chan struct{}
	once             sync.Once
}

func (*rejectionHeldCloseBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *rejectionHeldCloseBody) Close() error {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return nil
}

func TestEndpointPublishesRejectionBeforeBodyClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body := &rejectionHeldCloseBody{entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(body.release) })
	var calls atomic.Int32
	e, client := testEndpoint(t, ctx, func(context.Context, Request) (Response, error) {
		if calls.Add(1) == 1 {
			return Response{200, "text/html", body}, nil
		}
		return rejectionSuccess("text/event-stream"), nil
	})
	if e.Open() != nil {
		t.Fatal("open")
	}
	type result struct {
		status int
		err    error
	}
	first := make(chan result, 1)
	go func() {
		status, _, err := testInference(ctx, client)
		first <- result{status, err}
	}()
	select {
	case <-body.entered:
	case <-ctx.Done():
		t.Fatal("rejected response did not begin closing its body")
	}
	if status, _, err := testInference(ctx, client); err != nil || status != 503 || calls.Load() != 1 {
		t.Fatalf("slow cleanup delayed rejection: status=%d calls=%d err=%v", status, calls.Load(), err)
	}
	releaseOnce.Do(func() { close(body.release) })
	select {
	case got := <-first:
		if got.err != nil || got.status != 502 {
			t.Fatalf("first policy failure status=%d err=%v", got.status, got.err)
		}
	case <-ctx.Done():
		t.Fatal("first request did not finish")
	}
	waitEndpointExchanges(t, ctx, e, 2)
	d := e.Diagnostics()
	if len(d.Exchanges) != 2 {
		t.Fatalf("exchanges=%d", len(d.Exchanges))
	}
	if got := d.Exchanges[0]; got.Stage != "upstream_policy" || got.Reason != "media_type_mismatch" || got.MediaClass != "html" || !got.UpstreamAuthorized || got.UpstreamStatus != 200 {
		t.Fatalf("wrong-media rejection evidence missing: %+v", got)
	}
	checkLocalRejection(t, d.Exchanges[1], "media_type_mismatch")
}
