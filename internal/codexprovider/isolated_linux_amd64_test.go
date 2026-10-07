//go:build linux && amd64

package codexprovider

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
)

type isolatedTestOwner struct {
	before, after *OwnerAuth
	reads, forced atomic.Int32
	invalid       atomic.Bool
	resolveFn     func(context.Context, bool) (*OwnerAuth, bool, error)
	closeFn       func(context.Context) error
}

func (o *isolatedTestOwner) resolve(ctx context.Context, force bool) (*OwnerAuth, bool, error) {
	if force {
		o.forced.Add(1)
	} else {
		o.reads.Add(1)
	}
	if o.resolveFn != nil {
		return o.resolveFn(ctx, force)
	}
	if force {
		return o.after, true, nil
	}
	return o.before, false, nil
}
func (o *isolatedTestOwner) close(ctx context.Context) error {
	if o.closeFn != nil {
		return o.closeFn(ctx)
	}
	return nil
}
func (o *isolatedTestOwner) invalidate() { o.invalid.Store(true) }

func isolatedOwnerFixture(t *testing.T) *isolatedTestOwner {
	t.Helper()
	old, err := ParseOwnerAuth(syntheticOwnerAuth("OWNER_ACCOUNT_CANARY", "OWNER_SUBJECT_CANARY", "2026-09-19T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	next, err := ParseOwnerAuth(bytes.ReplaceAll(old.encoded, []byte("SYNTHETIC_ACCESS_SECRET"), []byte("ROTATED_ACCESS_SECRET")))
	if err != nil {
		t.Fatal(err)
	}
	return &isolatedTestOwner{before: old, after: next}
}

func isolatedFixture(t *testing.T, ctx context.Context, owner isolatedOwner, send responder) (*isolatedProvider, *http.Client, map[string]string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("concrete non-root endpoint peer required")
	}
	directory, err := os.MkdirTemp("", "hsg-isolated-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	p, err := makeIsolatedProvider(ctx, directory, localidentity.UID(os.Geteuid()), owner, send)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if p.Close(closeCtx) != nil {
			t.Error("isolated provider did not join")
		}
	})
	data, err := p.initialAuth()
	if err != nil {
		t.Fatal("missing local seed")
	}
	var seed struct {
		Tokens map[string]string `json:"tokens"`
		Time   time.Time         `json:"last_refresh"`
	}
	if json.Unmarshal(data, &seed) != nil || len(seed.Tokens) != 4 || time.Since(seed.Time) < 0 || time.Since(seed.Time) > time.Minute {
		t.Fatal("initial local auth is malformed or stale")
	}
	if _, err := p.initialAuth(); err == nil {
		t.Fatal("local seed reissued")
	}
	ca, err := os.ReadFile(p.endpoint.ca)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("endpoint CA")
	}
	proxy, _ := url.Parse("http://fixed.invalid")
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableCompression: true,
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", p.endpoint.socket)
		}}
	t.Cleanup(transport.CloseIdleConnections)
	return p, &http.Client{Transport: transport, Timeout: 3 * time.Second}, seed.Tokens
}

func isolatedRequest(op Operation, tokens map[string]string) Request {
	h := make(http.Header)
	var body []byte
	if op == Refresh {
		h.Set("Content-Type", "application/json")
		body, _ = json.Marshal(map[string]string{"refresh_token": tokens["refresh_token"], "grant_type": "refresh_token", "client_id": "app_EMoamEEZ73f0CkXaXp7hrann"})
	} else {
		h.Set("Authorization", "Bearer "+tokens["access_token"])
		h.Set("Chatgpt-Account-Id", tokens["account_id"])
		if op == Inference {
			h.Set("Content-Type", "application/json")
			body = []byte(inferenceBody)
		}
	}
	return Request{Operation: op, Header: h, Body: body}
}

func isolatedHTTP(ctx context.Context, client *http.Client, request Request) (int, []byte, error) {
	method, host, path := route(request.Operation)
	r, err := http.NewRequestWithContext(ctx, method, "https://"+host+path, bytes.NewReader(request.Body))
	if err != nil {
		return 0, nil, err
	}
	r.Header = request.Header.Clone()
	response, err := client.Do(r)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	return response.StatusCode, data, err
}

func isolatedReply(status int, text string) Response {
	return Response{Status: status, MediaType: "text/event-stream", Body: io.NopCloser(strings.NewReader(text))}
}

func isolatedRead(t *testing.T, response Response) []byte {
	t.Helper()
	if response.Body == nil {
		t.Fatal("missing response owner")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func isolatedAssertNoOwner(t *testing.T, owner *isolatedTestOwner, data []byte) {
	t.Helper()
	for _, auth := range []*OwnerAuth{owner.before, owner.after} {
		for _, value := range []string{auth.access, auth.refresh, auth.identity, auth.account, auth.subject} {
			if bytes.Contains(data, []byte(value)) {
				t.Fatal("owner secret/identity escaped to local result")
			}
		}
	}
}

func TestIsolatedHTTPRecoverySubstitutionAndSecretBoundary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	owner := isolatedOwnerFixture(t)
	var calls atomic.Int32
	p, client, local := isolatedFixture(t, ctx, owner, func(_ context.Context, request Request) (Response, error) {
		n := calls.Add(1)
		want := owner.before
		if n > 1 {
			want = owner.after
		}
		if request.Operation != Inference || request.Header.Get("Authorization") != "Bearer "+want.access || request.Header.Get("Chatgpt-Account-Id") != want.account {
			t.Error("upstream did not receive fixed owner auth")
		}
		if n == 1 || n == 3 {
			return isolatedReply(401, string(want.encoded)), nil // Poison error body.
		}
		return isolatedReply(200, "data: accepted\n\n"), nil
	})
	seed, _ := json.Marshal(local)
	isolatedAssertNoOwner(t, owner, seed)
	if owner.reads.Load() != 0 || owner.forced.Load() != 0 || calls.Load() != 0 {
		t.Fatal("constructor used provider/source before registration")
	}
	if openIsolated(p) != nil || openIsolated(p) == nil || owner.reads.Load() != 1 {
		t.Fatal("one-time owner readiness before admission")
	}
	request := isolatedRequest(Inference, local)
	status, body, err := isolatedHTTP(ctx, client, request)
	if err != nil || status != 401 || calls.Load() != 1 || owner.forced.Load() != 1 {
		t.Fatal("first 401 failed exactly-one recovery", status, err)
	}
	isolatedAssertNoOwner(t, owner, body)
	status, body, err = isolatedHTTP(ctx, client, request)
	if err != nil || status != 401 || calls.Load() != 1 {
		t.Fatal("old local retry reached upstream or original inference was replayed")
	}
	isolatedAssertNoOwner(t, owner, body)
	status, body, err = isolatedHTTP(ctx, client, isolatedRequest(Refresh, local))
	var next map[string]string
	if err != nil || status != 200 || json.Unmarshal(body, &next) != nil || next["access_token"] == local["access_token"] || next["account_id"] != local["account_id"] || owner.forced.Load() != 1 {
		t.Fatal("local refresh coupled to another owner refresh")
	}
	isolatedAssertNoOwner(t, owner, body)
	status, body, err = isolatedHTTP(ctx, client, isolatedRequest(Inference, next))
	if err != nil || status != 200 || string(body) != "data: accepted\n\n" || calls.Load() != 2 {
		t.Fatal("new local auth/stream did not complete", status, err)
	}
	status, body, err = isolatedHTTP(ctx, client, isolatedRequest(Inference, next))
	if err != nil || status != 502 || calls.Load() != 3 || owner.forced.Load() != 1 || !owner.invalid.Load() {
		t.Fatal("second current-owner 401 did not fail closed")
	}
	isolatedAssertNoOwner(t, owner, body)
	if request.Header.Get("Authorization") != "Bearer "+local["access_token"] {
		t.Fatal("substitution mutated untrusted input")
	}
	waitEndpointExchanges(t, ctx, p.endpoint, 5)
	d := p.endpoint.Diagnostics()
	if !d.Exchanges[0].UpstreamAuthorized || d.Exchanges[0].UpstreamStatus != 401 || d.Exchanges[1].LocalAuth != "denied" || d.Exchanges[2].LocalAuth != "refresh" {
		t.Fatal("wrong local/upstream diagnostic provenance")
	}
	for _, index := range []int{1, 2} {
		if d.Exchanges[index].UpstreamAuthorized || d.Exchanges[index].UpstreamStatus != 0 {
			t.Fatal("local response claimed upstream dispatch/status")
		}
	}
	encoded, _ := json.Marshal(d)
	isolatedAssertNoOwner(t, owner, encoded)
	isolatedAssertNoOwner(t, owner, []byte(fmt.Sprintf("%+v", p)))
	if p.Close(ctx) != nil || !owner.invalid.Load() || openIsolated(p) == nil {
		t.Fatal("taint conflated with failed cleanup, or closed provider reopened")
	}
}

func TestIsolatedLocalRefreshCannotAuthorizeRealRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	owner := isolatedOwnerFixture(t)
	var calls atomic.Int32
	p, client, local := isolatedFixture(t, ctx, owner, func(context.Context, Request) (Response, error) {
		calls.Add(1)
		return isolatedReply(200, "data: accepted\n\n"), nil
	})
	if openIsolated(p) != nil {
		t.Fatal("open")
	}
	status, data, err := isolatedHTTP(ctx, client, isolatedRequest(Refresh, local))
	var next map[string]string
	if err != nil || status != 200 || json.Unmarshal(data, &next) != nil || owner.forced.Load() != 0 || calls.Load() != 0 {
		t.Fatal("client refresh granted real provider authority")
	}
	isolatedAssertNoOwner(t, owner, data)
	status, _, err = isolatedHTTP(ctx, client, isolatedRequest(Inference, local))
	if err != nil || status != 401 || calls.Load() != 0 {
		t.Fatal("rotated old local access reused")
	}
	status, _, err = isolatedHTTP(ctx, client, isolatedRequest(Refresh, next))
	if err != nil || status != 503 || calls.Load() != 0 || owner.forced.Load() != 0 || owner.invalid.Load() {
		t.Fatal("existing single local-refresh budget changed or tainted source")
	}
	status, _, err = isolatedHTTP(ctx, client, isolatedRequest(Inference, next))
	if err != nil || status != 200 || calls.Load() != 1 {
		t.Fatal("valid current local auth stopped after harmless rejected refresh")
	}
}

func TestIsolatedCrossRunAndOwnerTokensCannotSelectAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	owner := isolatedOwnerFixture(t)
	var calls atomic.Int32
	send := func(context.Context, Request) (Response, error) { calls.Add(1); return isolatedReply(200, "ok"), nil }
	p, _, local := isolatedFixture(t, ctx, owner, send)
	other, _, foreign := isolatedFixture(t, ctx, isolatedOwnerFixture(t), send)
	if openIsolated(p) != nil || openIsolated(other) != nil {
		t.Fatal("open")
	}
	for _, tokens := range []map[string]string{foreign, {"access_token": owner.before.access, "refresh_token": owner.before.refresh, "account_id": owner.before.account}} {
		for _, op := range []Operation{Inference, Catalog, Refresh} {
			response, err := p.respond(ctx, isolatedRequest(op, tokens))
			isolatedRead(t, response)
			if err != nil || response.Status != 401 || calls.Load() != 0 || owner.forced.Load() != 0 || owner.invalid.Load() {
				t.Fatal("foreign or real token accepted as local authority")
			}
		}
	}
	response, err := p.respond(ctx, isolatedRequest(Inference, local))
	isolatedRead(t, response)
	if err != nil || response.Status != 200 || calls.Load() != 1 {
		t.Fatal("live matching local positive control failed")
	}
	if p.Close(ctx) != nil {
		t.Fatal("close")
	}
	response, _ = p.respond(ctx, isolatedRequest(Inference, local))
	isolatedRead(t, response)
	if response.Status != 503 || calls.Load() != 1 {
		t.Fatal("closed local channel reused")
	}
}

func TestIsolatedConcurrentAndLate401ShareOneRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	owner := isolatedOwnerFixture(t)
	entered := make(chan struct{}, 2)
	first, late, native, resolving := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	owner.resolveFn = func(ctx context.Context, force bool) (*OwnerAuth, bool, error) {
		if !force {
			return owner.before, false, nil
		}
		close(resolving)
		select {
		case <-native:
			return owner.after, true, nil
		case <-ctx.Done():
			return nil, false, ErrOwnerAuth
		}
	}
	var calls atomic.Int32
	p, client, local := isolatedFixture(t, ctx, owner, func(ctx context.Context, r Request) (Response, error) {
		n := calls.Add(1)
		if n <= 2 {
			entered <- struct{}{}
			wait := first
			if n == 2 {
				wait = late
			}
			select {
			case <-wait:
				return isolatedReply(401, "denied"), nil
			case <-ctx.Done():
				return Response{}, ErrUpstream
			}
		}
		if r.Header.Get("Authorization") != "Bearer "+owner.after.access {
			t.Error("post-recovery request used previous owner auth")
		}
		return isolatedReply(200, "ok"), nil
	})
	if openIsolated(p) != nil {
		t.Fatal("open")
	}
	type result struct {
		r   Response
		err error
	}
	one, two := make(chan result, 1), make(chan result, 1)
	go func() { r, err := p.respond(ctx, isolatedRequest(Inference, local)); one <- result{r, err} }()
	<-entered
	go func() { r, err := p.respond(ctx, isolatedRequest(Inference, local)); two <- result{r, err} }()
	<-entered
	close(first)
	<-resolving
	response, err := p.respond(ctx, isolatedRequest(Inference, local))
	isolatedRead(t, response)
	if err != nil || response.Status != 401 || calls.Load() != 2 {
		t.Fatal("old auth dispatched while recovery in progress")
	}
	type httpResult struct {
		status int
		data   []byte
		err    error
	}
	refresh := make(chan httpResult, 1)
	go func() {
		status, data, err := isolatedHTTP(ctx, client, isolatedRequest(Refresh, local))
		refresh <- httpResult{status, data, err}
	}()
	// Wait for actual HTTP admission, not a direct responder call that would
	// bypass the Endpoint's one-refresh counter. The owner is still held.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for p.endpoint.hasRefreshBudget() {
		select {
		case <-ctx.Done():
			t.Fatal("HTTP refresh was not admitted")
		case <-ticker.C:
		}
	}
	p.mu.Lock()
	stillWaiting := p.state == isolatedRecovering && !p.localUsed
	p.mu.Unlock()
	if !stillWaiting {
		t.Fatal("HTTP refresh published before owner recovery joined")
	}
	close(native)
	a := <-one
	isolatedRead(t, a.r)
	if a.err != nil || a.r.Status != 401 {
		t.Fatal("original inference was converted to a replay/success")
	}
	refreshed := <-refresh
	var next map[string]string
	if refreshed.err != nil || refreshed.status != 200 || json.Unmarshal(refreshed.data, &next) != nil {
		t.Fatal("local refresh did not follow joined recovery")
	}
	response, err = p.respond(ctx, isolatedRequest(Inference, next))
	isolatedRead(t, response)
	if err != nil || response.Status != 200 {
		t.Fatal("new auth positive control failed")
	}
	close(late)
	b := <-two
	isolatedRead(t, b.r)
	if b.err != nil || b.r.Status != 401 || owner.forced.Load() != 1 || owner.invalid.Load() {
		t.Fatal("late old-version 401 revoked new auth or repeated refresh")
	}
	response, err = p.respond(ctx, isolatedRequest(Inference, next))
	isolatedRead(t, response)
	if err != nil || response.Status != 200 || calls.Load() != 4 {
		t.Fatal("late response broke current auth or speculative replay occurred")
	}
}

func TestIsolatedOnlyVerified401CanForceOwner(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		failure error
	}{
		{"forbidden", 403, nil}, {"rate limited", 429, nil}, {"server error", 500, nil},
		{"SSE text is data", 200, nil}, {"transport failure", 401, ErrUpstream},
		{"policy failure", 401, upstreamFailure{stage: "upstream_policy", status: 401, rejection: rejectionLocation}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			owner := isolatedOwnerFixture(t)
			p, _, local := isolatedFixture(t, ctx, owner, func(context.Context, Request) (Response, error) {
				return isolatedReply(tc.status, "data: status=401\n\n"), tc.failure
			})
			if openIsolated(p) != nil {
				t.Fatal("open")
			}
			response, _ := p.respond(ctx, isolatedRequest(Inference, local))
			isolatedRead(t, response)
			if owner.forced.Load() != 0 || owner.invalid.Load() {
				t.Fatal("unverified status/text widened refresh authority")
			}
		})
	}
}

func TestIsolatedRecoveryRequiresPersistedJoinedAuth(t *testing.T) {
	for _, mode := range []string{"failure", "no refresh", "no auth", "cleanup failed"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			owner := isolatedOwnerFixture(t)
			owner.resolveFn = func(_ context.Context, force bool) (*OwnerAuth, bool, error) {
				if !force {
					return owner.before, false, nil
				}
				switch mode {
				case "failure":
					return nil, false, ErrOwnerAuth
				case "no refresh":
					return owner.after, false, nil
				case "no auth":
					return nil, true, nil
				default:
					return owner.after, true, ErrCleanup
				}
			}
			var calls atomic.Int32
			p, _, local := isolatedFixture(t, ctx, owner, func(context.Context, Request) (Response, error) {
				calls.Add(1)
				return isolatedReply(401, "poison"), nil
			})
			if openIsolated(p) != nil {
				t.Fatal("open")
			}
			response, err := p.respond(ctx, isolatedRequest(Inference, local))
			isolatedRead(t, response)
			if !errors.Is(err, ErrOwnerAuth) || !owner.invalid.Load() {
				t.Fatal("unproved refresh accepted")
			}
			response, _ = p.respond(ctx, isolatedRequest(Refresh, local))
			isolatedRead(t, response)
			if response.Status != 503 || calls.Load() != 1 || owner.forced.Load() != 1 {
				t.Fatal("failed recovery issued/replayed auth")
			}
			if p.Close(ctx) != nil {
				t.Fatal("taint persisted as a cleanup error after resources joined")
			}
		})
	}
}

func TestIsolatedCloseRetainsOpenAndRecoveryObligations(t *testing.T) {
	for _, during := range []string{"open", "recovery"} {
		t.Run(during, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			owner := isolatedOwnerFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			owner.resolveFn = func(ctx context.Context, force bool) (*OwnerAuth, bool, error) {
				if !force && during != "open" {
					return owner.before, false, nil
				}
				close(entered)
				<-release // Deliberately retains cleanup despite cancellation.
				return owner.after, force, nil
			}
			p, _, local := isolatedFixture(t, ctx, owner, func(context.Context, Request) (Response, error) { return isolatedReply(401, "poison"), nil })
			done := make(chan error, 1)
			if during == "open" {
				go func() { done <- openIsolated(p) }()
			} else {
				if openIsolated(p) != nil {
					t.Fatal("open")
				}
				go func() { r, err := p.respond(p.ctx, isolatedRequest(Inference, local)); r.Body.Close(); done <- err }()
			}
			<-entered
			short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
			err := p.Close(short)
			stop()
			if !errors.Is(err, ErrCleanup) {
				t.Error("unjoined operation discharged")
			}
			response, _ := p.respond(ctx, isolatedRequest(Refresh, local))
			isolatedRead(t, response)
			if response.Status != 503 {
				t.Error("Close admitted local refresh")
			}
			close(release)
			if <-done == nil {
				t.Error("auth published after Close")
			}
			if p.Close(ctx) != nil || openIsolated(p) == nil {
				t.Fatal("joined retry failed or reopened")
			}
		})
	}
}

func TestIsolatedExhaustedLocalRefreshDoesNotRotateOrTaintOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	owner := isolatedOwnerFixture(t)
	p, _, local := isolatedFixture(t, ctx, owner, func(context.Context, Request) (Response, error) { return isolatedReply(401, "poison"), nil })
	if openIsolated(p) != nil {
		t.Fatal("open")
	}
	response, _ := p.respond(ctx, isolatedRequest(Refresh, local))
	var next map[string]string
	if json.Unmarshal(isolatedRead(t, response), &next) != nil || response.Status != 200 {
		t.Fatal("local refresh")
	}
	response, err := p.respond(ctx, isolatedRequest(Inference, next))
	isolatedRead(t, response)
	if err == nil || owner.forced.Load() != 0 || owner.invalid.Load() {
		t.Fatal("local budget failure widened refresh or tainted unmodified storage")
	}
	response, _ = p.respond(ctx, isolatedRequest(Inference, next))
	isolatedRead(t, response)
	if response.Status != 503 {
		t.Fatal("exhausted Run stayed usable")
	}
}

func TestIsolatedRejectedRefreshSpendsEndpointBudgetBeforeRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	owner := isolatedOwnerFixture(t)
	var calls atomic.Int32
	p, client, local := isolatedFixture(t, ctx, owner, func(context.Context, Request) (Response, error) {
		calls.Add(1)
		return isolatedReply(401, "poison"), nil
	})
	if openIsolated(p) != nil {
		t.Fatal("open")
	}
	wrong := map[string]string{"refresh_token": "wrong-local-token"}
	status, _, err := isolatedHTTP(ctx, client, isolatedRequest(Refresh, wrong))
	if err != nil || status != 401 || owner.invalid.Load() {
		t.Fatal("local refresh rejection")
	}
	status, _, err = isolatedHTTP(ctx, client, isolatedRequest(Inference, local))
	if err != nil || status != 502 || calls.Load() != 1 || owner.forced.Load() != 0 || owner.invalid.Load() {
		t.Fatal("spent endpoint budget still authorized unusable owner recovery", status, owner.forced.Load())
	}
}

// Legacy component schedules explicitly prepare before admission.
func openIsolated(p *isolatedProvider) error {
	if err := p.Prepare(p.ctx); err != nil {
		return err
	}
	return p.Open()
}

func TestIsolatedPrepareDoesNotOpenBootstrapAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	owner := isolatedOwnerFixture(t)
	p, _, _ := isolatedFixture(t, ctx, owner, func(context.Context, Request) (Response, error) { return isolatedReply(200, "synthetic"), nil })
	if p.Open() == nil || owner.reads.Load() != 0 {
		t.Fatal("bootstrap performed native preparation")
	}
	if p.Prepare(ctx) != nil || owner.reads.Load() != 1 || p.endpoint.Diagnostics().Opened {
		t.Fatal("preparation admitted client before bootstrap")
	}
	if p.Prepare(ctx) == nil || p.Open() != nil || owner.reads.Load() != 1 {
		t.Fatal("fast admission repeated native work")
	}
}
