//go:build linux && amd64

package codexprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

// Candidate only, not selected by any executable/profile. The fixed runtime
// must register this resource before Open, and retain the controller's original
// HeldSource behind owner. The local representation is usable only on this
// endpoint; it neither carries nor selects enrolled-generation authority.
type isolatedProvider struct {
	ctx      context.Context
	cancel   context.CancelFunc
	endpoint *Endpoint
	owner    isolatedOwner
	send     responder

	mu              sync.Mutex
	state           isolatedState
	closed, seeded  bool
	localUsed       bool
	local           localAuth
	auth            *OwnerAuth
	ownerVersion    uint8 // In-memory auth version, NOT enrolled generation.
	recoveryStarted bool
	recoveryDone    chan struct{}
	calls           int
	drained         chan struct{}
	release         func() // Immutable service artifact borrow, after all joins.
	releaseOnce     sync.Once
}

// Private fault seam. Production construction requires the concrete consumer;
// no callback, URL or auth implementation is selectable from configuration.
type isolatedOwner interface {
	resolve(context.Context, bool) (*OwnerAuth, bool, error)
	close(context.Context) error
	invalidate()
}

type isolatedState uint8

const (
	isolatedNew isolatedState = iota
	isolatedOpening
	isolatedPrepared
	isolatedReady
	isolatedRecovering
	isolatedAwaitRefresh
	isolatedBlocked
)

func (*isolatedProvider) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "codexprovider.isolatedProvider[redacted]")
}

func newIsolatedProvider(ctx context.Context, directory string, peer localidentity.UID, owner *ownerNativeConsumer) (*isolatedProvider, error) {
	if owner == nil {
		return nil, ErrConfiguration
	}
	return makeIsolatedProvider(ctx, directory, peer, owner, liveResponse)
}

// Only the unopened endpoint/CA are created here. No source read, native
// invocation or external provider connection occurs before registered Open.
func makeIsolatedProvider(ctx context.Context, directory string, peer localidentity.UID, owner isolatedOwner, send responder) (*isolatedProvider, error) {
	if ctx == nil || owner == nil || send == nil {
		return nil, ErrConfiguration
	}
	local, err := newLocalAuth("", "")
	if err != nil {
		return nil, ErrConfiguration
	}
	run, cancel := context.WithCancel(ctx)
	p := &isolatedProvider{ctx: run, cancel: cancel, owner: owner, send: send, local: local, drained: make(chan struct{})}
	p.endpoint, err = newEndpoint(run, directory, peer, p.respond)
	if err != nil {
		cancel()
		return nil, err
	}
	return p, nil
}

// One-time input for a fresh Runner auth file, never the enrolled source.
// The future runtime must independently verify this file's mount/bootstrap.
func (p *isolatedProvider) initialAuth() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.seeded || p.state != isolatedNew || p.ctx.Err() != nil {
		return nil, ErrClosed
	}
	data, err := p.local.file()
	if err != nil {
		return nil, ErrConfiguration
	}
	p.seeded = true
	return data, nil
}

// InitialAuth returns only the one-use disposable client representation.
func (p *isolatedProvider) InitialAuth() ([]byte, error) { return p.initialAuth() }

func (p *isolatedProvider) Paths() (string, string)     { return p.endpoint.Paths() }
func (p *isolatedProvider) VerifyMounted(pid int) error { return p.endpoint.VerifyMounted(pid) }

func (p *isolatedProvider) begin(ctx context.Context) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || p.closed || p.ctx.Err() != nil {
		return false
	}
	p.calls++
	return true
}

func (p *isolatedProvider) end() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls--
	if p.closed && p.calls == 0 {
		close(p.drained)
	}
}

func validResolvedOwner(auth *OwnerAuth) bool {
	_, _, err := auth.ProviderIdentity()
	return err == nil
}

// Prepare resolves native readiness while admission remains closed. Runtime
// must register this resource first, and call this before container launch.
func (p *isolatedProvider) Prepare(ctx context.Context) error {
	if !p.begin(ctx) {
		return ErrClosed
	}
	defer p.end()
	p.mu.Lock()
	if p.state != isolatedNew || !p.seeded {
		p.mu.Unlock()
		return ErrClosed
	}
	p.state = isolatedOpening
	p.mu.Unlock()
	run, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.ctx, cancel)
	defer stop()
	defer cancel()
	auth, _, err := p.owner.resolve(run, false)
	if err != nil || !validResolvedOwner(auth) {
		p.owner.invalidate()
		p.mu.Lock()
		p.state = isolatedBlocked
		p.mu.Unlock()
		return ErrOwnerAuth
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || run.Err() != nil || p.ctx.Err() != nil {
		p.state = isolatedBlocked
		return ErrClosed
	}
	p.auth, p.state = auth, isolatedPrepared
	return nil
}

// Open performs no credential/native preparation. It belongs only to the
// verified, bounded inert-bootstrap admission phase.
func (p *isolatedProvider) Open() error {
	if !p.begin(p.ctx) {
		return ErrClosed
	}
	defer p.end()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != isolatedPrepared || p.endpoint.Open() != nil {
		return ErrClosed
	}
	p.state = isolatedReady
	return nil
}

func (p *isolatedProvider) respond(ctx context.Context, request Request) (Response, error) {
	if !p.begin(ctx) {
		return localAuthResponse(503, "unavailable", nil), nil
	}
	defer p.end()
	// Endpoint owns this context through response-body completion. Cancelling
	// it on responder return would close a successful streaming body too early.
	call := ctx
	if request.Operation == Refresh {
		return p.refreshLocal(call, request), nil
	}
	if request.Operation != Catalog && request.Operation != Inference {
		return localAuthResponse(400, "denied", nil), nil
	}
	p.mu.Lock()
	if p.closed || call.Err() != nil || p.state == isolatedBlocked || p.state == isolatedNew || p.state == isolatedOpening {
		p.mu.Unlock()
		return localAuthResponse(503, "unavailable", nil), nil
	}
	if !p.local.matches(request) || p.state != isolatedReady {
		p.mu.Unlock()
		return localAuthResponse(401, "denied", nil), nil
	}
	// This is the owner-auth dispatch authorization boundary. Previously
	// authorized calls may finish; no later old-version call passes this lock
	// after the first verified 401 has fenced it. Never hold it across I/O.
	auth, version := p.auth, p.ownerVersion
	p.mu.Unlock()
	access, account, err := auth.ProviderIdentity()
	if err != nil {
		p.block(true)
		return localAuthResponse(503, "unavailable", nil), nil
	}
	upstream := request
	upstream.Header = request.Header.Clone()
	upstream.Header.Set("Authorization", "Bearer "+access)
	upstream.Header.Set("Chatgpt-Account-Id", account)
	response, err := p.send(call, upstream)
	// A status attached to a transport/policy failure, an absent body, or an
	// SSE error string cannot grant refresh authority. Never replay this request.
	if err == nil && response.Status == 401 && response.Body != nil {
		err = p.recoverOwner(call, version)
	}
	return response, err
}

func (p *isolatedProvider) block(taint bool) {
	p.mu.Lock()
	p.state, p.auth = isolatedBlocked, nil
	p.mu.Unlock()
	if taint {
		p.owner.invalidate()
	}
}

func (p *isolatedProvider) recoverOwner(ctx context.Context, version uint8) error {
	p.mu.Lock()
	if p.closed || ctx.Err() != nil || version != p.ownerVersion || p.state != isolatedReady {
		p.mu.Unlock()
		return nil // Concurrent/late response cannot spend another recovery.
	}
	if p.recoveryStarted || p.localUsed || !p.endpoint.hasRefreshBudget() {
		taint := p.recoveryStarted // Local-budget exhaustion alone is not taint.
		p.state, p.auth = isolatedBlocked, nil
		p.mu.Unlock()
		if taint {
			p.owner.invalidate()
		}
		return ErrOwnerAuth
	}
	p.recoveryStarted, p.state = true, isolatedRecovering
	p.recoveryDone = make(chan struct{})
	p.mu.Unlock()

	auth, refreshed, err := p.owner.resolve(ctx, true)
	if err != nil || !refreshed || !validResolvedOwner(auth) {
		p.owner.invalidate()
		err = ErrOwnerAuth
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	defer close(p.recoveryDone)
	if err != nil || p.closed || ctx.Err() != nil {
		p.state, p.auth = isolatedBlocked, nil
		return ErrOwnerAuth
	}
	p.auth = auth
	p.ownerVersion++
	p.state = isolatedAwaitRefresh
	return nil
}

func (p *isolatedProvider) refreshLocal(ctx context.Context, request Request) Response {
	var fields map[string]string
	if request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Authorization") != "" || request.Header.Get("Chatgpt-Account-Id") != "" ||
		strictjson.Decode(request.Body, 8192, 4, &fields) != nil || len(fields) != 3 || fields["grant_type"] != "refresh_token" || fields["client_id"] != "app_EMoamEEZ73f0CkXaXp7hrann" {
		return localAuthResponse(400, "denied", nil)
	}
	for {
		p.mu.Lock()
		if p.closed || ctx.Err() != nil || p.state == isolatedNew || p.state == isolatedOpening || p.state == isolatedBlocked {
			p.mu.Unlock()
			return localAuthResponse(503, "unavailable", nil)
		}
		if p.localUsed || !equalLocal(fields["refresh_token"], p.local.refresh) {
			p.mu.Unlock()
			return localAuthResponse(401, "denied", nil)
		}
		if p.state == isolatedRecovering {
			done := p.recoveryDone
			p.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return localAuthResponse(503, "unavailable", nil)
			}
		}
		next, err := newLocalAuth(p.local.account, p.local.subject)
		if err != nil {
			p.state, p.auth = isolatedBlocked, nil
			p.mu.Unlock()
			return localAuthResponse(503, "unavailable", nil)
		}
		data, err := json.Marshal(next.tokens())
		if err != nil {
			p.mu.Unlock()
			return localAuthResponse(503, "unavailable", nil)
		}
		p.local, p.localUsed, p.state = next, true, isolatedReady
		p.mu.Unlock()
		return localAuthResponse(200, "refresh", data)
	}
}

// Successful cleanup says nothing about credential health. Invalidation lives
// on the original controller-held source and survives removing this resource
// from runtime's map; controller must retire it before releasing occupancy.
func (p *isolatedProvider) Close(ctx context.Context) error {
	p.mu.Lock()
	if !p.closed {
		p.closed, p.auth = true, nil
		p.cancel()
		if p.calls == 0 {
			close(p.drained)
		}
	}
	p.mu.Unlock()
	p.endpoint.Stop()
	if ctx == nil {
		return ErrCleanup
	}
	// Attempt both joins even if one fails. Timeouts remain retryable, with no
	// resource/occupancy release by this object and no detached recovery task.
	ownerErr := p.owner.close(ctx)
	endpointErr := p.endpoint.Close(ctx)
	select {
	case <-p.drained:
	case <-ctx.Done():
		return ErrCleanup
	}
	if ownerErr != nil || endpointErr != nil {
		return ErrCleanup
	}
	p.releaseOnce.Do(func() {
		if p.release != nil {
			p.release()
		}
	})
	return nil
}

type localAuth struct {
	access, refresh, identity, account, subject string
	minted                                      time.Time
}

func localRandom() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", ErrConfiguration
	}
	return hex.EncodeToString(nonce[:]), nil
}

func newLocalAuth(account, subject string) (localAuth, error) {
	var a localAuth
	values := make([]string, 5)
	for i := range values {
		var err error
		values[i], err = localRandom()
		if err != nil {
			return a, err
		}
	}
	if account == "" {
		account, subject = "hsg-local-account-"+values[2], "hsg-local-subject-"+values[3]
	}
	a = localAuth{access: "hsg-local-access-" + values[0], refresh: "hsg-local-refresh-" + values[1], account: account, subject: subject, minted: time.Now().UTC()}
	claims, err := json.Marshal(map[string]any{"sub": subject, "email": "local@hsg.invalid", "exp": a.minted.Add(time.Hour).Unix(),
		"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": account, "chatgpt_plan_type": "pro"}})
	if err != nil {
		return localAuth{}, ErrConfiguration
	}
	// A fictional native-compatible identity, not a signed upstream credential.
	a.identity = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims) + "." + values[4]
	return a, nil
}

func (a localAuth) tokens() map[string]string {
	return map[string]string{"access_token": a.access, "refresh_token": a.refresh, "id_token": a.identity, "account_id": a.account}
}
func (a localAuth) file() ([]byte, error) {
	return json.Marshal(map[string]any{"auth_mode": "chatgpt", "OPENAI_API_KEY": nil, "tokens": a.tokens(), "last_refresh": a.minted.Format(time.RFC3339Nano)})
}
func equalLocal(received, expected string) bool {
	return expected != "" && subtle.ConstantTimeCompare([]byte(received), []byte(expected)) == 1
}
func (a localAuth) matches(request Request) bool {
	return equalLocal(request.Header.Get("Authorization"), "Bearer "+a.access) && equalLocal(request.Header.Get("Chatgpt-Account-Id"), a.account)
}

// Provenance is private metadata for diagnostics only; it never grants request
// authority and cannot be manufactured by response bytes from the upstream.
type localAuthBody struct {
	io.ReadCloser
	kind string
}

func (b *localAuthBody) localAuthResult() string { return b.kind }

func localAuthResponse(status int, kind string, data []byte) Response {
	return Response{Status: status, MediaType: "application/json", Body: &localAuthBody{io.NopCloser(bytes.NewReader(data)), kind}}
}
