//go:build linux

package codexprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

// ownerRefresh is private to the trusted native consumer. Its ephemeral URL is
// never a configuration/wire option or a Runner-facing refresh endpoint. At most
// one exchange reaches the fixed upstream, including rejection/timeout cases.
// The constructor starts only the local listener; the inert consumer must be
// registered as a Run resource before constructing it or starting native code.
type ownerRefresh struct {
	mu       sync.Mutex
	before   *OwnerAuth
	path     string
	address  string
	server   *http.Server
	listener net.Listener
	serveEnd chan struct{}
	joinEnd  chan struct{}
	joinOnce sync.Once
	workers  sync.WaitGroup
	cancel   context.CancelFunc
	send     responder
	closed   bool
	attempt  bool
	rejected bool
	receipt  *OwnerAuth // Complete validated upstream token group, never just RPC.
}

func (*ownerRefresh) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "codexprovider.ownerRefresh[redacted]")
}

func newOwnerRefresh(ctx context.Context, before *OwnerAuth, send responder) (*ownerRefresh, error) {
	if before == nil || before.refresh == "" || send == nil || ctx.Err() != nil {
		return nil, ErrOwnerAuth
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrOwnerAuth
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, ErrOwnerAuth
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &ownerRefresh{before: before, path: "/" + hex.EncodeToString(nonce[:]), address: ln.Addr().String(),
		listener: ln, serveEnd: make(chan struct{}), joinEnd: make(chan struct{}), cancel: cancel, send: send}
	r.server = &http.Server{Handler: r, ReadHeaderTimeout: HeaderTimeout, ReadTimeout: 5 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: MaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context { return ctx }, ErrorLog: log.New(io.Discard, "", 0)}
	r.server.SetKeepAlivesEnabled(false)
	go func() { defer close(r.serveEnd); _ = r.server.Serve(ln) }()
	return r, nil
}

func (r *ownerRefresh) nativeURL() string { return "http://" + r.address + r.path }

func (r *ownerRefresh) attempted() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.attempt
}

func (r *ownerRefresh) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	// A random local port is not authority. An unrelated scanner which lacks
	// the private nonce must not poison a legitimate invocation's state.
	if request.RequestURI != r.path {
		http.NotFound(w, request)
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	r.workers.Add(1) // Close latches admission under this same lock before Wait.
	r.mu.Unlock()
	defer r.workers.Done()
	deny := func() {
		r.mu.Lock()
		r.rejected = true
		r.mu.Unlock()
		http.Error(w, "unavailable", http.StatusBadGateway)
	}
	if request.Method != http.MethodPost || request.Proto != "HTTP/1.1" || request.Host != r.address ||
		request.RequestURI != r.path || request.URL.IsAbs() || request.URL.RawPath != "" ||
		len(request.TransferEncoding) != 0 || len(request.Trailer) != 0 ||
		request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Authorization") != "" {
		deny()
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 8193))
	defer clear(body)
	if err != nil || len(body) > 8192 || request.ContentLength != int64(len(body)) {
		deny()
		return
	}
	var fields map[string]string
	if strictjson.Decode(body, 8192, 4, &fields) != nil || len(fields) != 3 || fields["grant_type"] != "refresh_token" ||
		fields["client_id"] != "app_EMoamEEZ73f0CkXaXp7hrann" ||
		subtle.ConstantTimeCompare([]byte(fields["refresh_token"]), []byte(r.before.refresh)) != 1 {
		deny()
		return
	}
	r.mu.Lock()
	if r.closed || r.attempt || r.rejected {
		r.rejected = true
		r.mu.Unlock()
		http.Error(w, "unavailable", http.StatusBadGateway)
		return
	}
	r.attempt = true // Latch BEFORE dispatch; cancellation cannot authorize replay.
	r.mu.Unlock()
	ctx, cancel := context.WithTimeout(request.Context(), 50*time.Second)
	defer cancel()
	response, err := r.send(ctx, Request{Operation: Refresh, Header: http.Header{"Content-Type": {"application/json"}}, Body: body})
	if response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil || response.Status != http.StatusOK || response.MediaType != "application/json" || response.Body == nil {
		deny()
		return
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxOwnerAuthBytes+1))
	defer clear(data)
	if err != nil || response.Body.Close() != nil || ctx.Err() != nil {
		deny()
		return
	}
	receipt, err := ownerRefreshReceipt(r.before, data)
	if err != nil {
		deny()
		return
	}
	r.mu.Lock()
	r.receipt = receipt
	r.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if n, err := w.Write(data); err != nil || n != len(data) {
		deny()
	}
}

// Parse only the complete supported token group. Auxiliary OAuth metadata is
// not authority; missing/partial tokens are rejected rather than guessing the
// native version's merge behavior. ID claims check consistency, not signatures.
func ownerRefreshReceipt(before *OwnerAuth, data []byte) (*OwnerAuth, error) {
	var fields map[string]json.RawMessage
	if before == nil || strictjson.Decode(data, maxOwnerAuthBytes, 8, &fields) != nil || fields == nil {
		return nil, ErrOwnerAuth
	}
	tokens := map[string]string{"account_id": before.account}
	for _, k := range []string{"access_token", "refresh_token", "id_token"} {
		var value string
		if json.Unmarshal(fields[k], &value) != nil {
			return nil, ErrOwnerAuth
		}
		tokens[k] = value
	}
	for key := range fields {
		for _, k := range []string{"access_token", "refresh_token", "id_token", "account_id"} {
			if strings.EqualFold(k, key) && k != key {
				return nil, ErrOwnerAuth
			}
		}
	}
	if value, exists := fields["account_id"]; exists {
		var account string
		if json.Unmarshal(value, &account) != nil || account != before.account {
			return nil, ErrOwnerAuth
		}
	}
	canonical, err := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": tokens, "last_refresh": before.refreshed.Format(time.RFC3339Nano)})
	if err != nil {
		return nil, ErrOwnerAuth
	}
	defer clear(canonical)
	return ValidateOwnerAuthUpdate(before.encoded, canonical)
}

// close stops admission, sockets and cancellation-aware upstream work, and joins
// both Serve and every admitted callback. Timeout is not successful cleanup; the
// consumer retains this object and may join again during Run resource cleanup.
func (r *ownerRefresh) close(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.cancel()
	_ = r.listener.Close() // Also covers Close racing the first Serve call.
	_ = r.server.Close()
	r.joinOnce.Do(func() { go func() { <-r.serveEnd; r.workers.Wait(); close(r.joinEnd) }() })
	select {
	case <-r.joinEnd:
		return nil
	case <-ctx.Done():
		return ErrCleanup
	}
}

// candidate is called only after native and relay joins. No refresh means exact
// unchanged storage; an observed refresh requires its full token group plus an
// advancing native persistence marker, even when all token strings stay equal.
func (r *ownerRefresh) candidate(data []byte, force bool) (*OwnerAuth, bool, error) {
	select {
	case <-r.joinEnd:
	default:
		return nil, false, ErrOwnerAuth
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed || r.rejected || (r.attempt && r.receipt == nil) {
		return nil, false, ErrOwnerAuth
	}
	if !r.attempt {
		if force || !bytes.Equal(data, r.before.encoded) {
			return nil, false, ErrOwnerAuth
		}
		return r.before, false, nil
	}
	next, err := ValidateOwnerAuthUpdate(r.before.encoded, data)
	if err != nil || !next.refreshed.After(r.before.refreshed) || next.access != r.receipt.access ||
		next.refresh != r.receipt.refresh || next.identity != r.receipt.identity {
		return nil, false, ErrOwnerAuth
	}
	return next, true, nil
}
