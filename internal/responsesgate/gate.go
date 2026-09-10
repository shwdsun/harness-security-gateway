// Package responsesgate implements the bounded synthetic Responses consumer.
// It is not a provider proxy or an authority resolver. Trusted runtime code must
// bind one instance to one admitted Run and open it only after runtime checks.
package responsesgate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	MaxBodyBytes   = 2 << 20
	MaxHeaderBytes = 16 << 10
	MaxConnections = 8
	MaxAttempts    = 8
	MaxInferences  = 2
	HeaderTimeout  = 2 * time.Second
	IdleTimeout    = 5 * time.Second
)

var (
	ErrConfiguration = errors.New("responsesgate: invalid synthetic construction")
	ErrClosed        = errors.New("responsesgate: closed or already used")
	ErrServing       = errors.New("responsesgate: serving failed")
	ErrCleanup       = errors.New("responsesgate: cleanup incomplete")
)

// Request contains only a validated body and freshly constructed headers.
// There is no request-selected destination, operation, client or credential
// locator. The only operation is synthetic POST /v1/responses.
type Request struct {
	Header http.Header
	Body   []byte
}

type Response struct {
	StatusCode int
	Header     http.Header
	Body       io.ReadCloser
}

// Responder is a fixed in-process simulator supplied by trusted construction.
// It must honor context cancellation, perform no external I/O, and return a Body
// whose Close interrupts Read and joins any producer work before returning.
// Arbitrary model or repository code must never implement this callback.
// Serve waits for dispatched callbacks/body cleanup;
// an uncooperative callback cannot be declared cleaned up by a timeout.
type Responder func(context.Context, Request) (Response, error)

// Gate has one context, fresh synthetic bearer, authority and lifetime. It has
// no persistence/recovery API, public HTTP management route or runtime pin.
// Stop revokes immediately; the original Serve call waits for callback cleanup.
type Gate struct {
	ctx           context.Context
	cancel        context.CancelFunc
	responder     Responder
	authority     string
	bearer        string
	server        *http.Server
	mu            sync.Mutex
	opened        bool
	closed        bool
	served        bool
	active        bool
	attempts      int
	dispatches    int
	handlers      sync.WaitGroup
	cleanupFailed bool
}

// NewSynthetic constructs a closed instance. ctx must carry the admitted Run's
// deadline; its owner must cancel it on revocation, invalidation or owner loss.
// authority is the exact HTTP Host of the fixture-owned listener, not a dial
// target. No listener, DNS lookup, provider connection or goroutine is created.
func NewSynthetic(ctx context.Context, authority string, responder Responder) (*Gate, error) {
	if ctx == nil || ctx.Err() != nil || responder == nil || !validAuthority(authority) {
		return nil, ErrConfiguration
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrConfiguration
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, ErrConfiguration
	}
	run, cancel := context.WithCancel(ctx)
	g := &Gate{ctx: run, cancel: cancel, responder: responder, authority: authority,
		bearer: "Bearer " + hex.EncodeToString(token[:])}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	g.server = &http.Server{
		Handler: http.HandlerFunc(g.handle), Protocols: protocols,
		ReadHeaderTimeout: HeaderTimeout, ReadTimeout: IdleTimeout,
		WriteTimeout: IdleTimeout, IdleTimeout: IdleTimeout,
		// The pinned Go server adds a 4096-byte read allowance. Reserve it
		// inside the 16 KiB envelope, rather than claim a larger wire bound.
		MaxHeaderBytes: MaxHeaderBytes - 4096,
		ErrorLog:       log.New(io.Discard, "", 0),
		BaseContext:    func(net.Listener) context.Context { return g.ctx },
	}
	// One exchange per connection bounds parser failures and avoids any
	// pipelining/framing ambiguity reaching a second dispatch.
	g.server.SetKeepAlivesEnabled(false)
	return g, nil
}

func validAuthority(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".-:[]", c)) {
			return false
		}
	}
	return true
}

// SyntheticAuthorization returns only the freshly generated fixture bearer.
// It is not a provider credential or proof of the client's process identity.
func (g *Gate) SyntheticAuthorization() string { return g.bearer }

// Open is a one-use trusted Go operation, never an HTTP request. Its caller
// must serialize it with final runtime verification and cancellation. It does
// not itself verify a mount, runtime identity or durable admission record.
func (g *Gate) Open() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.opened || g.ctx.Err() != nil {
		return ErrClosed
	}
	g.opened = true
	return nil
}

// Stop is idempotent and closes the owned HTTP server and all its connections.
// It does not release source authority or report callback cleanup complete;
// the owner must wait for Serve to return before releasing that obligation.
func (g *Gate) Stop() {
	g.mu.Lock()
	g.closed = true
	g.cancel()
	g.mu.Unlock()
	g.recordCleanup(g.server.Close())
}

func (g *Gate) recordCleanup(err error) {
	if err != nil && !errors.Is(err, net.ErrClosed) {
		g.mu.Lock()
		g.cleanupFailed = true
		g.closed = true
		g.cancel()
		g.mu.Unlock()
	}
}

// Serve takes ownership of the fixture listener, even on failure. It may be
// called once, and returns only after admitted handlers and responders finish.
// It cannot be resumed for a new Run. No socket or listener is exposed to tools
// by this API; the composed runtime must enforce that transport separation.
func (g *Gate) Serve(listener net.Listener) error {
	if listener == nil {
		g.Stop()
		return ErrConfiguration
	}
	g.mu.Lock()
	if g.served || g.closed || g.ctx.Err() != nil {
		g.mu.Unlock()
		_ = listener.Close()
		return ErrClosed
	}
	g.served = true
	g.mu.Unlock()
	stop := context.AfterFunc(g.ctx, g.Stop)
	defer stop()
	err := g.server.Serve(&limitedListener{Listener: listener, ctx: g.ctx, record: g.recordCleanup})
	g.Stop()
	// handle adds while holding mu only before closed; Stop excludes every
	// future Add before this Wait, including a late connection handler.
	g.handlers.Wait()
	g.mu.Lock()
	failed := g.cleanupFailed
	g.mu.Unlock()
	if failed {
		return ErrCleanup
	}
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return ErrServing
}

type limitedListener struct {
	net.Listener
	ctx      context.Context
	accepted int // Accept is called serially by http.Server.
	record   func(error)
	once     sync.Once
	closeErr error
}

func (l *limitedListener) Close() error {
	l.once.Do(func() { l.closeErr = l.Listener.Close(); l.record(l.closeErr) })
	return l.closeErr
}

type ownedConn struct {
	net.Conn
	record   func(error)
	once     sync.Once
	closeErr error
}

func (c *ownedConn) Close() error {
	c.once.Do(func() { c.closeErr = c.Conn.Close(); c.record(c.closeErr) })
	return c.closeErr
}

func (l *limitedListener) Accept() (net.Conn, error) {
	if l.accepted == MaxConnections {
		// The underlying listener is already closed. Keep Serve alive for
		// the last accepted exchange until its owner closes the Run.
		<-l.ctx.Done()
		return nil, net.ErrClosed
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.ctx.Err() != nil {
		l.record(conn.Close())
		return nil, net.ErrClosed
	}
	l.accepted++
	if l.accepted == MaxConnections {
		_ = l.Close()
	}
	return &ownedConn{Conn: conn, record: l.record}, nil
}
