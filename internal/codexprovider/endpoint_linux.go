package codexprovider

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"golang.org/x/sys/unix"
)

type responder func(context.Context, Request) (Response, error)

type Endpoint struct {
	ctx                           context.Context
	cancel                        context.CancelFunc
	listener                      net.Listener
	certificate                   tls.Certificate
	respond                       responder
	socket, ca                    string
	socketDev, socketIno          uint64
	caDev, caIno                  uint64
	caHash                        string
	uid                           uint32
	mu                            sync.Mutex
	opened, closed, cleanupFailed bool
	active                        map[net.Conn]struct{}
	counts                        map[Operation]int
	rejected                      map[Operation]responseRejection
	diagnostics                   []ExchangeDiagnostic
	workers                       sync.WaitGroup
	done                          chan struct{}
}

// NewLive creates no external connection. Only a later verified Open followed
// by an accepted operation can use the fixed TLS upstream. Normal executable
// configuration selects it only through the opt-in fixed Codex factory.
func NewLive(ctx context.Context, directory string, peer localidentity.UID) (*Endpoint, error) {
	return newEndpoint(ctx, directory, peer, liveResponse)
}

func newEndpoint(ctx context.Context, directory string, peer localidentity.UID, respond responder) (*Endpoint, error) {
	if ctx == nil || ctx.Err() != nil || peer.Validate() != nil || peer.Uint32() != uint32(os.Geteuid()) || respond == nil ||
		!filepath.IsAbs(directory) || filepath.Clean(directory) != directory || strings.ContainsAny(directory, "\x00,\r\n") {
		return nil, ErrConfiguration
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrConfiguration
	}
	resolved, err := filepath.EvalSymlinks(directory)
	var root unix.Stat_t
	entries, readErr := os.ReadDir(directory)
	if err != nil || resolved != directory || unix.Lstat(directory, &root) != nil || root.Mode&unix.S_IFMT != unix.S_IFDIR || root.Mode&0o777 != 0o700 || root.Uid != peer.Uint32() || readErr != nil || len(entries) != 0 {
		return nil, ErrConfiguration
	}
	certificate, ca, err := newCertificate()
	if err != nil {
		return nil, ErrConfiguration
	}
	caPath := filepath.Join(directory, "ca.pem")
	file, err := os.OpenFile(caPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, ErrConfiguration
	}
	_, writeErr := file.Write(ca)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return nil, ErrConfiguration
	}
	socket := filepath.Join(directory, "owner.sock")
	listener, err := localhttp.Listen(socket, peer)
	if err != nil {
		return nil, ErrConfiguration
	}
	var ss, cs unix.Stat_t
	if unix.Stat(socket, &ss) != nil || unix.Stat(caPath, &cs) != nil {
		_ = listener.Close()
		return nil, ErrConfiguration
	}
	run, cancel := context.WithCancel(ctx)
	digest := sha256.Sum256(ca)
	e := &Endpoint{ctx: run, cancel: cancel, listener: listener, certificate: certificate, respond: respond, socket: socket, ca: caPath,
		socketDev: uint64(ss.Dev), socketIno: ss.Ino, caDev: uint64(cs.Dev), caIno: cs.Ino, caHash: hex.EncodeToString(digest[:]), uid: peer.Uint32(),
		active: make(map[net.Conn]struct{}), counts: make(map[Operation]int), rejected: make(map[Operation]responseRejection), done: make(chan struct{})}
	go e.serve()
	return e, nil
}

func newCertificate() (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "HSG per-Run provider CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "HSG fixed provider endpoint"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
		DNSNames: []string{"chatgpt.com", "auth.openai.com"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{leafDER, der}, PrivateKey: leafKey}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), err
}

// Paths are trusted runtime construction inputs. Neither is accepted from a
// message or a model. The private key has no file or accessor.
func (e *Endpoint) Paths() (socket, ca string) { return e.socket, e.ca }
func (e *Endpoint) Done() <-chan struct{}      { return e.done }
func (e *Endpoint) Open() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.opened || e.ctx.Err() != nil {
		return ErrClosed
	}
	e.opened = true
	return nil
}
func (e *Endpoint) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.closed = true
	e.cancel()
	e.remember(e.listener.Close())
	for conn := range e.active {
		e.remember(conn.Close())
	}
}
func (e *Endpoint) remember(err error) {
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
		e.cleanupFailed = true
	}
}

// A timeout is not joined cleanup. The owner retains the obligation and can
// retry waiting; an actual close error is sticky until process replacement.
func (e *Endpoint) Close(ctx context.Context) error {
	e.Stop()
	if ctx == nil {
		return ErrCleanup
	}
	select {
	case <-e.done:
	case <-ctx.Done():
		return errors.Join(ErrCleanup, ctx.Err())
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cleanupFailed {
		return ErrCleanup
	}
	return nil
}
func (e *Endpoint) serve() {
	stop := context.AfterFunc(e.ctx, e.Stop)
	defer stop()
	for accepted := 0; accepted < MaxConnections; accepted++ {
		conn, err := e.listener.Accept()
		if err != nil {
			e.Stop()
			break
		}
		e.mu.Lock()
		e.diagnostics = append(e.diagnostics, ExchangeDiagnostic{Operation: "unknown", Stage: "admission"})
		if e.closed || !e.opened || len(e.active) == MaxConcurrent {
			e.diagnostics[accepted].Finished = true
			e.remember(conn.Close())
			e.mu.Unlock()
			continue
		}
		e.active[conn] = struct{}{}
		e.workers.Add(1)
		e.mu.Unlock()
		go func(index int) {
			defer e.workers.Done()
			defer func() { e.mu.Lock(); e.remember(conn.Close()); delete(e.active, conn); e.mu.Unlock() }()
			diagnostic := e.exchange(conn)
			e.mu.Lock()
			e.diagnostics[index] = diagnostic
			e.mu.Unlock()
		}(accepted)
	}
	// Exhaustion stops new connections while accepted work retains its deadline.
	e.mu.Lock()
	e.remember(e.listener.Close())
	e.mu.Unlock()
	e.workers.Wait()
	e.Stop()
	close(e.done)
}

func deadline(ctx context.Context, duration time.Duration) time.Time {
	end := time.Now().Add(duration)
	if limit, ok := ctx.Deadline(); ok && limit.Before(end) {
		end = limit
	}
	return end
}
func readRequest(conn net.Conn) (*http.Request, *bufio.Reader, *io.LimitedReader, error) {
	limit := &io.LimitedReader{R: conn, N: MaxHeaderBytes}
	reader := bufio.NewReader(limit)
	r, err := http.ReadRequest(reader)
	return r, reader, limit, err
}

// This lock is the upstream dispatch authorization boundary. Previously
// authorized calls can finish after a rejection; no later call may acquire
// authority for that operation. The lock is never held across upstream I/O.
func (e *Endpoint) authorizeUpstream(ctx context.Context, operation Operation) (bool, responseRejection) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.opened || e.closed || ctx.Err() != nil {
		return false, rejectionNone
	}
	reason := e.rejected[operation]
	return reason == rejectionNone, reason
}

func (e *Endpoint) rejectOperation(operation Operation, reason responseRejection) {
	if reason == rejectionNone {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.rejected[operation] == rejectionNone {
		e.rejected[operation] = reason
	}
}

func (e *Endpoint) exchange(conn net.Conn) (diagnostic ExchangeDiagnostic) {
	diagnostic.Operation, diagnostic.Stage = "unknown", "connect"
	defer func() {
		diagnostic.Finished = true
		diagnostic.Cancelled = diagnostic.Cancelled || e.ctx.Err() != nil
	}()
	if conn.SetDeadline(deadline(e.ctx, HeaderTimeout)) != nil {
		return
	}
	r, reader, _, err := readRequest(conn)
	if err != nil {
		return
	}
	defer r.Body.Close()
	if r.Method != "CONNECT" || r.Proto != "HTTP/1.1" || (r.Host != "chatgpt.com:443" && r.Host != "auth.openai.com:443") ||
		r.RequestURI != r.Host || r.ContentLength > 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || reader.Buffered() != 0 {
		return
	}
	for name, values := range r.Header {
		if name != "User-Agent" || len(values) != 1 || len(values[0]) > 512 {
			return
		}
	}
	if _, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{e.certificate}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	diagnostic.Stage = "client_tls"
	if secure.HandshakeContext(e.ctx) != nil {
		return
	}
	diagnostic.Stage = "request_headers"
	inner, _, limit, err := readRequest(secure)
	if err != nil {
		return
	}
	defer inner.Body.Close()
	if inner.Host != strings.TrimSuffix(r.Host, ":443") {
		return
	}
	limit.N = MaxBodyBytes + 1
	diagnostic.Stage = "request_body"
	body, err := io.ReadAll(io.LimitReader(inner.Body, MaxBodyBytes+1))
	if err != nil || len(body) > MaxBodyBytes {
		return
	}
	diagnostic.Stage = "request_policy"
	request, err := project(inner, body)
	if err != nil {
		writeDenied(secure, 400)
		return
	}
	diagnostic.Operation = diagnosticOperation(request.Operation)
	diagnostic.Stage = "operation_budget"
	e.mu.Lock()
	allowed := e.opened && !e.closed && e.ctx.Err() == nil
	if allowed {
		e.counts[request.Operation]++
		bound := MaxConnections
		if request.Operation == Refresh {
			bound = 1
		}
		if request.Operation == Catalog {
			bound = 2
		}
		allowed = e.counts[request.Operation] <= bound
	}
	e.mu.Unlock()
	if !allowed {
		writeDenied(secure, 503)
		return
	}
	if request.Operation == Settings {
		diagnostic.Stage = "local_settings"
		writeDenied(secure, 404)
		return
	}
	diagnostic.Stage = "exchange_deadline"
	if conn.SetDeadline(deadline(e.ctx, IdleTimeout)) != nil {
		return
	}
	callCtx, cancel := context.WithCancel(e.ctx)
	var closeResponse func()
	defer func() {
		diagnostic.Cancelled = callCtx.Err() != nil
		cancel()
		if closeResponse != nil {
			closeResponse()
		}
	}()
	idle := time.AfterFunc(IdleTimeout, cancel)
	defer idle.Stop()
	diagnostic.Stage = "upstream_admission"
	var rejection responseRejection
	diagnostic.UpstreamAuthorized, rejection = e.authorizeUpstream(callCtx, request.Operation)
	if !diagnostic.UpstreamAuthorized {
		if rejection != rejectionNone {
			diagnostic.Stage = "operation_rejected"
			diagnostic.Reason = diagnosticRejection(rejection)
		}
		writeDenied(secure, 503)
		return
	}
	diagnostic.Stage = "upstream"
	response, err := e.respond(callCtx, request)
	diagnostic.UpstreamStatus = diagnosticStatus(response.Status)
	var failure upstreamFailure
	if errors.As(err, &failure) {
		diagnostic.Stage = failure.stage
		diagnostic.UpstreamStatus = diagnosticStatus(failure.status)
		diagnostic.Reason = diagnosticRejection(failure.rejection)
		// Publish rejection before client writes or response-body cleanup can
		// block. Neither diagnostics nor cleanup completion grants new calls.
		e.rejectOperation(request.Operation, failure.rejection)
	}
	if response.Body == nil {
		writeDenied(secure, 502)
		return
	}
	var closeOnce sync.Once
	closeBody := func() {
		closeOnce.Do(func() { err := response.Body.Close(); e.mu.Lock(); e.remember(err); e.mu.Unlock() })
	}
	stopClose := context.AfterFunc(callCtx, closeBody)
	closeResponse = func() {
		stopClose()
		closeBody()
	}
	if body, ok := response.Body.(*upstreamBody); ok {
		diagnostic.ResponseProtocol = body.metadata.protocol
		diagnostic.ContentTypeState = body.metadata.contentType
		diagnostic.ResponseFraming = body.metadata.framing
		diagnostic.DeclaredBody = body.metadata.length
	}
	if err != nil || callCtx.Err() != nil {
		if callCtx.Err() == nil && (failure.rejection == rejectionContentTypeMissing || failure.rejection == rejectionContentTypeInvalid) {
			diagnostic.observeRejectedBody(callCtx, response.Body)
		}
		writeDenied(secure, 502)
		return
	}
	if response.Status != 200 {
		diagnostic.Stage = "upstream_status"
		status := 502
		if response.Status == 400 || response.Status == 401 || response.Status == 403 || response.Status == 429 {
			status = response.Status
		}
		writeDenied(secure, status)
		return
	}
	media := "application/json"
	if request.Operation == Inference {
		media = "text/event-stream"
	}
	diagnostic.MediaClass = diagnosticMedia(response.MediaType)
	if response.MediaType != media {
		diagnostic.Stage = "upstream_policy"
		diagnostic.Reason = diagnosticRejection(rejectionMediaType)
		e.rejectOperation(request.Operation, rejectionMediaType)
		diagnostic.observeRejectedBody(callCtx, response.Body)
		writeDenied(secure, 502)
		return
	}
	// An explicit message boundary is required: raw EOF without TLS close_notify
	// is truncation to native TLS clients. End chunks only after a clean body EOF;
	// cancellation, an over-budget body or a producer error must stay incomplete.
	diagnostic.Stage = "response_headers"
	if _, err := fmt.Fprintf(secure, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n", media); err != nil {
		return
	}
	remaining, empty := MaxBodyBytes, 0
	var buffer [32 << 10]byte
	for {
		diagnostic.Stage = "response_read"
		n, readErr := response.Body.Read(buffer[:min(len(buffer), remaining+1)])
		if callCtx.Err() != nil {
			return
		}
		if n > remaining {
			diagnostic.Stage = "response_budget"
			return
		}
		if n > 0 {
			diagnostic.Stage = "response_write"
			empty = 0
			idle.Reset(IdleTimeout)
			if conn.SetWriteDeadline(deadline(callCtx, IdleTimeout)) != nil {
				return
			}
			if _, err := fmt.Fprintf(secure, "%x\r\n", n); err != nil {
				return
			}
			if _, err := secure.Write(buffer[:n]); err != nil {
				return
			}
			if _, err := io.WriteString(secure, "\r\n"); err != nil {
				return
			}
			remaining -= n
		} else {
			empty++
		}
		if readErr == io.EOF {
			diagnostic.Stage = "response_write"
			if _, err := io.WriteString(secure, "0\r\n\r\n"); err == nil {
				diagnostic.Stage = "complete"
			}
			return
		}
		if readErr != nil || empty >= 3 {
			diagnostic.Stage = "response_read"
			return
		}
	}
}

func writeDenied(conn net.Conn, status int) {
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: 15\r\nConnection: close\r\n\r\nrequest denied\n", status, http.StatusText(status))
}

// VerifyMounted is called only while the independently attested bootstrap is
// inert, with its PID/start identity rechecked by the runtime afterward.
func (e *Endpoint) VerifyMounted(pid int) error {
	if pid <= 1 {
		return ErrDenied
	}
	for _, entry := range []struct {
		path     string
		dev, ino uint64
		kind     uint32
		hash     string
	}{
		{SocketPath, e.socketDev, e.socketIno, unix.S_IFSOCK, ""}, {CAPath, e.caDev, e.caIno, unix.S_IFREG, e.caHash},
	} {
		path := fmt.Sprintf("/proc/%d/root%s", pid, entry.path)
		var st unix.Stat_t
		if unix.Stat(path, &st) != nil || uint64(st.Dev) != entry.dev || st.Ino != entry.ino || st.Mode&unix.S_IFMT != entry.kind || st.Mode&0o777 != 0o600 || st.Uid != e.uid {
			return ErrDenied
		}
		if entry.hash != "" {
			data, err := os.ReadFile(path)
			if err != nil || len(data) > 8192 {
				return ErrDenied
			}
			sum := sha256.Sum256(data)
			if hex.EncodeToString(sum[:]) != entry.hash {
				return ErrDenied
			}
		}
	}
	return nil
}
