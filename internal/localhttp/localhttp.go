// Package localhttp provides the deliberately small HTTP-over-Unix-socket
// transport used between local trust domains.
package localhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

const (
	DefaultMaxHeaderBytes = 16 << 10
	DefaultReadTimeout    = 10 * time.Second
	DefaultWriteTimeout   = 30 * time.Second
	DefaultIdleTimeout    = 30 * time.Second
)

var (
	ErrNonAbsoluteSocket = errors.New("Unix socket path must be absolute")
	ErrSocketExists      = errors.New("Unix socket path already exists")
	ErrSocketInUse       = errors.New("Unix socket is accepting connections")
	ErrUnsafeSocket      = errors.New("existing Unix socket is not safe to remove")
	ErrContentType       = errors.New("request Content-Type must be application/json")
	ErrBodyTooLarge      = errors.New("request body exceeds byte limit")
	ErrPeerCredentials   = errors.New("cannot authenticate Unix peer credentials")
	ErrPeerUnsupported   = errors.New("Unix peer credentials are unsupported on this platform")
)

// RemoveStaleSocket removes only a non-listening Unix socket owned by the
// current effective user. Regular files, symlinks, foreign-owner sockets, and
// a socket that accepts a connection are never removed.
func RemoveStaleSocket(path string, probeTimeout time.Duration) (bool, error) {
	if !filepath.IsAbs(path) {
		return false, ErrNonAbsoluteSocket
	}
	if probeTimeout <= 0 || strings.ContainsRune(path, '\x00') {
		return false, ErrUnsafeSocket
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect Unix socket: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return false, ErrUnsafeSocket
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return false, ErrUnsafeSocket
	}
	connection, dialErr := net.DialTimeout("unix", path, probeTimeout)
	if dialErr == nil {
		_ = connection.Close()
		return false, ErrSocketInUse
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, syscall.ENOENT) {
		return false, fmt.Errorf("probe Unix socket: %w", dialErr)
	}

	// Recheck the inode after probing so a concurrently replaced listener is
	// not removed using stale information.
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reinspect Unix socket: %w", err)
	}
	currentStat, ok := current.Sys().(*syscall.Stat_t)
	if !ok || current.Mode()&os.ModeSocket == 0 || current.Mode()&os.ModeSymlink != 0 ||
		currentStat.Dev != stat.Dev || currentStat.Ino != stat.Ino || int(currentStat.Uid) != os.Geteuid() {
		return false, ErrUnsafeSocket
	}
	if err := os.Remove(path); err != nil {
		return false, fmt.Errorf("remove stale Unix socket: %w", err)
	}
	return true, nil
}

// Listen creates a mandatory peer-authenticated Unix listener without deleting
// anything already at path. An accepted connection reaches its caller only
// when Linux recorded exactly peerUID at connect time. Crash reconciliation
// must inspect a stale socket explicitly before removal.
func Listen(path string, peerUID localidentity.UID) (net.Listener, error) {
	if err := peerUID.Validate(); err != nil {
		return nil, err
	}
	if !peerCredentialsSupported() {
		return nil, ErrPeerUnsupported
	}
	listener, err := listenUnix(path, socketPermissions(peerUID))
	if err != nil {
		return nil, err
	}
	authenticated, err := newPeerUIDListener(listener, peerUID, connectedPeerUID)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	return authenticated, nil
}

func socketPermissions(peerUID localidentity.UID) os.FileMode {
	if peerUID.Uint32() == uint32(os.Geteuid()) {
		return 0o600
	}
	return 0o660
}

func listenUnix(path string, perm os.FileMode) (*net.UnixListener, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrNonAbsoluteSocket
	}
	if perm.Perm() == 0 || perm.Perm()&0007 != 0 {
		return nil, fmt.Errorf("socket permissions must be nonzero and deny other users: %04o", perm.Perm())
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, ErrSocketExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect Unix socket: %w", err)
	}

	addr := &net.UnixAddr{Name: path, Net: "unix"}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on Unix socket: %w", err)
	}
	ln.SetUnlinkOnClose(true)
	if err := os.Chmod(path, perm.Perm()); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("set Unix socket permissions: %w", err)
	}
	return ln, nil
}

type peerUIDReader func(net.Conn) (localidentity.UID, error)

type peerUIDListener struct {
	net.Listener
	expectedUID localidentity.UID
	readUID     peerUIDReader
}

func newPeerUIDListener(
	listener net.Listener,
	expectedUID localidentity.UID,
	readUID peerUIDReader,
) (net.Listener, error) {
	if listener == nil || readUID == nil {
		return nil, fmt.Errorf("%w: listener is not initialized", ErrPeerCredentials)
	}
	if err := expectedUID.Validate(); err != nil {
		return nil, err
	}
	return &peerUIDListener{Listener: listener, expectedUID: expectedUID, readUID: readUID}, nil
}

func (listener *peerUIDListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, credentialErr := listener.readUID(connection)
		if credentialErr != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("%w: %v", ErrPeerCredentials, credentialErr)
		}
		if uid == listener.expectedUID {
			return connection, nil
		}
		// Authentication rejection is deliberately byte-silent. Do not read
		// from or write to a connection before its UID has matched.
		_ = connection.Close()
	}
}

// NewClient returns an HTTP/1.1 client whose only dial target is socketPath.
func NewClient(socketPath string, timeout time.Duration) (*http.Client, error) {
	if !filepath.IsAbs(socketPath) {
		return nil, ErrNonAbsoluteSocket
	}
	if timeout <= 0 {
		return nil, errors.New("client timeout must be positive")
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   false,
		DisableCompression:  true,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}

// NewRequest builds a local request. The URL host is a fixed placeholder and
// is never used for dialing.
func NewRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	if len(path) == 0 || path[0] != '/' {
		return nil, errors.New("request path must begin with slash")
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://local"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// NewServer applies bounded defaults suitable for small local control APIs.
func NewServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: DefaultReadTimeout,
		ReadTimeout:       DefaultReadTimeout,
		WriteTimeout:      DefaultWriteTimeout,
		IdleTimeout:       DefaultIdleTimeout,
		MaxHeaderBytes:    DefaultMaxHeaderBytes,
	}
}

// ReadJSON reads and strictly decodes one application/json request body.
func ReadJSON(r *http.Request, maxBytes, maxDepth int, dst any) error {
	if maxBytes <= 0 || maxDepth <= 0 {
		return errors.New("JSON limits must be positive")
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return ErrContentType
	}
	if r.Body == nil {
		return errors.New("request body is required")
	}
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, int64(maxBytes)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	if len(data) > maxBytes {
		return ErrBodyTooLarge
	}
	return strictjson.Decode(data, maxBytes, maxDepth, dst)
}

// WriteJSON writes one bounded control-plane response.
func WriteJSON(w http.ResponseWriter, status int, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode response: %w", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if _, err := w.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}

// WriteProblem emits a stable error code without leaking internal details.
func WriteProblem(w http.ResponseWriter, status int, code string) {
	_ = WriteJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: code})
}
