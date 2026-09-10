// Package providerrelay supplies an opaque, bounded loopback-to-Unix relay.
// It performs no TLS termination, HTTP authorization or external networking.
// Trusted runtime construction must supply a per-Run endpoint and enforce the
// native-tool boundary; a reachable relay is not proof of client identity.
package providerrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
)

const (
	MaxConnections = 16
	MaxConcurrent  = 4
	MaxBytes       = 4 << 20 // Per direction and connection, including TLS bytes.
	DialTimeout    = 2 * time.Second
)

var (
	ErrConfiguration = errors.New("providerrelay: invalid fixed endpoint")
	ErrEndpoint      = errors.New("providerrelay: endpoint unavailable or mismatched")
	ErrBudget        = errors.New("providerrelay: byte budget exhausted")
	ErrServing       = errors.New("providerrelay: listener failed")
	ErrCleanup       = errors.New("providerrelay: cleanup failed")
)

type connection struct{ client, owner net.Conn }

// Relay has one pinned socket inode, peer UID, deadline and listener. It has
// no reopen, destination selection or retry API. The endpoint owner must check
// every operation itself; neither CONNECT bytes nor the loopback address grant
// authority. Limits here are a component ceiling, not a production Run policy.
type Relay struct {
	ctx      context.Context
	cancel   context.CancelFunc
	endpoint *os.File
	peer     localidentity.UID
	listener net.Listener
	address  string
	done     chan struct{}
	mu       sync.Mutex
	closed   bool
	failure  error
	active   map[*connection]struct{}
	workers  sync.WaitGroup
}

// Start pins an existing Unix socket without following symlinks, then listens
// on a fresh IPv4 loopback port. ctx must have the admitted Run's deadline.
// socket and peer are trusted construction inputs, never request fields.
// The runtime must protect the endpoint's ancestry/mount and bind it to the
// verified Run before opening provider admission. This component does not do
// enrollment, runtime attestation or global routing configuration.
func Start(ctx context.Context, socket string, peer localidentity.UID) (*Relay, error) {
	if ctx == nil || ctx.Err() != nil || peer.Validate() != nil || !filepath.IsAbs(socket) ||
		filepath.Clean(socket) != socket || strings.ContainsRune(socket, 0) {
		return nil, ErrConfiguration
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrConfiguration
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, socket, &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, ErrConfiguration
	}
	endpoint := os.NewFile(uintptr(fd), "fixed-provider-socket")
	var metadata unix.Stat_t
	if unix.Fstat(fd, &metadata) != nil || metadata.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		metadata.Uid != peer.Uint32() || metadata.Mode&0o007 != 0 {
		_ = endpoint.Close()
		return nil, ErrConfiguration
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = endpoint.Close()
		return nil, ErrServing
	}
	run, cancel := context.WithCancel(ctx)
	r := &Relay{ctx: run, cancel: cancel, endpoint: endpoint, peer: peer,
		listener: listener, address: listener.Addr().String(), done: make(chan struct{}), active: make(map[*connection]struct{})}
	go r.serve()
	return r, nil
}

// Address is only the loopback transport address. A future immutable adapter
// must separately bind its proxy/CA settings; this is not a credential token.
func (r *Relay) Address() string { return r.address }

// Close stops admission, cancels dialing/copying and joins every owned worker
// before closing the pinned descriptor. It is safe to call concurrently.
func (r *Relay) Close() error {
	r.stop(nil)
	return r.Wait()
}

// Wait reports completion after all owned descriptors and copy workers close.
// It never interprets an upstream EOF as a successful provider operation.
func (r *Relay) Wait() error {
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failure
}

func (r *Relay) remember(err error) {
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) && r.failure == nil {
		r.failure = ErrCleanup
	}
}

func (r *Relay) closePair(pair *connection) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remember(pair.client.Close())
	if pair.owner != nil {
		r.remember(pair.owner.Close())
	}
}

func (r *Relay) stop(reason error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if reason != nil && r.failure == nil {
		r.failure = reason
	}
	if r.closed {
		return
	}
	r.closed = true
	r.cancel()
	r.remember(r.listener.Close())
	for pair := range r.active {
		r.remember(pair.client.Close())
		if pair.owner != nil {
			r.remember(pair.owner.Close())
		}
	}
}

func (r *Relay) serve() {
	stopContext := context.AfterFunc(r.ctx, func() { r.stop(nil) })
	defer stopContext()
	for accepted := 0; accepted < MaxConnections; accepted++ {
		client, err := r.listener.Accept()
		if err != nil {
			if r.ctx.Err() == nil {
				r.stop(ErrServing)
			}
			break
		}
		r.mu.Lock()
		if r.closed || len(r.active) == MaxConcurrent {
			r.remember(client.Close())
			r.mu.Unlock()
			continue
		}
		pair := &connection{client: client}
		r.active[pair] = struct{}{}
		r.workers.Add(1)
		r.mu.Unlock()
		go r.bridge(pair)
	}
	// Exhausting admission closes the listener without prematurely closing
	// the last accepted exchange. The deadline/Close still interrupts workers.
	r.mu.Lock()
	r.remember(r.listener.Close())
	r.mu.Unlock()
	r.workers.Wait()
	r.stop(nil)
	r.mu.Lock()
	r.remember(r.endpoint.Close())
	r.mu.Unlock()
	close(r.done)
}

func (r *Relay) bridge(pair *connection) {
	defer r.workers.Done()
	defer func() {
		r.closePair(pair)
		r.mu.Lock()
		delete(r.active, pair)
		r.mu.Unlock()
	}()
	// Dial the held socket object, never re-resolve its original pathname.
	// The O_PATH descriptor remains live until every worker has joined.
	dialer := net.Dialer{Timeout: DialTimeout}
	owner, err := dialer.DialContext(r.ctx, "unix", fmt.Sprintf("/proc/self/fd/%d", r.endpoint.Fd()))
	if err != nil {
		if r.ctx.Err() == nil {
			r.stop(ErrEndpoint)
		}
		return
	}
	if !matchesPeer(owner, r.peer) {
		_ = owner.Close()
		r.stop(ErrEndpoint)
		return
	}
	r.mu.Lock()
	if r.closed {
		r.remember(owner.Close())
		r.mu.Unlock()
		return
	}
	pair.owner = owner
	r.mu.Unlock()
	deadline, _ := r.ctx.Deadline()
	if pair.client.SetDeadline(deadline) != nil || owner.SetDeadline(deadline) != nil {
		return
	}
	copied := make(chan int64, 2)
	copyOne := func(dst, src net.Conn) {
		n, _ := io.Copy(dst, io.LimitReader(src, MaxBytes))
		copied <- n
	}
	go copyOne(owner, pair.client)
	go copyOne(pair.client, owner)
	first := <-copied
	r.closePair(pair) // Either end or a byte limit terminates both directions.
	second := <-copied
	if first == MaxBytes || second == MaxBytes {
		r.stop(ErrBudget)
	}
}

func matchesPeer(conn net.Conn, expected localidentity.UID) bool {
	socket, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return false
	}
	matched := false
	err = raw.Control(func(fd uintptr) {
		peer, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		matched = err == nil && peer != nil && localidentity.UID(peer.Uid).Validate() == nil && peer.Uid == expected.Uint32()
	})
	return err == nil && matched
}
