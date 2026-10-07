//go:build linux && amd64

package codexprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"golang.org/x/sys/unix"
)

// Constructed by the isolated V4 candidate and registered as a Run resource
// before resolve. It uses the startup gate obtained before durable recovery and
// artifact FDs acquired from the sealed profile, never remote configuration.
// The candidate's composed acceptance and activation gates remain open.
type ownerNativeConsumer struct {
	mu      sync.Mutex
	serial  chan struct{}
	source  ownerNativeStorage
	files   *ownerNativeFiles // Borrowed from immutable owner-startup artifacts.
	root    string
	startup *ownerStartup
	send    responder
	active  *ownerNativeInvocation
	closed  bool
	failed  bool
}

type ownerNativeStorage interface {
	Read() ([]byte, error)
	Commit([]byte, []byte) error
	Invalidate()
}

type ownerNativeFiles struct{ launcher, native *os.File }

type ownerNativeInvocation struct {
	directory string
	process   *nativeAccountProcess
	relay     *ownerRefresh
	cancel    context.CancelFunc
}

func (*ownerNativeConsumer) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "codexprovider.ownerNativeConsumer[redacted]")
}

// The adapter's semantic auth failure must reach the same HeldSource retained
// by the controller. This changes health, never cleanup/occupancy ownership.
func (o *ownerNativeConsumer) invalidate() {
	o.source.Invalidate()
	o.mu.Lock()
	o.failed = true
	o.mu.Unlock()
}

// Inert: no source read, temporary home, listener, goroutine or process. Concrete
// OwnerAccess is mandatory outside tests; it remains owned by the controller.
func newOwnerNative(source *credentialsource.OwnerAccess, root string, startup *ownerStartup, files *ownerNativeFiles) (*ownerNativeConsumer, error) {
	if source == nil || startup == nil || startup.pid != os.Getpid() || files == nil || files.native == nil || files.launcher == nil ||
		!filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrOwnerAuth
	}
	return &ownerNativeConsumer{source: source, root: root, startup: startup, files: files, serial: make(chan struct{}, 1), send: liveResponse}, nil
}

// The isolated profile pins launcherSHA in its build manifest; this private
// function is not a configuration API. Native identity is the existing fixed
// CLI. Open FDs avoid a pathname replacement between verification and exec;
// root-controlled artifact installation must separately prevent in-place writes.
func openOwnerNativeFiles(launcherPath, nativePath, launcherSHA string) (*ownerNativeFiles, error) {
	launcher, err := openOwnerExecutable(launcherPath, launcherSHA, 4<<20)
	if err != nil {
		return nil, err
	}
	native, err := openOwnerExecutable(nativePath, codexprofile.CLIBinarySHA256V1, 270815680)
	if err != nil {
		launcher.Close()
		return nil, err
	}
	return &ownerNativeFiles{launcher: launcher, native: native}, nil
}

func openOwnerExecutable(path, digest string, limit int64) (*os.File, error) {
	want, err := hex.DecodeString(digest)
	if err != nil || len(want) != sha256.Size || !filepath.IsAbs(path) {
		return nil, ErrOwnerAuth
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrOwnerAuth
	}
	f := os.NewFile(uintptr(fd), "owner-native-artifact")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 ||
		st.Mode&(0022|unix.S_ISUID|unix.S_ISGID) != 0 || st.Mode&0111 == 0 ||
		(st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Size <= 0 || st.Size > limit {
		f.Close()
		return nil, ErrOwnerAuth
	}
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(f, 0, limit+1))
	var after unix.Stat_t
	if err != nil || n != st.Size || hex.EncodeToString(h.Sum(nil)) != digest || unix.Fstat(fd, &after) != nil ||
		after.Dev != st.Dev || after.Ino != st.Ino || after.Size != st.Size || after.Mode != st.Mode ||
		after.Uid != st.Uid || after.Gid != st.Gid || after.Nlink != st.Nlink || after.Mtim != st.Mtim || after.Ctim != st.Ctim {
		f.Close()
		return nil, ErrOwnerAuth
	}
	return f, nil
}

// resolve serializes native invocations within this Run. force is an owner
// decision (e.g. a verified upstream rejection), not a downstream refresh bit.
// It returns only after persistence and joins; an error latches invalidity and
// never replays or rolls back. The controller must retire failed generations.
func (o *ownerNativeConsumer) resolve(ctx context.Context, force bool) (*OwnerAuth, bool, error) {
	select {
	case o.serial <- struct{}{}:
	case <-ctx.Done():
		return nil, false, ErrOwnerAuth
	}
	defer func() { <-o.serial }()
	o.mu.Lock()
	if o.closed || o.failed || o.active != nil || o.startup == nil || o.startup.pid != os.Getpid() || ctx.Err() != nil {
		o.mu.Unlock()
		return nil, false, ErrOwnerAuth
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	inv := &ownerNativeInvocation{cancel: cancel}
	o.active = inv // Every resource from this point is reachable by close().
	o.mu.Unlock()

	auth, refreshed, err := o.invoke(ctx, inv, force)
	if err != nil {
		o.source.Invalidate()
		o.mu.Lock()
		o.failed = true
		o.mu.Unlock()
	}
	cancel()
	cleanup, stop := context.WithTimeout(context.Background(), 12*time.Second)
	defer stop()
	if inv.stop(cleanup) != nil {
		o.source.Invalidate()
		o.mu.Lock()
		o.failed = true
		o.mu.Unlock()
		return nil, false, ErrCleanup // Retain inv; close() must join it later.
	}
	o.mu.Lock()
	o.active = nil
	closed := o.closed
	o.mu.Unlock()
	if err != nil || closed {
		return nil, false, ErrOwnerAuth
	}
	return auth, refreshed, nil
}

func (o *ownerNativeConsumer) invoke(ctx context.Context, inv *ownerNativeInvocation, force bool) (*OwnerAuth, bool, error) {
	before, err := o.source.Read()
	defer clear(before)
	if err != nil {
		return nil, false, ErrOwnerAuth
	}
	parsed, err := ParseOwnerAuth(before)
	if err != nil {
		return nil, false, err
	}
	if err := inv.prepare(o.root, before); err != nil {
		return nil, false, err
	}
	inv.relay, err = newOwnerRefresh(ctx, parsed, o.send)
	if err != nil {
		return nil, false, err
	}
	cmd := exec.Command("/proc/self/fd/4")
	cmd.ExtraFiles = []*os.File{o.files.native, o.files.launcher}
	cmd.Dir = filepath.Join(inv.directory, "user")
	cmd.Env = []string{"HOME=" + cmd.Dir, "CODEX_HOME=" + filepath.Join(inv.directory, "auth"),
		"CODEX_SQLITE_HOME=" + filepath.Join(inv.directory, "state"), "TMPDIR=" + filepath.Join(inv.directory, "tmp"),
		"PATH=/nonexistent", "LANG=C.UTF-8", "CODEX_REFRESH_TOKEN_URL_OVERRIDE=" + inv.relay.nativeURL()}
	inv.process = &nativeAccountProcess{cmd: cmd}
	if ctx.Err() != nil || inv.process.start() != nil {
		return nil, false, ErrOwnerAuth
	}
	if inv.process.account(ctx, inv.relay, force) != nil {
		return nil, false, ErrOwnerAuth
	}
	// The normal EOF allowance plus TERM/KILL, reader joins and relay margin.
	// Cancellation ends the natural wait; cleanup carries only stop obligations.
	cleanup, cancel := context.WithTimeout(context.Background(), nativeFinishGrace+8*time.Second)
	defer cancel()
	if inv.process.finish(ctx, cleanup) != nil || inv.relay.close(cleanup) != nil {
		return nil, false, ErrCleanup
	}
	if !inv.process.cleanExit() || ctx.Err() != nil {
		return nil, false, ErrOwnerAuth
	}
	candidate, err := readNativeCandidate(filepath.Join(inv.directory, "auth", "auth.json"))
	defer clear(candidate)
	if err != nil {
		return nil, false, err
	}
	accepted, refreshed, err := inv.relay.candidate(candidate, force)
	if err != nil {
		return nil, false, err
	}
	// Linearize persistence against cancellation/admission closure. Close first
	// marks closed and cancels; it never reports success while resolve holds serial.
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || ctx.Err() != nil || o.source.Commit(before, candidate) != nil {
		return nil, false, ErrOwnerAuth
	}
	return accepted, refreshed, nil
}

func (i *ownerNativeInvocation) prepare(root string, before []byte) error {
	// A system config/requirements tree is an external trusted input, not an
	// implicit customization channel. The fixed candidate rejects it pending an
	// explicitly measured profile; fresh HOME/working directory exclude user/repo.
	if _, err := os.Lstat("/etc/codex"); !os.IsNotExist(err) {
		return ErrOwnerAuth
	}
	var st unix.Stat_t
	if unix.Lstat(root, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid()) {
		return ErrOwnerAuth
	}
	dir, err := os.MkdirTemp(root, "native-auth-")
	if err != nil {
		return ErrOwnerAuth
	}
	i.directory = dir
	for _, name := range []string{"user", "auth", "state", "tmp"} {
		if os.Mkdir(filepath.Join(dir, name), 0700) != nil {
			return ErrOwnerAuth
		}
	}
	f, err := os.OpenFile(filepath.Join(dir, "auth", "auth.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrOwnerAuth
	}
	n, err := f.Write(before)
	closeErr := f.Close()
	if err != nil || n != len(before) || closeErr != nil {
		return ErrOwnerAuth
	}
	return nil
}

func readNativeCandidate(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrOwnerAuth
	}
	f := os.NewFile(uintptr(fd), "owner-native-candidate")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
		return nil, ErrOwnerAuth
	}
	data, err := io.ReadAll(io.LimitReader(f, maxOwnerAuthBytes+1))
	if err != nil || len(data) > maxOwnerAuthBytes {
		clear(data)
		return nil, ErrOwnerAuth
	}
	return data, nil
}

func (i *ownerNativeInvocation) stop(ctx context.Context) error {
	i.cancel()
	failed := false
	if i.relay != nil && i.relay.close(ctx) != nil {
		failed = true
	}
	if i.process != nil && i.process.stop(ctx) != nil {
		failed = true
	}
	if failed {
		return ErrCleanup
	}
	if i.directory != "" {
		if os.RemoveAll(i.directory) != nil {
			return ErrCleanup
		}
		i.directory = ""
	}
	return nil
}

func (o *ownerNativeConsumer) close(ctx context.Context) error {
	o.mu.Lock()
	o.closed = true
	if o.active != nil {
		o.active.cancel()
	}
	o.mu.Unlock()
	select {
	case o.serial <- struct{}{}:
	case <-ctx.Done():
		return ErrCleanup
	}
	defer func() { <-o.serial }()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.active != nil {
		if o.active.stop(ctx) != nil {
			return ErrCleanup
		}
		o.active = nil
	}
	return nil // Does not close OwnerAccess, release occupancy or retire anything.
}
