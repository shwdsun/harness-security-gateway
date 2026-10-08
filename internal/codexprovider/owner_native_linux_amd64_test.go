//go:build linux && amd64

package codexprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type nativeTestStorage struct {
	mu           sync.Mutex
	data         []byte
	commits      int
	invalid      bool
	fail         bool
	beforeCommit func()
}

func (s *nativeTestStorage) Read() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.data), nil
}
func (s *nativeTestStorage) Invalidate() { s.mu.Lock(); s.invalid = true; s.mu.Unlock() }
func (s *nativeTestStorage) Commit(before, after []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.beforeCommit != nil {
		s.beforeCommit()
	}
	if s.fail || s.invalid || !bytes.Equal(s.data, before) {
		return ErrOwnerAuth
	}
	s.commits++
	s.data = bytes.Clone(after)
	return nil
}

func nativeTestFiles(t *testing.T) *ownerNativeFiles {
	t.Helper()
	launcher := compileAuthC(t, "native_launcher/main.c", "launcher")
	native := filepath.Join(t.TempDir(), "synthetic-account")
	cmd := exec.Command("go", "build", "-o", native, "./testdata/owner-account")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0") // Offline test-driver env; never used for launched account helper.
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("synthetic account fixture: %v %s", err, out)
	}
	if err := os.Chmod(native, 0500); err != nil {
		t.Fatal(err)
	}
	open := func(path string) *os.File {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(data)
		f, err := openOwnerExecutable(path, hex.EncodeToString(h[:]), 16<<20)
		if err != nil {
			t.Fatal("synthetic executable failed artifact checks", err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	return &ownerNativeFiles{launcher: open(launcher), native: open(native)}
}

func nativeTestConsumer(t *testing.T, files *ownerNativeFiles, mode string) (*ownerNativeConsumer, *nativeTestStorage) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "fixture-mode"), []byte(mode), 0600); err != nil {
		t.Fatal(err)
	}
	source := &nativeTestStorage{data: ownerFixture(t, "2026-09-19T00:00:00Z").encoded}
	o := &ownerNativeConsumer{serial: make(chan struct{}, 1), source: source, root: root, files: files, startup: &ownerStartup{pid: os.Getpid()},
		send: func(context.Context, Request) (Response, error) {
			return Response{Status: 200, MediaType: "application/json", Body: io.NopCloser(bytes.NewReader(refreshData(t, ownerFixture(t, "2026-09-19T00:00:01Z"))))}, nil
		}}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		if o.close(ctx) != nil {
			t.Error("synthetic consumer cleanup incomplete")
		}
	})
	return o, source
}

func TestNativeConsumerJoinsBeforePersistenceAndRefreshesOnce(t *testing.T) {
	files := nativeTestFiles(t)
	for _, mode := range []string{"cached", "refresh", "stale"} {
		t.Run(mode, func(t *testing.T) {
			o, source := nativeTestConsumer(t, files, mode)
			var calls atomic.Int32
			send := o.send
			o.send = func(ctx context.Context, r Request) (Response, error) { calls.Add(1); return send(ctx, r) }
			source.beforeCommit = func() {
				if o.active == nil || !o.active.process.cleanExit() {
					t.Error("persistence with live process/readers")
				}
				select {
				case <-o.active.relay.joinEnd:
				default:
					t.Error("persistence with live relay")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			auth, refreshed, err := o.resolve(ctx, mode != "cached")
			if err != nil || auth == nil || refreshed != (mode != "cached") || source.commits != 1 || source.invalid {
				t.Fatal("native readiness/refresh not accepted", err)
			}
			want := int32(0)
			if mode != "cached" {
				want = 1
			}
			if calls.Load() != want {
				t.Fatal("extra or missing refresh")
			}
			if o.active != nil {
				t.Fatal("successful invocation retained active resources")
			}
			entries, err := filepath.Glob(filepath.Join(o.root, "native-auth-*"))
			if err != nil || len(entries) != 0 {
				t.Fatal("joined invocation left native home")
			}
		})
	}
}

func TestNativeConsumerRejectsFailedStorageProtocolAndTeardown(t *testing.T) {
	files := nativeTestFiles(t)
	for _, mode := range []string{"readonly", "mismatch", "invalid-account", "badjson", "stderr", "extra-response", "hang", "kill", "persistence"} {
		t.Run(mode, func(t *testing.T) {
			o, source := nativeTestConsumer(t, files, mode)
			source.fail = mode == "persistence"
			var calls atomic.Int32
			send := o.send
			o.send = func(ctx context.Context, r Request) (Response, error) { calls.Add(1); return send(ctx, r) }
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if a, _, err := o.resolve(ctx, true); a != nil || err == nil || !source.invalid || source.commits != 0 {
				t.Fatal("invalid native result accepted")
			}
			before := calls.Load()
			if a, _, err := o.resolve(ctx, true); a != nil || err == nil || calls.Load() != before {
				t.Fatal("failed invocation replayed")
			}
			if err := o.close(ctx); err != nil {
				t.Fatal("negative case did not join", err)
			}
		})
	}
}

func TestNativeConsumerCloseCancelsAndWaitsForInFlightRefresh(t *testing.T) {
	files := nativeTestFiles(t)
	o, source := nativeTestConsumer(t, files, "refresh")
	entered, release := make(chan struct{}), make(chan struct{})
	o.send = func(ctx context.Context, r Request) (Response, error) {
		close(entered)
		<-release
		return Response{}, ErrUpstream
	}
	resolved := make(chan error, 1)
	go func() { _, _, err := o.resolve(context.Background(), true); resolved <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture never reached refresh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	if o.close(ctx) != ErrCleanup {
		t.Fatal("close treated cancellation as callback join")
	}
	cancel()
	close(release)
	select {
	case err := <-resolved:
		if err == nil {
			t.Fatal("canceled invocation accepted")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("native failed to join")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if o.close(ctx) != nil || !source.invalid || source.commits != 0 {
		t.Fatal("cleanup failed or canceled refresh committed")
	}
}

func TestNativeArtifactRejectsDigestAndWritableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	if os.WriteFile(path, []byte("synthetic executable bytes"), 0700) != nil {
		t.Fatal("fixture write")
	}
	sum := sha256.Sum256([]byte("synthetic executable bytes"))
	for _, digest := range []string{"", "0000000000000000000000000000000000000000000000000000000000000000"} {
		if f, err := openOwnerExecutable(path, digest, 100); f != nil || err == nil {
			t.Fatal("unpinned artifact accepted")
		}
	}
	if os.Chmod(path, 0770) != nil {
		t.Fatal("fixture chmod")
	}
	if f, err := openOwnerExecutable(path, hex.EncodeToString(sum[:]), 100); f != nil || err == nil {
		t.Fatal("group-writable artifact accepted")
	}
}
