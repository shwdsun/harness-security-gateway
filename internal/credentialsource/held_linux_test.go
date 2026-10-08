//go:build linux

package credentialsource

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fixture struct{ parent, root, slot, auth string }

func newFixture(t *testing.T) fixture {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("held source requires an unprivileged operator")
	}
	parent := t.TempDir()
	// testing.TempDir's numbered child follows the process umask. Tighten only
	// this newly created fixture, never an operator-supplied source directory.
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	f := fixture{parent: parent, root: filepath.Join(parent, "credentials")}
	f.slot = filepath.Join(f.root, "slot-one")
	f.auth = filepath.Join(f.slot, "auth.json")
	if err := os.MkdirAll(f.slot, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSynthetic(t, f.auth)
	return f
}

func writeSynthetic(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("synthetic-before"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func holdFixture(t *testing.T, f fixture) *HeldSource {
	t.Helper()
	h, err := Hold(f.root, "slot-one")
	if err != nil {
		t.Fatalf("hold synthetic source: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	return h
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestHeldSourceRefreshKeepsObjectAndDoesNotReadOrRewrite(t *testing.T) {
	f := newFixture(t)
	h := holdFixture(t, f)
	// These deliberately non-JSON bytes are never parsed by the guard.
	before, err := os.ReadFile(f.auth)
	must(t, err)
	if string(before) != "synthetic-before" {
		t.Fatal("Hold changed synthetic bytes")
	}
	initial := h.identity
	must(t, os.WriteFile(f.auth, []byte("synthetic-after-different-length"), 0o600))
	must(t, h.Validate())
	if h.identity != initial {
		t.Fatal("in-place refresh changed held comparison identity")
	}
	// File offset stays at zero: the guard has issued no content read.
	offset, err := h.file.Seek(0, io.SeekCurrent)
	must(t, err)
	if offset != 0 {
		t.Fatal("guard read credential content")
	}
	for _, file := range []*os.File{h.root, h.slot, h.file} {
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
		must(t, err)
		if flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("held descriptor can leak across exec")
		}
	}
	must(t, h.Close())
	must(t, h.Close())
	if !errors.Is(h.Validate(), ErrClosed) {
		t.Fatal("closed source validated")
	}
	holdFixture(t, f)
}

func TestHeldSourceRejectsUnsafeInputs(t *testing.T) {
	for _, directory := range []string{"", ".", "..", ".hidden", "auth.json", "../slot-one", "a/b", "/slot-one", "A", "a\x00", strings.Repeat("a", 129)} {
		t.Run("directory_"+fmt.Sprintf("%q", directory), func(t *testing.T) {
			f := newFixture(t)
			if h, err := Hold(f.root, directory); !errors.Is(err, ErrUnsafe) || h != nil {
				t.Fatalf("invalid slot accepted: %v", err)
			}
		})
	}
	for _, root := range []string{"", "/", "relative", "/tmp/../tmp", "/tmp/", "/tmp//root", "/tmp/secret\n", "/tmp/secret\x00"} {
		if h, err := Hold(root, "slot-one"); !errors.Is(err, ErrUnsafe) || h != nil {
			t.Fatalf("invalid root accepted: %v", err)
		}
	}
	setups := map[string]func(*testing.T, fixture){
		"file symlink": func(t *testing.T, f fixture) {
			must(t, os.Rename(f.auth, filepath.Join(f.parent, "synthetic")))
			must(t, os.Symlink(filepath.Join(f.parent, "synthetic"), f.auth))
		},
		"slot symlink": func(t *testing.T, f fixture) {
			must(t, os.Rename(f.slot, filepath.Join(f.parent, "moved-slot")))
			must(t, os.Symlink(filepath.Join(f.parent, "moved-slot"), f.slot))
		},
		"root symlink": func(t *testing.T, f fixture) {
			must(t, os.Rename(f.root, filepath.Join(f.parent, "moved-root")))
			must(t, os.Symlink(filepath.Join(f.parent, "moved-root"), f.root))
		},
		"hardlink alias": func(t *testing.T, f fixture) {
			must(t, os.Link(f.auth, filepath.Join(f.parent, "alias")))
		},
		"extra entry":       func(t *testing.T, f fixture) { writeSynthetic(t, filepath.Join(f.slot, "config.toml")) },
		"file permissions":  func(t *testing.T, f fixture) { must(t, os.Chmod(f.auth, 0o640)) },
		"file special bits": func(t *testing.T, f fixture) { must(t, os.Chmod(f.auth, 0o600|os.ModeSetuid)) },
		"slot permissions":  func(t *testing.T, f fixture) { must(t, os.Chmod(f.slot, 0o750)) },
		"root permissions":  func(t *testing.T, f fixture) { must(t, os.Chmod(f.root, 0o750)) },
		"unsafe ancestor":   func(t *testing.T, f fixture) { must(t, os.Chmod(f.parent, 0o777)) },
		"missing":           func(t *testing.T, f fixture) { must(t, os.Remove(f.auth)) },
		"directory": func(t *testing.T, f fixture) {
			must(t, os.Remove(f.auth))
			must(t, os.Mkdir(f.auth, 0o600))
		},
		"fifo": func(t *testing.T, f fixture) {
			must(t, os.Remove(f.auth))
			must(t, unix.Mkfifo(f.auth, 0o600))
		},
	}
	for name, setup := range setups {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			setup(t, f)
			h, err := Hold(f.root, "slot-one")
			if h != nil || err == nil {
				t.Fatalf("unsafe source accepted: %v", err)
			}
			if strings.Contains(err.Error(), f.parent) || strings.Contains(err.Error(), "synthetic-before") {
				t.Fatal("diagnostic disclosed source data")
			}
		})
	}
	t.Run("symlink ancestor", func(t *testing.T) {
		f := newFixture(t)
		aliasParent := t.TempDir()
		must(t, os.Chmod(aliasParent, 0o700))
		alias := filepath.Join(aliasParent, "alias")
		must(t, os.Symlink(f.parent, alias))
		if h, err := Hold(filepath.Join(alias, "credentials"), "slot-one"); h != nil || !errors.Is(err, ErrUnsafe) {
			t.Fatalf("symlink ancestor accepted: %v", err)
		}
	})
}

func TestHeldSourceReplacementInvalidatesAndRetainsSlotLock(t *testing.T) {
	f := newFixture(t)
	h := holdFixture(t, f)
	old := filepath.Join(f.parent, "old-auth")
	must(t, os.Rename(f.auth, old))
	writeSynthetic(t, f.auth)
	if err := h.Validate(); !errors.Is(err, ErrChanged) {
		t.Fatalf("replacement accepted: %v", err)
	}
	if next, err := Hold(f.root, "slot-one"); next != nil || !errors.Is(err, ErrBusy) {
		t.Fatalf("replacement bypassed retained slot lock: %v", err)
	}
	must(t, os.Remove(f.auth))
	must(t, os.Rename(old, f.auth))
	if !errors.Is(h.Validate(), ErrChanged) {
		t.Fatal("restoring the old object revived an invalidated handle")
	}
	must(t, h.Close())
	holdFixture(t, f)
}

func TestHeldSourceDetectsDirectoryAndMetadataChanges(t *testing.T) {
	for _, kind := range []string{"root replacement", "slot replacement", "hardlink", "file mode", "root mode", "slot mode", "extra entry", "symlink", "unlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			h := holdFixture(t, f)
			switch kind {
			case "root replacement":
				must(t, os.Rename(f.root, filepath.Join(f.parent, "old-root")))
				must(t, os.MkdirAll(f.slot, 0o700))
				writeSynthetic(t, f.auth)
			case "slot replacement":
				must(t, os.Rename(f.slot, filepath.Join(f.parent, "old-slot")))
				must(t, os.Mkdir(f.slot, 0o700))
				writeSynthetic(t, f.auth)
			case "hardlink":
				must(t, os.Link(f.auth, filepath.Join(f.parent, "alias")))
			case "file mode":
				must(t, os.Chmod(f.auth, 0o640))
			case "root mode":
				must(t, os.Chmod(f.root, 0o750))
			case "slot mode":
				must(t, os.Chmod(f.slot, 0o750))
			case "extra entry":
				writeSynthetic(t, filepath.Join(f.slot, "extra"))
			case "symlink":
				must(t, os.Rename(f.auth, filepath.Join(f.parent, "old-auth")))
				must(t, os.Symlink(filepath.Join(f.parent, "old-auth"), f.auth))
			case "unlink":
				must(t, os.Remove(f.auth))
			}
			if !errors.Is(h.Validate(), ErrChanged) {
				t.Fatal("changed source validated")
			}
		})
	}
}

func TestHeldSourceAdmissionConcurrencyAndIndependentSlots(t *testing.T) {
	f := newFixture(t)
	start := make(chan struct{})
	results := make(chan *HeldSource, 12)
	errs := make(chan error, 12)
	for range 12 {
		go func() {
			<-start
			h, err := Hold(f.root, "slot-one")
			results <- h
			errs <- err
		}()
	}
	close(start)
	winners := 0
	for range 12 {
		if h := <-results; h != nil {
			winners++
			t.Cleanup(func() { must(t, h.Close()) })
		}
		if err := <-errs; err != nil && !errors.Is(err, ErrBusy) {
			t.Errorf("unexpected contender error: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("got %d holders, want 1", winners)
	}
	other := filepath.Join(f.root, "slot-two")
	must(t, os.Mkdir(other, 0o700))
	writeSynthetic(t, filepath.Join(other, "auth.json"))
	h, err := Hold(f.root, "slot-two")
	must(t, err)
	must(t, h.Close())
}

func TestHeldSourceFileLockAndFailedAcquireCleanup(t *testing.T) {
	f := newFixture(t)
	file, err := os.Open(f.auth)
	must(t, err)
	defer file.Close()
	must(t, unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB))
	if h, err := Hold(f.root, "slot-one"); h != nil || !errors.Is(err, ErrBusy) {
		t.Fatalf("file lock ignored: %v", err)
	}
	must(t, file.Close())
	// Failed file acquisition must release its already-acquired slot lock.
	holdFixture(t, f)
}

func TestHeldSourceLateAcquireFailureReleasesDescriptorsAndLocks(t *testing.T) {
	f := newFixture(t)
	extra := filepath.Join(f.slot, "extra")
	writeSynthetic(t, extra)
	for range 4 {
		if h, err := Hold(f.root, "slot-one"); h != nil || !errors.Is(err, ErrChanged) {
			t.Fatalf("expected late dedicated-slot rejection, got %v", err)
		}
	}
	entries, err := os.ReadDir("/proc/self/fd")
	must(t, err)
	for _, entry := range entries {
		target, _ := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if target == f.root || strings.HasPrefix(target, f.root+"/") {
			t.Fatal("failed acquisition leaked a source descriptor")
		}
	}
	must(t, os.Remove(extra))
	holdFixture(t, f)
}

func TestHeldSourceConcurrentCloseAndValidate(t *testing.T) {
	h := holdFixture(t, newFixture(t))
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if err := h.Validate(); err != nil && !errors.Is(err, ErrClosed) {
				t.Errorf("validation: %v", err)
			}
			if err := h.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		})
	}
	wg.Wait()
	var zero HeldSource
	if !errors.Is(zero.Validate(), ErrClosed) {
		t.Fatal("zero source validated")
	}
	must(t, zero.Close())
}

func TestHeldSourceRejectsCrossMountResolution(t *testing.T) {
	// Read-only check of the existing procfs mount; creates no mount/namespace.
	root, err := openAt(unix.AT_FDCWD, "/", unix.O_PATH|unix.O_DIRECTORY, unix.RESOLVE_NO_SYMLINKS)
	must(t, err)
	defer root.Close()
	proc, err := openAt(unix.AT_FDCWD, "/proc", unix.O_PATH|unix.O_DIRECTORY, unix.RESOLVE_NO_SYMLINKS)
	must(t, err)
	defer proc.Close()
	r, err := metadata(root)
	must(t, err)
	p, err := metadata(proc)
	must(t, err)
	if r.Mnt_id == p.Mnt_id {
		t.Skip("procfs is not a separate mount in this environment")
	}
	if f, err := openBelow(root, "proc", unix.O_PATH|unix.O_DIRECTORY); f != nil || !errors.Is(err, ErrUnsafe) {
		t.Fatalf("mount crossing accepted: %v", err)
	}
}

func TestHeldSourceWrongOwner(t *testing.T) {
	f := newFixture(t)
	file, err := os.Open(f.auth)
	must(t, err)
	defer file.Close()
	// Exercise the metadata owner rule without changing a host file's owner.
	if _, err := privateObject(file, uint32(os.Geteuid()+1), true); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("wrong owner accepted: %v", err)
	}
}

func TestHeldSourceSubprocess(t *testing.T) {
	mode := os.Getenv("HGW_SYNTHETIC_HELD_SOURCE_HELPER")
	if mode == "" {
		return
	}
	h, err := Hold(os.Getenv("HGW_SYNTHETIC_HELD_SOURCE_ROOT"), "slot-one")
	if mode == "busy" {
		if h != nil || !errors.Is(err, ErrBusy) {
			os.Exit(2)
		}
		os.Exit(0)
	}
	if mode != "hold" || err != nil {
		os.Exit(3)
	}
	fmt.Println("held")
	_, _ = io.Copy(io.Discard, os.Stdin)
	_ = h.Close()
	os.Exit(0)
}

func child(t *testing.T, root, mode string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestHeldSourceSubprocess$")
	cmd.Env = []string{"HGW_SYNTHETIC_HELD_SOURCE_HELPER=" + mode, "HGW_SYNTHETIC_HELD_SOURCE_ROOT=" + root}
	return cmd
}

func TestHeldSourceAcrossProcessAndDeath(t *testing.T) {
	f := newFixture(t)
	h := holdFixture(t, f)
	if output, err := child(t, f.root, "busy").CombinedOutput(); err != nil {
		t.Fatalf("cross-process lock: %v, %s", err, output)
	}
	must(t, h.Close())
	cmd := child(t, f.root, "hold")
	stdin, err := cmd.StdinPipe()
	must(t, err)
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	must(t, err)
	must(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	must(t, err)
	if line != "held\n" {
		t.Fatal("child did not acquire its synthetic source")
	}
	if next, err := Hold(f.root, "slot-one"); next != nil || !errors.Is(err, ErrBusy) {
		t.Fatalf("child lock ignored: %v", err)
	}
	must(t, cmd.Process.Kill())
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed helper unexpectedly succeeded")
	}
	// This proves why process-local locks cannot replace durable Run occupancy:
	// the lock disappears on death without any runtime-cleanup evidence.
	holdFixture(t, f)
}
