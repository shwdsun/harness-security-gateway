//go:build linux

package credentialsource

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func ownerFixture(t *testing.T) (fixture, *HeldSource, *OwnerAccess) {
	t.Helper()
	f := newFixture(t)
	h := holdFixture(t, f)
	source, proof, err := h.observeProof(syntheticReader, nil)
	must(t, err)
	binding := Binding{Root: f.root, Directory: "slot-one", SlotRef: "auth", Generation: 1, WorkspaceRef: "workspace", AuthProfileRef: "profile"}
	o, err := h.borrowForOwner("admitted-run", strings.Repeat("a", 64), binding, source, proof, syntheticReader)
	must(t, err)
	return f, h, o
}

func TestOwnerCommitPreservesEnrollmentObjectAndShortensContent(t *testing.T) {
	f, h, o := ownerFixture(t)
	initial, err := os.Stat(f.auth)
	must(t, err)
	before, err := o.Read()
	must(t, err)
	candidate := []byte("new")
	must(t, o.Commit(before, candidate))
	after, err := o.Read()
	must(t, err)
	if !bytes.Equal(after, candidate) {
		t.Fatal("candidate not fully persisted or old suffix retained")
	}
	after[0] = 'X'
	again, err := o.Read()
	must(t, err)
	if !bytes.Equal(again, candidate) {
		t.Fatal("returned bytes alias source storage")
	}
	current, err := os.Stat(f.auth)
	must(t, err)
	if !os.SameFile(initial, current) || current.Mode().Perm() != 0o600 {
		t.Fatal("commit replaced enrolled object or permissions")
	}
	entries, err := os.ReadDir(f.slot)
	must(t, err)
	if len(entries) != 1 || entries[0].Name() != "auth.json" {
		t.Fatal("commit created an extra credential file")
	}
	must(t, h.Validate())
	// An identical candidate is a valid storage operation, not refresh proof.
	must(t, o.Commit(again, again))
	if next, err := Hold(f.root, "slot-one"); next != nil || !errors.Is(err, ErrBusy) {
		t.Fatal("successful commit released source ownership")
	}
}

func TestOwnerAndMountCapabilitiesCannotCoexist(t *testing.T) {
	for _, first := range []string{"owner", "mount"} {
		t.Run(first, func(t *testing.T) {
			f := newFixture(t)
			h := holdFixture(t, f)
			source, proof, err := h.observeProof(syntheticReader, nil)
			must(t, err)
			binding := Binding{Root: f.root, Directory: "slot-one", SlotRef: "auth", Generation: 1, WorkspaceRef: "workspace", AuthProfileRef: "profile"}
			fingerprint := strings.Repeat("a", 64)
			if first == "owner" {
				o, err := h.borrowForOwner("run", fingerprint, binding, source, proof, syntheticReader)
				must(t, err)
				o.Close()
				if next, err := h.handoff("run", fingerprint, binding, source, proof, syntheticReader); next != nil || err == nil {
					t.Fatal("owner close permitted a real credential mount")
				}
				if next, err := h.borrowForOwner("run", fingerprint, binding, source, proof, syntheticReader); next != nil || err == nil {
					t.Fatal("reopened an already used owner borrow")
				}
			} else {
				m, err := h.handoff("run", fingerprint, binding, source, proof, syntheticReader)
				must(t, err)
				m.Close()
				if next, err := h.borrowForOwner("run", fingerprint, binding, source, proof, syntheticReader); next != nil || err == nil {
					t.Fatal("mount close permitted owner-only content access")
				}
			}
			must(t, h.Validate())
		})
	}
}

func TestOwnerScopeCopiesRevocationAndDiagnostics(t *testing.T) {
	f, h, o := ownerFixture(t)
	s := o.state
	must(t, o.Validate(s.runID, s.fingerprint, s.binding))
	for _, field := range []string{"run", "fingerprint", "root", "directory", "slot", "generation", "workspace", "profile"} {
		run, fp, b := s.runID, s.fingerprint, s.binding
		switch field {
		case "run":
			run += "x"
		case "fingerprint":
			fp = strings.Repeat("b", 64)
		case "root":
			b.Root += "x"
		case "directory":
			b.Directory += "x"
		case "slot":
			b.SlotRef += "x"
		case "generation":
			b.Generation++
		case "workspace":
			b.WorkspaceRef += "x"
		case "profile":
			b.AuthProfileRef += "x"
		}
		if o.Validate(run, fp, b) == nil {
			t.Fatal("foreign scope accepted")
		}
	}
	for _, value := range []any{o, *o} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("owner capability serialized")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%d", "%f", "%x", "%q", "%#+v"} {
			output := fmt.Sprintf(format, value)
			if strings.Contains(output, f.root) || strings.Contains(output, s.runID) {
				t.Fatal("owner diagnostic disclosed state")
			}
		}
	}
	var missing OwnerAccess
	if json.Unmarshal([]byte(`{}`), &missing) == nil {
		t.Fatal("wire created an owner capability")
	}
	if data, err := missing.Read(); err == nil || data != nil {
		t.Fatal("zero borrow read content")
	}
	var nilOwner *OwnerAccess
	nilOwner.Close()
	nilOwner.Invalidate()
	copy := *o
	copy.Close()
	if data, err := o.Read(); !errors.Is(err, ErrClosed) || data != nil {
		t.Fatal("copy survived revocation")
	}
	if o.Commit([]byte("x"), []byte("y")) == nil {
		t.Fatal("closed borrow wrote")
	}
	must(t, h.Validate())
	if next, err := Hold(f.root, "slot-one"); next != nil || !errors.Is(err, ErrBusy) {
		t.Fatal("borrow close released locks")
	}
}

func TestOwnerStaleContentAndReplacementFailWithoutRollback(t *testing.T) {
	for _, kind := range []string{"bytes", "inode", "semantic"} {
		t.Run(kind, func(t *testing.T) {
			f, h, o := ownerFixture(t)
			before, err := o.Read()
			must(t, err)
			if kind == "inode" {
				must(t, os.Rename(f.auth, filepath.Join(f.parent, "retained")))
			}
			current := []byte("newer-synthetic-auth")
			must(t, os.WriteFile(f.auth, current, 0o600))
			if kind == "semantic" {
				o.Invalidate()
			}
			if o.Commit(before, []byte("candidate")) == nil {
				t.Fatal("stale source committed")
			}
			actual, err := os.ReadFile(f.auth)
			must(t, err)
			if !bytes.Equal(actual, current) {
				t.Fatal("replaced newer content or rolled source back")
			}
			if h.Validate() == nil {
				t.Fatal("failed operation did not latch invalidity")
			}
			if data, err := o.Read(); err == nil || data != nil {
				t.Fatal("invalid owner still read content")
			}
			if next, err := Hold(f.root, "slot-one"); next != nil || !errors.Is(err, ErrBusy) {
				t.Fatal("failure released slot lock")
			}
		})
	}
}

type faultyContent struct {
	*os.File
	mode             string
	entered, proceed chan struct{}
}

func (f *faultyContent) WriteAt(p []byte, off int64) (int, error) {
	if f.mode == "block" {
		close(f.entered)
		<-f.proceed
	}
	if f.mode == "short" {
		n, _ := f.File.WriteAt(p[:1], off)
		return n, io.ErrShortWrite
	}
	return f.File.WriteAt(p, off)
}
func (f *faultyContent) Truncate(n int64) error {
	if f.mode == "truncate" {
		return errors.New("synthetic secret path")
	}
	return f.File.Truncate(n)
}
func (f *faultyContent) Sync() error {
	if f.mode == "sync" {
		return errors.New("synthetic secret token")
	}
	return f.File.Sync()
}
func (f *faultyContent) ReadAt(p []byte, off int64) (int, error) {
	n, err := f.File.ReadAt(p, off)
	if f.mode == "readback" && n > 0 {
		p[0] ^= 1
	}
	return n, err
}
func (f *faultyContent) Close() error {
	err := f.File.Close()
	if f.mode == "close" {
		return errors.New("synthetic close failure")
	}
	return err
}

func TestOwnerFailedWriteSyncReadbackAndCloseLatchWithoutRollback(t *testing.T) {
	for _, mode := range []string{"short", "truncate", "sync", "readback", "close"} {
		t.Run(mode, func(t *testing.T) {
			f, h, o := ownerFixture(t)
			before, err := o.Read()
			must(t, err)
			candidate := []byte("ROTATED")
			err = o.commit(before, candidate, func(file *os.File) contentFile {
				flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
				must(t, err)
				if flags&unix.FD_CLOEXEC == 0 {
					t.Fatal("write descriptor inheritable")
				}
				return &faultyContent{File: file, mode: mode}
			})
			if !errors.Is(err, ErrOwnerContent) || err.Error() != ErrOwnerContent.Error() {
				t.Fatal("failure accepted or raw error exposed")
			}
			actual, err := os.ReadFile(f.auth)
			must(t, err)
			if bytes.Equal(actual, before) {
				t.Fatal("partial/finished write was rolled back")
			}
			if !errors.Is(h.Validate(), ErrChanged) {
				t.Fatal("source revived after persistence failure")
			}
			if o.Commit(actual, before) == nil {
				t.Fatal("failed source accepted rollback retry")
			}
			if next, err := Hold(f.root, "slot-one"); next != nil || !errors.Is(err, ErrBusy) {
				t.Fatal("persistence failure released locks")
			}
		})
	}
}

func TestOwnerReadBoundsAndCommitBounds(t *testing.T) {
	for _, size := range []int{0, MaxOwnerBytes + 1} {
		f, h, o := ownerFixture(t)
		must(t, os.WriteFile(f.auth, bytes.Repeat([]byte("x"), size), 0o600))
		if data, err := o.Read(); err == nil || data != nil || h.Validate() == nil {
			t.Fatal("unsafe size read or returned partial content")
		}
	}
	for _, candidate := range [][]byte{nil, bytes.Repeat([]byte("x"), MaxOwnerBytes+1)} {
		f, h, o := ownerFixture(t)
		before, err := o.Read()
		must(t, err)
		if o.Commit(before, candidate) == nil || h.Validate() == nil {
			t.Fatal("unsafe candidate accepted")
		}
		after, err := os.ReadFile(f.auth)
		must(t, err)
		if !bytes.Equal(before, after) {
			t.Fatal("invalid input touched the source")
		}
	}
}

func TestOwnerCommitSerializesCloseUntilWriteBackEnds(t *testing.T) {
	f, h, o := ownerFixture(t)
	before, err := o.Read()
	must(t, err)
	entered, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(proceed) })
	committed, closed := make(chan error, 1), make(chan error, 1)
	go func() {
		committed <- o.commit(before, []byte("rotated"), func(file *os.File) contentFile {
			return &faultyContent{File: file, mode: "block", entered: entered, proceed: proceed}
		})
	}()
	<-entered
	go func() { closed <- h.Close() }()
	select {
	case <-closed:
		t.Fatal("Close released source during write-back")
	case <-time.After(25 * time.Millisecond):
	}
	if next, err := Hold(f.root, "slot-one"); next != nil || !errors.Is(err, ErrBusy) {
		t.Fatal("write in flight lost source lock")
	}
	once.Do(func() { close(proceed) })
	must(t, <-committed)
	must(t, <-closed)
	if data, err := o.Read(); !errors.Is(err, ErrClosed) || data != nil {
		t.Fatal("borrow survived held-source Close")
	}
	holdFixture(t, f)
}

func TestOwnerAndMountRaceHasOneWinningMode(t *testing.T) {
	f := newFixture(t)
	h := holdFixture(t, f)
	source, proof, err := h.observeProof(syntheticReader, nil)
	must(t, err)
	binding := Binding{Root: f.root, Directory: "slot-one", SlotRef: "auth", Generation: 1, WorkspaceRef: "workspace", AuthProfileRef: "profile"}
	ready := make(chan struct{})
	owner, mount := make(chan error, 1), make(chan error, 1)
	go func() {
		<-ready
		_, err := h.borrowForOwner("run", strings.Repeat("a", 64), binding, source, proof, syntheticReader)
		owner <- err
	}()
	go func() {
		<-ready
		_, err := h.handoff("run", strings.Repeat("a", 64), binding, source, proof, syntheticReader)
		mount <- err
	}()
	close(ready)
	one, two := <-owner, <-mount
	if (one == nil) == (two == nil) {
		t.Fatal("race must grant exactly one source mode")
	}
}
