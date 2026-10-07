//go:build linux

package credentialsource

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// MaxOwnerBytes bounds local content I/O, not the lifetime of filesystem calls.
const MaxOwnerBytes = 64 << 10

var ErrOwnerContent = errors.New("credentialsource: owner content unavailable")

type sourceUse uint8

const (
	sourceUnused sourceUse = iota
	sourceMount
	sourceOwner
)

// Mode selection lasts for the whole held-source lifetime. Revoking a borrowed
// capability never makes the same source available to the other trust domain.
func (h *HeldSource) selectUse(want sourceUse) error {
	if h == nil {
		return ErrClosed
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.file == nil {
		return ErrClosed
	}
	if h.invalid {
		return ErrChanged
	}
	if want != sourceMount && want != sourceOwner {
		return ErrOwnerContent
	}
	if h.use != sourceUnused && !(h.use == sourceMount && want == sourceMount) {
		return ErrBusy
	}
	h.use = want
	return nil
}

// OwnerAccess is a non-serializable, owner-only borrowed content capability.
// Unlike Handoff it can disclose bytes to trusted local code, never a path/FD.
// The caller must own durable Run occupancy; this object cannot grant or release
// it, retire a generation, verify OAuth, or supervise an external writer.
// Do not pass it or its returned bytes to a Runner, Core or a diagnostic sink.
type OwnerAccess struct{ state *ownerState }

type ownerState struct {
	held               *HeldSource
	runID, fingerprint string
	binding            Binding
	closed             bool // All state and I/O use held.mu, including Close.
	claimed            bool // Copies consume the same single Create attempt.
}

func (OwnerAccess) String() string               { return "credentialsource.OwnerAccess[redacted]" }
func (o OwnerAccess) GoString() string           { return o.String() }
func (v OwnerAccess) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, v.String()) }
func (OwnerAccess) MarshalJSON() ([]byte, error) { return nil, ErrOwnerContent }
func (*OwnerAccess) UnmarshalJSON([]byte) error  { return ErrOwnerContent }

// BorrowForOwner verifies the same immutable scope/proof as a mount handoff,
// but permanently selects owner-only content access on this HeldSource. It
// creates no file, reads no secret and starts no process. Only one owner borrow
// is allowed, even if it was subsequently closed or copied.
func (h *HeldSource) BorrowForOwner(runID, fingerprint string, binding Binding, source string, proof Proof) (*OwnerAccess, error) {
	return h.borrowForOwner(runID, fingerprint, binding, source, proof, nativeIdentity)
}

// Private identity seam follows the existing proof tests; production always
// supplies nativeIdentity. Neither config nor a caller can provide a verifier.
func (h *HeldSource) borrowForOwner(runID, fingerprint string, binding Binding, source string, proof Proof, read identityReader) (*OwnerAccess, error) {
	if h == nil || runID == "" || len(runID) > 128 || !digestText(fingerprint) || binding.SlotRef == "" ||
		binding.Generation == 0 || binding.WorkspaceRef == "" || binding.AuthProfileRef == "" {
		return nil, ErrInvalidHandoff
	}
	h.mu.Lock()
	matched := !h.closed && !h.invalid && h.rootPath == binding.Root && h.directory == binding.Directory
	h.mu.Unlock()
	if !matched {
		return nil, ErrInvalidHandoff
	}
	if _, _, err := h.observeProof(read, &proofExpectation{source, proof}); err != nil {
		return nil, ErrInvalidHandoff
	}
	if err := h.selectUse(sourceOwner); err != nil {
		return nil, err
	}
	return &OwnerAccess{state: &ownerState{held: h, runID: runID, fingerprint: fingerprint, binding: binding}}, nil
}

func (o *OwnerAccess) shared() *ownerState {
	if o == nil || o.state == nil || o.state.held == nil {
		return nil
	}
	return o.state
}

// Validate is an exact local scope check, not new authority or cached readiness.
func (o *OwnerAccess) Validate(runID, fingerprint string, binding Binding) error {
	s := o.shared()
	if s == nil {
		return ErrClosed
	}
	s.held.mu.Lock()
	defer s.held.mu.Unlock()
	if s.runID != runID || s.fingerprint != fingerprint || s.binding != binding {
		return ErrInvalidHandoff
	}
	return s.validate()
}

// Claim consumes this exact one-Run capability before runtime/native work.
// Closing or copying the borrow cannot restore Create authority.
func (o *OwnerAccess) Claim(runID, fingerprint string, binding Binding) error {
	s := o.shared()
	if s == nil {
		return ErrInvalidHandoff
	}
	s.held.mu.Lock()
	defer s.held.mu.Unlock()
	if s.claimed || s.runID != runID || s.fingerprint != fingerprint || s.binding != binding || s.validate() != nil {
		return ErrInvalidHandoff
	}
	s.claimed = true
	return nil
}

func (o *OwnerAccess) ValidateClaimed(runID, fingerprint string, binding Binding) error {
	s := o.shared()
	if s == nil {
		return ErrInvalidHandoff
	}
	s.held.mu.Lock()
	defer s.held.mu.Unlock()
	if !s.claimed || s.runID != runID || s.fingerprint != fingerprint || s.binding != binding {
		return ErrInvalidHandoff
	}
	return s.validate()
}

func (s *ownerState) validate() error {
	h := s.held
	if s.closed || h.closed || h.file == nil {
		return ErrClosed
	}
	if h.invalid || h.use != sourceOwner || h.validate() != nil {
		h.invalid = true
		return ErrChanged
	}
	return nil
}

func readOwner(r io.ReaderAt) ([]byte, error) {
	data, err := io.ReadAll(io.NewSectionReader(r, 0, MaxOwnerBytes+1))
	if err != nil || len(data) == 0 || len(data) > MaxOwnerBytes {
		clear(data)
		return nil, ErrOwnerContent
	}
	return data, nil
}

// Read returns a bounded copy to the trusted owner. It uses the pinned regular
// file, not a fresh path open, and validates the source before and after I/O.
func (o *OwnerAccess) Read() ([]byte, error) {
	s := o.shared()
	if s == nil {
		return nil, ErrClosed
	}
	h := s.held
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := s.validate(); err != nil {
		return nil, err
	}
	data, err := readOwner(h.file)
	if err != nil || s.validate() != nil {
		clear(data)
		h.invalid = true
		return nil, ErrOwnerContent
	}
	return data, nil
}

type contentFile interface {
	io.ReaderAt
	io.WriterAt
	Truncate(int64) error
	Sync() error
	Close() error
}

// Commit saves an already validated candidate; it proves no provider refresh.
// The expected bytes must match a previous Read exactly. All writers must have
// stopped before calling this method. This preserves the enrolled inode and
// single-entry slot: write, truncate, fsync, read back and revalidate, no rename.
// Every failed comparison/write/sync/readback latches invalidity and retains
// the held locks. A partial write is never rolled back to an older credential.
func (o *OwnerAccess) Commit(expected, candidate []byte) error {
	return o.commit(expected, candidate, func(f *os.File) contentFile { return f })
}

// A private wrapper permits fault injection into real pinned-file operations.
func (o *OwnerAccess) commit(expected, candidate []byte, wrap func(*os.File) contentFile) error {
	s := o.shared()
	if s == nil {
		return ErrClosed
	}
	h := s.held
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := s.validate(); err != nil {
		return err
	}
	failed := func() error { h.invalid = true; return ErrOwnerContent }
	if len(expected) == 0 || len(expected) > MaxOwnerBytes || len(candidate) == 0 || len(candidate) > MaxOwnerBytes {
		return failed()
	}
	before, err := readOwner(h.file)
	defer clear(before)
	if err != nil || !bytes.Equal(before, expected) {
		return failed()
	}
	// Reopen the held regular object, never the possibly replaced directory
	// entry. CLOEXEC prevents accidental inheritance of write authority.
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(int(h.file.Fd())), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return failed()
	}
	file := os.NewFile(uintptr(fd), "owner-credential")
	id, err := privateObject(file, h.uid, true)
	if err != nil || id != h.identity[2] || s.validate() != nil {
		_ = file.Close()
		return failed()
	}
	writer := wrap(file)
	var operationErr error
	if n, err := writer.WriteAt(candidate, 0); err != nil || n != len(candidate) {
		operationErr = ErrOwnerContent
	} else if writer.Truncate(int64(len(candidate))) != nil || writer.Sync() != nil {
		operationErr = ErrOwnerContent
	} else {
		after, err := readOwner(writer)
		if err != nil || !bytes.Equal(after, candidate) || s.validate() != nil {
			operationErr = ErrOwnerContent
		}
		clear(after)
	}
	if writer.Close() != nil || operationErr != nil {
		return failed()
	}
	return nil
}

// Invalidate is for a trusted consumer's semantic failure. It revokes every
// capability on this HeldSource without releasing its locks or durable lease.
func (o *OwnerAccess) Invalidate() {
	if s := o.shared(); s != nil {
		s.held.mu.Lock()
		s.held.invalid = true
		s.held.mu.Unlock()
	}
}

// Close revokes the borrow only. Copies share this state; the original held
// source and its locks remain under the controller's cleanup ownership.
func (o *OwnerAccess) Close() {
	if s := o.shared(); s != nil {
		s.held.mu.Lock()
		s.closed = true
		s.held.mu.Unlock()
	}
}
