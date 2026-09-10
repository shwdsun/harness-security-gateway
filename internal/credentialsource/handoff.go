package credentialsource

import (
	"errors"
	"sync"
)

var ErrInvalidHandoff = errors.New("credentialsource: invalid runtime handoff")

// Receiver is a pinned observation of an inert runtime bootstrap. Closing it
// releases observations only; the controller still owns the held source.
type Receiver interface {
	Validate() error
	Close() error
}

// Handoff borrows a held source for exactly one Run and one Create attempt.
// Only the native held-source constructor can populate it. It exposes no path,
// descriptor, credential bytes or source Close method. The runtime already owns
// its frozen Binding and must match it before constructing a mount argument.
// This object is not an enrollment or a substitute for durable Run admission.
type Handoff struct {
	state *handoffState
}

type handoffState struct {
	mu                 sync.Mutex
	runID, fingerprint string
	binding            Binding
	verify             func() error
	open               func(int, string, string, uint32) (Receiver, error)
	claimed, observed  bool
	closed             bool
}

func (h Handoff) MarshalJSON() ([]byte, error) { return nil, ErrInvalidHandoff }
func (h *Handoff) UnmarshalJSON([]byte) error  { return ErrInvalidHandoff }

// Claim is called before the only external Create dispatch. A failed or
// ambiguous Create cannot reuse this capability for another attempt.
func (h *Handoff) Claim(runID, fingerprint string, binding Binding) error {
	s := h.shared()
	if s == nil {
		return ErrInvalidHandoff
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claimed || s.matches(runID, fingerprint, binding) != nil {
		return ErrInvalidHandoff
	}
	s.claimed = true
	return nil
}

// Validate checks the same frozen identity after Claim, including while the
// bootstrap is still inert. Source replacement remains a latched failure in
// HeldSource; restoring the original pathname cannot revive the handoff.
func (h *Handoff) Validate(runID, fingerprint string, binding Binding) error {
	s := h.shared()
	if s == nil {
		return ErrInvalidHandoff
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.claimed {
		return ErrInvalidHandoff
	}
	return s.matches(runID, fingerprint, binding)
}

func (s *handoffState) matches(runID, fingerprint string, binding Binding) error {
	if s.closed || s.verify == nil || s.open == nil || runID == "" ||
		s.runID != runID || s.fingerprint != fingerprint || s.binding != binding || s.verify() != nil {
		return ErrInvalidHandoff
	}
	return nil
}

// OpenReceiver accepts independently attributed facts from the trusted runtime,
// not an init PID or executable digest supplied by a Runner. It is one-use even
// on failure. The expected nonzero inner UID is part of the startup template.
func (h *Handoff) OpenReceiver(pid int, ref, bootstrap string, uid uint32) (Receiver, error) {
	s := h.shared()
	if s == nil {
		return nil, ErrInvalidHandoff
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.claimed || s.observed || uid == 0 ||
		s.matches(s.runID, s.fingerprint, s.binding) != nil {
		return nil, ErrInvalidHandoff
	}
	s.observed = true
	return s.open(pid, ref, bootstrap, uid)
}

// Close revokes only this borrowed launch capability. It cannot unlock or
// close the original held source and is safe to call more than once.
func (h *Handoff) Close() {
	s := h.shared()
	if s != nil {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
	}
}

func (h *Handoff) shared() *handoffState {
	if h == nil {
		return nil
	}
	return h.state
}
