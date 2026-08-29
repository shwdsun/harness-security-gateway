package runnerwire

import (
	"errors"
	"fmt"
)

var ErrEventSequence = errors.New("invalid HRP/1 event sequence")

// Sequence validates the lifecycle of events for one Run. The first event must
// be run.started with seq 1; subsequent seq values must be contiguous; and
// exactly one terminal event must end the stream. HRP/1 is a direct pipe, so a
// gap is a protocol violation rather than evidence of a missing transport event.
type Sequence struct {
	runID    string
	lastSeq  uint64
	started  bool
	terminal bool
}

func NewSequence(runID string) (*Sequence, error) {
	if err := validateIdentifier("run_id", runID, MaxRunIDBytes); err != nil {
		return nil, err
	}
	return &Sequence{runID: runID}, nil
}

func (s *Sequence) Accept(event RunEvent) error {
	if s == nil {
		return fmt.Errorf("%w: nil validator", ErrEventSequence)
	}
	if event == nil {
		return fmt.Errorf("%w: nil event", ErrEventSequence)
	}
	if err := event.Validate(); err != nil {
		return err
	}
	if event.EventRunID() != s.runID {
		return fmt.Errorf("%w: run_id %q does not match %q", ErrEventSequence, event.EventRunID(), s.runID)
	}
	if s.terminal {
		return fmt.Errorf("%w: event received after terminal event", ErrEventSequence)
	}
	if !s.started {
		if event.FrameType() != TypeRunStarted {
			return fmt.Errorf("%w: first event must be %q", ErrEventSequence, TypeRunStarted)
		}
		if event.EventSequence() != 1 {
			return fmt.Errorf("%w: first event seq must be 1", ErrEventSequence)
		}
		s.started = true
	} else if event.FrameType() == TypeRunStarted {
		return fmt.Errorf("%w: %q may appear only once", ErrEventSequence, TypeRunStarted)
	}
	if s.lastSeq != 0 && event.EventSequence() != s.lastSeq+1 {
		return fmt.Errorf("%w: seq %d must follow %d", ErrEventSequence, event.EventSequence(), s.lastSeq)
	}
	s.lastSeq = event.EventSequence()
	if event.Terminal() {
		s.terminal = true
	}
	return nil
}

// Finalize verifies that the runner stream ended after exactly one terminal
// event. It should be called when EOF or process exit is observed.
func (s *Sequence) Finalize() error {
	if s == nil {
		return fmt.Errorf("%w: nil validator", ErrEventSequence)
	}
	if !s.started {
		return fmt.Errorf("%w: missing %q", ErrEventSequence, TypeRunStarted)
	}
	if !s.terminal {
		return fmt.Errorf("%w: missing terminal event", ErrEventSequence)
	}
	return nil
}

func (s *Sequence) LastSequence() uint64 {
	if s == nil {
		return 0
	}
	return s.lastSeq
}

func (s *Sequence) IsTerminal() bool {
	return s != nil && s.terminal
}
