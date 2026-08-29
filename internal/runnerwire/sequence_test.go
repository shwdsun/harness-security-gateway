package runnerwire

import (
	"errors"
	"testing"
)

func TestSequenceAcceptsContiguousLifecycle(t *testing.T) {
	sequence, err := NewSequence("run-1")
	if err != nil {
		t.Fatalf("NewSequence() error = %v", err)
	}
	events := []RunEvent{
		&RunStarted{Protocol: ProtocolV1, Type: TypeRunStarted, RunID: "run-1", Seq: 1},
		&RunProgress{Protocol: ProtocolV1, Type: TypeRunProgress, RunID: "run-1", Seq: 2, Kind: ProgressKindStatus, Text: "working"},
		&RunCompleted{Protocol: ProtocolV1, Type: TypeRunCompleted, RunID: "run-1", Seq: 3, Output: TextContent{MediaType: MediaTypeTextPlain, Text: "done"}},
	}
	for _, event := range events {
		if err := sequence.Accept(event); err != nil {
			t.Fatalf("Accept(%T) error = %v", event, err)
		}
	}
	if err := sequence.Finalize(); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if !sequence.IsTerminal() || sequence.LastSequence() != 3 {
		t.Fatalf("sequence state = terminal %t, seq %d; want true, 3", sequence.IsTerminal(), sequence.LastSequence())
	}
}

func TestSequenceRejectsInvalidLifecycle(t *testing.T) {
	started := func(runID string, seq uint64) *RunStarted {
		return &RunStarted{Protocol: ProtocolV1, Type: TypeRunStarted, RunID: runID, Seq: seq}
	}
	progress := func(runID string, seq uint64) *RunProgress {
		return &RunProgress{Protocol: ProtocolV1, Type: TypeRunProgress, RunID: runID, Seq: seq, Kind: ProgressKindStatus, Text: "working"}
	}
	completed := func(runID string, seq uint64) *RunCompleted {
		return &RunCompleted{Protocol: ProtocolV1, Type: TypeRunCompleted, RunID: runID, Seq: seq, Output: TextContent{MediaType: MediaTypeTextPlain, Text: "done"}}
	}

	t.Run("progress before started", func(t *testing.T) {
		sequence, _ := NewSequence("run-1")
		if err := sequence.Accept(progress("run-1", 1)); !errors.Is(err, ErrEventSequence) {
			t.Fatalf("Accept() error = %v, want ErrEventSequence", err)
		}
	})

	t.Run("wrong run id", func(t *testing.T) {
		sequence, _ := NewSequence("run-1")
		if err := sequence.Accept(started("run-2", 1)); !errors.Is(err, ErrEventSequence) {
			t.Fatalf("Accept() error = %v, want ErrEventSequence", err)
		}
	})

	t.Run("non-increasing sequence", func(t *testing.T) {
		sequence, _ := NewSequence("run-1")
		if err := sequence.Accept(started("run-1", 1)); err != nil {
			t.Fatalf("Accept(started) error = %v", err)
		}
		if err := sequence.Accept(progress("run-1", 1)); !errors.Is(err, ErrEventSequence) {
			t.Fatalf("Accept(progress) error = %v, want ErrEventSequence", err)
		}
	})

	t.Run("first sequence does not start at one", func(t *testing.T) {
		sequence, _ := NewSequence("run-1")
		if err := sequence.Accept(started("run-1", 2)); !errors.Is(err, ErrEventSequence) {
			t.Fatalf("Accept(started) error = %v, want ErrEventSequence", err)
		}
	})

	t.Run("sequence gap", func(t *testing.T) {
		sequence, _ := NewSequence("run-1")
		if err := sequence.Accept(started("run-1", 1)); err != nil {
			t.Fatalf("Accept(started) error = %v", err)
		}
		if err := sequence.Accept(progress("run-1", 3)); !errors.Is(err, ErrEventSequence) {
			t.Fatalf("Accept(progress) error = %v, want ErrEventSequence", err)
		}
	})

	t.Run("second started", func(t *testing.T) {
		sequence, _ := NewSequence("run-1")
		if err := sequence.Accept(started("run-1", 1)); err != nil {
			t.Fatalf("Accept(first) error = %v", err)
		}
		if err := sequence.Accept(started("run-1", 2)); !errors.Is(err, ErrEventSequence) {
			t.Fatalf("Accept(second) error = %v, want ErrEventSequence", err)
		}
	})

	t.Run("event after terminal", func(t *testing.T) {
		sequence, _ := NewSequence("run-1")
		if err := sequence.Accept(started("run-1", 1)); err != nil {
			t.Fatalf("Accept(started) error = %v", err)
		}
		if err := sequence.Accept(completed("run-1", 2)); err != nil {
			t.Fatalf("Accept(completed) error = %v", err)
		}
		if err := sequence.Accept(progress("run-1", 3)); !errors.Is(err, ErrEventSequence) {
			t.Fatalf("Accept(after terminal) error = %v, want ErrEventSequence", err)
		}
	})

	t.Run("missing terminal", func(t *testing.T) {
		sequence, _ := NewSequence("run-1")
		if err := sequence.Accept(started("run-1", 1)); err != nil {
			t.Fatalf("Accept(started) error = %v", err)
		}
		if err := sequence.Finalize(); !errors.Is(err, ErrEventSequence) {
			t.Fatalf("Finalize() error = %v, want ErrEventSequence", err)
		}
	})

	t.Run("missing started", func(t *testing.T) {
		sequence, _ := NewSequence("run-1")
		if err := sequence.Finalize(); !errors.Is(err, ErrEventSequence) {
			t.Fatalf("Finalize() error = %v, want ErrEventSequence", err)
		}
	})
}
