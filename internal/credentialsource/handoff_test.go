package credentialsource

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type handoffReceiver struct{ closed atomic.Int32 }

func (*handoffReceiver) Validate() error { return nil }
func (r *handoffReceiver) Close() error  { r.closed.Add(1); return nil }

func testHandoff() (*Handoff, *atomic.Bool, *atomic.Int32) {
	invalid, opens := new(atomic.Bool), new(atomic.Int32)
	return &Handoff{state: &handoffState{
		runID: "admitted-run", fingerprint: strings.Repeat("a", 64),
		binding: Binding{Root: "/owned/source", Directory: "slot", SlotRef: "auth", Generation: 1, WorkspaceRef: "workspace", AuthProfileRef: "profile"},
		verify: func() error {
			if invalid.Load() {
				return ErrInvalidHandoff
			}
			return nil
		},
		open: func(int, string, string, uint32) (Receiver, error) { opens.Add(1); return &handoffReceiver{}, nil },
	}}, invalid, opens
}

func TestHandoffBindsRunTargetAndCompleteLocalBinding(t *testing.T) {
	for _, field := range []string{"run", "target", "root", "directory", "slot", "generation", "workspace", "auth"} {
		t.Run(field, func(t *testing.T) {
			h, _, _ := testHandoff()
			s := h.state
			run, target, binding := s.runID, s.fingerprint, s.binding
			switch field {
			case "run":
				run += "-other"
			case "target":
				target = strings.Repeat("b", 64)
			case "root":
				binding.Root += "-other"
			case "directory":
				binding.Directory += "-other"
			case "slot":
				binding.SlotRef += "-other"
			case "generation":
				binding.Generation++
			case "workspace":
				binding.WorkspaceRef += "-other"
			case "auth":
				binding.AuthProfileRef += "-other"
			}
			if !errors.Is(h.Claim(run, target, binding), ErrInvalidHandoff) {
				t.Fatal("accepted different authority")
			}
			if h.Validate(s.runID, s.fingerprint, s.binding) == nil {
				t.Fatal("failed Claim granted validation")
			}
		})
	}
}

func TestHandoffCannotBeCopiedReplayedOrSerialized(t *testing.T) {
	h, invalid, opens := testHandoff()
	copied := *h
	s := h.state
	if _, err := h.OpenReceiver(12, "ref", "bootstrap", 1000); err == nil {
		t.Fatal("receiver before Create claim")
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Go(func() {
			if copied.Claim(s.runID, s.fingerprint, s.binding) == nil {
				winners.Add(1)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("Create claims=%d", winners.Load())
	}
	if h.Validate(s.runID, s.fingerprint, s.binding) != nil {
		t.Fatal("valid claimed source rejected")
	}
	receiver, err := copied.OpenReceiver(12, "ref", "bootstrap", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.OpenReceiver(12, "ref", "bootstrap", 1000); err == nil || opens.Load() != 1 {
		t.Fatal("receiver replayed")
	}
	if err := receiver.Close(); err != nil {
		t.Fatal(err)
	}
	if h.Validate(s.runID, s.fingerprint, s.binding) != nil {
		t.Fatal("observation close revoked held source")
	}
	invalid.Store(true)
	if h.Validate(s.runID, s.fingerprint, s.binding) == nil {
		t.Fatal("invalid source still usable")
	}
	h.Close()
	invalid.Store(false)
	if copied.Validate(s.runID, s.fingerprint, s.binding) == nil {
		t.Fatal("copied capability survived Close")
	}
	for _, value := range []any{h, *h} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("handoff serialized")
		}
	}
	var zero Handoff
	if json.Unmarshal([]byte(`{}`), &zero) == nil || zero.Claim(s.runID, s.fingerprint, s.binding) == nil {
		t.Fatal("wire bytes created authority")
	}
	var missing *Handoff
	missing.Close()
	if missing.Claim(s.runID, s.fingerprint, s.binding) == nil {
		t.Fatal("nil handoff accepted")
	}
}
