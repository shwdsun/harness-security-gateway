package targetmanifest

import (
	"encoding/json"
	"fmt"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

// RunnerStateKind is the closed discriminator of the v2 runner-state union.
type RunnerStateKind string

const (
	// RunnerStateNone: no persistent harness/runner-state resource exists for
	// the target. It says nothing about the workspace, which is separate.
	RunnerStateNone RunnerStateKind = "none"
	// RunnerStatePersistent: exactly one operator-defined logical runner-state
	// reference, resolved and ownership-bound by sandboxd (not in this package).
	RunnerStatePersistent RunnerStateKind = "persistent"
)

// RunnerState is a closed union: none, or persistent(ref). Fields are
// unexported to prevent mixed kinds/refs. Validate rejects the zero value and
// invalid persistent refs; constructors do not resolve or authorize resources.
type RunnerState struct {
	kind RunnerStateKind
	ref  string
}

func NoRunnerState() RunnerState { return RunnerState{kind: RunnerStateNone} }

func PersistentRunnerState(ref string) RunnerState {
	return RunnerState{kind: RunnerStatePersistent, ref: ref}
}

func (s RunnerState) Kind() RunnerStateKind { return s.kind }

// PersistentRef returns the logical ref only for persistent state.
func (s RunnerState) PersistentRef() (string, bool) {
	if s.kind != RunnerStatePersistent {
		return "", false
	}
	return s.ref, true
}

func (s RunnerState) Validate() error {
	switch s.kind {
	case RunnerStateNone:
		if s.ref != "" {
			return invalid("runner_state.ref", "must be absent for none")
		}
		return nil
	case RunnerStatePersistent:
		if s.ref == "" {
			return invalid("runner_state.ref", "persistent state requires a logical ref")
		}
		return validateName("runner_state.ref", s.ref)
	default:
		return invalid("runner_state.kind", "must be none or persistent")
	}
}

type runnerStateWire struct {
	Kind RunnerStateKind `json:"kind"`
	Ref  string          `json:"ref,omitempty"`
}

func (s RunnerState) MarshalJSON() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(runnerStateWire{Kind: s.kind, Ref: s.ref})
}

// UnmarshalJSON enforces the exact union shape, including when called outside
// DecodeV2. A failed decode leaves the previous value unchanged.
func (s *RunnerState) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := strictjson.Decode(data, MaxManifest, MaxJSONDepth, &raw); err != nil {
		return err
	}
	if raw == nil {
		return invalid("runner_state", "must be an object")
	}
	kindRaw, ok := raw["kind"]
	if !ok {
		return invalid("runner_state.kind", "is required")
	}
	delete(raw, "kind")
	var state RunnerState
	if err := json.Unmarshal(kindRaw, &state.kind); err != nil {
		return invalid("runner_state.kind", "must be a string")
	}
	if refRaw, ok := raw["ref"]; ok {
		if state.kind != RunnerStatePersistent {
			return invalid("runner_state.ref", "is only allowed for persistent state")
		}
		delete(raw, "ref")
		if err := json.Unmarshal(refRaw, &state.ref); err != nil {
			return invalid("runner_state.ref", "must be a string")
		}
	}
	for key := range raw {
		return invalid("runner_state", fmt.Sprintf("unknown field %q", key))
	}
	if err := state.Validate(); err != nil {
		return err
	}
	*s = state
	return nil
}
