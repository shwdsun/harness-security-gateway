package targetmanifest

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

var ErrUnsupportedSchema = errors.New("unsupported target manifest schema")

// Definition is sandboxd's single version-aware ExecutionTarget carrier. It
// retains exactly one decoded wire manifest and nothing else: Validate,
// Fingerprint and MarshalJSON are that struct's own methods under its own
// schema and hash domain, so no rebuilt wire struct can drift from it. Reads
// are derived views. v1 state is viewed as persistent(state_ref); no v2 -> v1
// conversion exists. Compare definitions by Fingerprint, never with ==.
type Definition struct {
	v1 *Manifest
	v2 *ManifestV2
}

// Common is a transient, schema-independent read view. It is derived on each
// call, never stored, never hashed and never an input to Validate.
type Common struct {
	Schema, ID, Revision, WorkspaceRef                           string
	WorkspaceMode                                                WorkspaceMode
	RunnerState                                                  RunnerState
	PolicyRef, AuthProfileRef, SkillBundleRef, NetworkProfileRef string
	SessionMode                                                  SessionMode
	Runner                                                       Runner // features deep-copied
	Limits                                                       Limits
}

func FromV1(m Manifest) (Definition, error) {
	if err := m.Validate(); err != nil {
		return Definition{}, err
	}
	return Definition{v1: &m}.Clone(), nil
}

func FromV2(m ManifestV2) (Definition, error) {
	if err := m.Validate(); err != nil {
		return Definition{}, err
	}
	return Definition{v2: &m}.Clone(), nil
}

// DecodeDefinition dispatches on the exact top-level "schema" key after strict framing.
// Only the exact string harness-target/v2 selects DecodeV2. Every other
// document (v1, unknown schema, missing, case-aliased or non-string key) takes
// the unchanged v1 Decode, preserving legacy acceptance and legacy errors. The
// peek only selects a decoder; each decoder re-verifies its own schema field,
// so an aliased "Schema":"harness-target/v2" fails v1's schema check and a v2
// document carrying a stray "Schema" fails v2's exact-field check.
func DecodeDefinition(data []byte) (Definition, error) {
	var raw map[string]json.RawMessage
	if err := strictjson.Decode(data, MaxManifest, MaxJSONDepth, &raw); err != nil {
		return Definition{}, err
	}
	var schema string
	if head, ok := raw["schema"]; ok {
		_ = json.Unmarshal(head, &schema) // non-string stays "" and takes the legacy path
	}
	if schema == SchemaV2 {
		manifest, err := DecodeV2(data)
		if err != nil {
			return Definition{}, err
		}
		return FromV2(manifest)
	}
	manifest, err := Decode(data)
	if err != nil {
		return Definition{}, err
	}
	return FromV1(manifest)
}

// UnmarshalJSON lets sandboxconfig hold one []Definition. Config-schema gating
// (sandboxd/v2 accepts v1 only) is Config.Validate's job, not the decoder's.
func (d *Definition) UnmarshalJSON(data []byte) error {
	decoded, err := DecodeDefinition(data)
	if err != nil {
		return err
	}
	*d = decoded
	return nil
}

// MarshalJSON emits the retained wire struct exactly; v2 goes through
// RunnerState's closed encoder. A zero Definition cannot be marshalled.
func (d Definition) MarshalJSON() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if d.v1 != nil {
		return json.Marshal(*d.v1)
	}
	return json.Marshal(*d.v2)
}

func (d Definition) Validate() error {
	switch {
	case d.v1 != nil && d.v2 == nil:
		return d.v1.Validate()
	case d.v2 != nil && d.v1 == nil:
		return d.v2.Validate()
	default:
		return fmt.Errorf("%w: definition must carry exactly one manifest", ErrUnsupportedSchema)
	}
}

// Fingerprint is the retained manifest's own digest: v1 under
// harness-gateway.target-manifest/v1, v2 under .../v2. Never mutates callers.
func (d Definition) Fingerprint() (string, error) {
	if err := d.Validate(); err != nil {
		return "", err
	}
	if d.v1 != nil {
		return d.v1.Fingerprint()
	}
	return d.v2.Fingerprint()
}

func (d Definition) Schema() string           { return d.Common().Schema }
func (d Definition) ID() string               { return d.Common().ID }
func (d Definition) Revision() string         { return d.Common().Revision }
func (d Definition) RunnerState() RunnerState { return d.Common().RunnerState }

// Manifest returns a private copy of the retained v1 manifest, if any. There
// is deliberately no v2 counterpart producing a Manifest.
func (d Definition) Manifest() (Manifest, bool) {
	if d.v1 == nil {
		return Manifest{}, false
	}
	return *d.Clone().v1, true
}

func (d Definition) ManifestV2() (ManifestV2, bool) {
	if d.v2 == nil {
		return ManifestV2{}, false
	}
	return *d.Clone().v2, true
}

func (d Definition) Common() Common {
	switch {
	case d.v1 != nil:
		m := d.v1
		return Common{
			Schema: m.Schema, ID: m.ID, Revision: m.Revision, WorkspaceRef: m.WorkspaceRef,
			WorkspaceMode: m.WorkspaceMode,
			// A validated v1 always carries a non-empty state_ref; the only
			// truthful view is persistent(ref). None is never synthesized.
			RunnerState: PersistentRunnerState(m.StateRef),
			PolicyRef:   m.PolicyRef, AuthProfileRef: m.AuthProfileRef,
			SkillBundleRef: m.SkillBundleRef, NetworkProfileRef: m.NetworkProfileRef,
			SessionMode: m.SessionMode, Runner: cloneRunner(m.Runner), Limits: m.Limits,
		}
	case d.v2 != nil:
		m := d.v2
		return Common{
			Schema: m.Schema, ID: m.ID, Revision: m.Revision, WorkspaceRef: m.WorkspaceRef,
			WorkspaceMode: m.WorkspaceMode, RunnerState: m.RunnerState,
			PolicyRef: m.PolicyRef, AuthProfileRef: m.AuthProfileRef,
			SkillBundleRef: m.SkillBundleRef, NetworkProfileRef: m.NetworkProfileRef,
			SessionMode: m.SessionMode, Runner: cloneRunner(m.Runner), Limits: m.Limits,
		}
	default:
		return Common{}
	}
}

// Clone deep-copies the retained manifest including the feature slice, so
// registry ingress/egress never aliases caller or registry memory.
func (d Definition) Clone() Definition {
	switch {
	case d.v1 != nil:
		m := *d.v1
		m.Runner = cloneRunner(m.Runner)
		return Definition{v1: &m}
	case d.v2 != nil:
		m := *d.v2
		m.Runner = cloneRunner(m.Runner)
		return Definition{v2: &m}
	default:
		return Definition{}
	}
}

func cloneRunner(r Runner) Runner {
	if r.RequiredFeatures != nil { // keep nil vs empty exactly as decoded
		r.RequiredFeatures = append(make([]runnerwire.Feature, 0, len(r.RequiredFeatures)), r.RequiredFeatures...)
	}
	return r
}
