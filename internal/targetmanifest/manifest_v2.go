package targetmanifest

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

const SchemaV2 = "harness-target/v2"

// ManifestV2 replaces v1's mandatory state_ref with the closed RunnerState
// union. It is a distinct type on purpose: no v1 consumer accepts it and no
// conversion to Manifest exists. Other field semantics stay the same, but v2
// requires exact JSON field names rather than encoding/json's case aliases.
type ManifestV2 struct {
	Schema            string        `json:"schema"`
	ID                string        `json:"id"`
	Revision          string        `json:"revision"`
	Runner            Runner        `json:"runner"`
	WorkspaceRef      string        `json:"workspace_ref"`
	WorkspaceMode     WorkspaceMode `json:"workspace_mode"`
	RunnerState       RunnerState   `json:"runner_state"`
	PolicyRef         string        `json:"policy_ref"`
	AuthProfileRef    string        `json:"auth_profile_ref"`
	SkillBundleRef    string        `json:"skill_bundle_ref"`
	NetworkProfileRef string        `json:"network_profile_ref"`
	SessionMode       SessionMode   `json:"session_mode"`
	Limits            Limits        `json:"limits"`
}

func DecodeV2(data []byte) (ManifestV2, error) {
	// A method-free type avoids recursively calling UnmarshalJSON while
	// preserving the explicit wire layout and RunnerState's closed decoder.
	type wire ManifestV2
	var manifest wire
	if err := strictjson.Decode(data, MaxManifest, MaxJSONDepth, &manifest); err != nil {
		return ManifestV2{}, err
	}
	if err := validateV2FieldNames(data); err != nil {
		return ManifestV2{}, err
	}
	result := ManifestV2(manifest)
	if err := result.Validate(); err != nil {
		return ManifestV2{}, err
	}
	return result, nil
}

// UnmarshalJSON preserves the v2 boundary when embedded in another document.
// This does not add v2 to any production configuration or execution registry.
func (m *ManifestV2) UnmarshalJSON(data []byte) error {
	manifest, err := DecodeV2(data)
	if err != nil {
		return err
	}
	*m = manifest
	return nil
}

func validateV2FieldNames(data []byte) error {
	fields, err := exactV2Object(data, "manifest", "schema", "id", "revision",
		"runner", "workspace_ref", "workspace_mode", "runner_state", "policy_ref",
		"auth_profile_ref", "skill_bundle_ref", "network_profile_ref", "session_mode", "limits")
	if err != nil {
		return err
	}
	if _, err := exactV2Object(fields["runner"], "runner", "family", "adapter_version",
		"protocol", "image", "required_features"); err != nil {
		return err
	}
	_, err = exactV2Object(fields["limits"], "limits", "timeout_seconds", "memory_bytes",
		"cpu_millis", "pids", "max_input_bytes", "max_output_bytes", "max_progress_bytes",
		"max_stderr_bytes", "max_events", "max_session_age_seconds", "max_session_turns")
	return err
}

// These temporary maps only check field names after strict framing. They are
// never options or stored authority. RunnerState checks its own exact keys.
func exactV2Object(data []byte, field string, allowed ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return nil, invalid(field, "must be an object")
	}
	for key := range fields {
		if !slices.Contains(allowed, key) {
			return nil, invalid(field, fmt.Sprintf("unknown field %q", key))
		}
	}
	return fields, nil
}

func (m ManifestV2) Validate() error {
	if m.Schema != SchemaV2 {
		return invalid("schema", "must be harness-target/v2")
	}
	if err := validateNames(
		namedRef{"id", m.ID},
		namedRef{"revision", m.Revision},
		namedRef{"workspace_ref", m.WorkspaceRef},
		namedRef{"policy_ref", m.PolicyRef},
		namedRef{"auth_profile_ref", m.AuthProfileRef},
		namedRef{"skill_bundle_ref", m.SkillBundleRef},
		namedRef{"network_profile_ref", m.NetworkProfileRef},
	); err != nil {
		return err
	}
	if m.WorkspaceMode != WorkspaceReadOnly && m.WorkspaceMode != WorkspaceReadWrite {
		return invalid("workspace_mode", "must be ro or rw")
	}
	if err := m.RunnerState.Validate(); err != nil {
		return err
	}
	if err := validateExecution(m.SessionMode, m.Runner, m.Limits); err != nil {
		return err
	}
	// Without a persistent runner-state resource there is nothing HSG can
	// vouch for as the durable home of a resumable local session.
	if m.RunnerState.Kind() == RunnerStateNone && m.SessionMode != SessionNewOnly {
		return invalid("session_mode", "runner_state none requires new_only")
	}
	return nil
}

// Fingerprint binds every semantic field including the runner-state kind and
// ref, excludes Revision and order-normalizes features under a separate v2
// hash domain. It relies on SHA-256 collision resistance, not impossibility.
func (m ManifestV2) Fingerprint() (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	normalized := m
	normalized.Revision = ""
	normalized.Runner.RequiredFeatures = sortedFeatures(m.Runner.RequiredFeatures)
	return digestManifest("harness-gateway.target-manifest/v2\x00", normalized)
}
