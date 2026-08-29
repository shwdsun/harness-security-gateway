// Package targetmanifest defines sandboxd's immutable, operator-authored
// ExecutionTarget configuration. It is never populated from a chat request.
package targetmanifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

const (
	SchemaV1                   = "harness-target/v1"
	MaxManifest                = 64 << 10
	MaxJSONDepth               = 8
	MaxNameBytes               = 160
	MaxImageBytes              = 512
	MaxTimeoutSecs             = 24 * 60 * 60
	MaxSessionAgeSeconds int64 = 30 * 24 * 60 * 60
	MaxSessionTurns            = 1024
)

var ErrInvalid = errors.New("invalid target manifest")

type WorkspaceMode string

const (
	WorkspaceReadOnly  WorkspaceMode = "ro"
	WorkspaceReadWrite WorkspaceMode = "rw"
)

type SessionMode string

const (
	SessionNewOnly      SessionMode = "new_only"
	SessionOpaqueResume SessionMode = "opaque_resume"
)

type Runner struct {
	Family           string               `json:"family"`
	AdapterVersion   string               `json:"adapter_version"`
	Protocol         string               `json:"protocol"`
	Image            string               `json:"image"`
	RequiredFeatures []runnerwire.Feature `json:"required_features"`
}

type Limits struct {
	TimeoutSeconds       int64 `json:"timeout_seconds"`
	MemoryBytes          int64 `json:"memory_bytes"`
	CPUMillis            int64 `json:"cpu_millis"`
	PIDs                 int64 `json:"pids"`
	MaxInputBytes        int   `json:"max_input_bytes"`
	MaxOutputBytes       int   `json:"max_output_bytes"`
	MaxProgressBytes     int   `json:"max_progress_bytes"`
	MaxStderrBytes       int   `json:"max_stderr_bytes"`
	MaxEvents            int   `json:"max_events"`
	MaxSessionAgeSeconds int64 `json:"max_session_age_seconds"`
	MaxSessionTurns      int   `json:"max_session_turns"`
}

type Manifest struct {
	Schema            string        `json:"schema"`
	ID                string        `json:"id"`
	Revision          string        `json:"revision"`
	Runner            Runner        `json:"runner"`
	WorkspaceRef      string        `json:"workspace_ref"`
	WorkspaceMode     WorkspaceMode `json:"workspace_mode"`
	StateRef          string        `json:"state_ref"`
	PolicyRef         string        `json:"policy_ref"`
	AuthProfileRef    string        `json:"auth_profile_ref"`
	SkillBundleRef    string        `json:"skill_bundle_ref"`
	NetworkProfileRef string        `json:"network_profile_ref"`
	SessionMode       SessionMode   `json:"session_mode"`
	Limits            Limits        `json:"limits"`
}

func Decode(data []byte) (Manifest, error) {
	var manifest Manifest
	if err := strictjson.Decode(data, MaxManifest, MaxJSONDepth, &manifest); err != nil {
		return Manifest{}, err
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m Manifest) Validate() error {
	if m.Schema != SchemaV1 {
		return invalid("schema", "must be harness-target/v1")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"id", m.ID},
		{"revision", m.Revision},
		{"workspace_ref", m.WorkspaceRef},
		{"state_ref", m.StateRef},
		{"policy_ref", m.PolicyRef},
		{"auth_profile_ref", m.AuthProfileRef},
		{"skill_bundle_ref", m.SkillBundleRef},
		{"network_profile_ref", m.NetworkProfileRef},
	} {
		if err := validateName(field.name, field.value); err != nil {
			return err
		}
	}
	if m.WorkspaceMode != WorkspaceReadOnly && m.WorkspaceMode != WorkspaceReadWrite {
		return invalid("workspace_mode", "must be ro or rw")
	}
	if m.SessionMode != SessionNewOnly && m.SessionMode != SessionOpaqueResume {
		return invalid("session_mode", "must be new_only or opaque_resume")
	}
	if err := m.Runner.validate(); err != nil {
		return err
	}
	if m.SessionMode == SessionOpaqueResume && !hasFeature(m.Runner.RequiredFeatures, runnerwire.FeatureSessionResume) {
		return invalid("runner.required_features", "opaque_resume requires session.resume")
	}
	if err := m.Limits.validate(); err != nil {
		return err
	}
	switch m.SessionMode {
	case SessionNewOnly:
		if m.Limits.MaxSessionAgeSeconds != 0 || m.Limits.MaxSessionTurns != 0 {
			return invalid("limits", "new_only requires zero session lifecycle limits")
		}
	case SessionOpaqueResume:
		if m.Limits.MaxSessionAgeSeconds == 0 || m.Limits.MaxSessionTurns == 0 {
			return invalid("limits", "opaque_resume requires positive session lifecycle limits")
		}
	}
	return nil
}

func (r Runner) validate() error {
	if err := validateName("runner.family", r.Family); err != nil {
		return err
	}
	if err := validateName("runner.adapter_version", r.AdapterVersion); err != nil {
		return err
	}
	if r.Protocol != runnerwire.ProtocolV1 {
		return invalid("runner.protocol", "must be hrp/1")
	}
	if err := validateDigestImage(r.Image); err != nil {
		return err
	}
	if r.RequiredFeatures == nil {
		return invalid("runner.required_features", "must be an array")
	}
	if len(r.RequiredFeatures) > runnerwire.MaxFeatures {
		return invalid("runner.required_features", "contains too many entries")
	}
	seen := make(map[runnerwire.Feature]struct{}, len(r.RequiredFeatures))
	for index, feature := range r.RequiredFeatures {
		if feature != runnerwire.FeatureSessionResume && feature != runnerwire.FeatureProgressText {
			return invalid(fmt.Sprintf("runner.required_features[%d]", index), "is not an HRP/1 feature")
		}
		if _, exists := seen[feature]; exists {
			return invalid(fmt.Sprintf("runner.required_features[%d]", index), "is duplicated")
		}
		seen[feature] = struct{}{}
	}
	return nil
}

func (l Limits) validate() error {
	switch {
	case l.TimeoutSeconds < 1 || l.TimeoutSeconds > MaxTimeoutSecs:
		return invalid("limits.timeout_seconds", "must be between 1 and 86400")
	case l.MemoryBytes < 64<<20 || l.MemoryBytes > 64<<30:
		return invalid("limits.memory_bytes", "must be between 64 MiB and 64 GiB")
	case l.CPUMillis < 100 || l.CPUMillis > 64_000:
		return invalid("limits.cpu_millis", "must be between 100 and 64000")
	case l.PIDs < 16 || l.PIDs > 4096:
		return invalid("limits.pids", "must be between 16 and 4096")
	case l.MaxInputBytes < 1 || l.MaxInputBytes > runnerwire.MaxInputTextBytes:
		return invalid("limits.max_input_bytes", "exceeds HRP/1 bounds")
	case l.MaxOutputBytes < 1 || l.MaxOutputBytes > runnerwire.MaxOutputTextBytes:
		return invalid("limits.max_output_bytes", "exceeds HRP/1 bounds")
	case l.MaxProgressBytes < 1 || l.MaxProgressBytes > runnerwire.MaxProgressTextBytes:
		return invalid("limits.max_progress_bytes", "exceeds HRP/1 bounds")
	case l.MaxStderrBytes < 1<<10 || l.MaxStderrBytes > 1<<20:
		return invalid("limits.max_stderr_bytes", "must be between 1 KiB and 1 MiB")
	case l.MaxEvents < 1 || l.MaxEvents > runnerwire.MaxEvents:
		return invalid("limits.max_events", "must be between 1 and 512")
	case l.MaxSessionAgeSeconds < 0 || l.MaxSessionAgeSeconds > MaxSessionAgeSeconds:
		return invalid("limits.max_session_age_seconds", "exceeds the session age bound")
	case l.MaxSessionTurns < 0 || l.MaxSessionTurns > MaxSessionTurns:
		return invalid("limits.max_session_turns", "exceeds the session turn bound")
	default:
		return nil
	}
}

// Fingerprint returns a semantic, order-normalized manifest digest. Revision
// is excluded so sandboxd can reject reuse of one revision for changed policy.
func (m Manifest) Fingerprint() (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	normalized := m
	normalized.Revision = ""
	normalized.Runner.RequiredFeatures = append([]runnerwire.Feature(nil), m.Runner.RequiredFeatures...)
	sort.Slice(normalized.Runner.RequiredFeatures, func(i, j int) bool {
		return normalized.Runner.RequiredFeatures[i] < normalized.Runner.RequiredFeatures[j]
	})
	data, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("canonicalize manifest: %w", err)
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("harness-gateway.target-manifest/v1\x00"))
	_, _ = digest.Write(data)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func validateName(field, value string) error {
	if value == "" || len(value) > MaxNameBytes || value == "." || value == ".." {
		return invalid(field, "has invalid byte length")
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("-_.:@", rune(char)) {
			continue
		}
		return invalid(field, "contains unsupported characters")
	}
	return nil
}

func validateDigestImage(value string) error {
	if value == "" || len(value) > MaxImageBytes {
		return invalid("runner.image", "has invalid byte length")
	}
	const separator = "@sha256:"
	position := strings.LastIndex(value, separator)
	if position <= 0 || strings.Contains(value[:position], "@") {
		return invalid("runner.image", "must be pinned by one sha256 digest")
	}
	digest := value[position+len(separator):]
	if len(digest) != 64 {
		return invalid("runner.image", "sha256 digest must contain 64 lowercase hex characters")
	}
	for index := 0; index < len(digest); index++ {
		if (digest[index] < '0' || digest[index] > '9') && (digest[index] < 'a' || digest[index] > 'f') {
			return invalid("runner.image", "sha256 digest must contain 64 lowercase hex characters")
		}
	}
	for index := 0; index < position; index++ {
		char := value[index]
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("-._/:", rune(char)) {
			continue
		}
		return invalid("runner.image", "repository contains unsupported characters")
	}
	return nil
}

func hasFeature(features []runnerwire.Feature, wanted runnerwire.Feature) bool {
	for _, feature := range features {
		if feature == wanted {
			return true
		}
	}
	return false
}

func invalid(field, problem string) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalid, field, problem)
}
