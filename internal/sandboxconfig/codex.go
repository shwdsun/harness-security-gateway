package sandboxconfig

import (
	"encoding/json"
	"math"
	"path/filepath"
	"strings"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

const SchemaCodexV1 = "sandboxd/codex-v1"

// FixedCodexImage is the measured cached template, not an acquisition request
// or production image approval. A different image requires another profile.
const FixedCodexImage = "golang@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd"

// Artifact contains only operator-owned, pre-existing input. No constructor
// downloads, builds or changes it. The runtime verifies its content hash.
type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// ApprovedScope is independently provisioned from the compiled Core Binding.
// Enrollment is compared against this scope; it cannot supply the expectation.
type ApprovedScope struct {
	BindingFingerprint string `json:"binding_fingerprint"`
	ConnectorID        string `json:"connector_id"`
	ActorRef           string `json:"actor_ref"`
	ConversationRef    string `json:"conversation_ref"`
	TargetID           string `json:"target_id"`
	TargetRevision     string `json:"target_revision"`
}

func (s ApprovedScope) SessionScope() sessionauth.Scope {
	return sessionauth.Scope{BindingFingerprint: s.BindingFingerprint, ConnectorID: s.ConnectorID,
		ActorRef: s.ActorRef, ConversationRef: s.ConversationRef,
		TargetID: s.TargetID, TargetRevision: s.TargetRevision}
}

// Codex is the one fixed daemon profile. Its presence cannot enable native
// execution in a default build. No URL, argv, environment or tool options exist.
type Codex struct {
	Credential   credentialsource.Binding `json:"credential"`
	Scope        ApprovedScope            `json:"scope"`
	ProviderRoot string                   `json:"provider_root"`
	ToolPackage  string                   `json:"tool_package"`
	OwnerSHA256  string                   `json:"owner_sha256"`
	UIDSetup     Artifact                 `json:"uid_setup"`
	Bootstrap    Artifact                 `json:"bootstrap"`
	Runner       Artifact                 `json:"runner"`
	Canary       Artifact                 `json:"canary"`
	Seccomp      Artifact                 `json:"seccomp"`
}

func matchCodex(target targetmanifest.Definition) error {
	if codexprofile.V3().MatchTarget(target) != nil || target.Common().Runner.Image != FixedCodexImage {
		return invalid("targets", "requires the fixed Codex V3 template")
	}
	return nil
}

func (c Config) validateCodex() error {
	if c.Codex == nil || len(c.Targets) != 1 || len(c.Workspaces) != 1 || len(c.RunnerStates) != 0 {
		return invalid("codex", "requires one target, workspace and credential; no persistent Runner state")
	}
	p := *c.Codex
	target := c.Targets[0]
	b := p.Credential
	if b.WorkspaceRef != target.Common().WorkspaceRef || b.AuthProfileRef != target.Common().AuthProfileRef ||
		b.Generation == 0 || b.Generation > math.MaxInt64 ||
		validateLogicalRef("slot_ref", b.SlotRef) != nil || validateRunnerStateName("slot_ref", b.SlotRef) != nil ||
		validateDirectory("directory", b.Directory) != nil || validateRunnerStateName("directory", b.Directory) != nil ||
		strings.HasPrefix(b.Directory, ".") || b.Directory == "auth.json" {
		return invalid("codex.credential", "invalid exact target binding")
	}
	if sessionauth.Validate(p.Scope.SessionScope()) != nil || p.Scope.TargetID != target.ID() || p.Scope.TargetRevision != target.Revision() {
		return invalid("codex.scope", "requires the complete approved scope for this exact target revision")
	}
	if sessionauth.ValidateDigest(p.OwnerSHA256) != nil {
		return invalid("codex.owner_sha256", "requires the running executable SHA-256")
	}
	// Separate writable control/provider/credential/workspace domains. These
	// lexical checks assume stable, trusted provisioning; the runtime also checks
	// existing directory chains. Neither check attests against a hostile host.
	roots := []string{c.WorkspaceRoot, c.RunnerStateRoot, b.Root, p.ProviderRoot, p.ToolPackage}
	for i, root := range roots {
		if !codexPath(root) {
			return invalid("codex.paths", "requires clean absolute non-root paths")
		}
		for _, other := range roots[:i] {
			if pathsOverlap(root, other) {
				return invalid("codex.paths", "storage domains must not overlap")
			}
		}
		for _, control := range []string{c.Socket, c.StateDatabase, c.ProcessLockPath(), c.Runtime.CLI, c.Runtime.SocketPath} {
			if pathsOverlap(root, control) {
				return invalid("codex.paths", "control paths must be outside Runner and provider storage")
			}
		}
	}
	seen := make(map[string]bool)
	for _, a := range []Artifact{p.UIDSetup, p.Bootstrap, p.Runner, p.Canary, p.Seccomp} {
		if !codexPath(a.Path) || sessionauth.ValidateDigest(a.SHA256) != nil || seen[a.Path] {
			return invalid("codex.artifacts", "requires distinct canonical paths and SHA-256 hashes")
		}
		seen[a.Path] = true
		for _, root := range roots {
			if pathsOverlap(a.Path, root) {
				return invalid("codex.artifacts", "must be separate from mutable storage and tool package")
			}
		}
		for _, control := range []string{c.Socket, c.StateDatabase, c.ProcessLockPath(), c.Runtime.CLI, c.Runtime.SocketPath} {
			if pathsOverlap(a.Path, control) {
				return invalid("codex.artifacts", "must be separate from control paths")
			}
		}
	}
	return nil
}

func codexPath(path string) bool {
	return filepath.IsAbs(path) && path != "/" && filepath.Clean(path) == path &&
		!strings.ContainsAny(path, "\x00,\r\n")
}

// Only the new schema requires all its fields with exact case and non-null
// values. Legacy mock decoding and manifest fingerprint bytes stay unchanged.
func exactCodexFields(data []byte) error {
	root, err := codexObject(data, "schema", "socket", "peer_uid", "state_database", "workspace_root", "runner_state_root", "runtime", "workspaces", "runner_states", "targets", "codex")
	if err != nil {
		return err
	}
	p, err := codexObject(root["codex"], "credential", "scope", "provider_root", "tool_package", "owner_sha256", "uid_setup", "bootstrap", "runner", "canary", "seccomp")
	if err != nil {
		return err
	}
	if _, err = codexObject(p["credential"], "workspace_ref", "auth_profile_ref", "slot_ref", "generation", "root", "directory"); err != nil {
		return err
	}
	if _, err = codexObject(p["scope"], "binding_fingerprint", "connector_id", "actor_ref", "conversation_ref", "target_id", "target_revision"); err != nil {
		return err
	}
	if _, err = codexObject(root["runtime"], "kind", "endpoint", "cli"); err != nil {
		return err
	}
	for _, name := range []string{"uid_setup", "bootstrap", "runner", "canary", "seccomp"} {
		if _, err = codexObject(p[name], "path", "sha256"); err != nil {
			return err
		}
	}
	var workspaces []json.RawMessage
	if json.Unmarshal(root["workspaces"], &workspaces) != nil {
		return invalid("codex", "invalid workspaces")
	}
	for _, w := range workspaces {
		if _, err = codexObject(w, "ref", "directory"); err != nil {
			return err
		}
	}
	var targets []json.RawMessage
	if json.Unmarshal(root["targets"], &targets) != nil {
		return invalid("codex", "invalid targets")
	}
	for _, raw := range targets {
		target, err := codexObject(raw, "schema", "id", "revision", "runner", "workspace_ref", "workspace_mode", "runner_state", "policy_ref", "auth_profile_ref", "skill_bundle_ref", "network_profile_ref", "session_mode", "limits")
		if err != nil {
			return err
		}
		if _, err = codexObject(target["runner"], "family", "adapter_version", "protocol", "image", "required_features"); err != nil {
			return err
		}
		if _, err = codexObject(target["runner_state"], "kind"); err != nil {
			return err
		}
		if _, err = codexObject(target["limits"], "timeout_seconds", "memory_bytes", "cpu_millis", "pids", "max_input_bytes", "max_output_bytes", "max_progress_bytes", "max_stderr_bytes", "max_events", "max_session_age_seconds", "max_session_turns"); err != nil {
			return err
		}
	}
	return nil
}

func codexObject(data []byte, names ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != len(names) {
		return nil, invalid("codex", "requires exact non-null configuration fields")
	}
	for _, name := range names {
		if value, ok := fields[name]; !ok || strings.TrimSpace(string(value)) == "null" {
			return nil, invalid("codex", "requires exact non-null configuration fields")
		}
	}
	return fields, nil
}
