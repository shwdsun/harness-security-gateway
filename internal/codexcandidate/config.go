// Package codexcandidate provides an offline, non-executable Codex preflight.
// Its result cannot be supplied to sandboxd as a target or revision authority.
package codexcandidate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

const (
	Schema            = "codex-candidate/v1"
	MaxBytes          = 128 << 10
	fingerprintDomain = "harness-security-gateway.codex-candidate/v1"
)

var ErrInvalid = errors.New("invalid Codex candidate configuration")

// These DTOs are private on purpose. Decode is the only input constructor;
// there is no partially validated exported config or mutable target accessor.
type config struct {
	Schema     string                    `json:"schema"`
	ProfileID  string                    `json:"profile_id"`
	Target     targetmanifest.Definition `json:"target"`
	Workspace  workspace                 `json:"workspace"`
	Credential credential                `json:"credential"`
}

type workspace struct {
	Ref  string `json:"ref"`
	Path string `json:"path"`
}

type credential struct {
	WorkspaceRef   string `json:"workspace_ref"`
	AuthProfileRef string `json:"auth_profile_ref"`
	SlotRef        string `json:"slot_ref"`
	Generation     uint64 `json:"generation"`
	Root           string `json:"root"`
	Directory      string `json:"directory"`
}

// Candidate carries only a validated configuration, not readiness or a live
// source handle. Its fingerprint is diagnostic and never an execution pin.
type Candidate struct {
	config              config
	profile             codexprofile.Contract
	fingerprint         string
	manifestFingerprint string
	profileFingerprint  string
}

// Load reads only the explicitly selected configuration file. It creates,
// chmods and locks nothing, and never opens the configured credential file.
func Load(path string) (Candidate, error) {
	// O_NONBLOCK prevents a substituted FIFO from hanging before fstat;
	// O_NOFOLLOW rejects the final symlink. This operator-owned configuration
	// read is not protection against a hostile same-UID writer or parent swap.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Candidate{}, invalid("config_file", "cannot open regular configuration")
	}
	file := os.NewFile(uintptr(fd), "codex-candidate-config")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return Candidate{}, invalid("config_file", "requires a regular file not writable by group or others")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return Candidate{}, invalid("config_file", "unexpected owner")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	if err != nil {
		return Candidate{}, invalid("config_file", "cannot read configuration")
	}
	return Decode(data)
}

func Decode(data []byte) (Candidate, error) {
	var cfg config
	if err := strictjson.Decode(data, MaxBytes, 12, &cfg); err != nil {
		// Parser errors can quote an attacker-controlled key or value. Do not
		// let a misplaced secret or a host path escape through diagnostics.
		return Candidate{}, invalid("json", "invalid, oversized or non-closed document")
	}
	root, err := exactObject(data, "schema", "profile_id", "target", "workspace", "credential")
	if err != nil {
		return Candidate{}, err
	}
	if _, err := exactObject(root["workspace"], "ref", "path"); err != nil {
		return Candidate{}, err
	}
	if _, err := exactObject(root["credential"], "workspace_ref", "auth_profile_ref", "slot_ref", "generation", "root", "directory"); err != nil {
		return Candidate{}, err
	}
	// Candidate files require explicit, non-null target values even for the
	// new_only zero session limits. Do not change legacy manifest decoding.
	target, err := exactObject(root["target"], "schema", "id", "revision", "runner", "workspace_ref", "workspace_mode", "runner_state", "policy_ref", "auth_profile_ref", "skill_bundle_ref", "network_profile_ref", "session_mode", "limits")
	if err != nil {
		return Candidate{}, err
	}
	if _, err := exactObject(target["runner"], "family", "adapter_version", "protocol", "image", "required_features"); err != nil {
		return Candidate{}, err
	}
	if _, err := exactObject(target["runner_state"], "kind"); err != nil {
		return Candidate{}, err
	}
	if _, err := exactObject(target["limits"], "timeout_seconds", "memory_bytes", "cpu_millis", "pids", "max_input_bytes", "max_output_bytes", "max_progress_bytes", "max_stderr_bytes", "max_events", "max_session_age_seconds", "max_session_turns"); err != nil {
		return Candidate{}, err
	}
	if cfg.Schema != Schema {
		return Candidate{}, invalid("schema", "unsupported candidate schema")
	}
	profile, err := codexprofile.Resolve(cfg.ProfileID)
	if err != nil {
		return Candidate{}, invalid("profile_id", "unknown sealed profile")
	}
	if err := profile.MatchTarget(cfg.Target); err != nil {
		return Candidate{}, invalid("target", "does not match the sealed profile")
	}
	m := cfg.Target.Common()
	if cfg.Workspace.Ref != m.WorkspaceRef {
		return Candidate{}, invalid("workspace.ref", "does not match the target")
	}
	if cfg.Credential.WorkspaceRef != m.WorkspaceRef || cfg.Credential.AuthProfileRef != m.AuthProfileRef {
		return Candidate{}, invalid("credential", "scope must exactly match target workspace and auth profile")
	}
	if !logicalName(cfg.Credential.SlotRef) || !component(cfg.Credential.Directory) || cfg.Credential.Generation == 0 || cfg.Credential.Generation > math.MaxInt64 {
		return Candidate{}, invalid("credential", "requires a slot ref, positive generation and canonical directory component")
	}
	if !absolutePath(cfg.Workspace.Path) || !absolutePath(cfg.Credential.Root) {
		return Candidate{}, invalid("paths", "require clean absolute non-root paths")
	}
	if overlaps(cfg.Workspace.Path, cfg.Credential.Root) {
		return Candidate{}, invalid("paths", "workspace and credential root must not overlap")
	}
	manifestFP, err := cfg.Target.Fingerprint()
	if err != nil {
		return Candidate{}, invalid("target", "cannot fingerprint target")
	}
	profileFP, err := profile.Fingerprint()
	if err != nil {
		return Candidate{}, invalid("profile_id", "cannot fingerprint profile")
	}
	// Only validated non-secret configuration and the COMPLETE sealed contract
	// digest are hashed. No credential bytes, size, mtime or inode are read or
	// hashed; routine refresh is not an operator binding-generation change.
	// Reuse the authoritative manifest digest; separately include revision
	// because ManifestV2.Fingerprint intentionally excludes it. This closed
	// JSON tuple is unambiguous; it contains no maps or optional fields.
	encoded, err := json.Marshal(struct {
		Schema              string     `json:"schema"`
		ProfileID           string     `json:"profile_id"`
		ProfileFingerprint  string     `json:"profile_fingerprint"`
		ManifestFingerprint string     `json:"manifest_fingerprint"`
		Revision            string     `json:"revision"`
		Workspace           workspace  `json:"workspace"`
		Credential          credential `json:"credential"`
	}{cfg.Schema, cfg.ProfileID, profileFP, manifestFP, cfg.Target.Revision(), cfg.Workspace, cfg.Credential})
	if err != nil {
		return Candidate{}, invalid("json", "cannot canonicalize configuration")
	}
	digest := sha256.Sum256(append([]byte(fingerprintDomain+"\x00"), encoded...))
	return Candidate{config: cfg, profile: profile, fingerprint: Schema + ":" + hex.EncodeToString(digest[:]), manifestFingerprint: manifestFP, profileFingerprint: profileFP}, nil
}

func exactObject(data []byte, names ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || len(object) != len(names) {
		return nil, invalid("json", "requires exact non-null fields")
	}
	for _, name := range names {
		value, ok := object[name]
		if !ok || strings.TrimSpace(string(value)) == "null" {
			return nil, invalid("json", "requires exact non-null fields")
		}
	}
	return object, nil
}

func absolutePath(value string) bool {
	if !filepath.IsAbs(value) || value == "/" || value != filepath.Clean(value) || len(value) > 4096 {
		return false
	}
	for _, char := range value {
		if char < 32 || char == 127 {
			return false
		}
	}
	return true
}

func logicalName(value string) bool {
	if len(value) == 0 || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || strings.ContainsRune("-_.", char)) {
			return false
		}
	}
	return true
}

func component(value string) bool {
	return logicalName(value) && !strings.HasPrefix(value, ".") && value != "auth.json"
}

func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func invalid(field, reason string) error { return fmt.Errorf("%w: %s: %s", ErrInvalid, field, reason) }
