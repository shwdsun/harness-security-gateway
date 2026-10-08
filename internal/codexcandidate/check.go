package codexcandidate

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Report is a local diagnostic only. No production component consumes it.
// Neither valid configuration nor matching metadata can make it ready.
type Report struct {
	Schema                   string   `json:"schema"`
	Status                   string   `json:"status"`
	Configuration            string   `json:"configuration"`
	ConfigurationFingerprint string   `json:"configuration_fingerprint"`
	TargetFingerprint        string   `json:"target_fingerprint"`
	ProfileFingerprint       string   `json:"profile_fingerprint"`
	Classification           string   `json:"classification"`
	LocalMetadata            string   `json:"local_metadata"`
	Findings                 []string `json:"findings"`
	ExecutionBlockers        []string `json:"execution_blockers"`
}

// Check optionally inspects metadata, without opening the auth file, changing
// the filesystem, invoking a CLI, or accessing a database/socket. Observations
// are non-atomic and confer no source lease or execution authority. A runtime
// resolver must separately pin/revalidate sources under exclusive ownership.
func (c Candidate) Check(inspect bool) (Report, error) {
	return c.check(inspect, os.Geteuid(), localMetadataFS{})
}

// The inspector deliberately has no file-open/content-read capability. This
// seam also permits deterministic tests of ownership under remapped test UIDs.
type metadataFS interface {
	Lstat(string) (os.FileInfo, error)
	ReadDir(string) ([]os.DirEntry, error)
}

type localMetadataFS struct{}

func (localMetadataFS) Lstat(path string) (os.FileInfo, error)     { return os.Lstat(path) }
func (localMetadataFS) ReadDir(path string) ([]os.DirEntry, error) { return os.ReadDir(path) }

func (c Candidate) check(inspect bool, uid int, fs metadataFS) (Report, error) {
	if c.fingerprint == "" {
		return Report{}, invalid("candidate", "uninitialized candidate")
	}
	report := Report{
		Schema: "hgwctl/codex-check/v1", Status: "blocked", Configuration: "valid",
		ConfigurationFingerprint: c.fingerprint, TargetFingerprint: c.manifestFingerprint,
		ProfileFingerprint: c.profileFingerprint, Classification: c.profile.Classification,
		LocalMetadata: "not_checked", Findings: []string{},
		// V3 configures the native host, but no profile has complete accepted
		// image/provider/tool evidence. This offline report inspects neither
		// the CLI package nor the provider's resolved model metadata.
		ExecutionBlockers: []string{"image_provenance", "model_tool_compatibility", "network_mediation", "context_closure",
			"credential_lifecycle", "confidentiality_domains", "revision_security_binding", "runtime_canaries"},
	}
	if !inspect {
		return report, nil
	}
	if uid == 0 {
		report.LocalMetadata = "inconclusive"
		report.Findings = append(report.Findings, "root_operator_unsupported")
		return report, nil
	}
	report.LocalMetadata = "matches"
	slot := filepath.Join(c.config.Credential.Root, c.config.Credential.Directory)
	paths := []struct {
		code, path string
		file       bool
	}{
		{"workspace_metadata", c.config.Workspace.Path, false},
		{"credential_root_metadata", c.config.Credential.Root, false},
		{"credential_slot_metadata", slot, false},
		{"credential_file_metadata", filepath.Join(slot, "auth.json"), true},
	}
	for _, item := range paths {
		if !matchesMetadata(fs, uid, item.path, item.file) {
			report.Findings = append(report.Findings, item.code)
		}
	}
	// A dedicated slot is not the user's normal Codex home or an extension
	// bundle. Inspect names only, never any auth.json bytes.
	if len(report.Findings) == 0 {
		entries, err := fs.ReadDir(slot)
		if err != nil || len(entries) != 1 || entries[0].Name() != "auth.json" {
			report.Findings = append(report.Findings, "credential_slot_entries")
		}
	}
	if len(report.Findings) != 0 {
		report.LocalMetadata = "rejected"
	}
	return report, nil
}

func matchesMetadata(fs metadataFS, uid int, path string, file bool) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := "/"
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := fs.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return false
		}
		final := index == len(parts)-1
		if final {
			want := os.FileMode(0o700)
			if file {
				want = 0o600
			}
			if int(stat.Uid) != uid || info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != want {
				return false
			}
			if file {
				return info.Mode().IsRegular() && stat.Nlink == 1
			}
			return info.IsDir()
		}
		if !info.IsDir() || int(stat.Uid) != uid && stat.Uid != 0 {
			return false
		}
		// Permit root-owned sticky /tmp ancestors used by tests/operator work;
		// reject replaceable non-sticky or foreign-owned path prefixes.
		if info.Mode().Perm()&0o022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return false
		}
	}
	return false
}
