//go:build linux && amd64 && codexintegration

package dockerruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// SyntheticArtifact is a frozen fixture input, not an acquisition instruction.
type SyntheticArtifact struct{ Path, SHA256 string }

// SyntheticV3Config is a trusted, local integration constructor input. It is
// absent from normal builds/configuration and accepts no provider connection.
// Fixture files must already exist; this constructor writes or launches nothing.
type SyntheticV3Config struct {
	Manifest                                     targetmanifest.Definition
	WorkspaceRoot, WorkspaceDirectory            string
	Credential                                   credentialsource.Binding
	UIDSetup, Bootstrap, Runner, Canary, Seccomp SyntheticArtifact
	ToolPackage                                  string
}

// NewSyntheticV3 binds only the offline fixture's exact artifacts, local
// seccomp/UID startup template and credential locator. The returned pin is
// explicitly synthetic authority, not resolution of a real-provider policy.
// Inventory is scoped to this pin, so an integration fixture cannot sweep or
// clean other configured/production runtime inventories on the same daemon.
func NewSyntheticV3(config SyntheticV3Config) (*Runtime, string, error) {
	if os.Geteuid() == 0 || codexprofile.V3().MatchTarget(config.Manifest) != nil ||
		config.WorkspaceDirectory == "" || filepath.Base(config.WorkspaceDirectory) != config.WorkspaceDirectory ||
		config.WorkspaceDirectory == "." || config.WorkspaceDirectory == ".." ||
		config.Credential.WorkspaceRef != config.Manifest.Common().WorkspaceRef ||
		config.Credential.AuthProfileRef != config.Manifest.Common().AuthProfileRef ||
		config.Credential.SlotRef == "" || config.Credential.Generation == 0 ||
		config.Credential.Directory == "" || filepath.Base(config.Credential.Directory) != config.Credential.Directory ||
		config.Credential.Directory == "." || config.Credential.Directory == ".." {
		return nil, "", ErrInvalidConfig
	}
	workspace := filepath.Join(config.WorkspaceRoot, config.WorkspaceDirectory)
	for _, directory := range []string{config.WorkspaceRoot, workspace, config.Credential.Root, filepath.Join(config.Credential.Root, config.Credential.Directory), config.ToolPackage} {
		if validateDirectory(directory, directory) != nil {
			return nil, "", ErrInvalidStorage
		}
	}
	for _, a := range []string{config.WorkspaceRoot, config.Credential.Root, config.ToolPackage} {
		for _, b := range []string{config.WorkspaceRoot, config.Credential.Root, config.ToolPackage} {
			if a != b && strings.HasPrefix(a+"/", b+"/") {
				return nil, "", ErrInvalidStorage
			}
		}
	}
	if config.WorkspaceRoot == config.Credential.Root || config.ToolPackage == config.Credential.Root || config.WorkspaceRoot == config.ToolPackage {
		return nil, "", ErrInvalidStorage
	}
	c := &credentialSpec{binding: config.Credential, bootstrap: config.Bootstrap.SHA256, seccompPath: config.Seccomp.Path, seccompDigest: config.Seccomp.SHA256}
	for _, item := range []struct {
		artifact    SyntheticArtifact
		destination string
	}{
		{config.UIDSetup, "/hsg-uid-setup"}, {config.Bootstrap, "/hsg-next"},
		{config.Runner, "/codex-tools-runner"}, {config.Canary, "/hsg-canary"},
	} {
		if !safeSyntheticArtifact(item.artifact) {
			return nil, "", ErrInvalidConfig
		}
		if strings.HasPrefix(item.artifact.Path, config.WorkspaceRoot+"/") || strings.HasPrefix(item.artifact.Path, config.Credential.Root+"/") {
			return nil, "", ErrInvalidStorage
		}
		c.files = append(c.files, credentialArtifact{item.artifact.Path, item.artifact.SHA256})
		c.binds = append(c.binds, credentialBind{item.artifact.Path, item.destination})
	}
	if !safeSyntheticArtifact(config.Seccomp) {
		return nil, "", ErrInvalidConfig
	}
	if strings.HasPrefix(config.Seccomp.Path, config.WorkspaceRoot+"/") || strings.HasPrefix(config.Seccomp.Path, config.Credential.Root+"/") {
		return nil, "", ErrInvalidStorage
	}
	for _, item := range []credentialArtifact{
		{"bin/codex", codexprofile.CLIBinarySHA256V1}, {"bin/codex-code-mode-host", codexprofile.CodeModeHostSHA256V3},
		{"codex-package.json", codexprofile.PackageManifestSHA256V3}, {"codex-path/rg", codexprofile.RipgrepSHA256V3},
		{"codex-resources/bwrap", codexprofile.BubblewrapSHA256V3}, {"codex-resources/zsh/bin/zsh", codexprofile.ZshSHA256V3},
	} {
		c.files = append(c.files, credentialArtifact{filepath.Join(config.ToolPackage, item.path), item.digest})
	}
	c.binds = append(c.binds, credentialBind{config.ToolPackage, "/opt/hsg/codex"})
	if c.checkArtifacts() != nil {
		return nil, "", ErrCredentialUnavailable
	}
	policy, err := os.ReadFile(config.Seccomp.Path)
	if err != nil || len(policy) > 64<<10 {
		return nil, "", ErrInvalidConfig
	}
	policyHash := sha256.Sum256(policy)
	if hex.EncodeToString(policyHash[:]) != config.Seccomp.SHA256 || !sameSeccompJSON(policy, policy) {
		return nil, "", ErrInvalidConfig
	}
	c.seccomp = append([]byte(nil), policy...)
	fingerprint, err := config.Manifest.Fingerprint()
	if err != nil {
		return nil, "", ErrInvalidConfig
	}
	// The domain specifies fixed paths, network-none, RO root, 512 MiB noexec
	// tmpfs, transient SETFCAP and UID 1000 with all capabilities cleared before
	// the v1 bootstrap gate. Artifact hashes bind the synthetic responder/code.
	data, err := json.Marshal(config)
	if err != nil {
		return nil, "", ErrInvalidConfig
	}
	digest := sha256.Sum256(append([]byte("harness-security-gateway.synthetic-v3-runtime/uid-bootstrap-v1\x00"), data...))
	c.pin = hex.EncodeToString(digest[:])
	spec := targetSpec{fingerprint: fingerprint, image: config.Manifest.Common().Runner.Image,
		workspacePath: workspace, workspaceRoot: config.WorkspaceRoot, stateKind: targetmanifest.RunnerStateNone,
		stdinLimit: streamInputLimit(config.Manifest), stdoutLimit: streamOutputLimit(config.Manifest),
		stderrLimit: int64(config.Manifest.Common().Limits.MaxStderrBytes), credential: c}
	if validateSpecStorage(spec) != nil {
		return nil, "", ErrInvalidStorage
	}
	return &Runtime{cli: "/usr/bin/docker", endpoint: "unix:///run/user/" + strconv.Itoa(os.Geteuid()) + "/docker.sock",
		targets: map[targetKey]targetSpec{{config.Manifest.ID(), config.Manifest.Revision()}: spec}, inventoryPin: c.pin}, c.pin, nil
}

func safeSyntheticArtifact(a SyntheticArtifact) bool {
	if !validContainerID(a.SHA256) || !filepath.IsAbs(a.Path) || filepath.Clean(a.Path) != a.Path || strings.ContainsAny(a.Path, "\x00,\r\n") {
		return false
	}
	resolved, err := filepath.EvalSymlinks(a.Path)
	if err != nil || resolved != a.Path {
		return false
	}
	info, err := os.Lstat(a.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && (st.Uid == 0 || st.Uid == uint32(os.Geteuid())) && st.Nlink == 1
}
