//go:build linux && amd64 && codexintegration

package dockerruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/shwdsun/harness-security-gateway/internal/codexprovider"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
)

// NewConfiguredCodex resolves the one opt-in daemon template without Docker,
// provider I/O, credential reads, or enrollment. The fixed factory verifies the
// running owner and artifact bytes. Each admitted Run gets its own endpoint;
// no single-canary diagnostic capture or filtered inventory is retained.
func NewConfiguredCodex(config sandboxconfig.Config) (*Runtime, string, error) {
	return configuredCodex(config, func(c ProviderCanaryConfig) (*Runtime, string, error) {
		if err := validateLiveProvider(c); err != nil {
			return nil, "", err
		}
		return newProviderCanary(c, "daemon-live", func(ctx context.Context, dir string) (runProvider, error) {
			return codexprovider.NewLive(ctx, dir, localidentity.UID(os.Geteuid()))
		})
	})
}

// The private constructor seam permits deterministic wiring tests without
// weakening any production artifact or provider check.
func configuredCodex(config sandboxconfig.Config, build func(ProviderCanaryConfig) (*Runtime, string, error)) (*Runtime, string, error) {
	if config.Schema != sandboxconfig.SchemaCodexV1 || config.Validate() != nil || build == nil {
		return nil, "", ErrInvalidConfig
	}
	p := *config.Codex
	// Linux sockaddr_un has 108 bytes including its trailing NUL. Refuse an
	// unusable fixed location before a Run can create a provider directory.
	if len(filepath.Join(p.ProviderRoot, deterministicName(""), "owner.sock")) > 107 {
		return nil, "", ErrInvalidConfig
	}
	artifact := func(a sandboxconfig.Artifact) SyntheticArtifact { return SyntheticArtifact{a.Path, a.SHA256} }
	r, basePin, err := build(ProviderCanaryConfig{
		Runtime: SyntheticV3Config{Manifest: config.Targets[0].Clone(), WorkspaceRoot: config.WorkspaceRoot,
			WorkspaceDirectory: config.Workspaces[0].Directory, Credential: p.Credential,
			UIDSetup: artifact(p.UIDSetup), Bootstrap: artifact(p.Bootstrap), Runner: artifact(p.Runner),
			Canary: artifact(p.Canary), Seccomp: artifact(p.Seccomp), ToolPackage: p.ToolPackage},
		ProviderRoot: p.ProviderRoot, OwnerSHA256: p.OwnerSHA256,
	})
	if err != nil {
		return nil, "", err
	}
	if r == nil || !validContainerID(basePin) || len(r.targets) != 1 {
		return nil, "", ErrInvalidConfig
	}
	data, err := json.Marshal(struct {
		BasePin string
		Config  sandboxconfig.Config
	}{basePin, config})
	if err != nil {
		return nil, "", ErrInvalidConfig
	}
	digest := sha256.Sum256(append([]byte("harness-security-gateway.codex-daemon/v1\x00"), data...))
	pin := hex.EncodeToString(digest[:])
	for key, spec := range r.targets {
		if spec.credential == nil {
			return nil, "", ErrInvalidConfig
		}
		spec.credential.pin = pin
		r.targets[key] = spec
	}
	r.cli, r.endpoint = config.Runtime.CLI, config.Runtime.Endpoint
	// Ordinary sandboxd owns the whole user lane. A changed/foreign managed
	// container must block startup; a per-pin list could silently hide it.
	r.inventoryPin = ""
	return r, pin, nil
}
