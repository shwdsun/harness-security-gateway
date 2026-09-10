package sandboxconfig

import (
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// ResolveTargetAuthority resolves only a configured, immutable locked-down mock
// target. The base pin covers that implemented built-in authority; all historical
// v1/v2 encodings remain unchanged. The opt-in fixed Codex runtime has a separate
// artifact/owner-bound resolver; it cannot produce authority through this helper.
// This function never opens credentials or invokes a runtime.
func (c Config) ResolveTargetAuthority(manifest targetmanifest.Definition, fingerprint string) (sandboxservice.ResolvedAuthority, error) {
	if err := c.Validate(); err != nil {
		return sandboxservice.ResolvedAuthority{}, err
	}
	if err := manifest.Validate(); err != nil {
		return sandboxservice.ResolvedAuthority{}, invalid("target authority", "invalid manifest")
	}
	// Apply the closed mock matcher to both versions on this new resolver path.
	// Legacy standalone fingerprint helpers retain their historical semantics.
	if err := validateMockProfile(manifest); err != nil {
		return sandboxservice.ResolvedAuthority{}, err
	}
	registry, err := c.Registry()
	if err != nil {
		return sandboxservice.ResolvedAuthority{}, err
	}
	entry, err := registry.Resolve(manifest.ID(), manifest.Revision())
	if err != nil || entry.Fingerprint != fingerprint {
		return sandboxservice.ResolvedAuthority{}, invalid("target authority", "target is not the exact configured revision")
	}
	pin, err := c.RevisionSecurityFingerprint(manifest, fingerprint)
	if err != nil {
		return sandboxservice.ResolvedAuthority{}, err
	}
	ownership, err := c.RunnerStateOwnership(manifest)
	if err != nil {
		return sandboxservice.ResolvedAuthority{}, err
	}
	return sandboxservice.ResolvedAuthority{RevisionPin: pin, RunnerState: ownership}, nil
}
