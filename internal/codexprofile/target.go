package codexprofile

import (
	"fmt"

	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// MatchTarget checks the complete manifest projection of a sealed contract.
// It does not approve an image, resolve executable network policy, inspect a
// credential, or admit execution. Other manifest fields (identity, image,
// workspace mode and resource limits) keep their validated manifest semantics
// and must be bound by the caller's configuration fingerprint.
func (c Contract) MatchTarget(target targetmanifest.Definition) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := target.Validate(); err != nil {
		return fmt.Errorf("%w: invalid target manifest", ErrInvalid)
	}
	m, ok := target.ManifestV2()
	if !ok || m.RunnerState.Kind() != targetmanifest.RunnerStateNone {
		return fmt.Errorf("%w: target v2 with runner_state none required", ErrInvalid)
	}
	if m.Runner.Family != c.Runner.Family ||
		m.Runner.AdapterVersion != c.Runner.AdapterVersion ||
		m.Runner.Protocol != c.Runner.Protocol ||
		len(m.Runner.RequiredFeatures) != 0 ||
		string(m.SessionMode) != c.Runner.SessionMode {
		return fmt.Errorf("%w: runner or session does not match the sealed contract", ErrInvalid)
	}
	if m.PolicyRef != c.Profiles.Policy || m.AuthProfileRef != c.Profiles.Auth ||
		m.SkillBundleRef != c.Profiles.Skill || m.NetworkProfileRef != c.Profiles.Network {
		return fmt.Errorf("%w: profile references do not match the sealed contract", ErrInvalid)
	}
	// V2's compiled instruction states about five minutes and a 2,000-byte
	// transport ceiling. Do not approve configuration contradicting those facts.
	// The requested 1,500-byte answer remains probabilistic guidance only.
	if c.ID == IDV2 && (m.Limits.TimeoutSeconds != 300 || m.Limits.MaxOutputBytes != 2000 || m.WorkspaceMode != targetmanifest.WorkspaceReadWrite) {
		return fmt.Errorf("%w: messaging target requires rw workspace, 300 seconds and 2000 output bytes", ErrInvalid)
	}
	return nil
}
