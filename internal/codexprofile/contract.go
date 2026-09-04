// Package codexprofile defines the sealed authority contract for the first
// Codex target candidate. It is local sandbox policy, never a message or wire
// format. The current Docker runtime deliberately does not implement it.
package codexprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	SchemaV1 = "codex-profile/v1"
	IDV1     = "codex.chatgpt-personal-v1"
	SchemaV2 = "codex-profile/v2"
	IDV2     = "codex.chatgpt-personal-messaging-v2"

	ClassificationV1 = "credential-exposed-personal"

	RunnerFamilyV1          = "codex"
	AdapterVersionV1        = "0.1.0-new-only"
	AdapterVersionV2        = "0.2.0-new-only"
	RunnerProtocolV1        = "hrp/1"
	RequiredFeaturesV1      = "none"
	SessionModeV1           = "new_only"
	PersistentRunnerStateV1 = "none"

	PolicyProfileRefV1  = "codex.locked-v1"
	AuthProfileRefV1    = "codex.chatgpt-file-personal-v1"
	SkillBundleRefV1    = "builtin.none"
	NetworkProfileRefV1 = "codex.provider-control-v1"

	CLIVersionV1      = "0.151.0"
	CLIPlatformV1     = "x86_64-unknown-linux-musl"
	CLIBinaryPathV1   = "/usr/local/bin/codex"
	CLIBinarySHA256V1 = "9739cbc928b9c573be83256acd46668f5dd4f119d2d09e05246895ca2aaf0c9a"

	ModelNameV1            = "gpt-5.6-sol"
	ModelReasoningEffortV1 = "medium"
	ModelIdentityClaimV1   = "provider-alias-may-drift"

	LoginMethodV1             = "chatgpt"
	CredentialStoreV1         = "file"
	CredentialContainerPathV1 = "/tmp/hgw-codex-home/auth.json"
	CredentialMountV1         = "single-file-bind-rw"
	CredentialScopeRuleV1     = "exact-workspace-auth-profile-v1"

	CodexHomePathV1      = "/tmp/hgw-codex-home"
	CodexHomeLifetimeV1  = "per-run-disposable-tmpfs"
	SQLiteHomePathV1     = "/tmp/hgw-codex-runner"
	SQLiteHomeLifetimeV1 = "per-run-disposable-tmpfs"
	PersistentEntriesV1  = "auth-file-only"

	ControlEgressV1  = "mediated-provider-control-v1"
	ToolEgressV1     = "deny"
	PrivateNetworkV1 = "deny"

	ProjectInstructionsV1      = "none"
	UserManagedCustomizationV1 = "none"
	DynamicExtensionsV1        = "none"
	WorkspaceContentV1         = "untrusted-readable"

	InstructionProfileRefV2         = MessagingInstructionIDV1
	InstructionProfileFingerprintV2 = MessagingInstructionFingerprintV1
	InstructionRoleV2               = "developer"
	InstructionInjectionV2          = "codex.config.developer_instructions"

	ContainerLifetimeV1 = "one-run"
	TerminalReleaseV1   = "after-outer-quiescence"

	ContractFingerprintV1 = "96ca4f1845f5ee673d7302fb938e698d1344435d62280b8174e31200738f143d"
	ContractFingerprintV2 = "d8ee4889edd0bac79fd8ee6278bf10c06a29b0dcdc743433ecad17a5cee0aa68"

	fingerprintDomainV1 = "harness-security-gateway.codex-profile/v1"
	fingerprintDomainV2 = "harness-security-gateway.codex-profile/v2"
)

var ErrInvalid = errors.New("invalid Codex profile contract")

// Contract is intentionally comparable and contains no maps, option bags,
// paths supplied by an operator, or credential bytes. V1 accepts exactly the
// value returned by V1; a semantic change requires a new versioned contract.
type Contract struct {
	Schema         string             `json:"schema"`
	ID             string             `json:"id"`
	Classification string             `json:"classification"`
	Runner         RunnerContract     `json:"runner"`
	Profiles       ProfileRefs        `json:"profiles"`
	CLI            CLIArtifact        `json:"cli"`
	Model          ModelSelection     `json:"model"`
	Credential     CredentialContract `json:"credential"`
	State          StateContract      `json:"state"`
	Network        NetworkContract    `json:"network"`
	Context        ContextContract    `json:"context"`
	Teardown       TeardownContract   `json:"teardown"`
}

type RunnerContract struct {
	Family                string `json:"family"`
	AdapterVersion        string `json:"adapter_version"`
	Protocol              string `json:"protocol"`
	RequiredFeatures      string `json:"required_features"`
	SessionMode           string `json:"session_mode"`
	PersistentRunnerState string `json:"persistent_runner_state"`
}

type ProfileRefs struct {
	Policy  string `json:"policy"`
	Auth    string `json:"auth"`
	Skill   string `json:"skill"`
	Network string `json:"network"`
}

type CLIArtifact struct {
	Version      string `json:"version"`
	Platform     string `json:"platform"`
	BinaryPath   string `json:"binary_path"`
	BinarySHA256 string `json:"binary_sha256"`
}

type ModelSelection struct {
	Name            string `json:"name"`
	ReasoningEffort string `json:"reasoning_effort"`
	IdentityClaim   string `json:"identity_claim"`
}

type CredentialContract struct {
	LoginMethod   string `json:"login_method"`
	Store         string `json:"store"`
	ContainerPath string `json:"container_path"`
	Mount         string `json:"mount"`
	ScopeRule     string `json:"scope_rule"`
}

type StateContract struct {
	CodexHome          string `json:"codex_home"`
	CodexHomeLifetime  string `json:"codex_home_lifetime"`
	SQLiteHome         string `json:"sqlite_home"`
	SQLiteHomeLifetime string `json:"sqlite_home_lifetime"`
	PersistentEntries  string `json:"persistent_entries"`
}

type NetworkContract struct {
	ControlEgress  string `json:"control_egress"`
	ToolEgress     string `json:"tool_egress"`
	PrivateNetwork string `json:"private_network"`
}

type ContextContract struct {
	ProjectInstructions           string `json:"project_instructions"`
	UserManagedCustomization      string `json:"user_managed_customization"`
	DynamicExtensions             string `json:"dynamic_extensions"`
	WorkspaceContent              string `json:"workspace_content"`
	InstructionProfileRef         string `json:"instruction_profile_ref,omitempty"`
	InstructionProfileFingerprint string `json:"instruction_profile_fingerprint,omitempty"`
	InstructionRole               string `json:"instruction_role,omitempty"`
	InstructionInjection          string `json:"instruction_injection,omitempty"`
}

type TeardownContract struct {
	ContainerLifetime string `json:"container_lifetime"`
	TerminalRelease   string `json:"terminal_release"`
}

// V1 returns the only accepted value for this contract version. The selected
// CLI digest is a candidate image input, not proof that an approved image or
// provider path exists.
func V1() Contract {
	return Contract{
		Schema:         SchemaV1,
		ID:             IDV1,
		Classification: ClassificationV1,
		Runner: RunnerContract{
			Family:                RunnerFamilyV1,
			AdapterVersion:        AdapterVersionV1,
			Protocol:              RunnerProtocolV1,
			RequiredFeatures:      RequiredFeaturesV1,
			SessionMode:           SessionModeV1,
			PersistentRunnerState: PersistentRunnerStateV1,
		},
		Profiles: ProfileRefs{
			Policy:  PolicyProfileRefV1,
			Auth:    AuthProfileRefV1,
			Skill:   SkillBundleRefV1,
			Network: NetworkProfileRefV1,
		},
		CLI: CLIArtifact{
			Version:      CLIVersionV1,
			Platform:     CLIPlatformV1,
			BinaryPath:   CLIBinaryPathV1,
			BinarySHA256: CLIBinarySHA256V1,
		},
		Model: ModelSelection{
			Name:            ModelNameV1,
			ReasoningEffort: ModelReasoningEffortV1,
			IdentityClaim:   ModelIdentityClaimV1,
		},
		Credential: CredentialContract{
			LoginMethod:   LoginMethodV1,
			Store:         CredentialStoreV1,
			ContainerPath: CredentialContainerPathV1,
			Mount:         CredentialMountV1,
			ScopeRule:     CredentialScopeRuleV1,
		},
		State: StateContract{
			CodexHome:          CodexHomePathV1,
			CodexHomeLifetime:  CodexHomeLifetimeV1,
			SQLiteHome:         SQLiteHomePathV1,
			SQLiteHomeLifetime: SQLiteHomeLifetimeV1,
			PersistentEntries:  PersistentEntriesV1,
		},
		Network: NetworkContract{
			ControlEgress:  ControlEgressV1,
			ToolEgress:     ToolEgressV1,
			PrivateNetwork: PrivateNetworkV1,
		},
		Context: ContextContract{
			ProjectInstructions:      ProjectInstructionsV1,
			UserManagedCustomization: UserManagedCustomizationV1,
			DynamicExtensions:        DynamicExtensionsV1,
			WorkspaceContent:         WorkspaceContentV1,
		},
		Teardown: TeardownContract{
			ContainerLifetime: ContainerLifetimeV1,
			TerminalRelease:   TerminalReleaseV1,
		},
	}
}

// V2 preserves V1's authority envelope but adds one exact, non-secret
// operator-behavior profile at Codex's developer-instruction layer. It is a
// distinct adapter and TargetRevision semantic; it never mutates V1 in place.
func V2() Contract {
	contract := V1()
	contract.Schema = SchemaV2
	contract.ID = IDV2
	contract.Runner.AdapterVersion = AdapterVersionV2
	contract.Context.InstructionProfileRef = InstructionProfileRefV2
	contract.Context.InstructionProfileFingerprint = InstructionProfileFingerprintV2
	contract.Context.InstructionRole = InstructionRoleV2
	contract.Context.InstructionInjection = InstructionInjectionV2
	return contract
}

// Validate accepts only one of the two sealed contracts. This is not a generic
// profile parser and deliberately offers no extension map.
func (c Contract) Validate() error {
	switch c {
	case V1(), V2():
		return nil
	default:
		return fmt.Errorf("%w: contract does not exactly match a sealed profile", ErrInvalid)
	}
}

// Resolve returns a sealed contract by its local ID. The ID is never accepted
// from HRP or message data.
func Resolve(id string) (Contract, error) {
	switch id {
	case IDV1:
		return V1(), nil
	case IDV2:
		return V2(), nil
	default:
		return Contract{}, fmt.Errorf("%w: unknown profile ID", ErrInvalid)
	}
}

// Fingerprint returns the domain-separated digest of the complete contract.
// It excludes the future local credential slot, its generation/source identity,
// and credential bytes by construction. sandboxd must later combine this digest
// with resolved policy, auth, network, any nontrivial skill authority, and the
// local credential binding in a new revision-security fingerprint domain before
// enablement.
func (c Contract) Fingerprint() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	return fingerprint(c)
}

func fingerprint(c Contract) (string, error) {
	encoded, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("canonicalize Codex profile: %w", err)
	}
	domain := fingerprintDomainV1
	if c.Schema == SchemaV2 {
		domain = fingerprintDomainV2
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(encoded)
	return hex.EncodeToString(digest.Sum(nil)), nil
}
