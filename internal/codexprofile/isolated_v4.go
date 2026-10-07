package codexprofile

// V4 is a blocked isolation candidate. Its new references cannot reclassify an
// existing exposed target; composed runtime/native acceptance is still required.
const (
	SchemaV4              = "codex-profile/v4"
	IDV4                  = "codex.chatgpt-personal-messaging-isolated-v4"
	AdapterVersionV4      = "0.4.0-new-only"
	PolicyProfileRefV4    = "codex.locked-tools-isolated-v4"
	AuthProfileRefV4      = "codex.owner-auth-v1"
	OwnerLauncherSHA256V4 = "94427818c0c718c5e9791807cfc803751229c93f825948a220bece2293733ed7"
	ContractFingerprintV4 = "8edb914c08502d5b19682bdbdf661414e76301cf8ea61c91561b707d17219edc"
	fingerprintDomainV4   = "harness-security-gateway.codex-profile/v4"
)

type OwnerRuntimeContract struct {
	LauncherSHA256 string `json:"launcher_sha256"`
	Readiness      string `json:"readiness"`
	Refresh        string `json:"refresh"`
	Startup        string `json:"startup"`
}

func V4() Contract {
	c := V3()
	c.Schema, c.ID, c.Classification = SchemaV4, IDV4, "credential-isolated-candidate"
	c.Runner.AdapterVersion = AdapterVersionV4
	c.Profiles.Policy, c.Profiles.Auth = PolicyProfileRefV4, AuthProfileRefV4
	c.Credential.Mount = "per-run-local-file-bind-rw"
	c.Credential.ScopeRule = "exact-owner-held-run-channel-v1"
	c.State.PersistentEntries = "owner-auth-only-outside-runner"
	c.OwnerRuntime = OwnerRuntimeContract{OwnerLauncherSHA256V4, "before-container-create-after-resource-registration", "one-owner-recovery-on-valid-upstream-401", "root-controlled-single-process-service-cgroup-before-recovery"}
	return c
}
