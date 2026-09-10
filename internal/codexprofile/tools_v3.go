package codexprofile

// V3 binds the native tool host and the complete six-file standalone package.
// These are observed candidate artifacts, not an approved image or provenance.
const (
	SchemaV3                = "codex-profile/v3"
	IDV3                    = "codex.chatgpt-personal-messaging-tools-v3"
	AdapterVersionV3        = "0.3.0-new-only"
	PolicyProfileRefV3      = "codex.locked-tools-v3"
	CLIBinaryPathV3         = "/opt/hsg/codex/bin/codex"
	CodeModeHostSHA256V3    = "a9adcea47799d8caaec5fbf073966fef2869f754bc7b463e30783880dfb12913"
	PackageManifestSHA256V3 = "ed8beb433be66cf74a75af94f4b2e2df35ef25325620ddad1a377bba8f1ffeea"
	RipgrepSHA256V3         = "e62198eb19b136b88c330af83647b5a962cb99b6b1f066758568f12de1974849"
	BubblewrapSHA256V3      = "7df960565a0dece99240ea4b9d0e011307817f9f3b73176c7b71fda44fe84765"
	ZshSHA256V3             = "67faaaa89242c4a332e16e508a1977cffc24bf7fca31d4411cdfd101f3831ef3"
	ContractFingerprintV3   = "8bbae8b91929e32c4eca53270716c35e03999ec03d535f7011a088472b80ce50"
	fingerprintDomainV3     = "harness-security-gateway.codex-profile/v3"
)

// The zero value is omitted from the canonical v1/v2 bytes. No local paths,
// optional dependencies, download locations or user-selected tool options enter
// this tuple. Package paths are fixed by standalone layout 1.
type ToolRuntimeContract struct {
	PackageLayout         string `json:"package_layout"`
	CodeModeHostSHA256    string `json:"code_mode_host_sha256"`
	PackageManifestSHA256 string `json:"package_manifest_sha256"`
	RipgrepSHA256         string `json:"ripgrep_sha256"`
	BubblewrapSHA256      string `json:"bubblewrap_sha256"`
	ZshSHA256             string `json:"zsh_sha256"`
	ToolMode              string `json:"tool_mode"`
	HostTransport         string `json:"host_transport"`
	AgentCapacity         string `json:"agent_capacity"`
}

func V3() Contract {
	c := V2()
	c.Schema, c.ID = SchemaV3, IDV3
	c.Runner.AdapterVersion = AdapterVersionV3
	c.Profiles.Policy = PolicyProfileRefV3
	c.CLI.BinaryPath = CLIBinaryPathV3
	c.Context.DynamicExtensions = "pinned-cli-builtins-only"
	c.ToolRuntime = ToolRuntimeContract{
		PackageLayout:         "codex-standalone-layout-1-six-files",
		CodeModeHostSHA256:    CodeModeHostSHA256V3,
		PackageManifestSHA256: PackageManifestSHA256V3,
		RipgrepSHA256:         RipgrepSHA256V3,
		BubblewrapSHA256:      BubblewrapSHA256V3,
		ZshSHA256:             ZshSHA256V3,
		ToolMode:              "model-required-code-mode-only",
		HostTransport:         "local-child-stdio-no-in-process-fallback",
		AgentCapacity:         "one-including-root",
	}
	return c
}
