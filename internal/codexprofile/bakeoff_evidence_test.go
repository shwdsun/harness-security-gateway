package codexprofile_test

import (
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
)

// REPO-01 asserts that repository instructions, hooks, MCP configuration,
// plugins and skills cannot activate or widen authority. In this profile none
// of those inputs is accepted at all, which is a stronger statement than
// filtering them, and it is the contract rather than a runtime decision.
func TestNoRepositorySuppliedExtensionIsAccepted(t *testing.T) {
	for name, value := range map[string]string{
		"project instructions":       codexprofile.ProjectInstructionsV1,
		"user-managed customization": codexprofile.UserManagedCustomizationV1,
		"dynamic extensions":         codexprofile.DynamicExtensionsV1,
	} {
		if value != "none" {
			t.Fatalf("%s is %q, not none", name, value)
		}
	}
	if codexprofile.SkillBundleRefV1 != "builtin.none" {
		t.Fatalf("a skill bundle other than builtin.none is referenced: %q",
			codexprofile.SkillBundleRefV1)
	}
	// The workspace is read as untrusted task data. Saying so is the point:
	// the profile promises that repository content cannot become authority,
	// not that a Run which reads a file is unaffected by it.
	if codexprofile.WorkspaceContentV1 != "untrusted-readable" {
		t.Fatalf("the workspace content claim changed: %q", codexprofile.WorkspaceContentV1)
	}
}

// NET-01 asserts that required model traffic succeeds while tool-controlled
// traffic reaches nothing. The profile states both halves separately, so a
// change that opened tool egress could not hide behind the control path.
func TestToolEgressAndPrivateNetworkAreDeniedSeparately(t *testing.T) {
	if codexprofile.ToolEgressV1 != "deny" || codexprofile.PrivateNetworkV1 != "deny" {
		t.Fatalf("egress is no longer denied: tool=%q private=%q",
			codexprofile.ToolEgressV1, codexprofile.PrivateNetworkV1)
	}
	if codexprofile.ControlEgressV1 != "mediated-provider-control-v1" {
		t.Fatalf("control egress is no longer mediated: %q", codexprofile.ControlEgressV1)
	}
}

// CRED-01 is the one P0 case this profile deliberately does not meet. The
// classification says so, and this test exists so that the claim and the
// mechanism cannot drift apart silently in either direction: weakening the
// mount without saying so, or claiming isolation without changing it.
func TestTheCredentialExposureClaimMatchesTheMechanism(t *testing.T) {
	if codexprofile.ClassificationV1 != "credential-exposed-personal" {
		t.Fatalf("the classification changed to %q; if the credential is now isolated the "+
			"bake-off's CRED-01 entry and the drift ledger must change with it",
			codexprofile.ClassificationV1)
	}
	if codexprofile.CredentialStoreV1 != "file" || codexprofile.CredentialMountV1 != "single-file-bind-rw" {
		t.Fatalf("the credential mechanism changed while the classification did not: store=%q mount=%q",
			codexprofile.CredentialStoreV1, codexprofile.CredentialMountV1)
	}
}
