//go:build linux && codexintegration

package codexadapter

import (
	"net"
	"os"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
)

// This is the first compatibility case of the composed acceptance fixture,
// not proof of admission, process transport separation or runtime cleanup.
// The external owner must first verify the mounted synthetic source under the
// inert bootstrap, and independently remove the exact runtime before unlocking.
func TestCodexSyntheticConsumerComposition(t *testing.T) {
	if os.Getenv("HSG_CODEX_COMPOSITION_CANARY") != "1" {
		t.Skip("opt-in owned offline container composition")
	}
	interfaces, err := net.Interfaces()
	if err != nil || os.Getpid() != 1 || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagUp == 0 {
		t.Fatal("requires owned PID-1 namespace with only active loopback")
	}
	if err := verifyToolsPackage(codexprofile.CLIBinaryPathV3); err != nil {
		t.Fatal(err)
	}
	toolsConfigurationConsumerCase(t, codexprofile.CLIBinaryPathV3, "command-exec", true)
	assertIntegrationQuiescence(t)
}
