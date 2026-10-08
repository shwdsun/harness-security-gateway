//go:build linux && amd64 && codexintegration

package sandboxcontroller

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/providerfixture"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

func nativeProviderAuthPath(config coreNativeConfig) string {
	return filepath.Join(config.Runtime.Credential.Root, config.Runtime.Credential.Directory, "auth.json")
}

func requireNativeProviderInitial(t *testing.T, config coreNativeConfig) os.FileInfo {
	t.Helper()
	if !config.ProviderHTTPS {
		return nil
	}
	if config.Case != "replay-cleanup" && config.Case != "cancel-held-tool" && config.Case != "owner-running" {
		t.Fatal("unsupported fixed HTTPS lifecycle case")
	}
	data, err := os.ReadFile(nativeProviderAuthPath(config))
	info, statErr := os.Stat(nativeProviderAuthPath(config))
	if err != nil || statErr != nil || !providerfixture.AuthMatches(data, false) || info.Mode().Perm() != 0o600 {
		t.Fatal("requires fresh exact synthetic subscription auth")
	}
	return info
}

func requireNativeProviderRefresh(t *testing.T, config coreNativeConfig, before os.FileInfo) {
	t.Helper()
	if !config.ProviderHTTPS {
		return
	}
	data, err := os.ReadFile(nativeProviderAuthPath(config))
	info, statErr := os.Stat(nativeProviderAuthPath(config))
	if err != nil || statErr != nil || !providerfixture.AuthMatches(data, true) || !os.SameFile(before, info) || info.Mode().Perm() != 0o600 {
		t.Fatal("refresh did not preserve the exact enrolled synthetic file")
	}
}

// A fixture witness, never an authority input. The frozen trusted responder
// emits it before the tool sees its command, or after joined normal cleanup.
func requireNativeProviderProgress(t *testing.T, config coreNativeConfig, toolNonce string, complete bool) *providerfixture.OperationProof {
	t.Helper()
	if !config.ProviderHTTPS {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(config.Runtime.WorkspaceRoot, config.Runtime.WorkspaceDirectory, "provider-operations-proof.json"))
	var proof providerfixture.OperationProof
	want := 1
	if complete {
		want = 2
	}
	if config.Provider != nil {
		if err != nil || strictjson.Decode(data, 8192, 4, &proof) != nil || proof.ToolNonce != toolNonce || !proof.Refreshed || proof.Closed != complete || len(proof.Counts) != 3 || proof.Counts["refresh"] != 1 || proof.Counts["catalog"] != 2 || proof.Counts["inference"] != want {
			t.Fatal("owner provider progress/join witness incomplete")
		}
		return &proof
	}
	if err != nil || strictjson.Decode(data, 8192, 4, &proof) != nil || proof.ToolNonce != toolNonce || !proof.Refreshed || proof.Closed != complete ||
		len(proof.Counts) != 5 || proof.Counts["refresh"] != 1 || proof.Counts["catalog"] != 2 || proof.Counts["settings_rejected"] != 1 || proof.Counts["inference"] != want || proof.Counts["attempts"] != want+4 || len(proof.Statuses) != want+4 {
		t.Fatal("fixed provider progress/cleanup witness incomplete")
	}
	notFound := 0
	for _, status := range proof.Statuses {
		if status == 404 {
			notFound++
		} else if status != 200 {
			t.Fatal("unexpected provider operation rejection")
		}
	}
	if notFound != 1 {
		t.Fatal("settings rejection not accounted for")
	}
	return &proof
}
