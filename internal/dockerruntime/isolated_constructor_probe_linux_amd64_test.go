//go:build linux && amd64 && codexintegration

package dockerruntime

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
)

// Separately frozen, opt-in fixture. A normal tagged test run cannot install,
// launch or contact anything by selecting this test. The outer network-none
// container, static bytes and mapped ownership require their own evidence.
func TestIsolatedInertConstructorProbe(t *testing.T) {
	if os.Getenv("HSG_ISOLATED_CONSTRUCTOR_PROBE") != "inert-v4-network-none-v1" {
		t.Skip("requires separately reviewed frozen constructor fixture")
	}
	if os.Getuid() != 1000 || os.Geteuid() != 1000 {
		t.Fatal("fixed non-root probe UID required")
	}
	config, err := sandboxconfig.Load("/hgw-artifacts/constructor.json")
	if err != nil || config.Schema != sandboxconfig.SchemaCodexV2 || config.Codex == nil {
		t.Fatal("fixed isolated fixture configuration", err)
	}
	const root = "/tmp/v4-constructor"
	if config.WorkspaceRoot != root+"/workspaces" || config.Codex.Credential.Root != root+"/credentials" || config.Codex.ProviderRoot != root+"/provider" || config.RunnerStateRoot != root+"/runner-state" || config.Codex.ToolPackage != "/hgw-artifacts/codex-package" {
		t.Fatal("fixture storage tuple changed")
	}
	for _, dir := range []string{root, config.WorkspaceRoot, filepath.Join(config.WorkspaceRoot, config.Workspaces[0].Directory), config.Codex.Credential.Root, filepath.Join(config.Codex.Credential.Root, config.Codex.Credential.Directory), config.Codex.ProviderRoot, config.RunnerStateRoot} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal("new private fixture directory", err)
		}
	}
	canary := []byte("inert-constructor-synthetic-auth-must-stay-unchanged")
	auth := filepath.Join(config.Codex.Credential.Root, config.Codex.Credential.Directory, "auth.json")
	if err := os.WriteFile(auth, canary, 0600); err != nil {
		t.Fatal(err)
	}
	runtime, pin, err := NewConfiguredCodex(config)
	if err != nil {
		t.Fatal("actual production V4 constructor", err)
	}
	t.Cleanup(func() {
		if err := runtime.CloseOwnerArtifacts(); err != nil {
			t.Error("inert artifact close", err)
		}
	})
	if !validContainerID(pin) || runtime.inventoryPin != "" || runtime.ownerStartup == nil || runtime.ownerArtifactsClose == nil || len(runtime.targets) != 1 || len(runtime.providers) != 0 || len(runtime.credentials) != 0 {
		t.Fatal("isolated constructor identity/ownership wiring")
	}
	for _, spec := range runtime.targets {
		if !spec.credential.ownerOnly || spec.credential.pin != pin || spec.credential.provider.createOwner == nil || spec.credential.provider.create != nil || spec.credential.binding != config.Codex.Credential {
			t.Fatal("isolated constructor selected an exposed template")
		}
	}
	if codexprofile.V4().MatchTarget(config.Targets[0]) != nil {
		t.Fatal("sealed V4 target lost")
	}
	// Do not Activate, Prepare, Create, enroll, recover or open stores/listeners.
	for _, path := range []string{config.Socket, config.StateDatabase} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("inert constructor created control state", err)
		}
	}
	entries, err := os.ReadDir(config.Codex.ProviderRoot)
	if err != nil || len(entries) != 0 {
		t.Fatal("inert constructor created Run/provider state", err)
	}
	after, err := os.ReadFile(auth)
	if err != nil || !bytes.Equal(after, canary) {
		t.Fatal("inert constructor changed synthetic auth")
	}
	if err := runtime.CloseOwnerArtifacts(); err != nil {
		t.Fatal("fixed artifact lifetime", err)
	}
	t.Log("actual isolated constructor passed; no startup gate, receiver, native helper, provider or model acceptance")
}
