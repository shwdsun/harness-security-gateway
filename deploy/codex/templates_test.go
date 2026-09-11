package codexdeployment_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
)

func TestDeploymentExamplesKeepMatchingAuthorityAndSeparateIdentities(t *testing.T) {
	coreData, err := os.ReadFile("agentd.example.json")
	if err != nil {
		t.Fatal(err)
	}
	corePath := filepath.Join(t.TempDir(), "agentd.json")
	if err := os.WriteFile(corePath, coreData, 0o600); err != nil {
		t.Fatal(err)
	}
	core, err := agentconfig.Load(corePath)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := agentpolicy.Compile(core)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("sandboxd.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"endpoint": "unix:///run/user/21002/docker.sock"`) {
		t.Fatal("example runtime does not belong to the sandbox service UID")
	}
	// Load enforces the actual process UID. Adapt only this environment detail
	// in a disposable file; this test cannot establish cross-UID runtime access.
	data = []byte(strings.Replace(string(data), "unix:///run/user/21002/docker.sock",
		fmt.Sprintf("unix:///run/user/%d/docker.sock", os.Geteuid()), 1))
	path := filepath.Join(t.TempDir(), "sandboxd.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sandbox, err := sandboxconfig.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if sandbox.PeerUID != 21001 || core.Connectors[0].PeerUID != 21003 || core.SandboxSocket != sandbox.Socket {
		t.Fatal("example peer identities or socket edges disagree")
	}
	endpoint, err := policy.Endpoint(core.Connectors[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := endpoint.SessionScope(core.Bindings[0].ActorRef, core.Bindings[0].ConversationRef)
	if err != nil {
		t.Fatal(err)
	}
	exampleScope := sandbox.Codex.Scope.SessionScope()
	if exampleScope.BindingFingerprint != strings.Repeat("0", 64) || sandbox.Codex.OwnerSHA256 != strings.Repeat("0", 64) {
		t.Fatal("inactive template unexpectedly contains a selected binding/owner hash")
	}
	exampleScope.BindingFingerprint = scope.BindingFingerprint
	if exampleScope != scope || scope.TargetID != sandbox.Targets[0].ID() || scope.TargetRevision != sandbox.Targets[0].Revision() {
		t.Fatal("templates would enroll a different authority from the Core binding")
	}
	if filepath.Dir(core.Database) == filepath.Dir(core.Connectors[0].Socket) ||
		filepath.Dir(sandbox.StateDatabase) == filepath.Dir(sandbox.Socket) {
		t.Fatal("shared IPC directory also contains a private database")
	}
}

func TestOfflinePackageLockMatchesCompiledV3Contract(t *testing.T) {
	var lock struct {
		Image         string `json:"image"`
		ProfileSHA256 string `json:"profile_sha256"`
		ToolPackage   map[string]struct {
			SHA256 string `json:"sha256"`
		} `json:"tool_package"`
	}
	data, err := os.ReadFile("inputs.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.Image != sandboxconfig.FixedCodexImage || lock.ProfileSHA256 != codexprofile.ContractFingerprintV3 {
		t.Fatal("offline lock differs from the fixed runtime/profile")
	}
	want := map[string]string{
		"bin/codex":                   codexprofile.CLIBinarySHA256V1,
		"bin/codex-code-mode-host":    codexprofile.CodeModeHostSHA256V3,
		"codex-package.json":          codexprofile.PackageManifestSHA256V3,
		"codex-path/rg":               codexprofile.RipgrepSHA256V3,
		"codex-resources/bwrap":       codexprofile.BubblewrapSHA256V3,
		"codex-resources/zsh/bin/zsh": codexprofile.ZshSHA256V3,
	}
	if len(lock.ToolPackage) != len(want) {
		t.Fatal("offline lock changed the tool package boundary")
	}
	for path, hash := range want {
		if lock.ToolPackage[path].SHA256 != hash {
			t.Fatalf("offline package pin differs: %s", path)
		}
	}
}
