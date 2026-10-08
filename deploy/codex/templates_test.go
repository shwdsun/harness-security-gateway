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
	"github.com/shwdsun/harness-security-gateway/internal/discordconnector"
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
	sandbox := loadSandboxExample(t)
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

func TestSandboxRuntimeUnitHasFixedEnvironmentAndSeparateDataRoot(t *testing.T) {
	data, err := os.ReadFile("hgw-sandboxd-docker.service")
	if err != nil {
		t.Fatal(err)
	}
	var environment, execStart []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Environment") {
			environment = append(environment, line)
		} else if strings.HasPrefix(line, "ExecStart") {
			execStart = append(execStart, line)
		}
	}
	// A copied developer unit embeds an ambient PATH; DOCKER_HOST, --host or a
	// context would move the daemon away from the endpoint sandboxd attests.
	if len(environment) != 1 || environment[0] != "Environment=PATH=/usr/bin:/usr/sbin" || len(execStart) != 1 {
		t.Fatal("runtime unit environment is not the fixed minimal one")
	}
	fields := strings.Fields(strings.TrimPrefix(execStart[0], "ExecStart="))
	if len(fields) != 2 || fields[0] != "/usr/bin/dockerd-rootless.sh" || !strings.HasPrefix(fields[1], "--data-root=") {
		t.Fatal("runtime unit accepts options beyond its fixed data root")
	}
	dataRoot := strings.TrimPrefix(fields[1], "--data-root=")
	users, err := os.ReadFile("hgw.sysusers")
	if err != nil {
		t.Fatal(err)
	}
	home := ""
	for _, line := range strings.Split(string(users), "\n") {
		if entry := strings.Fields(line); len(entry) > 2 && entry[0] == "u" && entry[1] == "hgw-sandboxd" {
			home = entry[len(entry)-2]
		}
	}
	if !filepath.IsAbs(dataRoot) || filepath.Clean(dataRoot) != dataRoot || filepath.Dir(dataRoot) != home {
		t.Fatal("runtime data root is not a direct child of the sandbox account home")
	}
	sandbox := loadSandboxExample(t)
	for _, path := range []string{sandbox.WorkspaceRoot, sandbox.RunnerStateRoot, sandbox.Codex.Credential.Root,
		sandbox.Codex.ProviderRoot, sandbox.Codex.ToolPackage, filepath.Dir(sandbox.StateDatabase),
		filepath.Dir(sandbox.Socket), filepath.Dir(sandbox.Codex.UIDSetup.Path)} {
		if within(dataRoot, path) || within(path, dataRoot) {
			t.Fatalf("runtime data root overlaps sandboxd storage or control path %s", path)
		}
	}
}

func loadSandboxExample(t *testing.T) sandboxconfig.Config {
	t.Helper()
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
	return sandbox
}

func within(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, "../")
}

func TestDiscordConnectorTemplatesKeepASeparateIdentityAndSocket(t *testing.T) {
	config, err := discordconnector.Load("discord-connector.example.json")
	if err != nil {
		t.Fatalf("example connector configuration rejected: %v", err)
	}
	// A second Connector instance must not share the local test Connector's
	// socket directory, or one identity could reach the other's socket.
	core, err := os.ReadFile("agentd.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(core), config.AgentdSocket) {
		t.Fatal("the Discord instance reuses the local test Connector's socket")
	}
	if filepath.Dir(config.TokenFile) == filepath.Dir(config.StateDatabase) {
		t.Fatal("the bot token shares a directory with mutable connector state")
	}

	tmpfiles, err := os.ReadFile("hgw-discord.tmpfiles")
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]string{}
	for _, line := range strings.Split(string(tmpfiles), "\n") {
		if fields := strings.Fields(line); len(fields) >= 5 && fields[0] == "d" {
			declared[fields[1]] = strings.Join(fields[2:5], " ")
		}
	}
	if declared[filepath.Dir(config.AgentdSocket)] != "02710 hgw-agentd hgw-discord-ipc" {
		t.Fatalf("socket parent is not an agentd-owned setgid directory: %q",
			declared[filepath.Dir(config.AgentdSocket)])
	}
	for _, private := range []string{filepath.Dir(config.StateDatabase), filepath.Dir(config.TokenFile)} {
		if declared[private] != "0700 hgw-connector-discord hgw-connector-discord" {
			t.Fatalf("%s is not private to the Connector identity: %q", private, declared[private])
		}
	}

	users, err := os.ReadFile("hgw-discord.sysusers")
	if err != nil {
		t.Fatal(err)
	}
	existing, err := os.ReadFile("hgw.sysusers")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"21004", "21103"} {
		if strings.Contains(string(existing), id) {
			t.Fatalf("the Discord identity reuses an existing service ID %s", id)
		}
	}
	// It joins only its own IPC edge: not Core's local edge and not the sandbox edge.
	for _, foreign := range []string{"hgw-local-ipc", "hgw-sandbox-ipc"} {
		if strings.Contains(string(users), foreign) {
			t.Fatalf("the Discord identity joins the foreign group %s", foreign)
		}
	}
	if !strings.Contains(string(users), "m hgw-connector-discord hgw-discord-ipc") ||
		!strings.Contains(string(users), "m hgw-agentd hgw-discord-ipc") {
		t.Fatal("the Discord IPC edge does not connect exactly agentd and the Connector")
	}

	unit, err := os.ReadFile("hgw-connector-discord.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"User=hgw-connector-discord", "Group=hgw-connector-discord",
		"SupplementaryGroups=hgw-discord-ipc", "NoNewPrivileges=yes",
		"CapabilityBoundingSet=", "Restart=no",
		"ExecStart=/opt/hgw/codex-dev/bin/discord-connector -config /etc/hgw/discord-connector.json",
	} {
		if !strings.Contains(string(unit), required) {
			t.Fatalf("the Connector unit is missing %q", required)
		}
	}
	if strings.Contains(string(unit), "[Install]") {
		t.Fatal("the Connector unit can be enabled at boot without a separate decision")
	}
}
