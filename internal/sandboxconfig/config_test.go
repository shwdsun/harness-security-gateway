package sandboxconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

func quote(value string) string {
	return fmt.Sprintf("%q", value)
}

func localRootlessSocket() string {
	return filepath.Join("/run/user", fmt.Sprint(os.Geteuid()), "docker.sock")
}

func localRootlessEndpoint() string {
	return "unix://" + localRootlessSocket()
}

func validConfigJSON(cli string) string {
	return `{
  "schema":"sandboxd/v2",
  "socket":"../runtime/sandboxd.sock",
  "peer_uid":1000,
  "state_database":"../runtime/sandboxd.sqlite3",
  "workspace_root":"../runtime/workspaces",
  "runner_state_root":"../runtime/runner-state",
  "runtime":{"kind":"rootless-docker","endpoint":` + quote(localRootlessEndpoint()) + `,"cli":` + quote(cli) + `},
  "workspaces":[{"ref":"project-main","directory":"project-main"}],
  "runner_states":[{"ref":"mock-state","directory":"mock-state"}],
  "targets":[{
    "schema":"harness-target/v1",
    "id":"project-mock",
    "revision":"project-mock-r1",
    "runner":{"family":"mock","adapter_version":"0.1.0","protocol":"hrp/1","image":"harness-gateway/mock-runner@sha256:0000000000000000000000000000000000000000000000000000000000000000","required_features":[]},
    "workspace_ref":"project-main",
    "workspace_mode":"rw",
    "state_ref":"mock-state",
    "policy_ref":"builtin.locked-down-v1",
    "auth_profile_ref":"builtin.none",
    "skill_bundle_ref":"builtin.none",
    "network_profile_ref":"builtin.none",
    "session_mode":"new_only",
    "limits":{"timeout_seconds":60,"memory_bytes":134217728,"cpu_millis":1000,"pids":64,"max_input_bytes":32768,"max_output_bytes":32768,"max_progress_bytes":4096,"max_stderr_bytes":4096,"max_events":16,"max_session_age_seconds":0,"max_session_turns":0}
  }]
}`
}

func executable(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(root, "bin", "docker")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeConfig(t *testing.T, root, document string, mode os.FileMode) string {
	t.Helper()
	directory := filepath.Join(root, "config")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "sandboxd.json")
	if err := os.WriteFile(path, []byte(document), mode); err != nil {
		t.Fatal(err)
	}
	// os.WriteFile applies the process umask when creating a file. Force the
	// requested fixture mode so permission tests mean the same thing on local
	// hosts and CI runners with different umasks.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadResolvesOnlyOperatorPathsAndBuildsRegistry(t *testing.T) {
	root := t.TempDir()
	cli := executable(t, root)
	path := writeConfig(t, root, validConfigJSON(cli), 0o600)
	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	wantRuntime := filepath.Join(root, "runtime")
	if config.Socket != filepath.Join(wantRuntime, "sandboxd.sock") ||
		config.StateDatabase != filepath.Join(wantRuntime, "sandboxd.sqlite3") {
		t.Fatalf("resolved control paths = %q, %q", config.Socket, config.StateDatabase)
	}
	workspace, ok := config.WorkspacePath("project-main")
	if !ok || workspace != filepath.Join(wantRuntime, "workspaces", "project-main") {
		t.Fatalf("WorkspacePath() = %q, %v", workspace, ok)
	}
	state, ok := config.RunnerStatePath("mock-state")
	if !ok || state != filepath.Join(wantRuntime, "runner-state", "mock-state") {
		t.Fatalf("RunnerStatePath() = %q, %v", state, ok)
	}
	if config.Runtime.SocketPath != localRootlessSocket() {
		t.Fatalf("runtime socket = %q", config.Runtime.SocketPath)
	}
	wantLock := filepath.Join("/run/user", fmt.Sprint(os.Geteuid()), "harness-gateway-sandboxd.lock")
	if config.ProcessLockPath() != wantLock {
		t.Fatalf("process lock = %q, want %q", config.ProcessLockPath(), wantLock)
	}
	registry, err := config.Registry()
	if err != nil || len(registry.Entries()) != 1 {
		t.Fatalf("Registry() entries = %#v, err = %v", registry, err)
	}
}

func TestLoadRejectsUnknownAndDuplicateFields(t *testing.T) {
	root := t.TempDir()
	cli := executable(t, root)
	valid := validConfigJSON(cli)
	tests := []struct {
		name string
		doc  string
		want error
	}{
		{"unknown", strings.TrimSuffix(valid, "}") + `,"docker_args":[]}`, nil},
		{"duplicate", strings.Replace(valid, `"schema":"sandboxd/v2"`, `"schema":"sandboxd/v2","schema":"sandboxd/v3"`, 1), strictjson.ErrDuplicateKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfig(t, filepath.Join(root, test.name), test.doc, 0o600)
			_, err := Load(path)
			if test.want != nil {
				if !errors.Is(err, test.want) {
					t.Fatalf("Load() error = %v, want %v", err, test.want)
				}
			} else if err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("Load() error = %v, want unknown field", err)
			}
		})
	}
}

func TestPeerUIDAndSchemaAreExplicitAndClosed(t *testing.T) {
	root := t.TempDir()
	cli := executable(t, root)
	path := writeConfig(t, root, validConfigJSON(cli), 0o600)
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	config.Schema = "sandboxd/v1"
	if err := config.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("legacy schema error = %v, want ErrInvalid", err)
	}
	for _, uid := range []localidentity.UID{0, localidentity.NobodyUID, localidentity.InvalidUID} {
		candidate := config
		candidate.Schema = SchemaV2
		candidate.PeerUID = uid
		if err := candidate.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("UID %d error = %v, want ErrInvalid", uid, err)
		}
	}
	for _, uid := range []localidentity.UID{1, 1000, localidentity.NobodyUID - 1, localidentity.NobodyUID + 1, localidentity.InvalidUID - 1} {
		candidate := config
		candidate.Schema = SchemaV2
		candidate.PeerUID = uid
		if err := candidate.Validate(); err != nil {
			t.Fatalf("UID %d rejected: %v", uid, err)
		}
	}
}

func TestLoadRejectsNonIntegerAndOutOfRangePeerUID(t *testing.T) {
	root := t.TempDir()
	cli := executable(t, root)
	valid := validConfigJSON(cli)
	for _, value := range []string{"-1", "1.5", "4294967296", `"1000"`} {
		document := strings.Replace(valid, `"peer_uid":1000`, `"peer_uid":`+value, 1)
		path := writeConfig(t, filepath.Join(root, strings.NewReplacer(".", "-", `"`, "quote").Replace(value)), document, 0o600)
		if _, err := Load(path); err == nil {
			t.Fatalf("peer_uid %s unexpectedly loaded", value)
		}
	}
	document := strings.Replace(valid, "  \"peer_uid\":1000,\n", "", 1)
	path := writeConfig(t, filepath.Join(root, "missing"), document, 0o600)
	if _, err := Load(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing peer_uid error = %v, want ErrInvalid", err)
	}
}

func TestLoadRejectsUnsafeConfigFile(t *testing.T) {
	root := t.TempDir()
	cli := executable(t, root)
	document := validConfigJSON(cli)
	path := writeConfig(t, filepath.Join(root, "writable"), document, 0o666)
	if _, err := Load(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("writable config error = %v", err)
	}
	target := writeConfig(t, filepath.Join(root, "target"), document, 0o600)
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink config error = %v", err)
	}
}

func TestValidationRejectsRootfulRuntimeAndUnsafeStorageMappings(t *testing.T) {
	root := t.TempDir()
	cli := executable(t, root)
	valid := validConfigJSON(cli)
	tests := []struct {
		name string
		doc  string
	}{
		{"rootful socket", strings.Replace(valid, localRootlessEndpoint(), "unix:///var/run/docker.sock", 1)},
		{"another user socket", strings.Replace(valid, localRootlessEndpoint(), "unix:///run/user/4294967294/docker.sock", 1)},
		{"noncanonical endpoint", strings.Replace(valid, localRootlessEndpoint(), "unix://"+filepath.Dir(localRootlessSocket())+"/../docker.sock", 1)},
		{"missing workspace", strings.Replace(valid, `"project-main","directory":"project-main"`, `"another","directory":"project-main"`, 1)},
		{"missing state", strings.Replace(valid, `"mock-state","directory":"mock-state"`, `"another","directory":"mock-state"`, 1)},
		{"noncanonical runner-state ref", strings.Replace(strings.Replace(valid, `"ref":"mock-state"`, `"ref":"Mock-state"`, 1), `"state_ref":"mock-state"`, `"state_ref":"Mock-state"`, 1)},
		{"noncanonical runner-state directory", strings.Replace(valid, `"directory":"mock-state"`, `"directory":"Mock-state"`, 1)},
		{"unicode runner-state directory", strings.Replace(valid, `"directory":"mock-state"`, `"directory":"móck-state"`, 1)},
		{"traversal directory", strings.Replace(valid, `"directory":"project-main"`, `"directory":".."`, 1)},
		{"duplicate directory", strings.Replace(valid, `"workspaces":[{"ref":"project-main","directory":"project-main"}]`, `"workspaces":[{"ref":"project-main","directory":"same"},{"ref":"other","directory":"same"}]`, 1)},
		{"overlap roots", strings.Replace(valid, `"runner_state_root":"../runtime/runner-state"`, `"runner_state_root":"../runtime/workspaces/state"`, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfig(t, filepath.Join(root, test.name), test.doc, 0o600)
			if _, err := Load(path); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestRuntimeCLIIsTrustedAndOutsideRunnerStorage(t *testing.T) {
	root := t.TempDir()
	cli := executable(t, root)
	valid := validConfigJSON(cli)

	if err := os.Chmod(cli, 0o722); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, filepath.Join(root, "writable-cli"), valid, 0o600)
	if _, err := Load(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("writable CLI error = %v", err)
	}

	root = t.TempDir()
	cli = executable(t, root)
	valid = validConfigJSON(cli)
	link := filepath.Join(root, "docker-link")
	if err := os.Symlink(cli, link); err != nil {
		t.Fatal(err)
	}
	valid = strings.Replace(valid, quote(cli), quote(link), 1)
	path = writeConfig(t, filepath.Join(root, "symlink-cli"), valid, 0o600)
	if _, err := Load(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink CLI error = %v", err)
	}
}

func TestControlAuthorityCannotOverlapRunnerStorageOrEachOther(t *testing.T) {
	root := t.TempDir()
	cli := executable(t, root)
	valid := validConfigJSON(cli)
	absoluteSandboxSocket := filepath.Join(root, "runtime", "sandboxd.sock")
	absoluteWorkspaceSocket := filepath.Join(root, "runtime", "workspaces", "docker.sock")
	tests := []struct {
		name string
		doc  string
	}{
		{
			name: "database in workspace root",
			doc:  strings.Replace(valid, `"state_database":"../runtime/sandboxd.sqlite3"`, `"state_database":"../runtime/workspaces/state.sqlite3"`, 1),
		},
		{
			name: "control socket in state root",
			doc:  strings.Replace(valid, `"socket":"../runtime/sandboxd.sock"`, `"socket":"../runtime/runner-state/sandboxd.sock"`, 1),
		},
		{
			name: "runtime socket in workspace root",
			doc:  strings.Replace(valid, localRootlessEndpoint(), "unix://"+absoluteWorkspaceSocket, 1),
		},
		{
			name: "database equals control socket",
			doc:  strings.Replace(valid, `"state_database":"../runtime/sandboxd.sqlite3"`, `"state_database":"../runtime/sandboxd.sock"`, 1),
		},
		{
			name: "runtime socket equals control socket",
			doc:  strings.Replace(valid, localRootlessEndpoint(), "unix://"+absoluteSandboxSocket, 1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfig(t, root, test.doc, 0o600)
			loaded, err := Load(path)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load() = %#v, error = %v, want ErrInvalid", loaded, err)
			}
		})
	}
}

func TestControlAuthorityRejectsGlobalProcessLockCollision(t *testing.T) {
	root := t.TempDir()
	cli := executable(t, root)
	configPath := writeConfig(t, root, validConfigJSON(cli), 0o600)
	config, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	config.Socket = config.ProcessLockPath()
	if err := config.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("process lock collision error = %v, want ErrInvalid", err)
	}
}

func TestTargetsCannotShareHarnessState(t *testing.T) {
	root := t.TempDir()
	cli := executable(t, root)
	path := writeConfig(t, root, validConfigJSON(cli), 0o600)
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	second := config.Targets[0]
	second.ID = "project-other"
	second.Revision = "project-other-r1"
	config.Targets = append(config.Targets, second)
	if err := config.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("shared target state error = %v", err)
	}
}
