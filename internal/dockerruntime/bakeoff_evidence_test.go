package dockerruntime

import (
	"strconv"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// The bake-off's NET-01, LIMIT-01 and the containment half of REPO-01 assert
// properties of the container this package creates. They are settled here
// against the real argument builder so the lab run confirms them rather than
// discovering them, and so a later change cannot quietly relax one.
func createdArguments(t *testing.T) ([]string, testFixture) {
	t.Helper()
	fixture := newFixture(t)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	spec := runtime.targets[targetKey{id: fixture.manifest.ID, revision: fixture.manifest.Revision}]
	return createArguments("safe-name", map[string]string{
		labelManaged: "v1", labelRunID: "run", labelTargetID: fixture.manifest.ID,
		labelTargetRevision: fixture.manifest.Revision, labelTargetFingerprint: spec.fingerprint,
	}, spec, runtimeDefinition(t, fixture.manifest)), fixture
}

// NET-01: a model-controlled tool cannot reach a collector, the internet, the
// LAN, host services or a metadata endpoint. The container has no network
// stack at all, so none of those destinations is addressable from inside it.
func TestTheContainerHasNoNetworkStack(t *testing.T) {
	arguments, _ := createdArguments(t)
	if !containsAdjacent(arguments, "--network", "none") {
		t.Fatalf("the container was not created network-none: %q", arguments)
	}
	for index, argument := range arguments {
		switch argument {
		case "--publish", "-p", "--add-host", "--dns", "--network-alias", "--link", "--expose":
			t.Fatalf("an addressable network option was supplied: %q", arguments[index:])
		}
		if strings.HasPrefix(argument, "--network=") && argument != "--network=none" {
			t.Fatalf("a network other than none was selected: %q", argument)
		}
	}
}

// NET-01 continued: the only egress is what the owner mounts. Nothing in the
// default path mounts a runtime socket, a host configuration directory or any
// path the operator did not name in the manifest.
func TestTheOnlyMountsAreTheOnesTheManifestNames(t *testing.T) {
	arguments, fixture := createdArguments(t)
	var mounts []string
	for index, argument := range arguments {
		if argument == "--mount" && index+1 < len(arguments) {
			mounts = append(mounts, arguments[index+1])
		}
		if argument == "-v" || argument == "--volume" {
			t.Fatalf("a bare volume flag bypasses the mount contract: %q", arguments[index:])
		}
	}
	allowed := map[string]bool{fixture.workspaceDir: true, fixture.stateDir: true}
	for _, mount := range mounts {
		source := ""
		for _, field := range strings.Split(mount, ",") {
			if strings.HasPrefix(field, "src=") {
				source = strings.TrimPrefix(field, "src=")
			}
		}
		if !allowed[source] {
			t.Fatalf("an unexpected source is mounted: %q", mount)
		}
	}
	// Compare path components: "runner-state" is not "/run".
	forbidden := map[string]bool{"etc": true, "proc": true, "sys": true, "run": true,
		"docker.sock": true, "var": true}
	for _, mount := range mounts {
		for _, field := range strings.Split(mount, ",") {
			if !strings.HasPrefix(field, "src=") {
				continue
			}
			for _, component := range strings.Split(strings.TrimPrefix(field, "src="), "/") {
				if forbidden[component] {
					t.Fatalf("a sensitive host path component is mounted: %q", mount)
				}
			}
		}
	}
}

// LIMIT-01: processor time, memory, process count and scratch growth are fixed
// before the container starts, from the immutable manifest, and enforced by the
// runtime rather than by the harness's cooperation.
func TestEveryResourceBoundComesFromTheManifest(t *testing.T) {
	arguments, fixture := createdArguments(t)
	limits := fixture.manifest.Limits
	memory := strconv.FormatInt(limits.MemoryBytes, 10)
	// The property is that every bound is the manifest's, whatever it says; a
	// default that happened to match would not be the same thing.
	for _, pair := range [][2]string{
		{"--memory", memory},
		{"--memory-swap", memory},
		{"--pids-limit", strconv.FormatInt(limits.PIDs, 10)},
		{"--cpus", formatCPU(limits.CPUMillis)},
	} {
		if !containsAdjacent(arguments, pair[0], pair[1]) {
			t.Fatalf("%s was not taken from the manifest (%s): %q", pair[0], pair[1], arguments)
		}
	}
	if limits.MemoryBytes == 0 || limits.PIDs == 0 || limits.CPUMillis == 0 {
		t.Fatal("the fixture carries no limits, so this test would assert nothing")
	}
	// Equal memory and memory-swap leaves no swap to grow into.
	var tmpfs string
	for index, argument := range arguments {
		if argument == "--tmpfs" && index+1 < len(arguments) {
			tmpfs = arguments[index+1]
		}
	}
	for _, required := range []string{"nosuid", "nodev", "noexec", "size="} {
		if !strings.Contains(tmpfs, required) {
			t.Fatalf("the scratch filesystem is missing %s: %q", required, tmpfs)
		}
	}
}

// REPO-01's containment half: whatever a repository contains, it executes with
// no capabilities, no privilege escalation, a read-only root and a fixed UID,
// so repository content cannot escalate by invoking something on the host.
func TestRepositoryContentExecutesWithoutPrivilege(t *testing.T) {
	arguments, _ := createdArguments(t)
	for _, pair := range [][2]string{
		{"--cap-drop", "ALL"},
		{"--security-opt", "no-new-privileges=true"},
		{"--user", "0:0"},
		{"--log-driver", "none"},
		{"--restart", "no"},
	} {
		if !containsAdjacent(arguments, pair[0], pair[1]) {
			t.Fatalf("%s %s is not fixed: %q", pair[0], pair[1], arguments)
		}
	}
	for _, flag := range []string{"--read-only", "--no-healthcheck", "--pull=never"} {
		found := false
		for _, argument := range arguments {
			if argument == flag {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s is not fixed: %q", flag, arguments)
		}
	}
	for index, argument := range arguments {
		switch argument {
		case "--privileged", "--cap-add", "--device", "--pid", "--userns":
			t.Fatalf("an escalating option was supplied: %q", arguments[index:])
		}
	}
}

// The workspace is the only writable surface a repository can use, and its mode
// comes from the manifest rather than from anything inside it.
func TestTheWorkspaceModeIsDecidedOutsideTheRepository(t *testing.T) {
	fixture := newFixture(t)
	fixture.manifest.WorkspaceMode = targetmanifest.WorkspaceReadOnly
	fixture.config.Targets[0] = runtimeDefinition(t, fixture.manifest)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	spec := runtime.targets[targetKey{id: fixture.manifest.ID, revision: fixture.manifest.Revision}]
	arguments := createArguments("safe-name", map[string]string{
		labelManaged: "v1", labelRunID: "run", labelTargetID: fixture.manifest.ID,
		labelTargetRevision: fixture.manifest.Revision, labelTargetFingerprint: spec.fingerprint,
	}, spec, runtimeDefinition(t, fixture.manifest))
	if !containsAdjacent(arguments, "--mount", "type=bind,src="+fixture.workspaceDir+
		",dst=/workspace,bind-propagation=rprivate,readonly") {
		t.Fatalf("a read-only workspace was not honoured: %q", arguments)
	}
}
