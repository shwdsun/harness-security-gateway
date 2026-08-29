package dockerruntime

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

const helperExecutableName = "docker-helper"

func rootlessInfoStep() helperStep {
	return helperStep{Stdout: `["name=seccomp,profile=builtin","name=rootless","name=cgroupns"]`}
}

type helperStep struct {
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	ExitCode   int    `json:"exit_code,omitempty"`
	ReadStdin  bool   `json:"read_stdin,omitempty"`
	DelayMS    int    `json:"delay_ms,omitempty"`
	RemoveSelf bool   `json:"remove_self,omitempty"`
}

type helperPlan struct {
	Next  int          `json:"next"`
	Steps []helperStep `json:"steps"`
}

type helperCall struct {
	Arguments   []string `json:"arguments"`
	Environment []string `json:"environment"`
	Stdin       string   `json:"stdin,omitempty"`
}

func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == helperExecutableName {
		os.Exit(runDockerHelper())
	}
	os.Exit(m.Run())
}

func runDockerHelper() int {
	base := os.Args[0]
	planData, err := os.ReadFile(base + ".plan")
	if err != nil {
		return 120
	}
	var plan helperPlan
	if err := json.Unmarshal(planData, &plan); err != nil || plan.Next >= len(plan.Steps) {
		return 121
	}
	step := plan.Steps[plan.Next]
	plan.Next++
	updatedPlan, err := json.Marshal(plan)
	if err != nil || os.WriteFile(base+".plan", updatedPlan, 0o600) != nil {
		return 122
	}

	call := helperCall{
		Arguments:   append([]string(nil), os.Args[1:]...),
		Environment: append([]string(nil), os.Environ()...),
	}
	if step.ReadStdin {
		stdin, readErr := io.ReadAll(os.Stdin)
		if readErr != nil {
			return 123
		}
		call.Stdin = string(stdin)
	}
	encodedCall, err := json.Marshal(call)
	if err != nil {
		return 124
	}
	log, err := os.OpenFile(base+".calls", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 125
	}
	_, writeErr := fmt.Fprintln(log, string(encodedCall))
	closeErr := log.Close()
	if writeErr != nil || closeErr != nil {
		return 126
	}
	if step.RemoveSelf {
		if err := os.Remove(base); err != nil {
			return 127
		}
	}
	if step.DelayMS > 0 {
		time.Sleep(time.Duration(step.DelayMS) * time.Millisecond)
	}
	_, _ = io.WriteString(os.Stdout, step.Stdout)
	_, _ = io.WriteString(os.Stderr, step.Stderr)
	return step.ExitCode
}

type testFixture struct {
	config       sandboxconfig.Config
	manifest     targetmanifest.Manifest
	helper       string
	workspaceDir string
	stateDir     string
}

func newFixture(t *testing.T) testFixture {
	t.Helper()
	root := t.TempDir()
	helper := filepath.Join(root, helperExecutableName)
	copyExecutable(t, helper)

	workspaceRoot := filepath.Join(root, "workspaces")
	stateRoot := filepath.Join(root, "runner-state")
	workspaceDir := filepath.Join(workspaceRoot, "project-main")
	stateDir := filepath.Join(stateRoot, "target-state")
	for _, directory := range []string{workspaceDir, stateDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	manifest := targetmanifest.Manifest{
		Schema:   targetmanifest.SchemaV1,
		ID:       "target-main",
		Revision: "target-main-r1",
		Runner: targetmanifest.Runner{
			Family:           "mock",
			AdapterVersion:   "0.1.0",
			Protocol:         runnerwire.ProtocolV1,
			Image:            "registry.example/mock-runner@sha256:" + strings.Repeat("a", 64),
			RequiredFeatures: []runnerwire.Feature{},
		},
		WorkspaceRef:      "workspace-main",
		WorkspaceMode:     targetmanifest.WorkspaceReadWrite,
		StateRef:          "state-main",
		PolicyRef:         LockedPolicyRef,
		AuthProfileRef:    NoneProfileRef,
		SkillBundleRef:    NoneProfileRef,
		NetworkProfileRef: NoneProfileRef,
		SessionMode:       targetmanifest.SessionNewOnly,
		Limits: targetmanifest.Limits{
			TimeoutSeconds:   60,
			MemoryBytes:      128 << 20,
			CPUMillis:        1000,
			PIDs:             64,
			MaxInputBytes:    1024,
			MaxOutputBytes:   1024,
			MaxProgressBytes: 1024,
			MaxStderrBytes:   1024,
			MaxEvents:        4,
		},
	}
	socketPath := filepath.Join("/run/user", strconv.Itoa(os.Geteuid()), "docker.sock")
	config := sandboxconfig.Config{
		Schema:          sandboxconfig.SchemaV2,
		PeerUID:         1000,
		Socket:          filepath.Join(root, "sandboxd.sock"),
		StateDatabase:   filepath.Join(root, "sandboxd.sqlite3"),
		WorkspaceRoot:   workspaceRoot,
		RunnerStateRoot: stateRoot,
		Runtime: sandboxconfig.Runtime{
			Kind:       sandboxconfig.RuntimeRootlessDocker,
			Endpoint:   "unix://" + socketPath,
			CLI:        helper,
			SocketPath: socketPath,
		},
		Workspaces:   []sandboxconfig.StorageEntry{{Ref: "workspace-main", Directory: "project-main"}},
		RunnerStates: []sandboxconfig.StorageEntry{{Ref: "state-main", Directory: "target-state"}},
		Targets:      []targetmanifest.Manifest{manifest},
	}
	return testFixture{
		config:       config,
		manifest:     manifest,
		helper:       helper,
		workspaceDir: workspaceDir,
		stateDir:     stateDir,
	}
}

func copyExecutable(t *testing.T, destination string) {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o700); err != nil {
		t.Fatal(err)
	}
}

func (fixture testFixture) setPlan(t *testing.T, steps ...helperStep) {
	t.Helper()
	data, err := json.Marshal(helperPlan{Steps: steps})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.helper+".plan", data, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(fixture.helper + ".calls")
}

func (fixture testFixture) calls(t *testing.T) []helperCall {
	t.Helper()
	data, err := os.ReadFile(fixture.helper + ".calls")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	calls := make([]helperCall, 0, len(lines))
	for _, line := range lines {
		var call helperCall
		if err := json.Unmarshal([]byte(line), &call); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, call)
	}
	return calls
}

func managedRecord(t *testing.T, fixture testFixture, runID, id string, state ContainerState) string {
	t.Helper()
	fingerprint, err := fixture.manifest.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	record := inspectRecord{
		ID:       id,
		Name:     "/" + deterministicName(runID),
		Image:    fixture.manifest.Runner.Image,
		State:    state,
		ExitCode: 0,
		Labels:   expectedLabels(runID, fixture.manifest, fingerprint),
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return string(data) + "\n"
}

func requireArguments(t *testing.T, got helperCall, want []string) {
	t.Helper()
	if fmt.Sprint(got.Arguments) != fmt.Sprint(want) {
		t.Fatalf("arguments mismatch\n got: %q\nwant: %q", got.Arguments, want)
	}
	if fmt.Sprint(got.Environment) != fmt.Sprint(minimalEnvironment) {
		t.Fatalf("environment mismatch\n got: %q\nwant: %q", got.Environment, minimalEnvironment)
	}
}
