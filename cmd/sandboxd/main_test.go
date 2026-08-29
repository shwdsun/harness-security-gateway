package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func TestParseOptions(t *testing.T) {
	parsed, err := parseOptions([]string{"-config", "config/sandboxd.json"})
	if err != nil || parsed.configPath != "config/sandboxd.json" {
		t.Fatalf("parseOptions = %#v, %v", parsed, err)
	}
	for _, arguments := range [][]string{nil, {"-config", "x", "extra"}, {"-unknown"}} {
		if _, err := parseOptions(arguments); err == nil {
			t.Fatalf("parseOptions(%q) unexpectedly succeeded", arguments)
		}
	}
}

func TestRunRejectsNilContextBeforeSideEffects(t *testing.T) {
	if err := run(nil, []string{"-config", "missing"}); err == nil {
		t.Fatal("nil context accepted")
	}
}

func TestPrepareFilesystemCreatesPrivateStorage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sandbox-private")
	config := sandboxconfig.Config{
		Socket:          filepath.Join(root, "control", "sandboxd.sock"),
		StateDatabase:   filepath.Join(root, "control", "sandboxd.sqlite3"),
		WorkspaceRoot:   filepath.Join(root, "workspaces"),
		RunnerStateRoot: filepath.Join(root, "runner-state"),
		Workspaces: []sandboxconfig.StorageEntry{
			{Ref: "project", Directory: "project"},
		},
		RunnerStates: []sandboxconfig.StorageEntry{
			{Ref: "mock-state", Directory: "mock-state"},
			{Ref: "unused-state", Directory: "unused-state"},
		},
		Targets: []targetmanifest.Manifest{{StateRef: "mock-state"}},
	}
	if err := prepareFilesystem(config); err != nil {
		t.Fatalf("prepareFilesystem: %v", err)
	}
	statePath := filepath.Join(config.RunnerStateRoot, "mock-state")
	if _, err := os.Lstat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runner-state leaf existed before durable ownership: %v", err)
	}
	if err := prepareRunnerStateFilesystem(config); err != nil {
		t.Fatalf("prepareRunnerStateFilesystem: %v", err)
	}
	paths := []string{
		filepath.Dir(config.Socket),
		config.WorkspaceRoot,
		filepath.Join(config.WorkspaceRoot, "project"),
		config.RunnerStateRoot,
		statePath,
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("Lstat(%q): %v", path, err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("%q mode = %v, want private directory 0700", path, info.Mode())
		}
	}
	if _, err := os.Lstat(filepath.Join(config.RunnerStateRoot, "unused-state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unowned runner-state leaf was created: %v", err)
	}
}

func TestCommittedRunnerStateOwnerSurvivesCrashBeforeLeafCreation(t *testing.T) {
	ctx := context.Background()
	config := runnerStateOwnershipConfig(t)
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if err := prepareFilesystem(config); err != nil {
		t.Fatalf("prepareFilesystem() = %v", err)
	}
	statePath, ok := config.RunnerStatePath(config.Targets[0].StateRef)
	if !ok {
		t.Fatal("configured runner state did not resolve")
	}
	if _, err := os.Lstat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state leaf before registration = %v, want absent", err)
	}

	store, err := sandboxstore.Open(ctx, config.StateDatabase)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := config.Registry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sandboxservice.New(
		ctx,
		registry,
		store,
		config.RunnerStateOwnership,
		sandboxservice.WithRevisionPin(config.RevisionSecurityFingerprint),
	); err != nil {
		_ = store.Close()
		t.Fatalf("first sandboxservice.New() = %v", err)
	}
	// Simulate a process crash at the only intentional commit/create gap.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state leaf after ownership commit = %v, want absent", err)
	}

	store, err = sandboxstore.Open(ctx, config.StateDatabase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	if _, err := sandboxservice.New(
		ctx,
		registry,
		store,
		config.RunnerStateOwnership,
		sandboxservice.WithRevisionPin(config.RevisionSecurityFingerprint),
	); err != nil {
		t.Fatalf("post-crash sandboxservice.New() = %v", err)
	}
	if err := prepareRunnerStateFilesystem(config); err != nil {
		t.Fatalf("prepareRunnerStateFilesystem() = %v", err)
	}
	info, err := os.Lstat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("recovered state leaf mode = %v", info.Mode())
	}
}

func TestExistingUnownedRunnerStateLeafIsNeverAdopted(t *testing.T) {
	tests := []struct {
		name   string
		create func(string) error
	}{
		{"empty directory", func(path string) error { return os.Mkdir(path, 0o700) }},
		{"regular file", func(path string) error { return os.WriteFile(path, []byte("foreign"), 0o600) }},
		{"dangling symlink", func(path string) error { return os.Symlink(path+"-missing", path) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			config := runnerStateOwnershipConfig(t)
			if err := config.Validate(); err != nil {
				t.Fatalf("Validate() = %v", err)
			}
			if err := prepareFilesystem(config); err != nil {
				t.Fatalf("prepareFilesystem() = %v", err)
			}
			statePath, ok := config.RunnerStatePath(config.Targets[0].StateRef)
			if !ok {
				t.Fatal("configured runner state did not resolve")
			}
			if err := test.create(statePath); err != nil {
				t.Fatal(err)
			}
			store, err := sandboxstore.Open(ctx, config.StateDatabase)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := store.Close(); err != nil {
					t.Errorf("Close() error = %v", err)
				}
			})
			registry, err := config.Registry()
			if err != nil {
				t.Fatal(err)
			}
			service, err := sandboxservice.New(
				ctx,
				registry,
				store,
				config.RunnerStateOwnership,
				sandboxservice.WithRevisionPin(config.RevisionSecurityFingerprint),
			)
			if service != nil || !errors.Is(err, sandboxstore.ErrRunnerStateOwnershipUnknown) {
				t.Fatalf("sandboxservice.New() = %#v, %v; want closed ownership error", service, err)
			}
		})
	}
}

func runnerStateOwnershipConfig(t *testing.T) sandboxconfig.Config {
	t.Helper()
	root := t.TempDir()
	cli := filepath.Join(root, "bin", "docker")
	if err := os.MkdirAll(filepath.Dir(cli), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cli, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	runtimeSocket := filepath.Join("/run/user", strconv.Itoa(os.Geteuid()), "docker.sock")
	manifest := targetmanifest.Manifest{
		Schema:   targetmanifest.SchemaV1,
		ID:       "target-codex",
		Revision: "target-codex-r1",
		Runner: targetmanifest.Runner{
			Family:           "mock",
			AdapterVersion:   "0.1.0",
			Protocol:         runnerwire.ProtocolV1,
			Image:            "harness-gateway/mock-runner@sha256:" + strings.Repeat("0", 64),
			RequiredFeatures: []runnerwire.Feature{},
		},
		WorkspaceRef:      "workspace-main",
		WorkspaceMode:     targetmanifest.WorkspaceReadWrite,
		StateRef:          "state-codex",
		PolicyRef:         "builtin.locked-down-v1",
		AuthProfileRef:    "builtin.none",
		SkillBundleRef:    "builtin.none",
		NetworkProfileRef: "builtin.none",
		SessionMode:       targetmanifest.SessionNewOnly,
		Limits: targetmanifest.Limits{
			TimeoutSeconds: 60, MemoryBytes: 128 << 20, CPUMillis: 1000, PIDs: 64,
			MaxInputBytes: 32 << 10, MaxOutputBytes: 32 << 10,
			MaxProgressBytes: 4 << 10, MaxStderrBytes: 4 << 10, MaxEvents: 16,
		},
	}
	return sandboxconfig.Config{
		Schema:          sandboxconfig.SchemaV2,
		Socket:          filepath.Join(root, "control", "sandboxd.sock"),
		PeerUID:         localidentity.UID(1000),
		StateDatabase:   filepath.Join(root, "control", "sandboxd.sqlite3"),
		WorkspaceRoot:   filepath.Join(root, "workspaces"),
		RunnerStateRoot: filepath.Join(root, "runner-state"),
		Runtime: sandboxconfig.Runtime{
			Kind:       sandboxconfig.RuntimeRootlessDocker,
			Endpoint:   "unix://" + runtimeSocket,
			CLI:        cli,
			SocketPath: runtimeSocket,
		},
		Workspaces:   []sandboxconfig.StorageEntry{{Ref: "workspace-main", Directory: "workspace-main"}},
		RunnerStates: []sandboxconfig.StorageEntry{{Ref: "state-codex", Directory: "state-codex"}},
		Targets:      []targetmanifest.Manifest{manifest},
	}
}

func TestPrepareFilesystemRefusesRelaxedExistingRoot(t *testing.T) {
	root := t.TempDir()
	workspaceRoot := filepath.Join(root, "workspaces")
	if err := os.Mkdir(workspaceRoot, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	config := sandboxconfig.Config{
		Socket:          filepath.Join(root, "control", "sandboxd.sock"),
		StateDatabase:   filepath.Join(root, "control", "sandboxd.sqlite3"),
		WorkspaceRoot:   workspaceRoot,
		RunnerStateRoot: filepath.Join(root, "runner-state"),
		Workspaces:      []sandboxconfig.StorageEntry{{Ref: "project", Directory: "project"}},
		RunnerStates:    []sandboxconfig.StorageEntry{{Ref: "state", Directory: "state"}},
	}
	if err := prepareFilesystem(config); err == nil {
		t.Fatal("relaxed existing workspace root accepted")
	}
}

func TestServeRejectsNilContext(t *testing.T) {
	if err := serve(nil, sandboxconfig.Config{}); err == nil {
		t.Fatal("nil context accepted")
	}
}

func TestAcquireOwnershipRejectsSecondLiveInstance(t *testing.T) {
	root := filepath.Join(t.TempDir(), "control")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	socketPath := filepath.Join(root, "sandboxd.sock")
	peerUID := localidentity.UID(os.Geteuid())
	first, err := acquireOwnership(socketPath, peerUID)
	if errors.Is(err, syscall.EPERM) {
		t.Skip("Unix listener setup is forbidden by the test sandbox")
	}
	if err != nil {
		t.Fatalf("first acquireOwnership: %v", err)
	}
	defer first.Close()

	second, err := acquireOwnership(socketPath, peerUID)
	if second != nil {
		_ = second.Close()
		t.Fatal("second live sandboxd acquired the same ownership socket")
	}
	if !errors.Is(err, localhttp.ErrSocketInUse) {
		t.Fatalf("second acquireOwnership error = %v, want ErrSocketInUse", err)
	}
}
