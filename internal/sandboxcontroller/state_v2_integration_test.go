package sandboxcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// Uses the production versioned config, registry, revision/ownership resolver,
// service, SQLite store, controller and HRP bridge; only the runtime is fake.
func TestV3NoStateRunKeepsPublicationAndWorkspaceFenceAcrossRestart(t *testing.T) {
	ctx := context.Background()
	wire := controllerManifest("mock-none", "mock-none-r1", "workspace-main",
		targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly)
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	document := strings.Replace(string(data), `"harness-target/v1"`, `"harness-target/v2"`, 1)
	document = strings.Replace(document, `"state_ref":"`+wire.StateRef+`"`, `"runner_state":{"kind":"none"}`, 1)
	target, err := targetmanifest.DecodeDefinition([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cli := filepath.Join(root, "fake-docker")
	if err := os.WriteFile(cli, []byte("not executed"), 0o700); err != nil {
		t.Fatal(err)
	}
	socket := fmt.Sprintf("/run/user/%d/docker.sock", os.Geteuid())
	config := sandboxconfig.Config{
		Schema: sandboxconfig.SchemaV3, PeerUID: 1000, Socket: filepath.Join(root, "control", "sandbox.sock"),
		StateDatabase: filepath.Join(root, "control", "state.sqlite3"),
		WorkspaceRoot: filepath.Join(root, "workspaces"), RunnerStateRoot: filepath.Join(root, "runner-state"),
		Runtime:      sandboxconfig.Runtime{Kind: sandboxconfig.RuntimeRootlessDocker, CLI: cli, Endpoint: "unix://" + socket, SocketPath: socket},
		Workspaces:   []sandboxconfig.StorageEntry{{Ref: wire.WorkspaceRef, Directory: "main"}},
		RunnerStates: []sandboxconfig.StorageEntry{}, Targets: []targetmanifest.Definition{target},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "sandboxd.json")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err = sandboxconfig.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := config.Registry()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(config.StateDatabase), 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := sandboxstore.Open(ctx, config.StateDatabase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	service, err := sandboxservice.New(ctx, registry, store, config.RunnerStateOwnership,
		sandboxservice.WithRevisionPin(config.RevisionSecurityFingerprint))
	if err != nil {
		t.Fatal(err)
	}
	deps := testDependencies{store: store, registry: registry, durable: service, dbPath: config.StateDatabase}
	request := controllerRequest("run_none_v3", wire, "work")
	var output bytes.Buffer
	encoder := runnerwire.NewEncoder(&output)
	for _, frame := range []runnerwire.Frame{
		&runnerwire.RunnerReady{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunnerReady,
			Adapter:  runnerwire.Adapter{Family: wire.Runner.Family, Version: wire.Runner.AdapterVersion},
			Features: wire.Runner.RequiredFeatures},
		&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: request.RunID, Seq: 1},
		&runnerwire.RunCompleted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunCompleted, RunID: request.RunID, Seq: 2,
			Output: runnerwire.TextContent{MediaType: runnerwire.MediaTypeTextPlain, Text: "v2 result"}},
	} {
		if err := encoder.Encode(frame); err != nil {
			t.Fatal(err)
		}
	}
	runtime := newFakeRuntime()
	process := newFakeProcess()
	process.output = io.NopCloser(bytes.NewReader(output.Bytes()))
	runtime.process = func() *fakeProcess { return process }
	runtime.removeErr = errors.New("injected removal failure")
	controller, err := New(ctx, service, registry, store, runtime,
		WithBootIDSource(fixedBootID(testBootID)), WithCleanupTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		_ = controller.Close(closeCtx)
	}()
	if _, err := controller.StartRun(ctx, request); err != nil {
		t.Fatal(err)
	}
	run := awaitRun(t, store, request.RunID, func(r sandboxstore.Run) bool { return r.TerminalPending })
	if !run.WorkspaceLockHeld || run.Output != nil || run.ResultSessionRef != nil {
		t.Fatalf("none bypassed cleanup fence: %#v", run)
	}
	snapshot, err := controller.GetRun(ctx, executionwire.GetRunRequest{RunID: request.RunID})
	if err != nil || snapshot.Status.State != executionwire.RunStateRunning || len(snapshot.Events) != 1 {
		t.Fatalf("unconfirmed result published: %#v %v", snapshot, err)
	}
	other := request
	other.RunID = "run_none_busy"
	_, err = controller.StartRun(ctx, other)
	var conflict *executionhttp.ServiceError
	if !errors.As(err, &conflict) || conflict.Code != executionhttp.ErrorConflict {
		t.Fatalf("no-state run lost workspace exclusion: %v", err)
	}
	if _, err := store.GetRun(ctx, other.RunID); !errors.Is(err, sandboxstore.ErrNotFound) {
		t.Fatalf("conflicting writer persisted: %v", err)
	}
	if _, err := os.Lstat(config.RunnerStateRoot); !os.IsNotExist(err) {
		t.Fatalf("none created runner-state resource: %v", err)
	}
	closeCtx, cancel := context.WithTimeout(ctx, time.Second)
	err = controller.Close(closeCtx)
	cancel()
	if !errors.Is(err, ErrCleanup) {
		t.Fatalf("cleanup failure was lost: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = sandboxstore.Open(ctx, config.StateDatabase)
	if err != nil {
		t.Fatal(err)
	}
	deps.store = store
	deps.durable, err = sandboxservice.New(ctx, registry, store, config.RunnerStateOwnership,
		sandboxservice.WithRevisionPin(config.RevisionSecurityFingerprint))
	if err != nil {
		t.Fatal(err)
	}
	// The old controller has fully closed, so no fake runtime call races this.
	runtime.removeErr = nil
	restarted := newTestController(t, deps, runtime, nil)
	snapshot, err = restarted.GetRun(ctx, executionwire.GetRunRequest{RunID: request.RunID})
	if err != nil || snapshot.Status.State != executionwire.RunStateCompleted || len(snapshot.Events) != 2 ||
		snapshot.Events[1].Result.Output.Text != "v2 result" || snapshot.Events[1].Result.SessionRef != nil {
		t.Fatalf("reopen lost no-state result: %#v %v", snapshot, err)
	}
	run, err = store.GetRun(ctx, request.RunID)
	if err != nil || run.WorkspaceLockHeld || run.RuntimeRef != nil || run.TerminalPending || runtimeCreateCount(runtime, request.RunID) != 1 {
		t.Fatalf("recovery retained authority or re-executed: %#v %v", run, err)
	}
	db, err := sql.Open("sqlite", config.StateDatabase)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM runner_state_owners").Scan(&count); err != nil || count != 0 {
		t.Fatalf("none acquired an owner: %d %v", count, err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&count); err != nil || count != 0 {
		t.Fatalf("none acquired provider session: %d %v", count, err)
	}
}
