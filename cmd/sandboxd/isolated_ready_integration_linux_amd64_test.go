//go:build linux && amd64 && codexintegration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/privatefs"
	"github.com/shwdsun/harness-security-gateway/internal/processlock"
	"github.com/shwdsun/harness-security-gateway/internal/runnerbridge"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxcontroller"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"golang.org/x/sys/unix"
)

const readyFixtureRoot = "/srv/hgw-v4-acceptance/ready"

// os.File has a finalizer. Failed joins must retain strong references after the
// test returns, until the one-shot service watchdog stops the whole cgroup.
// This test is deliberately not parallel and its driver permits only one run.
var isolatedReadyFailedOwner struct {
	lock       *processlock.Lock
	store      *sandboxstore.Store
	controller *sandboxcontroller.Controller
}

// Reserve the complete 240-second test/service budget inside a fixed one-day
// cached-auth window. Time rollback or reuse after expiry is a new fixture.
func isolatedReadyWithinWindow(now time.Time) bool {
	start := time.Date(2026, time.October, 5, 0, 0, 0, 0, time.UTC)
	end := start.Add(24*time.Hour - 240*time.Second)
	return !now.Before(start) && now.Before(end)
}

func TestIsolatedReadyWindow(t *testing.T) {
	start := time.Date(2026, time.October, 5, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{"rollback", start.Add(-time.Nanosecond), false},
		{"start", start, true},
		{"last-allowed", start.Add(24*time.Hour - 240*time.Second - time.Nanosecond), true},
		{"budget-boundary", start.Add(24*time.Hour - 240*time.Second), false},
		{"expired", start.Add(24 * time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if isolatedReadyWithinWindow(tc.now) != tc.want {
				t.Fatal("cached-auth freshness boundary mismatch")
			}
		})
	}
}

// Only a frozen, credential-free, no-NIC disposable VM may opt in. This uses
// the actual production constructor, startup and enrollment helpers. WithBridge
// observes Ready and deliberately stops before RunStart/native client launch.
// It is not evidence of serve's HTTP loop, tools, recovery or a live provider.
func TestIsolatedServiceReceiverReady(t *testing.T) {
	if os.Getenv("HSG_V4_READY_PROBE") != "offline-vm-ready-v1" {
		t.Skip("requires the frozen dedicated systemd VM fixture")
	}
	if isolatedReadyFailedOwner.lock != nil {
		t.Fatal("failed owner retained; terminate the whole fixture service instead of retrying")
	}
	if os.Getuid() != 1001 || os.Geteuid() != 1001 {
		t.Fatal("fixture requires its dedicated guest UID")
	}
	if !isolatedReadyWithinWindow(time.Now()) {
		t.Fatal("fixed cached-auth window expired; freeze a fresh fixture instead of refreshing")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("fixture requires a guest without any network interface except loopback")
	}
	config, err := sandboxconfig.Load("/opt/hgw-v4-acceptance/ready.json")
	if err != nil {
		t.Fatal("frozen config rejected:", err)
	}
	if config.Schema != sandboxconfig.SchemaCodexV2 || config.Codex == nil ||
		config.Runtime.Endpoint != "unix:///run/user/1001/docker.sock" ||
		config.Runtime.CLI != "/opt/hgw-v4-acceptance/docker/bin/docker" {
		t.Fatal("unexpected fixture authority")
	}
	for _, path := range []string{config.Socket, config.StateDatabase, config.WorkspaceRoot,
		config.RunnerStateRoot, config.Codex.ProviderRoot, config.Codex.Credential.Root} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || !bytes.HasPrefix([]byte(path), []byte(readyFixtureRoot+"/")) {
			t.Fatal("mutable fixture path escaped its owned root")
		}
	}
	if _, err := os.Lstat(config.StateDatabase); !os.IsNotExist(err) {
		t.Fatal("fresh fixture database required")
	}
	resultFile, err := os.OpenFile(filepath.Join(readyFixtureRoot, "result.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("result already exists or cannot be created")
	}
	var result struct {
		StartedAt, FinishedAt, Stage, Pin, SourceSHA256, ContainerRef, State    string
		FailureCode, AttachOperation, AttachKind                                string
		AttachExitCode                                                          int
		Startup, Enrollment, Ready, RemovedWhileHeld, ReleasedBeforePublication bool
		ControllerClosed, ArtifactsClosed, ProcessLockClosed, SourceUnchanged   bool
		Creates, Attaches                                                       int
		Events                                                                  []string
		Passed                                                                  bool
	}
	result.StartedAt, result.Stage = time.Now().UTC().Format(time.RFC3339Nano), "constructor"
	defer func() {
		result.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		result.Passed = !t.Failed() && result.Ready && result.RemovedWhileHeld && result.ReleasedBeforePublication &&
			result.ControllerClosed && result.ArtifactsClosed && result.ProcessLockClosed && result.SourceUnchanged
		if json.NewEncoder(resultFile).Encode(result) != nil || resultFile.Sync() != nil {
			t.Error("could not persist fixture result")
		}
		if resultFile.Close() != nil {
			t.Error("result close failed")
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	setup, err := prepareExecution(config)
	if err != nil || setup.startup == nil || setup.close == nil {
		t.Fatal("actual isolated execution setup rejected:", err)
	}
	var lock *processlock.Lock
	var db *sandboxstore.Store
	var retainedController *sandboxcontroller.Controller
	controllerCreated := false
	defer func() {
		if setup.close() != nil {
			t.Error("owner artifact borrow did not join")
		} else {
			result.ArtifactsClosed = true
		}
		// A failed join retains process ownership until the service watchdog
		// terminates the entire owned cgroup. Never create a takeover window.
		if lock != nil && result.ArtifactsClosed && (!controllerCreated || result.ControllerClosed) {
			if lock.Close() != nil {
				t.Error("global lock close failed")
			} else {
				result.ProcessLockClosed = true
			}
		} else if lock != nil {
			isolatedReadyFailedOwner.lock = lock
			isolatedReadyFailedOwner.store = db
			isolatedReadyFailedOwner.controller = retainedController
		}
	}()
	if privatefs.EnsureParent(config.ProcessLockPath(), 0700) != nil {
		t.Fatal("global lock parent unavailable")
	}
	lock, err = processlock.Acquire(config.ProcessLockPath())
	if err != nil {
		t.Fatal("global ownership unavailable")
	}
	if second, err := processlock.Acquire(config.ProcessLockPath()); !errors.Is(err, processlock.ErrLocked) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatal("global ownership was not exclusive")
	}
	result.Stage = "startup"
	if err := setup.startup(); err != nil {
		t.Fatal("actual service startup gate:", err)
	}
	result.Startup = true
	if _, err := os.Lstat(config.StateDatabase); !os.IsNotExist(err) {
		t.Fatal("store existed before startup observation")
	}
	if err := prepareFilesystem(config); err != nil {
		t.Fatal("private filesystem:", err)
	}
	native, err := setup.runtime()
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := sandboxcontroller.NewDockerRuntime(native)
	if err != nil {
		t.Fatal(err)
	}
	binding := config.Codex.Credential
	auth := filepath.Join(binding.Root, binding.Directory, "auth.json")
	before, err := os.ReadFile(auth)
	if err != nil {
		t.Fatal("synthetic source unavailable")
	}
	defer clear(before)
	if !bytes.Equal(before, isolatedReadySyntheticAuth()) {
		t.Fatal("source is not this fixed synthetic fixture")
	}
	sourceSHA := sha256.Sum256(before)
	result.SourceSHA256 = hex.EncodeToString(sourceSHA[:])
	result.Stage = "enrollment"
	db, err = sandboxstore.Open(ctx, config.StateDatabase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if controllerCreated && !result.ControllerClosed {
			t.Error("store retained until process exit after controller join failure")
			return
		}
		if db.Close() != nil {
			t.Error("store close failed")
		}
	}()
	if err := enrollSource(ctx, db, binding, config.Codex.Scope.SessionScope(),
		func(ctx context.Context) (bool, error) {
			refs, err := native.ListManaged(ctx)
			return len(refs) == 0, err
		}, holdEnrollmentSource); err != nil {
		t.Fatal("actual ext4 enrollment:", err)
	}
	result.Enrollment = true
	registry, err := config.Registry()
	if err != nil {
		t.Fatal(err)
	}
	durable, err := sandboxservice.New(ctx, registry, db, nil, sandboxservice.WithAuthorityResolver(setup.authority))
	if err != nil {
		t.Fatal("actual fixed revision authority:", err)
	}
	const runID = "isolated-ready-20261003-01"
	witness := &isolatedReadyWitness{DockerRuntime: adapter, Store: db, auth: auth, runID: runID}
	bridge := func(ctx context.Context, _ executionwire.StartRunRequest, manifest targetmanifest.Definition, token *string,
		output io.Reader, _ io.Writer, _ runnerbridge.Sink) error {
		if token != nil {
			return errors.New("Ready-only fixture received a session token")
		}
		// The controller's deadline closes the owned attach streams if Decode
		// stalls. No unjoined test reader goroutine is introduced here.
		frame, err := runnerwire.NewDecoder(output).DecodeRunnerFrame()
		if err != nil {
			return err
		}
		ready, ok := frame.(*runnerwire.RunnerReady)
		if !ok || ready.Adapter.Family != manifest.Common().Runner.Family || ready.Adapter.Version != manifest.Common().Runner.AdapterVersion {
			return errors.New("actual Runner Ready does not match the frozen target")
		}
		for _, required := range manifest.Common().Runner.RequiredFeatures {
			if !ready.Supports(required) {
				return errors.New("required Ready feature absent")
			}
		}
		witness.mu.Lock()
		witness.ready = true
		witness.mu.Unlock()
		return &runnerbridge.BridgeError{Class: runnerbridge.ErrorCancelled}
	}
	c, err := sandboxcontroller.New(ctx, durable, registry, witness, witness,
		sandboxcontroller.WithCredentialBindings(setup.bindings), sandboxcontroller.WithBridge(bridge),
		sandboxcontroller.WithCleanupTimeout(20*time.Second))
	if err != nil {
		t.Fatal("actual controller:", err)
	}
	controllerCreated = true
	retainedController = c
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 25*time.Second)
		defer stop()
		if c.Close(cleanup) != nil {
			t.Error("controller cleanup failed")
		} else {
			result.ControllerClosed = true
		}
		witness.mu.Lock()
		defer witness.mu.Unlock()
		result.Ready, result.ContainerRef = witness.ready, witness.ref
		result.AttachOperation, result.AttachKind, result.AttachExitCode = witness.attachOperation, witness.attachKind, witness.attachExitCode
		result.RemovedWhileHeld, result.ReleasedBeforePublication = witness.removed, witness.published
		result.Creates, result.Attaches = witness.creates, witness.attaches
		result.Events = append([]string(nil), witness.events...)
	}()
	manifest := config.Targets[0]
	fp, _ := manifest.Fingerprint()
	authority, err := setup.authority(manifest, fp)
	if err != nil {
		t.Fatal(err)
	}
	result.Pin = authority.RevisionPin
	scopeDigest, err := sessionauth.Digest(config.Codex.Scope.SessionScope())
	if err != nil {
		t.Fatal(err)
	}
	request := executionwire.StartRunRequest{RunID: runID, TargetID: manifest.ID(), ExpectedRevision: manifest.Revision(),
		SessionScopeDigest: scopeDigest, Input: executionwire.TextInput{MediaType: executionwire.MediaTypeTextPlain, Text: "offline Ready-only observer; no RunStart is sent"},
		Deadline: time.Now().UTC().Add(120 * time.Second).Truncate(time.Millisecond)}
	result.Stage = "create-attach-ready"
	if _, err := c.StartRun(ctx, request); err != nil {
		t.Fatal("actual admission:", err)
	}
	if _, err := c.StartRun(ctx, request); err != nil {
		t.Fatal("exact replay:", err)
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		run, err := db.GetRun(ctx, runID)
		if err != nil {
			t.Fatal(err)
		}
		if run.TerminalAt != nil {
			result.State = string(run.State)
			if run.Failure != nil {
				result.FailureCode = string(run.Failure.Code)
			}
			if run.State != executionwire.RunStateInterrupted || run.Output != nil || run.TerminalPending || run.CredentialLeaseHeld || run.RuntimeRef != nil || run.RuntimeIntentPending || run.WorkspaceLockHeld {
				t.Fatal("Ready observer did not finish with clean intentional interruption")
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture deadline reached")
		case <-tick.C:
		}
	}
	witness.mu.Lock()
	ref := witness.ref
	complete := witness.ready && witness.creates == 1 && witness.attaches == 1 && witness.removed && witness.published
	witness.mu.Unlock()
	if !complete {
		t.Fatal("missing composed witness")
	}
	if _, err := adapter.Inspect(ctx, ref); !errors.Is(err, dockerruntime.ErrNotFound) {
		t.Fatal("exact container absence unavailable")
	}
	if refs, err := adapter.ListManaged(ctx); err != nil || len(refs) != 0 {
		t.Fatal("managed runtime inventory not empty")
	}
	after, err := os.ReadFile(auth)
	defer clear(after)
	if err != nil || !bytes.Equal(before, after) || isolatedReadySourceLock(auth, false) != nil {
		t.Fatal("original source changed or remains locked")
	}
	result.SourceUnchanged, result.Stage = true, "complete"
	t.Log("actual startup/enrollment/owner readiness/receiver/permit/Runner Ready; intentional stop before RunStart; exact removal and source release verified")
}

// Deliberately invalid signature and fixed .invalid identity: never a credential.
func isolatedReadySyntheticAuth() []byte {
	claims, _ := json.Marshal(map[string]any{"sub": "hsg-v4-ready-subject", "email": "ready@example.invalid", "exp": 4102444800,
		"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": "hsg-v4-ready-account", "chatgpt_plan_type": "pro"}})
	identity := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims) + ".synthetic"
	data, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "OPENAI_API_KEY": nil, "last_refresh": "2026-10-05T00:00:00Z",
		"tokens": map[string]string{"access_token": "HSG_V4_READY_SYNTHETIC_ACCESS", "refresh_token": "HSG_V4_READY_SYNTHETIC_REFRESH", "id_token": identity, "account_id": "hsg-v4-ready-account"}})
	return data
}

type isolatedReadyWitness struct {
	*sandboxcontroller.DockerRuntime
	*sandboxstore.Store
	auth, runID                 string
	mu                          sync.Mutex
	ref                         string
	attachOperation, attachKind string
	attachExitCode              int
	creates, attaches           int
	ready, removed, published   bool
	events                      []string
}

func (w *isolatedReadyWitness) CreateWithOwner(ctx context.Context, id string, m targetmanifest.Definition, owner *credentialsource.OwnerAccess) (string, error) {
	w.mu.Lock()
	w.creates++
	w.events = append(w.events, "owner-create-start")
	w.mu.Unlock()
	ref, err := w.DockerRuntime.CreateWithOwner(ctx, id, m, owner)
	w.mu.Lock()
	w.ref = ref
	w.mu.Unlock()
	return ref, err
}

func (w *isolatedReadyWitness) AttachStart(ctx context.Context, ref string) (sandboxcontroller.Process, error) {
	w.mu.Lock()
	w.attaches++
	w.mu.Unlock()
	process, err := w.DockerRuntime.AttachStart(ctx, ref)
	w.mu.Lock()
	defer w.mu.Unlock()
	if err != nil {
		// CommandError retains only fixed local operation/exit metadata. Never
		// persist Cause, raw daemon output, paths or credential-bearing errors.
		var command *dockerruntime.CommandError
		if errors.As(err, &command) {
			w.attachOperation, w.attachExitCode = command.Operation, command.ExitCode
		}
		if errors.Is(err, dockerruntime.ErrCredentialUnavailable) {
			w.attachKind = "credential_unavailable"
		} else {
			w.attachKind = "runtime_error"
		}
	} else {
		w.events = append(w.events, "actual-receiver-permit-returned")
	}
	return process, err
}

func (w *isolatedReadyWitness) RemoveStopped(ctx context.Context, ref string) error {
	run, err := w.Store.GetRun(ctx, w.runID)
	if err != nil || !run.TerminalPending || !run.CredentialLeaseHeld || run.RuntimeRef == nil || *run.RuntimeRef != ref || run.Output != nil || isolatedReadySourceLock(w.auth, true) != nil {
		return errors.New("removal lost staged source authority")
	}
	if err := w.DockerRuntime.RemoveStopped(ctx, ref); err != nil {
		return err
	}
	if _, err := w.DockerRuntime.Inspect(ctx, ref); !errors.Is(err, dockerruntime.ErrNotFound) {
		return errors.New("exact removal unavailable")
	}
	if isolatedReadySourceLock(w.auth, true) != nil {
		return errors.New("source released before removal")
	}
	w.mu.Lock()
	w.removed = true
	w.events = append(w.events, "exact-container-absent-source-locked")
	w.mu.Unlock()
	return nil
}

func (w *isolatedReadyWitness) ConfirmRuntimeStopped(ctx context.Context, id string) (sandboxstore.Run, error) {
	if id != w.runID || isolatedReadySourceLock(w.auth, false) != nil {
		return sandboxstore.Run{}, errors.New("source not released before publication")
	}
	w.mu.Lock()
	removed := w.removed
	w.mu.Unlock()
	if !removed {
		return sandboxstore.Run{}, errors.New("publication preceded exact removal")
	}
	run, err := w.Store.ConfirmRuntimeStopped(ctx, id)
	if err == nil {
		w.mu.Lock()
		w.published = true
		w.events = append(w.events, "source-unlocked-before-publication")
		w.mu.Unlock()
	}
	return run, err
}

func isolatedReadySourceLock(path string, held bool) error {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if held {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil
		}
		if err == nil {
			_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		}
		return errors.New("source unexpectedly unlocked")
	}
	if err != nil {
		return err
	}
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
