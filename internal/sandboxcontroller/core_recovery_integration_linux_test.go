//go:build linux && amd64 && codexintegration

package sandboxcontroller

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
	"github.com/shwdsun/harness-security-gateway/internal/agentdispatch"
	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/agentservice"
	"github.com/shwdsun/harness-security-gateway/internal/codexprovider"
	"github.com/shwdsun/harness-security-gateway/internal/connectorhttp"
	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/hostepoch"
	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/processlock"
	"github.com/shwdsun/harness-security-gateway/internal/providerfixture"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
	"golang.org/x/sys/unix"
)

var errNativeRecoveryUnavailable = errors.New("owned recovery runtime observation unavailable")

type nativeRecoveryOwnerSummary struct {
	Phase, RunID, BootID, SyntheticPin, SourceDigest string
	PID, Creates, Attaches, CredentialOpens, Lookups int
	StaleSocketRemoved, StartupBlocked, Removed      bool
	PublishedAfterRemoval, Passed                    bool
}

type nativeRecoveryEvent struct {
	UTC, Operation, Ref string
	Retired             bool
}

type nativeRecoveryJournal struct {
	mu   sync.Mutex
	file *os.File
}

func (j *nativeRecoveryJournal) record(operation, ref string, retired bool) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := json.NewEncoder(j.file).Encode(nativeRecoveryEvent{time.Now().UTC().Format(time.RFC3339Nano), operation, ref, retired}); err != nil {
		return err
	}
	return j.file.Sync() // The crash point must not depend on buffered evidence.
}

// TestCoreNativeOwnerProcess is a fixed child role, not a new daemon or API.
// The actual process lock covers listener acquisition, DB mutation and cleanup.
func TestCoreNativeOwnerProcess(t *testing.T) {
	if os.Getenv("HSG_CORE_NATIVE_OWNER") != "1" {
		t.Skip("owned subprocess of the native recovery integration only")
	}
	config, root := readNativeRecoveryConfig(t)
	phase := os.Getenv("HSG_CORE_NATIVE_OWNER_PHASE")
	if phase != "initial" && phase != "blocked" && phase != "healthy" {
		t.Fatal("invalid owned child phase")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	settings := nativeRecoverySettings(root, config.Runtime.Manifest)
	owner, err := processlock.Acquire(settings.SandboxSocket + ".lock")
	if err != nil {
		t.Fatal("exclusive owner:", err)
	}
	defer owner.Close()
	file, err := os.OpenFile(filepath.Join(root, phase+".events.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	journal := &nativeRecoveryJournal{file: file}
	boot, err := hostepoch.Current()
	if err != nil {
		t.Fatal(err)
	}
	summary := nativeRecoveryOwnerSummary{Phase: phase, RunID: config.RunID, PID: os.Getpid(), BootID: boot}
	defer func() {
		summary.Passed = !t.Failed()
		writeNativeRecoveryRecord(t, filepath.Join(root, phase+".result.json"), summary)
	}()
	summary.StaleSocketRemoved, err = localhttp.RemoveStaleSocket(settings.SandboxSocket, 200*time.Millisecond)
	if err != nil {
		t.Fatal("safe stale listener reconciliation:", err)
	}
	listener, err := localhttp.Listen(settings.SandboxSocket, localidentity.UID(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	db, err := sandboxstore.Open(ctx, filepath.Join(root, "sandbox", "state.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	policy, err := agentpolicy.Compile(settings)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := policy.Endpoint("synthetic")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := endpoint.SessionScope("operator", "private")
	if err != nil {
		t.Fatal(err)
	}
	binding := config.Runtime.Credential
	if phase == "initial" {
		held, err := credentialsource.Hold(binding.Root, binding.Directory)
		if err != nil {
			t.Fatal("native enrollment:", err)
		}
		source, proof, proofErr := held.CaptureProof()
		closeErr := held.Close()
		if proofErr != nil || closeErr != nil {
			t.Fatal(proofErr, closeErr)
		}
		scopeDigest, err := sessionauth.Digest(scope)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.RegisterCredentialEnrollment(ctx, sandboxstore.CredentialGeneration{
			SlotRef: binding.SlotRef, Generation: int64(binding.Generation), SourceDigest: source,
			WorkspaceRef: binding.WorkspaceRef, AuthProfileRef: binding.AuthProfileRef, ScopeDigest: scopeDigest,
		}, proof); err != nil {
			t.Fatal(err)
		}
		summary.SourceDigest = source
	}
	native, pin, err := dockerruntime.NewSyntheticV3(config.Runtime)
	if config.Provider != nil {
		respond := func(context.Context, codexprovider.Request) (codexprovider.Response, error) {
			return codexprovider.Response{}, errors.New("recovery must never open a provider")
		}
		if phase == "initial" {
			respond = newCoreProviderFixture(t, config).respond
		}
		native, pin, err = dockerruntime.NewSyntheticProviderCanary(dockerruntime.ProviderCanaryConfig{Runtime: config.Runtime, ProviderRoot: config.Provider.Root, OwnerSHA256: config.Provider.OwnerSHA256}, respond)
	}
	if err != nil {
		t.Fatal("frozen runtime:", err)
	}
	summary.SyntheticPin = pin
	adapter, err := NewDockerRuntime(native)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := targetregistry.NewDefinitions([]targetmanifest.Definition{config.Runtime.Manifest})
	if err != nil {
		t.Fatal(err)
	}
	durable, err := sandboxservice.New(ctx, registry, db, nil, sandboxservice.WithAuthorityResolver(func(m targetmanifest.Definition, fingerprint string) (sandboxservice.ResolvedAuthority, error) {
		want, err := config.Runtime.Manifest.Fingerprint()
		if err != nil || fingerprint != want || m.ID() != config.Runtime.Manifest.ID() {
			return sandboxservice.ResolvedAuthority{}, errors.New("frozen synthetic authority mismatch")
		}
		return sandboxservice.ResolvedAuthority{RevisionPin: pin, RunnerState: sandboxstore.RunnerStateOwnership{Kind: targetmanifest.RunnerStateNone},
			Credential: &sandboxservice.ResolvedCredential{Ref: sandboxstore.CredentialRef{SlotRef: binding.SlotRef, Generation: int64(binding.Generation)}, Scope: scope}}, nil
	}))
	if err != nil {
		t.Fatal("reopen identical authority:", err)
	}
	readback := openNativeRecoveryReadback(t, filepath.Join(root, "sandbox", "state.sqlite3"))
	defer readback.Close()
	witness := &nativeRecoveryRuntime{DockerRuntime: adapter, store: db, readback: readback, journal: journal,
		config: config, root: root, phase: phase}
	if phase == "initial" {
		witness.createBudget.Store(1)
	}
	defer func() {
		summary.Creates, summary.Attaches = int(witness.creates.Load()), int(witness.attaches.Load())
		summary.CredentialOpens, summary.Lookups = int(witness.opens.Load()), int(witness.lookups.Load())
		summary.Removed, summary.PublishedAfterRemoval = witness.removed.Load(), witness.published.Load()
	}()
	guarded := &credentialFaultStore{Store: db, confirm: witness.confirm}
	c, err := New(ctx, durable, registry, guarded, witness, WithCredentialBindings([]credentialsource.Binding{binding}),
		WithCleanupTimeout(20*time.Second), WithWaitGrace(2*time.Second), WithReconcileInterval(200*time.Millisecond),
		func(o *options) error {
			o.openCredential = func(root, directory string) (credentialHandle, error) {
				witness.opens.Add(1)
				if phase != "initial" {
					return nil, errors.New("recovery tried to reacquire credential execution authority")
				}
				return openHeldCredential(root, directory)
			}
			return nil
		})
	if phase == "blocked" {
		if c != nil || !errors.Is(err, errNativeRecoveryUnavailable) {
			t.Fatal("recovery did not stop on unavailable observation:", err)
		}
		summary.StartupBlocked = true
		if err := journal.record("startup-refused-before-serving-workers", "", true); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err != nil {
		t.Fatal("owner startup:", err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 25*time.Second)
		defer stop()
		if err := c.Close(cleanup); err != nil {
			t.Error("owner cleanup:", err)
		}
	}()
	handler, err := executionhttp.NewHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	server := localhttp.NewServer(handler)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := server.Shutdown(cleanup); err != nil {
			_ = server.Close()
			t.Error(err)
		}
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	}()
	writeNativeRecoveryRecord(t, filepath.Join(root, phase+".ready.json"), summary)
	command, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || command != "stop\n" {
		t.Fatal("missing fixed owner shutdown command:", err)
	}
}

type nativeRecoveryRuntime struct {
	*DockerRuntime
	store        *sandboxstore.Store
	readback     *sql.DB
	journal      *nativeRecoveryJournal
	config       coreNativeConfig
	root, phase  string
	createBudget atomic.Int32
	creates      atomic.Int32
	attaches     atomic.Int32
	opens        atomic.Int32
	lookups      atomic.Int32
	removed      atomic.Bool
	published    atomic.Bool
}

func (r *nativeRecoveryRuntime) observe(ctx context.Context, operation, ref string) error {
	retired := false
	if r.phase != "initial" {
		binding := r.config.Runtime.Credential
		if err := r.readback.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM credential_revocations WHERE slot_ref=? AND generation=?)`, binding.SlotRef, binding.Generation).Scan(&retired); err != nil || !retired {
			return errors.New("runtime observation preceded occupied-generation retirement")
		}
	}
	return r.journal.record(operation, ref, retired)
}

func (r *nativeRecoveryRuntime) Create(context.Context, string, targetmanifest.Definition) (string, error) {
	r.creates.Add(1)
	return "", errors.New("credential-free Create forbidden in owned recovery fixture")
}

func (r *nativeRecoveryRuntime) CreateWithCredential(ctx context.Context, id string, m targetmanifest.Definition, h *credentialsource.Handoff) (string, error) {
	r.creates.Add(1)
	if r.createBudget.Swap(0) != 1 || r.phase != "initial" || id != r.config.RunID {
		return "", errors.New("owned recovery fixture Create budget exhausted")
	}
	if err := r.observe(ctx, "create-dispatched", ""); err != nil {
		return "", err
	}
	ref, err := r.DockerRuntime.CreateWithCredential(ctx, id, m, h)
	if err != nil {
		return "", err
	}
	if err := r.observe(ctx, "created-before-controller-bind", ref); err != nil {
		return "", err
	}
	if err := writeNativeRecoveryJSON(filepath.Join(r.root, "created.json"), struct{ Ref string }{ref}); err != nil {
		return "", err
	}
	if r.config.Case == "owner-unbound-created" {
		// Docker has returned; the controller has not received the reference.
		// Only this initial-owner process is killed at the frozen crash point.
		<-ctx.Done()
		return "", dockerruntime.ErrCreateUncertain
	}
	return ref, nil
}

func (r *nativeRecoveryRuntime) AttachStart(ctx context.Context, ref string) (Process, error) {
	r.attaches.Add(1)
	if r.phase != "initial" || r.config.Case != "owner-running" || r.attaches.Load() != 1 {
		return nil, errors.New("recovery or unbound fixture attempted Attach")
	}
	if err := r.observe(ctx, "attach-bootstrap", ref); err != nil {
		return nil, err
	}
	return r.DockerRuntime.AttachStart(ctx, ref)
}

func (r *nativeRecoveryRuntime) Inspect(ctx context.Context, ref string) (dockerruntime.Inspection, error) {
	if err := r.observe(ctx, "inspect", ref); err != nil {
		return dockerruntime.Inspection{}, err
	}
	if r.phase == "blocked" {
		return dockerruntime.Inspection{}, errNativeRecoveryUnavailable
	}
	return r.DockerRuntime.Inspect(ctx, ref)
}

func (r *nativeRecoveryRuntime) LookupIntent(ctx context.Context, id string, m targetmanifest.Definition) (string, bool, error) {
	r.lookups.Add(1)
	if err := r.observe(ctx, "lookup-intent", ""); err != nil {
		return "", false, err
	}
	ref, found, err := r.DockerRuntime.LookupIntent(ctx, id, m)
	if err == nil && found {
		err = r.observe(ctx, "lookup-found-exact-native-object", ref)
	}
	return ref, found, err
}

func (r *nativeRecoveryRuntime) ListManaged(ctx context.Context) ([]string, error) {
	if err := r.observe(ctx, "list-managed", ""); err != nil {
		return nil, err
	}
	return r.DockerRuntime.ListManaged(ctx)
}

func (r *nativeRecoveryRuntime) Stop(ctx context.Context, ref string) error {
	if err := r.observe(ctx, "stop", ref); err != nil {
		return err
	}
	return r.DockerRuntime.Stop(ctx, ref)
}

func (r *nativeRecoveryRuntime) Kill(ctx context.Context, ref string) error {
	if err := r.observe(ctx, "kill-container", ref); err != nil {
		return err
	}
	return r.DockerRuntime.Kill(ctx, ref)
}

func (r *nativeRecoveryRuntime) RemoveStopped(ctx context.Context, ref string) error {
	if err := r.observe(ctx, "remove-stopped", ref); err != nil {
		return err
	}
	run, err := r.store.GetRun(ctx, r.config.RunID)
	if err != nil || !run.CredentialLeaseHeld || !run.WorkspaceLockHeld || !run.TerminalPending || run.Output != nil {
		return errors.New("recovery removal lost durable cleanup ownership")
	}
	if err := r.DockerRuntime.RemoveStopped(ctx, ref); err != nil {
		return err
	}
	if _, err := r.DockerRuntime.Inspect(ctx, ref); !errors.Is(err, dockerruntime.ErrNotFound) {
		return errors.New("recovery exact removal unproved")
	}
	r.removed.Store(true)
	return r.observe(ctx, "exact-container-absent-occupancy-still-retained", ref)
}

func (r *nativeRecoveryRuntime) confirm(ctx context.Context, id string) (sandboxstore.Run, error) {
	if !r.removed.Load() || id != r.config.RunID {
		return sandboxstore.Run{}, errors.New("recovery publication preceded exact removal")
	}
	run, err := r.store.GetRun(ctx, id)
	if err != nil || !run.CredentialLeaseHeld || !run.WorkspaceLockHeld || !run.TerminalPending || run.RuntimeIntentPending || run.Output != nil {
		return sandboxstore.Run{}, errors.New("recovery publication lost staged ownership")
	}
	binding := r.config.Runtime.Credential
	if err := nativeCredentialLock(filepath.Join(binding.Root, binding.Directory, "auth.json"), false); err != nil {
		return sandboxstore.Run{}, err
	}
	if err := r.observe(ctx, "publish-after-exact-removal", ""); err != nil {
		return sandboxstore.Run{}, err
	}
	run, err = r.store.ConfirmRuntimeStopped(ctx, id)
	if err == nil {
		r.published.Store(true)
	}
	return run, err
}

type nativeRecoverySnapshot struct {
	State, Fingerprint, ScopeDigest, RuntimeRef, IntentBoot string
	Pending, Staged, Occupied, WriterLocked, OutputVisible  bool
	Revocations, Runs, LastSeq                              int
}

type nativeRecoveryResult struct {
	RunID, Case, ContainerRef, ToolNonce, BootID, Output, DeliveryID string
	KilledAt, RecoveredAt                                            string
	ContainerAfterDeath, ContainerAfterFailedRecovery                string
	BeforeDeath, AfterDeath, AfterFailedRecovery, Final              nativeRecoverySnapshot
	OldOwnerKilled, PhysicalLockLost, NoPrematureDelivery            bool
	NoCredentialReacquisition, NoRecreate, HostHelpersReaped, Passed bool
	InitialPID, RecoveryPID, HostHelpers                             int
	Provider                                                         *providerfixture.OperationProof
}

// Core stays alive while only its separately owned execution process dies.
// Each case has one real Create. The unbound case never starts that container.
func TestCoreSyntheticV3Recovery(t *testing.T) {
	if os.Getenv("HSG_CORE_NATIVE_RECOVERY") != "1" {
		t.Skip("requires a frozen, explicitly scoped native recovery fixture")
	}
	config, root := readNativeRecoveryConfig(t)
	providerFile := requireNativeProviderInitial(t, config)
	ctx, cancel := context.WithTimeout(context.Background(), 270*time.Second)
	defer cancel()
	// Linux Pdeathsig follows the creating thread. Keep that thread alive until
	// every owned subprocess has been joined, even if Go would retire workers.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// This temporary test process adopts/reaps only its recorded Docker child
	// helpers after the owner dies. It changes no host policy or other process.
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatal("owned helper reaper:", err)
	}
	result := nativeRecoveryResult{RunID: config.RunID, Case: config.Case}
	defer func() {
		result.Passed = !t.Failed()
		writeNativeRecoveryRecord(t, filepath.Join(root, "result.json"), result)
	}()
	for _, name := range []string{"core", "sandbox", "connector", "other-connector"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal("fresh owned state:", err)
		}
	}
	settings := nativeRecoverySettings(root, config.Runtime.Manifest)
	coreOwner, err := processlock.Acquire(settings.ProcessLockPath())
	if err != nil {
		t.Fatal(err)
	}
	defer coreOwner.Close()
	core, err := corestore.Open(ctx, settings.Database, corestore.Options{Admission: coreNativeAdmission(settings.Ingress)})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	policy, err := agentpolicy.Compile(settings)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := policy.Endpoint("synthetic")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := endpoint.SessionScope("operator", "private")
	if err != nil {
		t.Fatal(err)
	}
	scopeDigest, err := sessionauth.Digest(scope)
	if err != nil {
		t.Fatal(err)
	}
	service, err := agentservice.NewWithRunIDSource(endpoint, 30*time.Second, core, func() (string, error) { return config.RunID, nil })
	if err != nil {
		t.Fatal(err)
	}
	handler, err := connectorhttp.NewHandler(service)
	if err != nil {
		t.Fatal(err)
	}
	stopIngress := serveCoreNativeHTTP(t, settings.Connectors[0].Socket, handler)
	defer stopIngress()
	connector, err := connectorhttp.NewClient(settings.Connectors[0].Socket, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := executionhttp.NewClient(settings.SandboxSocket, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := agentdispatch.New(core, execution, 240*time.Second, 240*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	initial := startNativeRecoveryOwner(t, root, "initial")
	defer initial.cleanup(t)
	var ready nativeRecoveryOwnerSummary
	awaitNativeRecoveryRecord(t, ctx, filepath.Join(root, "initial.ready.json"), &ready)
	result.InitialPID, result.BootID = initial.command.Process.Pid, ready.BootID
	if ready.PID != result.InitialPID || ready.RunID != config.RunID || ready.SourceDigest == "" {
		t.Fatal("initial owner identity/enrollment mismatch")
	}
	lockPath := settings.SandboxSocket + ".lock"
	lockInfo, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if contender, err := processlock.Acquire(lockPath); !errors.Is(err, processlock.ErrLocked) {
		if contender != nil {
			_ = contender.Close()
		}
		t.Fatal("another owner acquired the live process lock:", err)
	}
	readback := openNativeRecoveryReadback(t, filepath.Join(root, "sandbox", "state.sqlite3"))
	defer readback.Close()
	event := connectorwire.InboundEventV1{EventID: "crash-event", ActorRef: "operator", ConversationRef: "private", MessageRef: "crash-message",
		OccurredAtUnixMS: time.Now().UnixMilli(), Content: connectorwire.InboundContentV1{Type: connectorwire.ContentTypeText, Text: "fixed offline owner recovery witness"}}
	receipt, err := connector.Ingest(ctx, event)
	if err != nil || receipt.RunID != config.RunID || receipt.Disposition != connectorwire.InboundAccepted {
		t.Fatal("Core admission:", err)
	}
	if _, claimed, err := engine.DispatchOne(ctx); err != nil || !claimed {
		t.Fatal("Core dispatch:", err)
	}
	var created struct{ Ref string }
	awaitNativeRecoveryRecord(t, ctx, filepath.Join(root, "created.json"), &created)
	if _, err := dockerruntime.ParseContainerRef(created.Ref); err != nil {
		t.Fatal("invalid exact created reference:", err)
	}
	result.ContainerRef = created.Ref
	workspace := filepath.Join(config.Runtime.WorkspaceRoot, config.Runtime.WorkspaceDirectory)
	if config.Case == "owner-running" {
		awaitCoreNative(t, ctx, func() bool {
			advanced, err := engine.Advance(ctx, config.RunID)
			if err != nil || advanced.Finished {
				t.Fatal("work ended before the owned crash point:", err, advanced)
			}
			result.ToolNonce = coreNativeHeldToolNonce(workspace)
			return advanced.CoreState == corestore.RunRunning && result.ToolNonce != ""
		}, "native tool never reached a live held-lock crash point")
		result.Provider = requireNativeProviderProgress(t, config, result.ToolNonce, false)
		requireNativeProviderRefresh(t, config, providerFile)
	}
	result.BeforeDeath = readNativeRecoverySnapshot(t, ctx, readback, config.RunID)
	before := result.BeforeDeath
	if !before.Occupied || !before.WriterLocked || before.Staged || before.OutputVisible || before.ScopeDigest != scopeDigest || before.Revocations != 0 {
		t.Fatal("missing exact live Run ownership before crash:", before)
	}
	state := nativeRecoveryContainerState(t, ctx, created.Ref)
	if config.Case == "owner-unbound-created" {
		boot, err := hostepoch.Current()
		if err != nil || !before.Pending || before.RuntimeRef != "" || before.IntentBoot != boot || boot != ready.BootID || state != "created" {
			t.Fatal("unbound Create crash point was not established:", err, before, state)
		}
	} else if before.RuntimeRef != created.Ref || before.Pending || state != "running" || coreNativeHeldToolNonce(workspace) != result.ToolNonce {
		t.Fatal("running crash point lost its exact native witness:", before, state)
	}
	auth := filepath.Join(config.Runtime.Credential.Root, config.Runtime.Credential.Directory, "auth.json")
	if err := nativeCredentialLock(auth, true); err != nil {
		t.Fatal("source was not physically held before owner death:", err)
	}
	helpers := captureNativeRecoveryHelpers(t, initial.command.Process.Pid)
	defer func() {
		for _, helper := range helpers {
			_ = unix.Close(helper.fd)
		}
	}()
	result.HostHelpers = len(helpers)
	if err := initial.command.Process.Kill(); err != nil {
		t.Fatal("kill exact owned controller:", err)
	}
	initial.wait(t, ctx, syscall.SIGKILL)
	result.OldOwnerKilled = true
	result.KilledAt = time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := os.Stat(filepath.Join(root, "initial.result.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("initial owner ran graceful finalizers instead of dying:", err)
	}
	if err := nativeCredentialLock(auth, false); err != nil {
		t.Fatal("process-owned source lock did not disappear on SIGKILL:", err)
	}
	result.PhysicalLockLost = true
	result.AfterDeath = readNativeRecoverySnapshot(t, ctx, readback, config.RunID)
	if result.AfterDeath != before {
		t.Fatal("SIGKILL changed durable ownership before recovery:", result.AfterDeath)
	}
	result.ContainerAfterDeath = nativeRecoveryContainerState(t, ctx, created.Ref)
	requireNativeRecoveryUnavailable(t, ctx, engine, connector, config.RunID)
	requireCoreNativeReplay(t, ctx, connector, event, config.RunID)

	blocked := startNativeRecoveryOwner(t, root, "blocked")
	defer blocked.cleanup(t)
	blocked.wait(t, ctx, 0)
	var failed nativeRecoveryOwnerSummary
	readNativeRecoveryRecord(t, filepath.Join(root, "blocked.result.json"), &failed)
	if !failed.Passed || !failed.StartupBlocked || !failed.StaleSocketRemoved || failed.Creates != 0 || failed.Attaches != 0 || failed.CredentialOpens != 0 || failed.Removed || failed.PublishedAfterRemoval {
		t.Fatal("failed startup widened or released authority:", failed)
	}
	result.AfterFailedRecovery = readNativeRecoverySnapshot(t, ctx, readback, config.RunID)
	held := result.AfterFailedRecovery
	if !held.Occupied || !held.WriterLocked || !held.Staged || held.OutputVisible || held.Revocations != 1 || held.RuntimeRef != before.RuntimeRef || held.Pending != before.Pending || held.IntentBoot != before.IntentBoot || held.Fingerprint != before.Fingerprint {
		t.Fatal("failed recovery did not retain original authority:", held)
	}
	result.ContainerAfterFailedRecovery = nativeRecoveryContainerState(t, ctx, created.Ref)
	requireNativeRecoveryUnavailable(t, ctx, engine, connector, config.RunID)
	result.NoPrematureDelivery = true
	if config.Case == "owner-unbound-created" && failed.Lookups != 1 {
		t.Fatal("failed recovery did not resolve the exact existing intent")
	}

	healthy := startNativeRecoveryOwner(t, root, "healthy")
	defer healthy.cleanup(t)
	var recovered nativeRecoveryOwnerSummary
	awaitNativeRecoveryRecord(t, ctx, filepath.Join(root, "healthy.ready.json"), &recovered)
	result.RecoveredAt = time.Now().UTC().Format(time.RFC3339Nano)
	result.RecoveryPID = healthy.command.Process.Pid
	if recovered.PID != result.RecoveryPID || recovered.PID == ready.PID || recovered.BootID != ready.BootID || recovered.SyntheticPin != ready.SyntheticPin {
		t.Fatal("recovery changed owner/boot/frozen runtime identity")
	}
	result.Final = readNativeRecoverySnapshot(t, ctx, readback, config.RunID)
	final := result.Final
	if final.State != string(executionwire.RunStateInterrupted) || final.Occupied || final.WriterLocked || final.Staged || final.Pending || final.RuntimeRef != "" || final.OutputVisible || final.Revocations != 1 || final.Fingerprint != before.Fingerprint || final.Runs != 1 {
		t.Fatal("healthy recovery failed to finish the original Run:", final)
	}
	if err := nativeCredentialLock(auth, false); err != nil {
		t.Fatal(err)
	}
	if config.Case == "owner-running" {
		if err := nativeCredentialLock(filepath.Join(workspace, "probe.lock"), false); err != nil {
			t.Fatal("native tool lock survived outer recovery cleanup:", err)
		}
	}
	requireNativeRecoveryAbsent(t, ctx, created.Ref, config.RunID)
	requireNativeProviderRefresh(t, config, providerFile)
	advanced, err := engine.Advance(ctx, config.RunID)
	if err != nil || !advanced.Finished || advanced.CoreState != corestore.RunInterrupted {
		t.Fatal("Core did not observe recovered interruption:", err, advanced)
	}
	fresh := executionwire.StartRunRequest{RunID: config.RunID + "-denied", TargetID: config.Runtime.Manifest.ID(), ExpectedRevision: config.Runtime.Manifest.Revision(),
		SessionScopeDigest: scopeDigest, Deadline: time.Now().UTC().Add(time.Minute).Truncate(time.Millisecond),
		Input: executionwire.TextInput{MediaType: executionwire.MediaTypeTextPlain, Text: "must remain denied after recovery"}}
	_, err = execution.StartRun(ctx, fresh)
	var remote *executionhttp.RemoteError
	// The dated 11:32–11:35 UTC witness returned generic internal. The later
	// feedback correction exposes a closed permanent denial for future runs.
	if !errors.As(err, &remote) || remote.StatusCode != http.StatusForbidden || remote.Code != string(executionhttp.ErrorPolicyDenied) {
		t.Fatal("retired generation authorized new work:", err)
	}
	if got := readNativeRecoverySnapshot(t, ctx, readback, config.RunID); got != final {
		t.Fatal("denied fresh work changed recovered ownership:", got)
	}
	claim, err := connector.Claim(ctx, connectorwire.DeliveryClaimV1{Limit: 2})
	if err != nil || len(claim.Deliveries) != 1 {
		t.Fatal("missing unique recovered Core delivery:", err)
	}
	delivery := claim.Deliveries[0]
	if delivery.ConversationRef != event.ConversationRef || delivery.ReplyToRef != event.MessageRef || delivery.Content.Text != "Run interrupted; it was not automatically retried." {
		t.Fatal("recovery reply escaped exact disclosure scope or retried work")
	}
	result.Output, result.DeliveryID = delivery.Content.Text, delivery.DeliveryID
	if err := connector.Complete(ctx, connectorwire.DeliveryCompleteV1{DeliveryID: delivery.DeliveryID, LeaseToken: delivery.LeaseToken,
		Outcome: connectorwire.DeliveryDelivered, ProviderMessageRef: "owned-recovery-delivery"}); err != nil {
		t.Fatal(err)
	}
	requireCoreNativeReplay(t, ctx, connector, event, config.RunID)
	if _, err := engine.Advance(ctx, config.RunID); err != nil {
		t.Fatal(err)
	}
	requireCoreNativeNoDelivery(t, ctx, connector)
	coreReadback := openNativeRecoveryReadback(t, settings.Database)
	defer coreReadback.Close()
	var runs, receipts, outbox int
	if err := coreReadback.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM runs),(SELECT count(*) FROM inbound_events),(SELECT count(*) FROM text_deliveries WHERE state='delivered')`).Scan(&runs, &receipts, &outbox); err != nil || runs != 1 || receipts != 1 || outbox != 1 {
		t.Fatal("recovery persistence counts:", err, runs, receipts, outbox)
	}
	healthy.stop(t, ctx)
	readNativeRecoveryRecord(t, filepath.Join(root, "healthy.result.json"), &recovered)
	if !recovered.Passed || recovered.Creates != 0 || recovered.Attaches != 0 || recovered.CredentialOpens != 0 || !recovered.Removed || !recovered.PublishedAfterRemoval {
		t.Fatal("recovery reacquired authority or bypassed cleanup:", recovered)
	}
	result.NoCredentialReacquisition, result.NoRecreate = true, true
	if config.Case == "owner-unbound-created" && recovered.Lookups != 1 {
		t.Fatal("healthy recovery did not use exact native intent lookup")
	}
	currentLock, err := os.Stat(lockPath)
	if err != nil || !os.SameFile(lockInfo, currentLock) {
		t.Fatal("owner lock inode replaced across restarts:", err)
	}
	for _, helper := range helpers {
		reapNativeRecoveryHelper(t, ctx, helper)
	}
	result.HostHelpersReaped = true
	t.Logf("case=%s: SIGKILL -> durable fences -> retirement before failed startup -> exact cleanup on healthy restart -> one scoped Core interruption", config.Case)
}

func readNativeRecoveryConfig(t *testing.T) (coreNativeConfig, string) {
	t.Helper()
	path := os.Getenv("HSG_CORE_NATIVE_FIXTURE")
	if os.Geteuid() != 1000 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Fatal("invalid owned recovery fixture identity")
	}
	data, err := os.ReadFile(path)
	var config coreNativeConfig
	if err != nil || strictjson.Decode(data, 64<<10, 12, &config) != nil ||
		(config.Case != "owner-running" && config.Case != "owner-unbound-created") {
		t.Fatal("invalid frozen recovery case")
	}
	root := filepath.Dir(path)
	for _, owned := range []string{config.Runtime.WorkspaceRoot, config.Runtime.Credential.Root} {
		if !strings.HasPrefix(owned, root+"/") {
			t.Fatal("recovery fixture write escaped owned root")
		}
	}
	return config, root
}

func nativeRecoverySettings(root string, manifest targetmanifest.Definition) agentconfig.Config {
	config := coreNativeSettings(root, manifest)
	config.RunTimeoutSeconds, config.RunDispatchLeaseSeconds = 240, 240
	return config
}

func openNativeRecoveryReadback(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	return db
}

func readNativeRecoverySnapshot(t *testing.T, ctx context.Context, db *sql.DB, id string) nativeRecoverySnapshot {
	t.Helper()
	var s nativeRecoverySnapshot
	err := db.QueryRowContext(ctx, `SELECT state,request_fingerprint,session_scope_digest,COALESCE(runtime_ref,''),COALESCE(runtime_intent_boot_id,''),
		runtime_intent_pending,EXISTS(SELECT 1 FROM staged_terminals st WHERE st.run_id=r.run_id),
		EXISTS(SELECT 1 FROM credential_occupancy co WHERE co.run_id=r.run_id),EXISTS(SELECT 1 FROM workspace_locks wl WHERE wl.run_id=r.run_id),
		output_text IS NOT NULL,(SELECT count(*) FROM credential_revocations),(SELECT count(*) FROM runs),last_event_seq
		FROM runs r WHERE run_id=?`, id).Scan(&s.State, &s.Fingerprint, &s.ScopeDigest, &s.RuntimeRef, &s.IntentBoot,
		&s.Pending, &s.Staged, &s.Occupied, &s.WriterLocked, &s.OutputVisible, &s.Revocations, &s.Runs, &s.LastSeq)
	if err != nil {
		t.Fatal("independent recovery readback:", err)
	}
	return s
}

func requireNativeRecoveryUnavailable(t *testing.T, ctx context.Context, engine *agentdispatch.Engine, connector *connectorhttp.Client, id string) {
	t.Helper()
	advanced, err := engine.Advance(ctx, id)
	var classified *agentdispatch.Error
	if !errors.As(err, &classified) || classified.Code != agentdispatch.ErrorSandboxUnavailable || advanced.Finished {
		t.Fatal("owner loss did not retain nonterminal Core state:", err, advanced)
	}
	requireCoreNativeNoDelivery(t, ctx, connector)
}

// Child markers are atomically published once in the new owned fixture. A
// partial file or a previous attempt cannot look like a ready replacement.
func writeNativeRecoveryJSON(path string, value any) error {
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("recovery evidence path already exists")
	}
	file, err := os.OpenFile(path+".writing", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encodeErr := json.NewEncoder(file).Encode(value)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(encodeErr, syncErr, closeErr); err != nil {
		return err
	}
	return os.Rename(path+".writing", path)
}

func writeNativeRecoveryRecord(t *testing.T, path string, value any) {
	t.Helper()
	if err := writeNativeRecoveryJSON(path, value); err != nil {
		t.Error("record recovery evidence:", err)
	}
}

func readNativeRecoveryRecord(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || strictjson.Decode(data, 32<<10, 8, value) != nil {
		t.Fatal("invalid recovery evidence:", path, err)
	}
}

func awaitNativeRecoveryRecord(t *testing.T, ctx context.Context, path string, value any) {
	t.Helper()
	awaitCoreNative(t, ctx, func() bool {
		_, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			if strings.HasSuffix(path, ".ready.json") {
				if _, ended := os.Stat(strings.TrimSuffix(path, ".ready.json") + ".result.json"); ended == nil {
					t.Fatal("owned process ended before readiness; inspect its retained result/log")
				}
			}
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		readNativeRecoveryRecord(t, path, value)
		return true
	}, "owned process did not reach its frozen boundary")
}

type nativeRecoveryChild struct {
	command  *exec.Cmd
	input    io.WriteCloser
	done     chan error
	finished bool
}

func startNativeRecoveryOwner(t *testing.T, root, phase string) *nativeRecoveryChild {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(root, phase+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(self, "-test.run=^TestCoreNativeOwnerProcess$", "-test.v", "-test.timeout=320s")
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C.UTF-8", "GORACE=halt_on_error=1",
		"HSG_CORE_NATIVE_OWNER=1", "HSG_CORE_NATIVE_OWNER_PHASE=" + phase, "HSG_CORE_NATIVE_FIXTURE=" + filepath.Join(root, "fixture.json")}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Stdout, command.Stderr = log, log
	input, err := command.StdinPipe()
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		_ = input.Close()
		_ = log.Close()
		t.Fatal(err)
	}
	child := &nativeRecoveryChild{command: command, input: input, done: make(chan error, 1)}
	go func() {
		err := command.Wait()
		closeErr := log.Close()
		child.done <- errors.Join(err, closeErr)
	}()
	return child
}

func (p *nativeRecoveryChild) wait(t *testing.T, ctx context.Context, signal syscall.Signal) {
	t.Helper()
	select {
	case err := <-p.done:
		p.finished = true
		_ = p.input.Close()
		if signal != 0 {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || !exit.Sys().(syscall.WaitStatus).Signaled() || exit.Sys().(syscall.WaitStatus).Signal() != signal {
				t.Fatal("owner did not die by the requested signal:", err)
			}
		} else if err != nil {
			t.Fatal("owned replacement process failed:", err)
		}
	case <-ctx.Done():
		t.Fatal("owned process did not exit:", ctx.Err())
	}
}

func (p *nativeRecoveryChild) stop(t *testing.T, ctx context.Context) {
	t.Helper()
	if _, err := io.WriteString(p.input, "stop\n"); err != nil {
		t.Fatal(err)
	}
	p.wait(t, ctx, 0)
}

func (p *nativeRecoveryChild) cleanup(t *testing.T) {
	if p.finished {
		return
	}
	_, _ = io.WriteString(p.input, "stop\n")
	_ = p.input.Close()
	select {
	case <-p.done:
		p.finished = true
	case <-time.After(35 * time.Second):
		_ = p.command.Process.Kill()
		<-p.done
		p.finished = true
		t.Error("owned process required forced fixture teardown")
	}
}

type nativeRecoveryHelper struct{ pid, fd int }

func captureNativeRecoveryHelpers(t *testing.T, ownerPID int) []nativeRecoveryHelper {
	t.Helper()
	paths, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", ownerPID))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[int]bool)
	var helpers []nativeRecoveryHelper
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range strings.Fields(string(data)) {
			pid, err := strconv.Atoi(field)
			if err != nil || pid <= 1 {
				t.Fatal("invalid owned child PID")
			}
			if seen[pid] {
				continue
			}
			seen[pid] = true
			fd, err := unix.PidfdOpen(pid, 0)
			if errors.Is(err, unix.ESRCH) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
			if err != nil || !strings.HasPrefix(string(argv), "/usr/bin/docker\x00--host\x00unix:///run/user/1000/docker.sock\x00") {
				_ = unix.Close(fd)
				t.Fatal("unrecognized owned helper process:", err)
			}
			helpers = append(helpers, nativeRecoveryHelper{pid, fd})
		}
	}
	return helpers
}

func reapNativeRecoveryHelper(t *testing.T, ctx context.Context, helper nativeRecoveryHelper) {
	t.Helper()
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	awaitCoreNative(t, bounded, func() bool {
		fds := []unix.PollFd{{Fd: int32(helper.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 0)
		if err != nil {
			t.Fatal(err)
		}
		return n == 1 && fds[0].Revents&unix.POLLIN != 0
	}, "owned Docker helper survived exact container cleanup")
	var status unix.WaitStatus
	if pid, err := unix.Wait4(helper.pid, &status, unix.WNOHANG, nil); err != nil || pid != helper.pid {
		t.Fatal("owned orphan helper was not reaped:", err)
	}
}

func nativeRecoveryDockerRead(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "/usr/bin/docker", append([]string{"--host", "unix:///run/user/1000/docker.sock"}, args...)...)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C"}
	data, err := command.Output()
	if err != nil || len(data) > 16<<10 {
		t.Fatal("independent read-only container observation:", err)
	}
	return string(data)
}

func nativeRecoveryContainerState(t *testing.T, ctx context.Context, ref string) string {
	t.Helper()
	data := nativeRecoveryDockerRead(t, ctx, "container", "inspect", "--format", `{"id":{{json .Id}},"state":{{json .State.Status}}}`, ref)
	var observed struct{ ID, State string }
	if strictjson.Decode([]byte(data), 4096, 3, &observed) != nil || observed.ID != ref {
		t.Fatal("independent container identity mismatch")
	}
	return observed.State
}

func requireNativeRecoveryAbsent(t *testing.T, ctx context.Context, ref, id string) {
	t.Helper()
	for _, filter := range []string{"id=" + ref, "label=io.harness-gateway.run-id=" + id} {
		if data := nativeRecoveryDockerRead(t, ctx, "container", "ls", "--all", "--no-trunc", "--filter", filter, "--format", "{{.ID}}"); strings.TrimSpace(data) != "" {
			t.Fatal("owned container survived recovery")
		}
	}
}
