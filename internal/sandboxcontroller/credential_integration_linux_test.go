//go:build linux && amd64 && codexintegration

package sandboxcontroller

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
	"golang.org/x/sys/unix"
)

// This local fixture composes native enrollment, the real service/controller,
// Docker attach/bootstrap, HRP bridge, V3 Runner and its offline Responses
// consumer. The inner fixture sends its terminal only after its native command
// assertions. This is neither a Connector/Core test nor provider approval.
func TestControllerSyntheticV3Handoff(t *testing.T) {
	if os.Getenv("HSG_CONTROLLER_HANDOFF_INTEGRATION") != "1" {
		t.Skip("requires an explicitly prepared, frozen local Docker fixture")
	}
	path := os.Getenv("HSG_CONTROLLER_HANDOFF_FIXTURE")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || os.Geteuid() == 0 {
		t.Fatal("invalid fixture path or operator identity")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Runtime dockerruntime.SyntheticV3Config
		RunID   string
	}
	if err := strictjson.Decode(data, 64<<10, 12, &config); err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(path)
	// All writable state must be new and owned by this fixture; tool artifacts
	// may refer to an independently frozen, existing read-only package.
	for _, name := range []string{config.Runtime.WorkspaceRoot, config.Runtime.Credential.Root} {
		if !strings.HasPrefix(name, root+"/") {
			t.Fatal("fixture write escaped its owned root")
		}
	}
	resultFile, err := os.OpenFile(filepath.Join(root, "result.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal("fixture already used or unwritable:", err)
	}
	defer resultFile.Close()
	var result struct {
		RunID, ContainerRef, State, Failure, Output, SyntheticPin string
		SourceDigest                                              string
		RemovedWhileHeld, ReleasedBeforePublication               bool
		Events                                                    []string
	}
	result.RunID = config.RunID
	defer func() { _ = json.NewEncoder(resultFile).Encode(result) }()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	native, pin, err := dockerruntime.NewSyntheticV3(config.Runtime)
	if err != nil {
		t.Fatal("synthetic runtime:", err)
	}
	result.SyntheticPin = pin
	adapter, err := NewDockerRuntime(native)
	if err != nil {
		t.Fatal(err)
	}
	if refs, err := adapter.ListManaged(ctx); err != nil || len(refs) != 0 {
		t.Fatal("fresh fixture inventory is not empty:", err)
	}
	binding := config.Runtime.Credential
	auth := filepath.Join(binding.Root, binding.Directory, "auth.json")
	if data, err := os.ReadFile(auth); err != nil || string(data) != "{}\n" {
		t.Fatal("fixture requires synthetic empty auth only")
	}
	held, err := credentialsource.Hold(binding.Root, binding.Directory)
	if err != nil {
		t.Fatal("enrollment hold:", err)
	}
	source, proof, proofErr := held.CaptureProof()
	closeErr := held.Close()
	if proofErr != nil || closeErr != nil {
		t.Fatal("native enrollment:", proofErr, closeErr)
	}
	result.SourceDigest = source
	manifest := config.Runtime.Manifest
	// This is a named synthetic local scope, not an invented Core approval.
	scope := sessionauth.Scope{BindingFingerprint: strings.Repeat("a", 64), ConnectorID: "synthetic-offline",
		ActorRef: "operator", ConversationRef: "owned-fixture", TargetID: manifest.ID(), TargetRevision: manifest.Revision()}
	scopeDigest, err := sessionauth.Digest(scope)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sandboxstore.Open(ctx, filepath.Join(root, "sandbox.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.RegisterCredentialEnrollment(ctx, sandboxstore.CredentialGeneration{
		SlotRef: binding.SlotRef, Generation: int64(binding.Generation), SourceDigest: source,
		WorkspaceRef: binding.WorkspaceRef, AuthProfileRef: binding.AuthProfileRef, ScopeDigest: scopeDigest,
	}, proof); err != nil {
		t.Fatal(err)
	}
	registry, err := targetregistry.NewDefinitions([]targetmanifest.Definition{manifest})
	if err != nil {
		t.Fatal(err)
	}
	durable, err := sandboxservice.New(ctx, registry, db, nil, sandboxservice.WithAuthorityResolver(func(m targetmanifest.Definition, fingerprint string) (sandboxservice.ResolvedAuthority, error) {
		want, err := manifest.Fingerprint()
		if err != nil || m.ID() != manifest.ID() || fingerprint != want {
			return sandboxservice.ResolvedAuthority{}, errors.New("synthetic authority mismatch")
		}
		return sandboxservice.ResolvedAuthority{RevisionPin: pin, RunnerState: sandboxstore.RunnerStateOwnership{Kind: targetmanifest.RunnerStateNone},
			Credential: &sandboxservice.ResolvedCredential{Ref: sandboxstore.CredentialRef{SlotRef: binding.SlotRef, Generation: int64(binding.Generation)}, Scope: scope}}, nil
	}))
	if err != nil {
		t.Fatal("service authority:", err)
	}
	witness := &nativeHandoffWitness{DockerRuntime: adapter, store: db, runID: config.RunID, auth: auth}
	guardedStore := &credentialFaultStore{Store: db, confirm: witness.confirm}
	c, err := New(ctx, durable, registry, guardedStore, witness,
		WithCredentialBindings([]credentialsource.Binding{binding}), WithCleanupTimeout(15*time.Second),
		WithWaitGrace(2*time.Second), WithReconcileInterval(200*time.Millisecond))
	if err != nil {
		t.Fatal("controller:", err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if err := c.Close(cleanup); err != nil {
			t.Error("controller cleanup:", err)
		}
		witness.mu.Lock()
		defer witness.mu.Unlock()
		result.ContainerRef, result.Events = witness.ref, append([]string(nil), witness.events...)
		result.RemovedWhileHeld, result.ReleasedBeforePublication = witness.removed, witness.released
	}()
	request := executionwire.StartRunRequest{RunID: config.RunID, TargetID: manifest.ID(), ExpectedRevision: manifest.Revision(),
		SessionScopeDigest: scopeDigest, Input: executionwire.TextInput{MediaType: executionwire.MediaTypeTextPlain, Text: "run the fixed offline native command witness"},
		Deadline: time.Now().UTC().Add(90 * time.Second).Truncate(time.Millisecond)}
	if _, err := c.StartRun(ctx, request); err != nil {
		t.Fatal("admission:", err)
	}
	// Receipt replay must not acquire a second source or dispatch another Create.
	if _, err := c.StartRun(ctx, request); err != nil {
		t.Fatal("exact replay:", err)
	}
	var run sandboxstore.Run
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		run, err = db.GetRun(ctx, config.RunID)
		if err != nil {
			t.Fatal(err)
		}
		if run.State == executionwire.RunStateCompleted || run.State == executionwire.RunStateFailed || run.State == executionwire.RunStateCancelled {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("controller did not terminate:", ctx.Err())
		case <-ticker.C:
		}
	}
	result.State = string(run.State)
	if run.Failure != nil {
		result.Failure = run.Failure.Message
	}
	if run.Output != nil {
		result.Output = run.Output.Text
	}
	if run.State != executionwire.RunStateCompleted || run.Output == nil || run.CredentialLeaseHeld || run.RuntimeRef != nil || run.TerminalPending {
		t.Fatalf("controller did not complete cleanly: state=%s failure=%v", run.State, run.Failure)
	}
	witness.mu.Lock()
	complete := witness.creates == 1 && witness.attaches == 1 && witness.removed && witness.released && witness.ref != ""
	ref := witness.ref
	witness.mu.Unlock()
	if !complete || c.hasRetainedCredentials() {
		t.Fatal("missing lifecycle witness or retained source")
	}
	if _, err := adapter.Inspect(ctx, ref); !errors.Is(err, dockerruntime.ErrNotFound) {
		t.Fatal("exact container survived:", err)
	}
	if err := nativeCredentialLock(auth, false); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(auth); err != nil || string(data) != "{}\n" {
		t.Fatal("synthetic source changed")
	}
	data, err = os.ReadFile(filepath.Join(config.Runtime.WorkspaceRoot, config.Runtime.WorkspaceDirectory, "native-command-proof.json"))
	var command struct {
		Nonce      string `json:"nonce"`
		Directory  string `json:"directory"`
		UID        int    `json:"uid"`
		NoNewPrivs string `json:"no_new_privs"`
		CapEff     string `json:"cap_eff"`
	}
	if err != nil || strictjson.Decode(data, 4096, 3, &command) != nil {
		t.Fatal("native command receipt:", err)
	}
	nonce, err := hex.DecodeString(command.Nonce)
	if err != nil || len(nonce) != 16 || run.Output.Text != "HSG_DONE_"+command.Nonce || command.Directory != "/workspace" || command.UID != 1000 || command.NoNewPrivs != "1" || command.CapEff != "0000000000000000" {
		t.Fatal("terminal did not match independent native command receipt")
	}
	t.Log("native enrollment -> one controller Create/Attach -> private receiver permit -> HRP/V3/native command -> remove while held -> close before publication: verified")
}

// These observers never replace a runtime operation or the bridge. They check
// physical file-lock and durable occupancy ordering at the real call boundary.
type nativeHandoffWitness struct {
	*DockerRuntime
	store             *sandboxstore.Store
	runID, auth       string
	mu                sync.Mutex
	ref               string
	creates, attaches int
	removed, released bool
	events            []string
}

func (w *nativeHandoffWitness) record(event string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, time.Now().UTC().Format(time.RFC3339Nano)+" "+event)
}

func (w *nativeHandoffWitness) Create(ctx context.Context, id string, m targetmanifest.Definition) (string, error) {
	return "", errors.New("synthetic credential run reached unguarded Create")
}

func (w *nativeHandoffWitness) CreateWithCredential(ctx context.Context, id string, m targetmanifest.Definition, h *credentialsource.Handoff) (string, error) {
	w.mu.Lock()
	w.creates++
	w.mu.Unlock()
	w.record("create-start")
	ref, err := w.DockerRuntime.CreateWithCredential(ctx, id, m, h)
	w.mu.Lock()
	w.ref = ref
	w.mu.Unlock()
	if err != nil {
		w.record("create-error: " + err.Error())
	} else {
		w.record("created: " + ref)
	}
	return ref, err
}

func (w *nativeHandoffWitness) AttachStart(ctx context.Context, ref string) (Process, error) {
	w.mu.Lock()
	w.attaches++
	w.mu.Unlock()
	w.record("attach-bootstrap-start")
	process, err := w.DockerRuntime.AttachStart(ctx, ref)
	if err != nil {
		w.record("attach-error: " + err.Error())
	} else {
		w.record("receiver-verified-permit-sent")
	}
	return process, err
}

func (w *nativeHandoffWitness) RemoveStopped(ctx context.Context, ref string) error {
	run, err := w.store.GetRun(ctx, w.runID)
	if err != nil || !run.TerminalPending || !run.CredentialLeaseHeld || run.Output != nil || run.RuntimeRef == nil || *run.RuntimeRef != ref {
		return errors.New("runtime removal lost staged authority")
	}
	if err := nativeCredentialLock(w.auth, true); err != nil {
		return err
	}
	if err := w.DockerRuntime.RemoveStopped(ctx, ref); err != nil {
		return err
	}
	if _, err := w.DockerRuntime.Inspect(ctx, ref); !errors.Is(err, dockerruntime.ErrNotFound) {
		return errors.New("exact removal not observed")
	}
	if err := nativeCredentialLock(w.auth, true); err != nil {
		return err
	}
	w.mu.Lock()
	w.removed = true
	w.mu.Unlock()
	w.record("exact-container-absent-source-still-locked")
	return nil
}

func (w *nativeHandoffWitness) confirm(ctx context.Context, id string) (sandboxstore.Run, error) {
	if err := nativeCredentialLock(w.auth, false); err != nil {
		return sandboxstore.Run{}, err
	}
	run, err := w.store.GetRun(ctx, id)
	if err != nil || id != w.runID || !run.TerminalPending || !run.CredentialLeaseHeld || run.Output != nil {
		return sandboxstore.Run{}, errors.New("publication boundary mismatch")
	}
	w.mu.Lock()
	ref, removed := w.ref, w.removed
	w.mu.Unlock()
	// Pre-create denial has no runtime. A successful run must have exact removal.
	if ref != "" && !removed {
		return sandboxstore.Run{}, errors.New("publication preceded removal")
	}
	w.mu.Lock()
	w.released = true
	w.mu.Unlock()
	w.record("source-unlocked-before-durable-publication")
	return w.store.ConfirmRuntimeStopped(ctx, id)
}

func nativeCredentialLock(path string, held bool) error {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if held {
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return errors.New("source lock released before cleanup")
		}
		return nil
	}
	if err != nil {
		return errors.New("source lock survived cleanup")
	}
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
