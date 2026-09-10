//go:build linux && amd64 && codexintegration

package sandboxcontroller

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
	"github.com/shwdsun/harness-security-gateway/internal/agentdispatch"
	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/agentservice"
	"github.com/shwdsun/harness-security-gateway/internal/connectorhttp"
	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/providerfixture"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
)

type coreNativeConfig struct {
	Runtime       dockerruntime.SyntheticV3Config
	RunID, Case   string
	ProviderHTTPS bool
	Provider      *coreProviderConfig
}

type coreNativeResult struct {
	RunID, Case, ContainerRef, SyntheticPin, ScopeDigest, SourceDigest string
	CoreState, SandboxState, Output, ToolNonce, DeliveryID             string
	Creates, Attaches, StartCalls, RemovalFailures                     int
	DroppedStartReply, ExactStartReplay, NoPrematureDelivery           bool
	RemovedWhileHeld, ReleasedBeforePublication, Passed                bool
	Events                                                             []string
	Provider                                                           *providerfixture.OperationProof
}

// This opt-in fixture uses the real peer-authenticated Unix transports and
// existing synchronous dispatcher. It does not enable a target in sandboxd,
// run a platform connector, or claim distinct deployed service identities.
func TestCoreSyntheticV3Flow(t *testing.T) {
	if os.Getenv("HSG_CORE_NATIVE_INTEGRATION") != "1" {
		t.Skip("requires a fresh, frozen, explicitly scoped offline Docker fixture")
	}
	path := os.Getenv("HSG_CORE_NATIVE_FIXTURE")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || os.Geteuid() != 1000 {
		t.Fatal("invalid owned fixture identity")
	}
	data, err := os.ReadFile(path)
	var config coreNativeConfig
	if err != nil || strictjson.Decode(data, 64<<10, 12, &config) != nil {
		t.Fatal("invalid frozen fixture")
	}
	if config.Case != "replay-cleanup" && config.Case != "cancel-held-tool" && config.Case != "replaced-source" {
		t.Fatal("unsupported fixture case")
	}
	root := filepath.Dir(path)
	for _, owned := range []string{config.Runtime.WorkspaceRoot, config.Runtime.Credential.Root} {
		if !strings.HasPrefix(owned, root+"/") {
			t.Fatal("fixture write escaped owned root")
		}
	}
	providerFile := requireNativeProviderInitial(t, config)
	file, err := os.OpenFile(filepath.Join(root, "result.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal("fixture already used:", err)
	}
	defer file.Close()
	result := coreNativeResult{RunID: config.RunID, Case: config.Case}
	defer func() {
		result.Passed = !t.Failed()
		if err := json.NewEncoder(file).Encode(result); err != nil {
			t.Error("archive fixture result:", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	for _, name := range []string{"core", "sandbox", "connector", "other-connector"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal("fresh local state:", err)
		}
	}
	settings := coreNativeSettings(root, config.Runtime.Manifest)
	policy, err := agentpolicy.Compile(settings)
	if err != nil {
		t.Fatal("compile exact authority:", err)
	}
	endpoint, err := policy.Endpoint("synthetic")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := endpoint.SessionScope("operator", "private")
	if err != nil {
		t.Fatal(err)
	}
	result.ScopeDigest, err = sessionauth.Digest(scope)
	if err != nil {
		t.Fatal(err)
	}
	core, err := corestore.Open(ctx, settings.Database, corestore.Options{Admission: coreNativeAdmission(settings.Ingress)})
	if err != nil {
		t.Fatal("Core store:", err)
	}
	defer core.Close()
	c, db, witness, pin, source := newCoreNativeController(t, ctx, root, config, scope)
	defer db.Close()
	result.SyntheticPin, result.SourceDigest = pin, source
	defer func() {
		witness.blockRemoval.Store(false)
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if err := c.Close(cleanup); err != nil {
			t.Error("controller cleanup:", err)
		}
		witness.mu.Lock()
		defer witness.mu.Unlock()
		result.ContainerRef, result.Events = witness.ref, append([]string(nil), witness.events...)
		result.Creates, result.Attaches = witness.creates, witness.attaches
		result.RemovedWhileHeld, result.ReleasedBeforePublication = witness.removed, witness.released
		result.RemovalFailures = int(witness.removalFailures.Load())
	}()
	if config.Case == "replaced-source" {
		// Preserve the enrolled object as evidence. Replace only the fresh,
		// synthetic owned path, after enrollment and before Core admission.
		if err := os.Rename(witness.auth, filepath.Join(root, "retained-enrolled-auth.json")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(witness.auth, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		witness.record("enrolled-source-replaced-with-new-owned-object")
	}
	tap := &coreNativeStartTap{Controller: c}
	executionHandler, err := executionhttp.NewHandler(tap)
	if err != nil {
		t.Fatal(err)
	}
	drop := &coreNativeDropReply{next: executionHandler, store: db, runID: config.RunID, witness: witness}
	drop.enabled.Store(config.Case != "replaced-source")
	stopExecution := serveCoreNativeHTTP(t, settings.SandboxSocket, drop)
	defer stopExecution()
	execution, err := executionhttp.NewClient(settings.SandboxSocket, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := agentdispatch.New(core, execution, 60*time.Second, 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var allocations atomic.Int32
	clients := make(map[string]*connectorhttp.Client)
	for _, connector := range settings.Connectors {
		endpoint, err := policy.Endpoint(connector.ID)
		if err != nil {
			t.Fatal(err)
		}
		service, err := agentservice.NewWithRunIDSource(endpoint, 30*time.Second, core, func() (string, error) {
			if allocations.Add(1) != 1 {
				return "", errors.New("unexpected second Core Run allocation")
			}
			return config.RunID, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		handler, err := connectorhttp.NewHandler(service)
		if err != nil {
			t.Fatal(err)
		}
		stop := serveCoreNativeHTTP(t, connector.Socket, handler)
		defer stop()
		clients[connector.ID], err = connectorhttp.NewClient(connector.Socket, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
	}
	client := clients["synthetic"]
	event := connectorwire.InboundEventV1{EventID: "owned-event", ActorRef: "operator", ConversationRef: "private", MessageRef: "owned-message",
		OccurredAtUnixMS: time.Now().UnixMilli(), Content: connectorwire.InboundContentV1{Type: connectorwire.ContentTypeText, Text: "run the fixed offline native witness"}}
	for _, field := range []string{"actor", "conversation", "self", "connector"} {
		denied, sender := event, client
		denied.EventID = "denied-" + field
		switch field {
		case "actor":
			denied.ActorRef = "other-actor"
		case "conversation":
			denied.ConversationRef = "other-conversation"
		case "self":
			denied.ActorRef = "bot"
		case "connector":
			sender = clients["other"]
		}
		_, err := sender.Ingest(ctx, denied)
		requireCoreNativeRemoteError(t, err, connectorhttp.ErrorForbidden)
	}
	if allocations.Load() != 0 {
		t.Fatal("denied ingress allocated a Run")
	}
	receipt, err := client.Ingest(ctx, event)
	if err != nil || receipt.RunID != config.RunID || receipt.Disposition != connectorwire.InboundAccepted {
		t.Fatal("authorized ingress:", err, receipt)
	}
	requireCoreNativeReplay(t, ctx, client, event, config.RunID)
	conflict := event
	conflict.Content.Text = "different untrusted content"
	_, err = client.Ingest(ctx, conflict)
	requireCoreNativeRemoteError(t, err, connectorhttp.ErrorEventConflict)
	admitted, err := core.GetRun(ctx, config.RunID)
	if err != nil || admitted.BindingFingerprint != scope.BindingFingerprint || admitted.TargetRevision != scope.TargetRevision || admitted.PolicyRevision != policy.Revision() {
		t.Fatal("Core did not persist the compiled exact binding:", err)
	}
	witness.record("exact-connector-binding-admitted-one-core-run")
	requireCoreNativeNoDelivery(t, ctx, client)
	_, claimed, dispatchErr := engine.DispatchOne(ctx)
	if !claimed {
		t.Fatal("Core did not claim admitted Run:", dispatchErr)
	}
	if config.Case != "replaced-source" {
		var classified *agentdispatch.Error
		if !errors.As(dispatchErr, &classified) || classified.Code != agentdispatch.ErrorSandboxUnavailable || ctx.Err() != nil || !drop.dropped.Load() {
			t.Fatal("missing actual lost-response transport failure:", dispatchErr)
		}
		prepared, err := core.GetRun(ctx, config.RunID)
		if err != nil || prepared.State != corestore.RunDispatching || !prepared.StartPrepared {
			t.Fatal("lost response did not retain prepared dispatch:", err)
		}
		if _, err := db.GetRun(ctx, config.RunID); err != nil {
			t.Fatal("lost reply preceded durable sandbox admission:", err)
		}
		requireCoreNativeNoDelivery(t, ctx, client)
		awaitCoreNative(t, ctx, func() bool {
			run, err := db.GetRun(ctx, config.RunID)
			return err == nil && run.State == executionwire.RunStateRunning
		}, "runtime never reached Running after the lost response")
		advanced, err := engine.Advance(ctx, config.RunID)
		if err != nil || advanced.CoreState != corestore.RunRunning || advanced.Finished {
			t.Fatal("exact prepared Start re-offer did not recover running state:", err, advanced)
		}
		tap.mu.Lock()
		result.StartCalls = len(tap.fingerprints)
		result.ExactStartReplay = result.StartCalls == 2 && tap.fingerprints[0] == tap.fingerprints[1]
		tap.mu.Unlock()
		result.DroppedStartReply = drop.dropped.Load()
		if !result.ExactStartReplay {
			t.Fatal("response recovery changed the frozen Start or retried unexpectedly")
		}
		witness.record("lost-response-recovered-by-exact-prepared-start")
	} else if dispatchErr != nil {
		t.Fatal("replaced-source dispatch failed outside closed lifecycle:", dispatchErr)
	}

	if config.Case == "replay-cleanup" {
		awaitCoreNative(t, ctx, func() bool { return witness.removalFailures.Load() >= 2 }, "cleanup fault was not retried")
		run, err := db.GetRun(ctx, config.RunID)
		if err != nil || !run.TerminalPending || !run.CredentialLeaseHeld || run.Output != nil || run.RuntimeRef == nil {
			t.Fatal("cleanup fault did not retain unpublished terminal/occupancy:", err)
		}
		if err := nativeCredentialLock(witness.auth, true); err != nil {
			t.Fatal(err)
		}
		if _, err := witness.DockerRuntime.Inspect(ctx, *run.RuntimeRef); err != nil {
			t.Fatal("cleanup-fault container already absent:", err)
		}
		advanced, err := engine.Advance(ctx, config.RunID)
		if err != nil || advanced.Finished || advanced.CoreState != corestore.RunRunning {
			t.Fatal("cleanup fault prematurely terminalized Core:", err, advanced)
		}
		requireCoreNativeNoDelivery(t, ctx, client)
		result.NoPrematureDelivery = true
		witness.record("repeated-cleanup-unavailable-source-held-core-running-no-delivery")
		witness.blockRemoval.Store(false)
		c.signalReconcile()
	} else if config.Case == "cancel-held-tool" {
		workspace := filepath.Join(config.Runtime.WorkspaceRoot, config.Runtime.WorkspaceDirectory)
		awaitCoreNative(t, ctx, func() bool {
			result.ToolNonce = coreNativeHeldToolNonce(workspace)
			return result.ToolNonce != ""
		}, "native tool did not hold its witnessed lock")
		run, err := db.GetRun(ctx, config.RunID)
		if err != nil || run.State != executionwire.RunStateRunning || run.RuntimeRef == nil || run.TerminalPending {
			t.Fatal("tool witness was not a running Run:", err)
		}
		inspection, err := witness.DockerRuntime.Inspect(ctx, *run.RuntimeRef)
		if err != nil || inspection.State != dockerruntime.StateRunning || nativeCredentialLock(witness.auth, true) != nil || coreNativeHeldToolNonce(workspace) != result.ToolNonce {
			t.Fatal("native tool/runtime/source were not live immediately before cancellation:", err)
		}
		requireCoreNativeNoDelivery(t, ctx, client)
		result.NoPrematureDelivery = true
		witness.record("native-tool-nonce-and-held-lock-observed-before-local-cancel")
		result.Provider = requireNativeProviderProgress(t, config, result.ToolNonce, false)
		requireNativeProviderRefresh(t, config, providerFile)
		status, err := execution.CancelRun(ctx, executionwire.CancelRunRequest{RunID: config.RunID})
		if err != nil || (status.State != executionwire.RunStateCancelling && status.State != executionwire.RunStateCancelled) {
			t.Fatal("local execution cancellation:", err, status)
		}
	}
	var terminal agentdispatch.Result
	awaitCoreNative(t, ctx, func() bool {
		var err error
		terminal, err = engine.Advance(ctx, config.RunID)
		if err != nil {
			t.Fatal("Core terminal polling:", err)
		}
		return terminal.Finished
	}, "Core did not reach terminal after cleanup")
	run, err := db.GetRun(ctx, config.RunID)
	if err != nil || run.TerminalPending || run.CredentialLeaseHeld || run.RuntimeRef != nil || c.hasRetainedCredentials() {
		t.Fatal("terminal retained runtime/source authority:", err)
	}
	result.CoreState, result.SandboxState = string(terminal.CoreState), string(run.State)
	wantState, wantOutput, wantCreates := corestore.RunCompleted, "", 1
	switch config.Case {
	case "replay-cleanup":
		data, err := os.ReadFile(filepath.Join(config.Runtime.WorkspaceRoot, config.Runtime.WorkspaceDirectory, "native-command-proof.json"))
		var proof struct {
			Nonce, Directory string
			UID              int
			NoNewPrivs       string `json:"no_new_privs"`
			CapEff           string `json:"cap_eff"`
		}
		if err != nil || strictjson.Decode(data, 4096, 3, &proof) != nil || !coreNativeNonce(proof.Nonce) || proof.Directory != "/workspace" || proof.UID != 1000 || proof.NoNewPrivs != "1" || proof.CapEff != "0000000000000000" {
			t.Fatal("independent native command receipt mismatch:", err)
		}
		result.ToolNonce, wantOutput = proof.Nonce, "HSG_DONE_"+proof.Nonce
		result.Provider = requireNativeProviderProgress(t, config, result.ToolNonce, true)
		if run.Output == nil || run.Output.Text != wantOutput {
			t.Fatal("sandbox output did not match native command receipt")
		}
	case "cancel-held-tool":
		wantState, wantOutput = corestore.RunCancelled, "Run cancelled."
		if err := nativeCredentialLock(filepath.Join(config.Runtime.WorkspaceRoot, config.Runtime.WorkspaceDirectory, "probe.lock"), false); err != nil || run.Output != nil {
			t.Fatal("cancelled native tool lock survived or output was fabricated:", err)
		}
	case "replaced-source":
		wantState, wantCreates = corestore.RunFailed, 0
		wantOutput = "Run failed: execution was denied by policy."
		if run.Failure == nil || run.Failure.Code != executionwire.FailurePolicyDenied {
			t.Fatal("replacement did not fail closed:", run.Failure)
		}
	}
	if terminal.CoreState != wantState {
		t.Fatal("unexpected Core terminal:", terminal, run.Failure)
	}
	witness.mu.Lock()
	countsOK := witness.creates == wantCreates && witness.attaches == wantCreates && witness.released && (wantCreates == 0 || witness.removed)
	witness.mu.Unlock()
	if !countsOK || allocations.Load() != 1 || nativeCredentialLock(witness.auth, false) != nil {
		t.Fatal("Run replay/lifecycle witness mismatch")
	}
	if refs, err := witness.ListManaged(ctx); err != nil || len(refs) != 0 {
		t.Fatal("owned native inventory survived:", err)
	}
	if config.ProviderHTTPS {
		requireNativeProviderRefresh(t, config, providerFile)
	} else if data, err := os.ReadFile(witness.auth); err != nil || string(data) != "{}\n" {
		t.Fatal("synthetic auth contents changed")
	}
	requireCoreNativeNoDelivery(t, ctx, clients["other"])
	deliveries, err := client.Claim(ctx, connectorwire.DeliveryClaimV1{Limit: 2})
	if err != nil || len(deliveries.Deliveries) != 1 {
		t.Fatal("expected one exact-destination delivery:", err)
	}
	delivery := deliveries.Deliveries[0]
	if delivery.ConversationRef != event.ConversationRef || delivery.ReplyToRef != event.MessageRef || delivery.Content.MediaType != string(executionwire.MediaTypeTextPlain) {
		t.Fatal("delivery escaped original disclosure scope")
	}
	if delivery.Content.Text != wantOutput {
		t.Fatal("Core delivery changed verified outcome")
	}
	result.Output, result.DeliveryID = delivery.Content.Text, delivery.DeliveryID
	completion := connectorwire.DeliveryCompleteV1{DeliveryID: delivery.DeliveryID, LeaseToken: delivery.LeaseToken,
		Outcome: connectorwire.DeliveryDelivered, ProviderMessageRef: "owned-synthetic-delivery"}
	if err := client.Complete(ctx, completion); err != nil {
		t.Fatal("complete synthetic delivery:", err)
	}
	if err := client.Complete(ctx, completion); err != nil {
		t.Fatal("exact delivery completion replay:", err)
	}
	requireCoreNativeReplay(t, ctx, client, event, config.RunID)
	if _, err := engine.Advance(ctx, config.RunID); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := engine.DispatchOne(ctx); err != nil || claimed {
		t.Fatal("replay queued a second Run:", err)
	}
	requireCoreNativeNoDelivery(t, ctx, client)
	readback, err := sql.Open("sqlite", "file:"+settings.Database+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer readback.Close()
	var runs, receipts, outbox, delivered int
	if err := readback.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM runs), (SELECT count(*) FROM inbound_events),
		(SELECT count(*) FROM text_deliveries), (SELECT count(*) FROM text_deliveries WHERE state = 'delivered')`).Scan(&runs, &receipts, &outbox, &delivered); err != nil || runs != 1 || receipts != 1 || outbox != 1 || delivered != 1 {
		t.Fatal("independent Core persistence count mismatch:", err, runs, receipts, outbox, delivered)
	}
	witness.record("one-core-run-receipt-and-delivered-outbox-row-independent-readback")
	t.Logf("case=%s: exact ingress/replay -> real Unix execution -> native lifecycle -> one scoped Core delivery verified", config.Case)
}

func newCoreNativeController(t *testing.T, ctx context.Context, root string, config coreNativeConfig, scope sessionauth.Scope, decorate ...func(*coreNativeRuntime) Runtime) (*Controller, *sandboxstore.Store, *coreNativeRuntime, string, string) {
	t.Helper()
	native, pin, err := dockerruntime.NewSyntheticV3(config.Runtime)
	var provider *coreProviderFixture
	if config.Provider != nil {
		provider = newCoreProviderFixture(t, config)
		native, pin, err = dockerruntime.NewSyntheticProviderCanary(dockerruntime.ProviderCanaryConfig{Runtime: config.Runtime, ProviderRoot: config.Provider.Root, OwnerSHA256: config.Provider.OwnerSHA256}, provider.respond)
	}
	if err != nil {
		t.Fatal("synthetic runtime:", err)
	}
	adapter, err := NewDockerRuntime(native)
	if err != nil {
		t.Fatal(err)
	}
	if refs, err := adapter.ListManaged(ctx); err != nil || len(refs) != 0 {
		t.Fatal("fresh fixture inventory not empty:", err)
	}
	binding := config.Runtime.Credential
	auth := filepath.Join(binding.Root, binding.Directory, "auth.json")
	if data, err := os.ReadFile(auth); err != nil || (config.ProviderHTTPS && !providerfixture.AuthMatches(data, false)) || (!config.ProviderHTTPS && string(data) != "{}\n") {
		t.Fatal("requires fresh synthetic empty auth")
	}
	held, err := credentialsource.Hold(binding.Root, binding.Directory)
	if err != nil {
		t.Fatal("native enrollment hold:", err)
	}
	source, proof, proofErr := held.CaptureProof()
	closeErr := held.Close()
	if proofErr != nil || closeErr != nil {
		t.Fatal("native enrollment:", proofErr, closeErr)
	}
	scopeDigest, err := sessionauth.Digest(scope)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sandboxstore.Open(ctx, filepath.Join(root, "sandbox", "state.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	ready := false
	defer func() {
		if !ready {
			_ = db.Close()
		}
	}()
	if err := db.RegisterCredentialEnrollment(ctx, sandboxstore.CredentialGeneration{
		SlotRef: binding.SlotRef, Generation: int64(binding.Generation), SourceDigest: source,
		WorkspaceRef: binding.WorkspaceRef, AuthProfileRef: binding.AuthProfileRef, ScopeDigest: scopeDigest,
	}, proof); err != nil {
		t.Fatal(err)
	}
	manifest := config.Runtime.Manifest
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
		t.Fatal(err)
	}
	witness := &coreNativeRuntime{nativeHandoffWitness: &nativeHandoffWitness{DockerRuntime: adapter, store: db, runID: config.RunID, auth: auth}}
	if config.Case != "replaced-source" {
		witness.createBudget.Store(1)
	}
	witness.provider = provider
	witness.blockRemoval.Store(config.Case == "replay-cleanup")
	guarded := &credentialFaultStore{Store: db, confirm: witness.confirm}
	var runtime Runtime = witness
	if len(decorate) > 1 {
		t.Fatal("one fixed fixture runtime observer permitted")
	}
	if len(decorate) == 1 {
		runtime = decorate[0](witness)
	}
	c, err := New(ctx, durable, registry, guarded, runtime, WithCredentialBindings([]credentialsource.Binding{binding}),
		WithCleanupTimeout(15*time.Second), WithWaitGrace(2*time.Second), WithReconcileInterval(200*time.Millisecond))
	if err != nil {
		t.Fatal("controller:", err)
	}
	ready = true
	return c, db, witness, pin, source
}

type coreNativeRuntime struct {
	*nativeHandoffWitness
	blockRemoval    atomic.Bool
	removalFailures atomic.Int32
	createBudget    atomic.Int32
	provider        *coreProviderFixture
}

func (r *coreNativeRuntime) CreateWithCredential(ctx context.Context, id string, manifest targetmanifest.Definition, handoff *credentialsource.Handoff) (string, error) {
	if r.createBudget.Swap(0) != 1 {
		r.mu.Lock()
		r.creates++ // A refused attempt still fails the lifecycle count assertion.
		r.mu.Unlock()
		r.record("fixture-create-budget-exceeded-before-docker")
		return "", errors.New("owned fixture Create budget exhausted")
	}
	return r.nativeHandoffWitness.CreateWithCredential(ctx, id, manifest, handoff)
}

func (r *coreNativeRuntime) RemoveStopped(ctx context.Context, ref string) error {
	if r.blockRemoval.Load() {
		if r.removalFailures.Add(1) <= 2 {
			r.record("injected-remove-unavailable")
		}
		return errors.New("owned fixture removal unavailable")
	}
	return r.nativeHandoffWitness.RemoveStopped(ctx, ref)
}

type coreNativeStartTap struct {
	*Controller
	mu           sync.Mutex
	fingerprints []string
}

func (s *coreNativeStartTap) StartRun(ctx context.Context, request executionwire.StartRunRequest) (executionwire.RunStatus, error) {
	fingerprint, err := executionwire.StartRunFingerprint(request)
	if err != nil {
		return executionwire.RunStatus{}, err
	}
	s.mu.Lock()
	s.fingerprints = append(s.fingerprints, fingerprint)
	s.mu.Unlock()
	return s.Controller.StartRun(ctx, request)
}

// Discard exactly one successful Start reply after checking the durable Run.
// Closing the actual Unix HTTP connection produces a transport error at Core.
type coreNativeDropReply struct {
	next             http.Handler
	store            *sandboxstore.Store
	runID            string
	witness          *coreNativeRuntime
	enabled, dropped atomic.Bool
}

func (d *coreNativeDropReply) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != executionhttp.PathStartRun || !d.enabled.CompareAndSwap(true, false) {
		d.next.ServeHTTP(w, r)
		return
	}
	recorder := httptest.NewRecorder()
	d.next.ServeHTTP(recorder, r)
	_, err := d.store.GetRun(r.Context(), d.runID)
	if recorder.Code == http.StatusAccepted && err == nil {
		if hijacker, ok := w.(http.Hijacker); ok {
			connection, _, err := hijacker.Hijack()
			if err == nil {
				d.dropped.Store(true)
				d.witness.record("http-start-reply-dropped-after-durable-admission")
				_ = connection.Close()
				return
			}
		}
	}
	http.Error(w, "fixture reply fault was not established", http.StatusInternalServerError)
}

func serveCoreNativeHTTP(t *testing.T, path string, handler http.Handler) func() {
	t.Helper()
	listener, err := localhttp.Listen(path, localidentity.UID(os.Geteuid()))
	if err != nil {
		t.Fatal("peer-authenticated fixture listener:", err)
	}
	server := localhttp.NewServer(handler)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			_ = server.Close()
			t.Error("fixture listener shutdown:", err)
		}
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error("fixture listener:", err)
		}
	}
}

func requireCoreNativeRemoteError(t *testing.T, err error, code connectorhttp.ErrorCode) {
	t.Helper()
	var remote *connectorhttp.RemoteError
	if !errors.As(err, &remote) || remote.Code != string(code) {
		t.Fatalf("expected closed Connector error %s: %v", code, err)
	}
}

func requireCoreNativeReplay(t *testing.T, ctx context.Context, client *connectorhttp.Client, event connectorwire.InboundEventV1, id string) {
	t.Helper()
	receipt, err := client.Ingest(ctx, event)
	if err != nil || receipt.RunID != id || receipt.Disposition != connectorwire.InboundDuplicate {
		t.Fatal("exact ingress replay:", err, receipt)
	}
}

func requireCoreNativeNoDelivery(t *testing.T, ctx context.Context, client *connectorhttp.Client) {
	t.Helper()
	claim, err := client.Claim(ctx, connectorwire.DeliveryClaimV1{Limit: 2})
	if err != nil || len(claim.Deliveries) != 0 {
		t.Fatal("unexpected Core delivery:", err)
	}
}

func awaitCoreNative(t *testing.T, ctx context.Context, predicate func() bool, failure string) {
	t.Helper()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for !predicate() {
		select {
		case <-ctx.Done():
			t.Fatal(failure, ctx.Err())
		case <-ticker.C:
		}
	}
}

func coreNativeNonce(nonce string) bool {
	decoded, err := hex.DecodeString(nonce)
	return err == nil && len(decoded) == 16
}

func coreNativeHeldToolNonce(workspace string) string {
	data, err := os.ReadFile(filepath.Join(workspace, "probe.json"))
	var proof struct {
		Nonce, Outcome string
		Errno          int
	}
	if err != nil || strictjson.Decode(data, 4096, 3, &proof) != nil || !coreNativeNonce(proof.Nonce) || proof.Outcome != "held" || proof.Errno != 0 || nativeCredentialLock(filepath.Join(workspace, "probe.lock"), true) != nil {
		return ""
	}
	return proof.Nonce
}

func coreNativeSettings(root string, manifest targetmanifest.Definition) agentconfig.Config {
	return agentconfig.Config{Schema: agentconfig.SchemaV3, Database: filepath.Join(root, "core", "state.sqlite3"),
		SandboxSocket: filepath.Join(root, "sandbox", "execution.sock"), RunTimeoutSeconds: 90, DeliveryLeaseSeconds: 30, RunDispatchLeaseSeconds: 60,
		Ingress: agentconfig.Ingress{AcceptWindowSeconds: 300, ReceiptWindowSeconds: 3600, FutureSkewSeconds: 60,
			MaxReceiptsPerConnector: 128, MaxQueuedRunsPerConnector: 16, MaxNonTerminalRunsPerConnector: 32,
			MaxPendingDeliveriesPerConnector: 128, MaxRetainedInputBytesPerConnector: 4 << 20, MaxDatabasePages: 16384},
		Connectors: []agentconfig.Connector{
			{ID: "synthetic", Socket: filepath.Join(root, "connector", "ingress.sock"), PeerUID: localidentity.UID(os.Geteuid()), SelfActorRef: "bot"},
			{ID: "other", Socket: filepath.Join(root, "other-connector", "ingress.sock"), PeerUID: localidentity.UID(os.Geteuid()), SelfActorRef: "bot"},
		},
		Bindings: []agentconfig.Binding{{ID: "approved", ConnectorID: "synthetic", ActorRef: "operator", ConversationRef: "private",
			Target: agentconfig.TargetRef{ID: manifest.ID(), Revision: manifest.Revision()}}},
	}
}

func coreNativeAdmission(bounds agentconfig.Ingress) corestore.AdmissionOptions {
	return corestore.AdmissionOptions{AcceptWindow: time.Duration(bounds.AcceptWindowSeconds) * time.Second,
		ReceiptWindow: time.Duration(bounds.ReceiptWindowSeconds) * time.Second, FutureSkew: time.Duration(bounds.FutureSkewSeconds) * time.Second,
		MaxReceiptsPerConnector: bounds.MaxReceiptsPerConnector, MaxQueuedRunsPerConnector: bounds.MaxQueuedRunsPerConnector,
		MaxNonTerminalRunsPerConnector: bounds.MaxNonTerminalRunsPerConnector, MaxPendingDeliveriesPerConnector: bounds.MaxPendingDeliveriesPerConnector,
		MaxRetainedInputBytesPerConnector: bounds.MaxRetainedInputBytesPerConnector, MaxDatabasePages: bounds.MaxDatabasePages}
}
