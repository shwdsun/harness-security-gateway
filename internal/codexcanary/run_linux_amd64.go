//go:build linux && amd64 && codexintegration

package codexcanary

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
	"github.com/shwdsun/harness-security-gateway/internal/agentdispatch"
	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/agentservice"
	"github.com/shwdsun/harness-security-gateway/internal/codexprovider"
	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/processlock"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxcontroller"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
)

type Result struct {
	RunID               string                     `json:"run_id"`
	State               string                     `json:"state"`
	MarkerVerified      bool                       `json:"marker_verified"`
	CleanupComplete     bool                       `json:"cleanup_complete"`
	ProviderDiagnostics *codexprovider.Diagnostics `json:"provider_diagnostics"`
}

// Execute serves one fixed, in-process fake ingress using real Core admission,
// durable dispatch and the controller. It does not expose a listener or platform.
// The plan digest is an operator arming interlock, not a new authorization API.
func Execute(ctx context.Context, c Config, approved string, recovery bool) (result Result, returned error) {
	plan, native, err := preflight(c, recovery)
	if err != nil || approved == "" || plan.Digest != approved || (!recovery && plan.Status != "awaiting_operator") {
		return result, ErrPreparation
	}
	result.RunID = c.RunID
	// Registered before controller cleanup so the snapshot observes its final
	// join attempt. Recovery has no endpoint and therefore returns null.
	defer func() { result.ProviderDiagnostics = native.diagnostics() }()
	if ctx == nil || ctx.Err() != nil {
		return result, ErrPreparation
	}
	lock, err := processlock.Acquire(filepath.Join(c.StateRoot, "canary-owner.lock"))
	if err != nil {
		return result, ErrPreparation
	}
	defer func() {
		if lock.Close() != nil {
			result.CleanupComplete, returned = false, ErrExecution
		}
	}()
	if c.Continuation != nil && checkDatabaseIdentities(c) != nil {
		return result, ErrPreparation
	}
	settings := settings(c)
	policy, err := agentpolicy.Compile(settings)
	if err != nil {
		return result, ErrPreparation
	}
	endpoint, err := policy.Endpoint(connectorID(c))
	if err != nil {
		return result, ErrPreparation
	}
	scope, err := endpoint.SessionScope("operator", "local")
	if err != nil {
		return result, ErrPreparation
	}
	scopeDigest, err := sessionauth.Digest(scope)
	if err != nil {
		return result, ErrPreparation
	}
	for _, name := range []string{"core", "sandbox"} {
		path := filepath.Join(c.StateRoot, name)
		if recovery || c.Continuation != nil {
			if _, err := databaseIdentity(filepath.Join(path, "state.sqlite3")); err != nil {
				return result, ErrPreparation
			}
		} else if os.Mkdir(path, 0o700) != nil {
			return result, ErrPreparation
		}
	}
	db, err := sandboxstore.Open(ctx, filepath.Join(c.StateRoot, "sandbox", "state.sqlite3"))
	if err != nil {
		return result, ErrExecution
	}
	defer db.Close()
	core, err := corestore.Open(ctx, settings.Database, corestore.Options{Admission: admission(settings.Ingress)})
	if err != nil {
		return result, ErrExecution
	}
	defer core.Close()
	var history continuationHistory
	if c.Continuation != nil {
		previous, err := previousConfig(c)
		if err != nil || checkDatabaseIdentities(c) != nil {
			return result, ErrPreparation
		}
		history, err = inspectHistory(ctx, c, previous)
		if err != nil || history.pin != *c.Continuation || (!recovery && (history.used || history.retired)) {
			return result, ErrPreparation
		}
	}
	runtime, err := sandboxcontroller.NewDockerRuntime(native.runtime)
	if err != nil {
		return result, ErrExecution
	}
	if !recovery || (c.Continuation != nil && !history.used) {
		refs, err := runtime.ListManaged(ctx)
		if err != nil || len(refs) != 0 {
			return result, ErrExecution
		}
	}
	if recovery && c.Continuation != nil && !history.used {
		// No child admission in either retained store, no foreign obligations,
		// and no managed runtime. Preserve any partial enrollment preparation.
		result.State, result.CleanupComplete = "recovery_only", true
		return result, nil
	}
	binding := c.Runtime.Runtime.Credential
	if !recovery {
		held, err := credentialsource.Hold(binding.Root, binding.Directory)
		if err != nil {
			return result, ErrExecution
		}
		source, proof, proofErr := held.CaptureProof()
		closeErr := held.Close()
		if proofErr != nil || closeErr != nil {
			return result, ErrExecution
		}
		if c.Continuation != nil {
			err = transitionEnrollment(ctx, c, db, history, source, proof)
		} else {
			err = db.RegisterCredentialEnrollment(ctx, sandboxstore.CredentialGeneration{SlotRef: binding.SlotRef, Generation: int64(binding.Generation), SourceDigest: source, WorkspaceRef: binding.WorkspaceRef, AuthProfileRef: binding.AuthProfileRef, ScopeDigest: scopeDigest}, proof)
		}
		if err != nil {
			return result, ErrExecution
		}
	}
	manifest := c.Runtime.Runtime.Manifest
	registry, err := targetregistry.NewDefinitions([]targetmanifest.Definition{manifest})
	if err != nil {
		return result, ErrPreparation
	}
	durable, err := sandboxservice.New(ctx, registry, db, nil, sandboxservice.WithAuthorityResolver(func(m targetmanifest.Definition, fingerprint string) (sandboxservice.ResolvedAuthority, error) {
		want, _ := manifest.Fingerprint()
		if m.ID() != manifest.ID() || m.Revision() != manifest.Revision() || fingerprint != want {
			return sandboxservice.ResolvedAuthority{}, ErrPreparation
		}
		return sandboxservice.ResolvedAuthority{RevisionPin: plan.CandidatePin, RunnerState: sandboxstore.RunnerStateOwnership{Kind: targetmanifest.RunnerStateNone}, Credential: &sandboxservice.ResolvedCredential{Ref: sandboxstore.CredentialRef{SlotRef: binding.SlotRef, Generation: int64(binding.Generation)}, Scope: scope}}, nil
	}))
	if err != nil {
		return result, ErrExecution
	}
	controller, err := sandboxcontroller.New(ctx, durable, registry, db, runtime, sandboxcontroller.WithCredentialBindings([]credentialsource.Binding{binding}), sandboxcontroller.WithCleanupTimeout(20*time.Second), sandboxcontroller.WithReconcileInterval(200*time.Millisecond))
	if err != nil {
		return result, ErrExecution
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := controller.Close(cleanup)
		refs, inspectErr := runtime.ListManaged(cleanup)
		run, readErr := db.GetRun(cleanup, c.RunID)
		result.CleanupComplete = err == nil && inspectErr == nil && len(refs) == 0 && cleanupPublished(c.RunID, run, readErr)
		if !result.CleanupComplete {
			returned = ErrExecution
		}
	}()
	if recovery {
		result.State = "recovery_only"
		return result, nil
	}
	service, err := agentservice.NewWithRunIDSource(endpoint, 30*time.Second, core, func() (string, error) { return c.RunID, nil })
	if err != nil {
		return result, ErrPreparation
	}
	event := canaryEvent(c)
	receipt, err := service.Ingest(ctx, event)
	if err != nil || receipt.RunID != c.RunID || receipt.Disposition != connectorwire.InboundAccepted {
		return result, ErrExecution
	}
	engine, err := agentdispatch.New(core, controller, 60*time.Second, 300*time.Second)
	if err != nil {
		return result, ErrPreparation
	}
	if _, claimed, err := engine.DispatchOne(ctx); err != nil || !claimed {
		return result, ErrExecution
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		advanced, err := engine.Advance(ctx, c.RunID)
		if err != nil {
			return result, ErrExecution
		}
		if advanced.Finished {
			result.State = string(advanced.CoreState)
			break
		}
		select {
		case <-ctx.Done():
			return result, ErrExecution
		case <-ticker.C:
		}
	}
	run, err := db.GetRun(ctx, c.RunID)
	if err != nil || run.State != executionwire.RunStateCompleted || run.TerminalPending || run.CredentialLeaseHeld || run.RuntimeRef != nil {
		return result, ErrExecution
	}
	result.MarkerVerified = verifyMarker(c)
	delivery, err := service.Claim(ctx, connectorwire.DeliveryClaimV1{Limit: 1})
	if err != nil || len(delivery.Deliveries) != 1 || !result.MarkerVerified {
		return result, ErrExecution
	}
	text := delivery.Deliveries[0]
	if text.ConversationRef != "local" || text.ReplyToRef != event.MessageRef || strings.TrimSpace(text.Content.Text) != "HSG_REAL_CANARY_OK" {
		return result, ErrExecution
	}
	if service.Complete(ctx, connectorwire.DeliveryCompleteV1{DeliveryID: text.DeliveryID, LeaseToken: text.LeaseToken, Outcome: connectorwire.DeliveryDelivered, ProviderMessageRef: "local-canary-only"}) != nil {
		return result, ErrExecution
	}
	return result, nil
}

// Close deliberately permits durable recovery obligations to survive process
// exit. Container absence alone therefore cannot make the operator report green.
func cleanupPublished(runID string, run sandboxstore.Run, err error) bool {
	if errors.Is(err, sandboxstore.ErrNotFound) {
		return true
	} // No admission occurred.
	if err != nil || run.RunID != runID || run.TerminalAt == nil || run.TerminalPending || run.RuntimeIntentPending || run.RuntimeRef != nil || run.WorkspaceLockHeld || run.CredentialLeaseHeld {
		return false
	}
	switch run.State {
	case executionwire.RunStateCompleted, executionwire.RunStateCancelled, executionwire.RunStateFailed, executionwire.RunStateInterrupted:
		return true
	}
	return false
}

func verifyMarker(c Config) bool {
	f, err := os.OpenFile(filepath.Join(c.Runtime.Runtime.WorkspaceRoot, "project", markerName(c)), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1024 {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(f, 1025))
	return err == nil && strings.TrimSpace(string(data)) == c.RunID
}

func settings(c Config) agentconfig.Config {
	return agentconfig.Config{Schema: agentconfig.SchemaV3, Database: filepath.Join(c.StateRoot, "core", "state.sqlite3"), SandboxSocket: filepath.Join(c.StateRoot, "sandbox", "unused.sock"), RunTimeoutSeconds: 300, DeliveryLeaseSeconds: 30, RunDispatchLeaseSeconds: 60,
		Ingress:    agentconfig.Ingress{AcceptWindowSeconds: 300, ReceiptWindowSeconds: 3600, FutureSkewSeconds: 60, MaxReceiptsPerConnector: 128, MaxQueuedRunsPerConnector: 16, MaxNonTerminalRunsPerConnector: 32, MaxPendingDeliveriesPerConnector: 128, MaxRetainedInputBytesPerConnector: 4 << 20, MaxDatabasePages: 16384},
		Connectors: []agentconfig.Connector{{ID: connectorID(c), Socket: filepath.Join(c.StateRoot, "connector", "unused.sock"), PeerUID: localidentity.UID(os.Geteuid()), SelfActorRef: "bot"}},
		Bindings:   []agentconfig.Binding{{ID: "canary", ConnectorID: connectorID(c), ActorRef: "operator", ConversationRef: "local", Target: agentconfig.TargetRef{ID: c.Runtime.Runtime.Manifest.ID(), Revision: c.Runtime.Runtime.Manifest.Revision()}}}}
}

func canaryEvent(c Config) connectorwire.InboundEventV1 {
	eventID, messageRef := "one-canary-event", "one-canary-message"
	if c.Continuation != nil {
		eventID, messageRef = c.RunID, c.RunID
	}
	return connectorwire.InboundEventV1{EventID: eventID, ActorRef: "operator", ConversationRef: "local", MessageRef: messageRef,
		OccurredAtUnixMS: time.Now().UnixMilli(), Content: connectorwire.InboundContentV1{Type: connectorwire.ContentTypeText, Text: promptFor(c)}}
}

func admission(b agentconfig.Ingress) corestore.AdmissionOptions {
	return corestore.AdmissionOptions{AcceptWindow: time.Duration(b.AcceptWindowSeconds) * time.Second, ReceiptWindow: time.Duration(b.ReceiptWindowSeconds) * time.Second, FutureSkew: time.Duration(b.FutureSkewSeconds) * time.Second, MaxReceiptsPerConnector: b.MaxReceiptsPerConnector, MaxQueuedRunsPerConnector: b.MaxQueuedRunsPerConnector, MaxNonTerminalRunsPerConnector: b.MaxNonTerminalRunsPerConnector, MaxPendingDeliveriesPerConnector: b.MaxPendingDeliveriesPerConnector, MaxRetainedInputBytesPerConnector: b.MaxRetainedInputBytesPerConnector, MaxDatabasePages: b.MaxDatabasePages}
}

// Compile-time ownership checks: this candidate reuses the normal controller.
var _ agentdispatch.Sandbox = (*sandboxcontroller.Controller)(nil)
