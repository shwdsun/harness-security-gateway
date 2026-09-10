package sandboxservice

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// Constructed local policy/proof only. No real provider resolver or credential.
func resolvedCredentialFixture(t *testing.T, target targetmanifest.Manifest) (ResolvedCredential, sandboxstore.CredentialGeneration, credentialsource.Proof) {
	t.Helper()
	config := agentconfig.Config{
		Schema: agentconfig.SchemaV3, Database: "/synthetic/core/state.sqlite3", SandboxSocket: "/synthetic/sandbox/execution.sock",
		RunTimeoutSeconds: 300, DeliveryLeaseSeconds: 30, RunDispatchLeaseSeconds: 30,
		Ingress: agentconfig.Ingress{AcceptWindowSeconds: 300, ReceiptWindowSeconds: 3600, FutureSkewSeconds: 60,
			MaxReceiptsPerConnector: 128, MaxQueuedRunsPerConnector: 16, MaxNonTerminalRunsPerConnector: 32,
			MaxPendingDeliveriesPerConnector: 128, MaxRetainedInputBytesPerConnector: 4 << 20, MaxDatabasePages: 16384},
		Connectors: []agentconfig.Connector{{ID: "synthetic", Socket: "/synthetic/connector/agentd.sock", PeerUID: 1000, SelfActorRef: "bot"}},
		Bindings: []agentconfig.Binding{{ID: "approved", ConnectorID: "synthetic", ActorRef: "operator", ConversationRef: "private",
			Target: agentconfig.TargetRef{ID: target.ID, Revision: target.Revision}}},
	}
	policy, err := agentpolicy.Compile(config)
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
	digest, err := sessionauth.Digest(scope)
	if err != nil {
		t.Fatal(err)
	}
	credential := ResolvedCredential{Ref: sandboxstore.CredentialRef{SlotRef: "dedicated", Generation: 1}, Scope: scope}
	g := sandboxstore.CredentialGeneration{SlotRef: "dedicated", Generation: 1, SourceDigest: strings.Repeat("b", 64),
		WorkspaceRef: target.WorkspaceRef, AuthProfileRef: target.AuthProfileRef, ScopeDigest: digest}
	proof := credentialsource.Proof{Scheme: credentialsource.EnrollmentScheme, RootObjectDigest: strings.Repeat("c", 64),
		SlotObjectDigest: strings.Repeat("d", 64), LocatorDigest: strings.Repeat("e", 64)}
	return credential, g, proof
}

func resolvedTestAuthority(m targetmanifest.Definition, fingerprint string) (ResolvedAuthority, error) {
	state, err := testRunnerStateOwnership(m)
	return ResolvedAuthority{RevisionPin: fingerprint, RunnerState: state}, err
}

func TestResolvedAuthorityFreezesScopeAndUsesStrictDurableRegistration(t *testing.T) {
	ctx := context.Background()
	a := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadOnly)
	b := manifest("target-b", "target-b-r1", "workspace-b", targetmanifest.WorkspaceReadOnly)
	registry, store := newRegistry(t, a, b), openStore(t)
	credential, generation, proof := resolvedCredentialFixture(t, a)
	approved := credential
	if err := store.RegisterCredentialEnrollment(ctx, generation, proof); err != nil {
		t.Fatal(err)
	}
	calls := 0
	resolve := func(m targetmanifest.Definition, fingerprint string) (ResolvedAuthority, error) {
		calls++
		result, err := resolvedTestAuthority(m, fingerprint)
		if m.ID() == a.ID {
			result.Credential = &credential
		} else {
			// A later callback must not change an earlier entry's owned values.
			credential.Ref.Generation = 999
			credential.Scope.TargetID = "mutated-target"
		}
		return result, err
	}
	service, err := New(ctx, registry, store, nil, WithAuthorityResolver(resolve), WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("resolver calls = %d", calls)
	}
	r := request("resolved-run", a.ID, a.Revision)
	r.SessionScopeDigest = generation.ScopeDigest
	wrong := r
	wrong.RunID, wrong.SessionScopeDigest = "wrong-scope", strings.Repeat("f", 64)
	if _, err := service.StartRun(ctx, wrong); !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
		t.Fatalf("wrong scope admitted: %v", err)
	} else {
		requireServiceCode(t, err, executionhttp.ErrorPolicyDenied)
	}
	if _, err := store.GetRun(ctx, wrong.RunID); !errors.Is(err, sandboxstore.ErrNotFound) {
		t.Fatalf("denied scope left a Run: %v", err)
	}
	first, err := service.StartRun(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	got, pins, err := store.GetRunCredentialEnrollment(ctx, r.RunID)
	if err != nil || got != generation || pins != proof {
		t.Fatalf("admitted Run did not join the resolved enrollment: %v", err)
	}
	if err := store.RevokeCredentialGeneration(ctx, approved.Ref); err != nil {
		t.Fatal(err)
	}
	replay, err := service.StartRun(ctx, r)
	if err != nil || replay != first || calls != 2 {
		t.Fatalf("replay changed receipt or reran resolver: %v, calls=%d", err, calls)
	}
	// Reconstructing the service re-registers exactly, without reviving history.
	resolveAgain := func(m targetmanifest.Definition, fingerprint string) (ResolvedAuthority, error) {
		result, err := resolvedTestAuthority(m, fingerprint)
		if m.ID() == a.ID {
			result.Credential = &approved
		}
		return result, err
	}
	restarted, err := New(ctx, registry, store, nil, WithAuthorityResolver(resolveAgain), WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := restarted.StartRun(ctx, r); err != nil || replay != first {
		t.Fatalf("reconstructed service lost exact replay: %v", err)
	}
	// No runtime was created in this synthetic test. Release the old Run's
	// occupancy so the next rejection specifically exercises revocation,
	// rather than the independent one-live-Run session fence.
	if _, err := store.StageTerminal(ctx, executionwire.RunEvent{RunID: r.RunID, Seq: 1, Type: executionwire.RunEventCancelled}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmRuntimeStopped(ctx, r.RunID); err != nil {
		t.Fatal(err)
	}
	r.RunID = "revoked-successor"
	if _, err := restarted.StartRun(ctx, r); !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
		t.Fatalf("historical registration revived admission: %v", err)
	} else {
		requireServiceCode(t, err, executionhttp.ErrorPolicyDenied)
	}
	changed := func(m targetmanifest.Definition, fingerprint string) (ResolvedAuthority, error) {
		result, err := resolveAgain(m, fingerprint)
		result.RevisionPin = strings.Repeat("f", 64)
		return result, err
	}
	if service, err := New(ctx, registry, store, nil, WithAuthorityResolver(changed)); service != nil || !errors.Is(err, sandboxstore.ErrConflict) {
		t.Fatalf("changed base authority reused revision: %v", err)
	}
}

func TestResolvedAuthorityRejectsScopeAndResolverFailuresBeforeRegistration(t *testing.T) {
	a := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadOnly)
	b := manifest("target-b", "target-b-r1", "workspace-b", targetmanifest.WorkspaceReadOnly)
	credential, _, _ := resolvedCredentialFixture(t, a)
	for _, failure := range []string{"target", "revision", "scope-shape", "empty-pin", "state-kind", "later-error"} {
		t.Run(failure, func(t *testing.T) {
			store := &fakeStore{}
			local := credential
			resolve := func(m targetmanifest.Definition, fingerprint string) (ResolvedAuthority, error) {
				result, err := resolvedTestAuthority(m, fingerprint)
				if m.ID() == a.ID {
					result.Credential = &local
					switch failure {
					case "target":
						local.Scope.TargetID = "wrong-target"
					case "revision":
						local.Scope.TargetRevision = "wrong-revision"
					case "scope-shape":
						local.Scope.BindingFingerprint = ""
					case "empty-pin":
						result.RevisionPin = ""
					case "state-kind":
						result.RunnerState.Kind = targetmanifest.RunnerStateNone
					}
				} else if failure == "later-error" {
					return ResolvedAuthority{}, errors.New("synthetic unresolved profile")
				}
				return result, err
			}
			service, err := New(context.Background(), newRegistry(t, a, b), store, nil, WithAuthorityResolver(resolve))
			if service != nil || err == nil || store.registerCalls != 0 {
				t.Fatalf("invalid resolution registered or fell back: %v, calls=%d", err, store.registerCalls)
			}
		})
	}
}

func TestResolvedAuthorityRequiresMatchingEnrollmentBeforeServiceExists(t *testing.T) {
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadOnly)
	for _, failure := range []string{"missing", "proofless", "workspace", "auth", "scope", "generation"} {
		t.Run(failure, func(t *testing.T) {
			ctx, store := context.Background(), openStore(t)
			credential, g, proof := resolvedCredentialFixture(t, target)
			switch failure {
			case "workspace":
				g.WorkspaceRef = "other-workspace"
			case "auth":
				g.AuthProfileRef = "other-auth"
			case "scope":
				g.ScopeDigest = strings.Repeat("f", 64)
			case "generation":
				credential.Ref.Generation++
			}
			var err error
			if failure == "proofless" {
				err = store.RegisterCredentialGeneration(ctx, g)
			} else if failure != "missing" {
				err = store.RegisterCredentialEnrollment(ctx, g, proof)
			}
			if err != nil {
				t.Fatal(err)
			}
			resolve := func(m targetmanifest.Definition, fingerprint string) (ResolvedAuthority, error) {
				result, err := resolvedTestAuthority(m, fingerprint)
				result.Credential = &credential
				return result, err
			}
			registry := newRegistry(t, target)
			if service, err := New(ctx, registry, store, nil, WithAuthorityResolver(resolve)); service != nil || !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
				t.Fatalf("unresolved credential produced service: %v", err)
			}
			// A different credential-free registration can use the same identity
			// only because the failed strict batch left no partial target/owner.
			if _, err := New(ctx, registry, store, testRunnerStateOwnership); err != nil {
				t.Fatalf("failed initialization retained partial authority: %v", err)
			}
		})
	}
}

func TestAuthorityResolverRejectsAmbiguousLegacyHooks(t *testing.T) {
	target := manifest("target-a", "target-a-r1", "workspace-a", targetmanifest.WorkspaceReadOnly)
	pin := func(_ targetmanifest.Definition, fingerprint string) (string, error) { return fingerprint, nil }
	for _, test := range []struct {
		state   RunnerStateOwnershipFunc
		options []Option
	}{
		{nil, []Option{WithAuthorityResolver(nil)}},
		{testRunnerStateOwnership, []Option{WithAuthorityResolver(resolvedTestAuthority)}},
		{nil, []Option{WithRevisionPin(pin), WithAuthorityResolver(resolvedTestAuthority)}},
		{nil, []Option{WithAuthorityResolver(resolvedTestAuthority), WithRevisionPin(pin)}},
		{nil, []Option{WithAuthorityResolver(resolvedTestAuthority), WithAuthorityResolver(resolvedTestAuthority)}},
	} {
		store := &fakeStore{}
		if service, err := New(context.Background(), newRegistry(t, target), store, test.state, test.options...); service != nil || err == nil || store.registerCalls != 0 {
			t.Fatalf("ambiguous resolution selected a fallback: %v", err)
		}
	}
}
