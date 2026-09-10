package agentdispatch

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
)

// Real service, Unix HTTP transport and both durable stores. Enrollment is
// synthetic; no runtime, credential file, provider or connector is involved.
func TestCredentialDenialHTTPFinishesCoreOnce(t *testing.T) {
	for _, reason := range []string{"revoked", "wrong-scope"} {
		t.Run(reason, func(t *testing.T) {
			ctx := context.Background()
			clock := &fakeClock{now: baseTime}
			core, corePath, _ := openCoreStore(t, clock, &tokenSequence{})
			run := ingestRun(t, core, "run_denied", "event_denied", sessionIntegrationTargetRevision)
			path := filepath.Join(t.TempDir(), "sandbox.sqlite3")
			store, err := sandboxstore.Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			target := sessionIntegrationManifest()
			target.WorkspaceMode = targetmanifest.WorkspaceReadWrite
			registry, err := targetregistry.New([]targetmanifest.Manifest{target})
			if err != nil {
				t.Fatal(err)
			}
			scope := sessionScopeForRun(run)
			if reason == "wrong-scope" {
				scope.BindingFingerprint = strings.Repeat("c", 64)
			}
			digest, err := sessionauth.Digest(scope)
			if err != nil {
				t.Fatal(err)
			}
			ref := sandboxstore.CredentialRef{SlotRef: "synthetic-denial", Generation: 1}
			generation := sandboxstore.CredentialGeneration{
				SlotRef: ref.SlotRef, Generation: ref.Generation, SourceDigest: strings.Repeat("b", 64),
				WorkspaceRef: target.WorkspaceRef, AuthProfileRef: target.AuthProfileRef, ScopeDigest: digest,
			}
			proof := credentialsource.Proof{Scheme: credentialsource.EnrollmentScheme,
				RootObjectDigest: strings.Repeat("c", 64), SlotObjectDigest: strings.Repeat("d", 64), LocatorDigest: strings.Repeat("e", 64)}
			if err := store.RegisterCredentialEnrollment(ctx, generation, proof); err != nil {
				t.Fatal(err)
			}
			service, err := sandboxservice.New(ctx, registry, store, nil,
				sandboxservice.WithClock(clock.Now),
				sandboxservice.WithAuthorityResolver(func(m targetmanifest.Definition, fingerprint string) (sandboxservice.ResolvedAuthority, error) {
					stateRef, _ := m.RunnerState().PersistentRef()
					return sandboxservice.ResolvedAuthority{RevisionPin: fingerprint,
						RunnerState: sandboxstore.RunnerStateOwnership{Kind: m.RunnerState().Kind(), Ref: stateRef, PathDigest: fingerprint, PathAbsent: true},
						Credential:  &sandboxservice.ResolvedCredential{Ref: ref, Scope: scope}}, nil
				}))
			if err != nil {
				t.Fatal(err)
			}
			if reason == "revoked" {
				if err := store.RevokeCredentialGeneration(ctx, ref); err != nil {
					t.Fatal(err)
				}
			}
			handler, err := executionhttp.NewHandler(service)
			if err != nil {
				t.Fatal(err)
			}
			// Keep Unix paths short regardless of test/subtest name length.
			socketRoot, err := os.MkdirTemp("", "hsg-denial-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(socketRoot)
			socket := filepath.Join(socketRoot, "execution.sock")
			listener, err := localhttp.Listen(socket, localidentity.UID(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			server := localhttp.NewServer(handler)
			done := make(chan error, 1)
			go func() { done <- server.Serve(listener) }()
			defer func() {
				_ = server.Close()
				if err := <-done; !errors.Is(err, http.ErrServerClosed) {
					t.Errorf("Serve: %v", err)
				}
			}()
			client, err := executionhttp.NewClient(socket, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			// The tracking wrapper delegates every request to the actual HTTP client.
			var startErr error
			sandbox := &fakeSandbox{getFn: client.GetRun,
				startFn: func(ctx context.Context, request executionwire.StartRunRequest) (executionwire.RunStatus, error) {
					status, err := client.StartRun(ctx, request)
					startErr = err
					return status, err
				}}
			engine := newEngine(t, core, sandbox, clock)
			result, claimed, err := engine.DispatchOne(ctx)
			if err != nil || !claimed || !result.Finished || result.CoreState != corestore.RunFailed {
				t.Fatalf("denial dispatch = %#v, claimed=%v, err=%v", result, claimed, err)
			}
			var remote *executionhttp.RemoteError
			if !errors.As(startErr, &remote) || remote.StatusCode != http.StatusForbidden || remote.Code != "policy_denied" {
				t.Fatalf("StartRun wire error = %v", startErr)
			}
			stored, err := core.GetRun(ctx, run.ID)
			if err != nil || stored.FailureCode == nil || *stored.FailureCode != corestore.RunFailurePolicyDenied {
				t.Fatalf("persisted denial = %#v, %v", stored, err)
			}
			starts := sandbox.Starts()
			if len(starts) != 1 || !starts[0].Deadline.After(clock.Now()) || len(sandbox.gets) != 1 {
				t.Fatal("denial waited for deadline, retried Start or skipped absence proof")
			}
			if replay := ingestRun(t, core, run.ID, run.EventID, run.TargetRevision); replay.ID != run.ID {
				t.Fatal("ingress replay created a new Run")
			}
			for attempt := 0; attempt < 2; attempt++ {
				if result, err := engine.Advance(ctx, run.ID); err != nil || !result.Finished {
					t.Fatalf("terminal replay = %#v, %v", result, err)
				}
			}
			if _, claimed, err := engine.DispatchOne(ctx); err != nil || claimed || sandbox.StartCount() != 1 {
				t.Fatal("terminal denial was dispatched again")
			}
			delivery := claimOneDelivery(t, core)
			if delivery.Text != "Run failed: execution was denied by policy." || delivery.RunID != run.ID || delivery.ConnectorID != run.ConnectorID || delivery.ConversationRef != run.ConversationRef {
				t.Fatalf("denial delivery = %#v", delivery)
			}
			// Independent readback also detects rejected-transaction residue.
			for _, check := range []struct {
				path, query string
				want        int
			}{
				{path, `SELECT (SELECT COUNT(*) FROM runs) + (SELECT COUNT(*) FROM credential_occupancy) + (SELECT COUNT(*) FROM workspace_locks)`, 0},
				{corePath, `SELECT COUNT(*) FROM text_deliveries`, 1},
				{corePath, `SELECT COUNT(*) FROM runs`, 1},
			} {
				db, err := sql.Open("sqlite", check.path+"?mode=ro")
				if err != nil {
					t.Fatal(err)
				}
				var count int
				err = db.QueryRowContext(ctx, check.query).Scan(&count)
				_ = db.Close()
				if err != nil || count != check.want {
					t.Fatalf("readback count=%d want=%d err=%v", count, check.want, err)
				}
			}
		})
	}
}
