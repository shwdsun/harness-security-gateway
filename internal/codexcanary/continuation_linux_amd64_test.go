//go:build linux && amd64 && codexintegration

package codexcanary

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentdispatch"
	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/agentservice"
	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/processlock"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
)

type continuationFixture struct {
	previous, next Config
	core           *corestore.Store
	sandbox        *sandboxstore.Store
	generation     sandboxstore.CredentialGeneration
	proof          credentialsource.Proof
}

func continuationMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newContinuationFixture(t *testing.T) continuationFixture {
	t.Helper()
	ctx := context.Background()
	f := continuationFixture{}
	f.previous = Config{Schema: "hsg-provider-canary/v1", StateRoot: t.TempDir(), RunID: "previous-canary"}
	for _, name := range []string{"core", "sandbox", "plans", "provider", "credentials/slot", "workspaces/project"} {
		continuationMust(t, os.MkdirAll(filepath.Join(f.previous.StateRoot, name), 0o700))
	}
	data, err := os.ReadFile("../../config/codex-tools-candidate.example.json")
	continuationMust(t, err)
	var example struct {
		Target targetmanifest.Definition `json:"target"`
	}
	continuationMust(t, json.Unmarshal(data, &example))
	runtime := &f.previous.Runtime.Runtime
	runtime.Manifest = example.Target
	runtime.WorkspaceRoot, runtime.WorkspaceDirectory = filepath.Join(f.previous.StateRoot, "workspaces"), "project"
	runtime.Credential = credentialsource.Binding{WorkspaceRef: example.Target.Common().WorkspaceRef,
		AuthProfileRef: example.Target.Common().AuthProfileRef, SlotRef: "dedicated", Generation: 1,
		Root: filepath.Join(f.previous.StateRoot, "credentials"), Directory: "slot"}
	f.previous.Runtime.ProviderRoot = filepath.Join(f.previous.StateRoot, "provider")
	data, err = json.Marshal(f.previous)
	continuationMust(t, err)
	continuationMust(t, os.WriteFile(configPath(f.previous), data, 0o600))
	_, hash, err := loadConfigFile(configPath(f.previous))
	continuationMust(t, err)
	f.next = f.previous
	f.next.Schema, f.next.RunID = "hsg-provider-canary/v2", "next-canary"
	manifest, _ := f.previous.Runtime.Runtime.Manifest.ManifestV2()
	manifest.Revision += "-next"
	f.next.Runtime.Runtime.Manifest, err = targetmanifest.FromV2(manifest)
	continuationMust(t, err)
	f.next.Runtime.Runtime.Credential.Generation = 2
	f.next.Continuation = &Continuation{PreviousRunID: f.previous.RunID, PreviousConfigSHA256: hash}
	f.sandbox, err = sandboxstore.Open(ctx, filepath.Join(f.previous.StateRoot, "sandbox", "state.sqlite3"))
	continuationMust(t, err)
	t.Cleanup(func() { continuationMust(t, f.sandbox.Close()) })
	f.core, err = corestore.Open(ctx, settings(f.previous).Database, corestore.Options{Admission: admission(settings(f.previous).Ingress)})
	continuationMust(t, err)
	t.Cleanup(func() { continuationMust(t, f.core.Close()) })
	scope, err := canaryScope(f.previous)
	continuationMust(t, err)
	scopeHash, err := sessionauth.Digest(scope)
	continuationMust(t, err)
	f.generation = sandboxstore.CredentialGeneration{SlotRef: "dedicated", Generation: 1, SourceDigest: strings.Repeat("b", 64),
		WorkspaceRef: runtime.Credential.WorkspaceRef, AuthProfileRef: runtime.Credential.AuthProfileRef, ScopeDigest: scopeHash}
	f.proof = credentialsource.Proof{Scheme: "linux-ext4-source/v1", RootObjectDigest: strings.Repeat("c", 64),
		SlotObjectDigest: strings.Repeat("d", 64), LocatorDigest: strings.Repeat("e", 64)}
	continuationMust(t, f.sandbox.RegisterCredentialEnrollment(ctx, f.generation, f.proof))
	service, engine := f.dispatch(t, f.previous)
	_ = service
	f.finish(t, engine, f.previous, false)
	history, err := inspectHistory(ctx, f.next, f.previous)
	continuationMust(t, err)
	f.next.Continuation = &history.pin
	return f
}

// Real admission/registration/dispatch/outbox APIs, with a synthetic source and
// a never-dispatched runtime. No native client, source file or provider exists.
func (f continuationFixture) dispatch(t *testing.T, c Config) (*agentservice.Service, *agentdispatch.Engine) {
	t.Helper()
	ctx := context.Background()
	registry, err := targetregistry.NewDefinitions([]targetmanifest.Definition{c.Runtime.Runtime.Manifest})
	continuationMust(t, err)
	scope, err := canaryScope(c)
	continuationMust(t, err)
	sandbox, err := sandboxservice.New(ctx, registry, f.sandbox, nil, sandboxservice.WithAuthorityResolver(
		func(m targetmanifest.Definition, pin string) (sandboxservice.ResolvedAuthority, error) {
			return sandboxservice.ResolvedAuthority{RevisionPin: pin, RunnerState: sandboxstore.RunnerStateOwnership{Kind: targetmanifest.RunnerStateNone},
				Credential: &sandboxservice.ResolvedCredential{Ref: sandboxstore.CredentialRef{SlotRef: "dedicated", Generation: int64(c.Runtime.Runtime.Credential.Generation)}, Scope: scope}}, nil
		}))
	continuationMust(t, err)
	policy, err := agentpolicy.Compile(settings(c))
	continuationMust(t, err)
	endpoint, err := policy.Endpoint(connectorID(c))
	continuationMust(t, err)
	service, err := agentservice.NewWithRunIDSource(endpoint, 30*time.Second, f.core, func() (string, error) { return c.RunID, nil })
	continuationMust(t, err)
	receipt, err := service.Ingest(ctx, canaryEvent(c))
	continuationMust(t, err)
	if receipt.RunID != c.RunID || receipt.Disposition != connectorwire.InboundAccepted {
		t.Fatal("wrong ingress identity")
	}
	engine, err := agentdispatch.New(f.core, sandbox, 60*time.Second, 300*time.Second)
	continuationMust(t, err)
	_, claimed, err := engine.DispatchOne(ctx)
	continuationMust(t, err)
	if !claimed {
		t.Fatal("no dispatch")
	}
	return service, engine
}

func (f continuationFixture) finish(t *testing.T, engine *agentdispatch.Engine, c Config, success bool) {
	t.Helper()
	ctx := context.Background()
	_, err := f.sandbox.AppendEvent(ctx, executionwire.RunEvent{RunID: c.RunID, Seq: 1, Type: executionwire.RunEventStarted}, nil)
	continuationMust(t, err)
	event := executionwire.RunEvent{RunID: c.RunID, Seq: 2, Type: executionwire.RunEventFailed,
		Failure: &executionwire.RunFailure{Code: executionwire.FailureRunnerFailed, Message: "synthetic failure"}}
	if success {
		event.Type, event.Failure = executionwire.RunEventCompleted, nil
		event.Result = &executionwire.RunResult{Output: executionwire.TextOutput{MediaType: executionwire.MediaTypeTextPlain, Text: "HSG_REAL_CANARY_OK"}}
	}
	_, err = f.sandbox.StageTerminal(ctx, event, nil)
	continuationMust(t, err)
	_, err = f.sandbox.ConfirmRuntimeStopped(ctx, c.RunID)
	continuationMust(t, err)
	advanced, err := engine.Advance(ctx, c.RunID)
	continuationMust(t, err)
	if !advanced.Finished {
		t.Fatal("no publication")
	}
}

func TestContinuationHistoryAndDelivery(t *testing.T) {
	ctx := context.Background()
	f := newContinuationFixture(t)
	previous, err := previousConfig(f.next)
	continuationMust(t, err)
	history, err := inspectHistory(ctx, f.next, previous)
	continuationMust(t, err)
	if history.pin != *f.next.Continuation || history.used || !pinnedContinuation(f.next) {
		t.Fatal("initial lineage pin")
	}
	before, err := f.sandbox.GetRun(ctx, f.previous.RunID)
	continuationMust(t, err)
	for range 2 {
		continuationMust(t, transitionEnrollment(ctx, f.next, f.sandbox, history, f.generation.SourceDigest, f.proof))
	}
	// Reopening the actual store preserves old proof and the new generation.
	continuationMust(t, f.sandbox.Close())
	f.sandbox, err = sandboxstore.Open(ctx, filepath.Join(f.next.StateRoot, "sandbox", "state.sqlite3"))
	continuationMust(t, err)
	defer f.sandbox.Close()
	history, err = inspectHistory(ctx, f.next, previous)
	continuationMust(t, err)
	if history.pin != *f.next.Continuation {
		t.Fatal("pre-admission progress changed recovery plan")
	}
	service, engine := f.dispatch(t, f.next)
	history, err = inspectHistory(ctx, f.next, previous)
	continuationMust(t, err)
	if !history.used || transitionEnrollment(ctx, f.next, f.sandbox, history, f.generation.SourceDigest, f.proof) == nil {
		t.Fatal("admitted plan could execute again")
	}
	f.finish(t, engine, f.next, true)
	delivery, err := service.Claim(ctx, connectorwire.DeliveryClaimV1{Limit: 1})
	continuationMust(t, err)
	if len(delivery.Deliveries) != 1 || delivery.Deliveries[0].ReplyToRef != f.next.RunID || delivery.Deliveries[0].Content.Text != "HSG_REAL_CANARY_OK" {
		t.Fatal("new connector claimed predecessor delivery")
	}
	after, err := f.sandbox.GetRun(ctx, f.previous.RunID)
	continuationMust(t, err)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("predecessor Run changed")
	}
	g, proof, err := f.sandbox.GetCredentialEnrollment(ctx, sandboxstore.CredentialRef{SlotRef: "dedicated", Generation: 1})
	continuationMust(t, err)
	if g != f.generation || proof != f.proof {
		t.Fatal("predecessor proof changed")
	}
	core, _, err := historyDB(ctx, settings(f.next).Database)
	continuationMust(t, err)
	defer core.Close()
	var pending int
	continuationMust(t, core.QueryRowContext(ctx, `SELECT count(*) FROM text_deliveries WHERE run_id=? AND state='pending' AND attempt_count=0`, f.previous.RunID).Scan(&pending))
	if pending != 1 {
		t.Fatal("predecessor outbox consumed")
	}
	if markerName(f.previous) == markerName(f.next) || connectorID(f.previous) == connectorID(f.next) {
		t.Fatal("shared test output identity")
	}
	// Old target authority remains present but cannot admit another Run.
	oldScope, _ := canaryScope(f.previous)
	digest, _ := sessionauth.Digest(oldScope)
	_, _, err = f.sandbox.RegisterStart(ctx, executionwire.StartRunRequest{RunID: "old-target-again", TargetID: oldScope.TargetID,
		ExpectedRevision: oldScope.TargetRevision, SessionScopeDigest: digest, Input: executionwire.TextInput{MediaType: executionwire.MediaTypeTextPlain, Text: "synthetic"}, Deadline: time.Now().Add(time.Minute)},
		oldScope.TargetRevision, g.WorkspaceRef, true, sandboxstore.SessionPolicy{Mode: targetmanifest.SessionNewOnly})
	if !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
		t.Fatal("old generation revived", err)
	}
}

func TestContinuationGuards(t *testing.T) {
	for _, mode := range []string{"history", "source", "proof", "generation", "target", "config-hash", "locator", "database", "foreign-core"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := newContinuationFixture(t)
			h, err := inspectHistory(ctx, f.next, f.previous)
			continuationMust(t, err)
			source, proof := f.generation.SourceDigest, f.proof
			switch mode {
			case "history":
				f.next.Continuation.HistorySHA256 = strings.Repeat("f", 64)
			case "source":
				source = strings.Repeat("f", 64)
			case "proof":
				proof.LocatorDigest = strings.Repeat("f", 64)
			case "generation":
				f.next.Runtime.Runtime.Credential.Generation++
			case "target":
				f.next.Runtime.Runtime.Manifest = f.previous.Runtime.Runtime.Manifest
			case "config-hash":
				f.next.Continuation.PreviousConfigSHA256 = strings.Repeat("f", 64)
			case "locator":
				f.next.Runtime.Runtime.Credential.Directory = "other"
			case "database":
				f.next.Continuation.Sandbox.Inode++
			case "foreign-core":
				policy, e := agentpolicy.Compile(settings(f.previous))
				continuationMust(t, e)
				endpoint, e := policy.Endpoint(connectorID(f.previous))
				continuationMust(t, e)
				service, e := agentservice.NewWithRunIDSource(endpoint, time.Second, f.core, func() (string, error) { return "foreign-core-run", nil })
				continuationMust(t, e)
				event := canaryEvent(f.previous)
				event.EventID, event.MessageRef = "foreign", "foreign"
				_, e = service.Ingest(ctx, event)
				continuationMust(t, e)
			}
			if mode == "generation" || mode == "target" || mode == "config-hash" || mode == "locator" {
				if _, err := previousConfig(f.next); err == nil {
					t.Fatal("widened continuation accepted")
				}
			} else if mode == "foreign-core" {
				if _, err := inspectHistory(ctx, f.next, f.previous); err == nil {
					t.Fatal("unresolved foreign Run ignored")
				}
			} else if transitionEnrollment(ctx, f.next, f.sandbox, h, source, proof) == nil {
				t.Fatal("mismatched source/history retired a generation")
			}
			db, _, err := historyDB(ctx, filepath.Join(f.next.StateRoot, "sandbox", "state.sqlite3"))
			continuationMust(t, err)
			defer db.Close()
			var count int
			continuationMust(t, db.QueryRowContext(ctx, `SELECT count(*) FROM credential_revocations`).Scan(&count))
			if count != 0 {
				t.Fatal("guard failure mutated authority")
			}
		})
	}
}

func TestContinuationInterruptedRegistration(t *testing.T) {
	ctx := context.Background()
	f := newContinuationFixture(t)
	h, err := inspectHistory(ctx, f.next, f.previous)
	continuationMust(t, err)
	// Fault at the second transaction: the first retirement must remain, then
	// an exact retry may finish enrollment without reviving generation 1.
	raw, err := sql.Open("sqlite", filepath.Join(f.next.StateRoot, "sandbox", "state.sqlite3"))
	continuationMust(t, err)
	defer raw.Close()
	_, err = raw.Exec(`CREATE TRIGGER canary_test_fault BEFORE INSERT ON credential_generations WHEN NEW.generation=2 BEGIN SELECT RAISE(ABORT,'synthetic enrollment fault'); END`)
	continuationMust(t, err)
	if transitionEnrollment(ctx, f.next, f.sandbox, h, f.generation.SourceDigest, f.proof) == nil {
		t.Fatal("fault not reached")
	}
	h, err = inspectHistory(ctx, f.next, f.previous)
	continuationMust(t, err)
	if h.pin != *f.next.Continuation || h.used {
		t.Fatal("partial transition lost exact plan")
	}
	var revoked int
	continuationMust(t, raw.QueryRow(`SELECT count(*) FROM credential_revocations WHERE generation=1`).Scan(&revoked))
	if revoked != 1 {
		t.Fatal("retirement disappeared")
	}
	_, err = raw.Exec(`DROP TRIGGER canary_test_fault`)
	continuationMust(t, err)
	continuationMust(t, transitionEnrollment(ctx, f.next, f.sandbox, h, f.generation.SourceDigest, f.proof))
}

func TestContinuationReadOnlyAndLock(t *testing.T) {
	ctx := context.Background()
	f := newContinuationFixture(t)
	lockPath := filepath.Join(f.next.StateRoot, "canary-owner.lock")
	_, err := inspectHistory(ctx, f.next, f.previous)
	continuationMust(t, err)
	if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preview created mutation lock")
	}
	db, _, err := historyDB(ctx, settings(f.next).Database)
	continuationMust(t, err)
	defer db.Close()
	if _, err := db.Exec(`DELETE FROM runs`); err == nil {
		t.Fatal("preview connection can write")
	}
	missing := filepath.Join(f.next.StateRoot, "core", "missing.sqlite3")
	if _, _, err := historyDB(ctx, missing); err == nil {
		t.Fatal("missing database adopted")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preview created database")
	}
	lock, err := processlock.Acquire(lockPath)
	continuationMust(t, err)
	defer lock.Close()
	if _, err := processlock.Acquire(lockPath); !errors.Is(err, processlock.ErrLocked) {
		t.Fatal("second mutation owner", err)
	}
	continuationMust(t, lock.Close())
	if _, err := os.Lstat(lockPath); err != nil {
		t.Fatal("persistent lock unlinked")
	}
}

func TestContinuationHotJournalRecovery(t *testing.T) {
	if path := os.Getenv("HSG_CANARY_TEST_JOURNAL"); path != "" {
		db, err := sql.Open("sqlite", path)
		continuationMust(t, err)
		_, err = db.Exec(`PRAGMA cache_size=1`)
		continuationMust(t, err)
		tx, err := db.Begin()
		continuationMust(t, err)
		_, err = tx.Exec(`INSERT INTO credential_revocations(slot_ref,generation) VALUES('dedicated',1)`)
		continuationMust(t, err)
		_, err = tx.Exec(`CREATE TABLE canary_journal_test(value BLOB)`)
		continuationMust(t, err)
		_, err = tx.Exec(`INSERT INTO canary_journal_test VALUES(zeroblob(262144))`)
		continuationMust(t, err)
		// Exit with a spilled, uncommitted rollback journal; no deferred Close.
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := newContinuationFixture(t)
	continuationMust(t, f.sandbox.Close())
	path := filepath.Join(f.next.StateRoot, "sandbox", "state.sqlite3")
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestContinuationHotJournalRecovery$")
	child.Env = append(os.Environ(), "HSG_CANARY_TEST_JOURNAL="+path)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("synthetic crash fixture: %v: %s", err, output)
	}
	info, err := os.Stat(path + "-journal")
	continuationMust(t, err)
	if info.Size() <= 512 {
		t.Fatal("no spilled rollback journal")
	}
	// A preview must refuse to recover, while an exact armed recovery can
	// verify the pinned objects before opening the writable stores.
	continuationMust(t, checkDatabaseIdentities(f.next))
	if _, err := inspectHistory(ctx, f.next, f.previous); err == nil {
		t.Fatal("read-only preview recovered a hot journal")
	}
	lock, err := processlock.Acquire(filepath.Join(f.next.StateRoot, "canary-owner.lock"))
	continuationMust(t, err)
	defer lock.Close()
	f.sandbox, err = sandboxstore.Open(ctx, path)
	continuationMust(t, err)
	defer f.sandbox.Close()
	h, err := inspectHistory(ctx, f.next, f.previous)
	continuationMust(t, err)
	if h.pin != *f.next.Continuation || h.used {
		t.Fatal("journal recovery changed the approved history")
	}
	db, _, err := historyDB(ctx, path)
	continuationMust(t, err)
	defer db.Close()
	var count int
	continuationMust(t, db.QueryRow(`SELECT count(*) FROM credential_revocations`).Scan(&count))
	if count != 0 {
		t.Fatal("recovery committed the interrupted enrollment")
	}
}

func TestContinuationRejectsReplacementAndRetirement(t *testing.T) {
	for _, mode := range []string{"replacement", "retired"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := newContinuationFixture(t)
			if mode == "replacement" {
				continuationMust(t, f.sandbox.Close())
				path := filepath.Join(f.next.StateRoot, "sandbox", "state.sqlite3")
				continuationMust(t, os.Rename(path, path+".preserved"))
				fresh, err := sandboxstore.Open(ctx, path)
				continuationMust(t, err)
				defer fresh.Close()
				if checkDatabaseIdentities(f.next) == nil {
					t.Fatal("fresh database adopted the previous identity")
				}
				if _, err := inspectHistory(ctx, f.next, f.previous); err == nil {
					t.Fatal("blank database accepted as continuation")
				}
				return
			}
			h, err := inspectHistory(ctx, f.next, f.previous)
			continuationMust(t, err)
			continuationMust(t, transitionEnrollment(ctx, f.next, f.sandbox, h, f.generation.SourceDigest, f.proof))
			continuationMust(t, f.sandbox.RevokeCredentialGeneration(ctx, sandboxstore.CredentialRef{SlotRef: "dedicated", Generation: 2}))
			h, err = inspectHistory(ctx, f.next, f.previous)
			continuationMust(t, err)
			if !h.retired || h.pin != *f.next.Continuation || transitionEnrollment(ctx, f.next, f.sandbox, h, f.generation.SourceDigest, f.proof) == nil {
				t.Fatal("retired child generation replayed")
			}
		})
	}
}
