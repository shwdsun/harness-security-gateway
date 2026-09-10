package sandboxstore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Every source identity here is synthetic resolver evidence. These tests do
// not establish that different host paths resolve to the same physical source.
func credentialFixture(t *testing.T, s *Store, target string) (CredentialGeneration, executionwire.StartRunRequest) {
	t.Helper()
	r := startRequest("credential-run", "synthetic input")
	r.TargetID, r.ExpectedRevision = target, target+"-r1"
	g := CredentialGeneration{SlotRef: "dedicated", Generation: 1, SourceDigest: strings.Repeat("b", 64), WorkspaceRef: "workspace", AuthProfileRef: "test.auth", ScopeDigest: r.SessionScopeDigest}
	if err := s.RegisterCredentialGeneration(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	bindCredentialTarget(t, s, r, g)
	return g, r
}

func bindCredentialTarget(t *testing.T, s *Store, r executionwire.StartRunRequest, g CredentialGeneration) {
	t.Helper()
	if err := s.RegisterTargetAuthorities(context.Background(), []TargetAuthority{{
		TargetID: r.TargetID, TargetRevision: r.ExpectedRevision, RevisionPin: strings.Repeat("c", 64),
		RunnerStateKind: targetmanifest.RunnerStateNone, Credential: &CredentialRef{g.SlotRef, g.Generation},
	}}); err != nil {
		t.Fatal(err)
	}
}

func admitCredential(s *Store, r executionwire.StartRunRequest, writable bool) (Run, bool, error) {
	return s.RegisterStart(context.Background(), r, r.ExpectedRevision, "workspace", writable, SessionPolicy{Mode: targetmanifest.SessionNewOnly})
}

func TestCredentialGenerationHistoryAndTargetBindingAreImmutable(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	g, r := credentialFixture(t, s, "credential-target")
	for _, changed := range []CredentialGeneration{
		{g.SlotRef, g.Generation, strings.Repeat("d", 64), g.WorkspaceRef, g.AuthProfileRef, g.ScopeDigest},
		{g.SlotRef, g.Generation, g.SourceDigest, g.WorkspaceRef, g.AuthProfileRef, strings.Repeat("d", 64)},
	} {
		if err := s.RegisterCredentialGeneration(ctx, changed); !errors.Is(err, ErrConflict) {
			t.Fatalf("changed generation: %v", err)
		}
	}
	alias := g
	alias.SlotRef = "other-logical-name"
	if err := s.RegisterCredentialGeneration(ctx, alias); !errors.Is(err, ErrConflict) {
		t.Fatalf("source reassignment: %v", err)
	}
	next := g
	next.Generation = 2
	if err := s.RegisterCredentialGeneration(ctx, next); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("unretired rotation: %v", err)
	}
	if err := s.RevokeCredentialGeneration(ctx, CredentialRef{g.SlotRef, g.Generation}); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeCredentialGeneration(ctx, CredentialRef{g.SlotRef, g.Generation}); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterCredentialGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	if _, _, err := admitCredential(s, r, false); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("revoked history reactivated: %v", err)
	}
	if err := s.RegisterCredentialGeneration(ctx, next); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterTargetAuthorities(ctx, []TargetAuthority{{TargetID: r.TargetID, TargetRevision: r.ExpectedRevision,
		RevisionPin: strings.Repeat("c", 64), RunnerStateKind: targetmanifest.RunnerStateNone, Credential: &CredentialRef{g.SlotRef, 2}}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("target binding mutation: %v", err)
	}
	for _, q := range []string{
		`UPDATE credential_generations SET scope_digest='` + strings.Repeat("e", 64) + `'`,
		`DELETE FROM credential_generations`, `DELETE FROM credential_sources`, `DELETE FROM credential_revocations`,
		`UPDATE target_revisions SET credential_kind='none' WHERE credential_kind='bound'`,
		`DELETE FROM target_credentials`,
		`INSERT OR REPLACE INTO credential_sources(source_digest,slot_ref) VALUES ('` + g.SourceDigest + `','foreign')`,
	} {
		if _, err := s.db.Exec(q); err == nil {
			t.Fatalf("history mutation accepted: %s", q)
		}
	}
}

func TestCredentialOccupancySerializesCanonicalSourceAcrossTargets(t *testing.T) {
	s, path := openTestStore(t)
	g, a := credentialFixture(t, s, "credential-a")
	b := a
	b.RunID = "credential-run-b"
	b.TargetID = "credential-b"
	b.ExpectedRevision = "credential-b-r1"
	// Deliberately give two synthetic resolver targets the same frozen scope
	// and source, so the credential fence (not the per-target scope fence) wins.
	bindCredentialTarget(t, s, b, g)
	otherStore, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer otherStore.Close()
	start := make(chan struct{})
	type admissionResult struct {
		store   *Store
		request executionwire.StartRunRequest
		err     error
	}
	results := make(chan admissionResult, 2)
	var wg sync.WaitGroup
	for _, attempt := range []struct {
		store   *Store
		request executionwire.StartRunRequest
	}{{s, a}, {otherStore, b}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := admitCredential(attempt.store, attempt.request, false)
			results <- admissionResult{attempt.store, attempt.request, err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	accepted, busy := 0, 0
	for result := range results {
		err := result.err
		var sqliteError *sqlite.Error
		if errors.As(err, &sqliteError) && sqliteError.Code()&0xff == sqlite3.SQLITE_BUSY {
			// Independent Store handles may lose a deferred SQLite write upgrade.
			// That attempt must have rolled back. Once the winner has committed,
			// retry must see its durable occupant, never admit another Run.
			_, _, err = admitCredential(result.store, result.request, false)
		}
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrCredentialBusy) {
			busy++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || busy != 1 {
		t.Fatalf("accepted=%d busy=%d", accepted, busy)
	}
	var runs, occupants, workspaceLocks int
	for q, dst := range map[string]*int{`SELECT COUNT(*) FROM runs`: &runs, `SELECT COUNT(*) FROM credential_occupancy`: &occupants, `SELECT COUNT(*) FROM workspace_locks`: &workspaceLocks} {
		if err := s.db.QueryRow(q).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}
	if runs != 1 || occupants != 1 || workspaceLocks != 0 {
		t.Fatalf("non-atomic read-only admission: %d %d %d", runs, occupants, workspaceLocks)
	}
}

func TestCredentialOccupancyRollsBackWhenLaterWriterLockFails(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	writer := startRequest("existing-writer", "synthetic input")
	if _, _, err := registerTestStart(s, ctx, writer, writer.ExpectedRevision, "workspace", true); err != nil {
		t.Fatal(err)
	}
	_, request := credentialFixture(t, s, "credential-target")
	if _, _, err := admitCredential(s, request, true); !errors.Is(err, ErrWorkspaceBusy) {
		t.Fatalf("writer conflict: %v", err)
	}
	if _, err := s.GetRun(ctx, request.RunID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected admission retained a Run: %v", err)
	}
	var occupants int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM credential_occupancy`).Scan(&occupants); err != nil || occupants != 0 {
		t.Fatalf("rejected admission retained occupancy: %d %v", occupants, err)
	}
}

func TestCredentialRevocationDoesNotReleaseAdmittedRun(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	g, r := credentialFixture(t, s, "credential-target")
	bad := r
	bad.SessionScopeDigest = strings.Repeat("f", 64)
	if _, _, err := admitCredential(s, bad, true); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("wrong scope: %v", err)
	}
	run, created, err := admitCredential(s, r, true)
	if err != nil || !created || !run.CredentialRequired || !run.CredentialLeaseHeld {
		t.Fatalf("admit: %#v %v", run, err)
	}
	if err := s.RevokeCredentialGeneration(ctx, CredentialRef{g.SlotRef, g.Generation}); err != nil {
		t.Fatal(err)
	}
	if _, created, err := admitCredential(s, r, true); err != nil || created {
		t.Fatalf("exact replay: created=%v err=%v", created, err)
	}
	if _, _, err := s.BeginRuntimeIntent(ctx, r.RunID, testBootID); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("revoked Create: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE runs SET runtime_intent_pending=1,runtime_intent_boot_id=? WHERE run_id=?`, testBootID, r.RunID); err == nil {
		t.Fatal("SQL bypassed revoked Create")
	}
	if _, err := s.ClearRuntimeIntent(ctx, r.RunID); err != nil {
		t.Fatal(err)
	}
	if run, err := s.GetRun(ctx, r.RunID); err != nil || !run.CredentialLeaseHeld || run.RuntimeIntentPending {
		t.Fatalf("clear released occupancy: %#v %v", run, err)
	}
	next := g
	next.Generation++
	if err := s.RegisterCredentialGeneration(ctx, next); !errors.Is(err, ErrCredentialBusy) {
		t.Fatalf("rotation during occupancy: %v", err)
	}
	event := executionwire.RunEvent{RunID: r.RunID, Seq: 1, Type: executionwire.RunEventCancelled}
	if _, err := s.AppendEvent(ctx, event, nil); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("direct terminal: %v", err)
	}
	if _, err := s.StageTerminal(ctx, event, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmRuntimeStopped(ctx, r.RunID); err != nil {
		t.Fatal(err)
	} // Synthetic pre-create cleanup proof.
	if err := s.RegisterCredentialGeneration(ctx, next); err != nil {
		t.Fatal(err)
	}
	oldAlias := g
	oldAlias.SlotRef = "recycled-name"
	if err := s.RegisterCredentialGeneration(ctx, oldAlias); !errors.Is(err, ErrConflict) {
		t.Fatalf("retirement erased source owner: %v", err)
	}
}

func TestCredentialOccupancySurvivesReopenAndLatePublicationRollback(t *testing.T) {
	s, path := openTestStore(t)
	ctx := context.Background()
	_, r := credentialFixture(t, s, "credential-target")
	if _, _, err := admitCredential(s, r, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.BeginRuntimeIntent(ctx, r.RunID, testBootID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRuntimeRef(ctx, r.RunID, "synthetic-runtime"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendEvent(ctx, executionwire.RunEvent{RunID: r.RunID, Seq: 1, Type: executionwire.RunEventStarted}, nil); err != nil {
		t.Fatal(err)
	}
	event := executionwire.RunEvent{RunID: r.RunID, Seq: 2, Type: executionwire.RunEventCompleted, Result: &executionwire.RunResult{Output: executionwire.TextOutput{MediaType: executionwire.MediaTypeTextPlain, Text: "synthetic result"}}}
	if _, err := s.StageTerminal(ctx, event, nil); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DELETE FROM credential_occupancy`, `UPDATE credential_occupancy SET generation=2`} {
		if _, err := s.db.Exec(q); err == nil {
			t.Fatalf("occupancy mutation accepted: %s", q)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec(`CREATE TRIGGER fail_credential_publication BEFORE DELETE ON staged_terminals BEGIN SELECT RAISE(ABORT,'synthetic late failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmRuntimeStopped(ctx, r.RunID); err == nil {
		t.Fatal("late fault not exercised")
	}
	run := assertHiddenCandidate(t, s, r.RunID, 1)
	if !run.CredentialLeaseHeld || !run.WorkspaceLockHeld || run.RuntimeRef == nil {
		t.Fatal("partial release after rollback")
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_credential_publication`); err != nil {
		t.Fatal(err)
	}
	// This is a simulated trusted cleanup result, not a real container canary.
	for range 2 {
		run, err = s.ConfirmRuntimeStopped(ctx, r.RunID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if run.CredentialLeaseHeld || run.WorkspaceLockHeld || run.RuntimeRef != nil || run.TerminalPending || run.State != executionwire.RunStateCompleted {
		t.Fatalf("publication: %#v", run)
	}
	unreconciled, err := s.ListUnreconciled(ctx)
	if err != nil || len(unreconciled) != 0 {
		t.Fatalf("remaining reconciliation: %#v %v", unreconciled, err)
	}
}

func TestCredentialRevocationAfterIntentRetainsRuntimeCleanupAuthority(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	g, r := credentialFixture(t, s, "credential-target")
	if _, _, err := admitCredential(s, r, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.BeginRuntimeIntent(ctx, r.RunID, testBootID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeCredentialGeneration(ctx, CredentialRef{g.SlotRef, g.Generation}); err != nil {
		t.Fatal(err)
	}
	// The external Create already had committed permission before revocation.
	// Its response still has to be recorded; revocation cannot imply absence.
	run, err := s.SetRuntimeRef(ctx, r.RunID, "synthetic-late-runtime")
	if err != nil || !run.CredentialLeaseHeld || run.RuntimeRef == nil || run.RuntimeIntentPending {
		t.Fatalf("late runtime lost: %#v %v", run, err)
	}
	if _, err := s.StageTerminal(ctx, executionwire.RunEvent{RunID: r.RunID, Seq: 1, Type: executionwire.RunEventCancelled}, nil); err != nil {
		t.Fatal(err)
	}
	run, err = s.ConfirmRuntimeStopped(ctx, r.RunID) // Synthetic exact-runtime cleanup.
	if err != nil || run.CredentialLeaseHeld || run.RuntimeRef != nil {
		t.Fatalf("revoked cleanup: %#v %v", run, err)
	}
}

func TestCredentialMissingOccupancyFailsClosedAcrossReopen(t *testing.T) {
	s, path := openTestStore(t)
	ctx := context.Background()
	_, r := credentialFixture(t, s, "credential-target")
	if _, _, err := admitCredential(s, r, false); err != nil {
		t.Fatal(err)
	}
	// Deliberate corruption after removing its guard; ordinary SQL cannot do this.
	if _, err := s.db.Exec(`DROP TRIGGER credential_release_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM credential_occupancy`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.BeginRuntimeIntent(ctx, r.RunID, testBootID); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("missing occupancy Create: %v", err)
	}
	if _, err := s.SetRuntimeRef(ctx, r.RunID, "synthetic-runtime"); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("missing occupancy runtime binding: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(ctx, path); !errors.Is(err, ErrCredentialAuthority) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatalf("corrupt reopen: %v", err)
	}
}

func TestCredentialOccupancySurvivesProcessSIGKILL(t *testing.T) {
	if path := os.Getenv("HGW_SYNTHETIC_CREDENTIAL_CRASH_DB"); path != "" {
		s, err := Open(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		_, r := credentialFixture(t, s, "crash-target")
		if _, _, err := admitCredential(s, r, false); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.BeginRuntimeIntent(context.Background(), r.RunID, testBootID); err != nil {
			t.Fatal(err)
		}
		fmt.Println("committed")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		t.Fatal("child was not killed")
	}
	path := filepath.Join(t.TempDir(), "crash.sqlite3")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCredentialOccupancySurvivesProcessSIGKILL$")
	cmd.Env = []string{"HGW_SYNTHETIC_CREDENTIAL_CRASH_DB=" + path}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "committed\n" {
		t.Fatalf("child commit: %q %v", line, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("child exited without SIGKILL")
	}
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	run, err := s.GetRun(context.Background(), "credential-run")
	if err != nil || !run.CredentialLeaseHeld || !run.RuntimeIntentPending {
		t.Fatalf("crash lost occupancy: %#v %v", run, err)
	}
	if _, err := s.ConfirmRuntimeStopped(context.Background(), run.RunID); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("pending intent released: %v", err)
	}
}

func TestMigrationTenKeepsHistoricalMockCredentialFree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v9.sqlite3")
	db := createLegacySandboxDatabase(t, path, 9)
	if _, err := db.Exec(`INSERT INTO target_revisions(target_id,revision,semantic_fingerprint,registered_at_unix_ms,runner_state_kind) VALUES ('mock','r1',?,1,'none')`, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var kind string
	if err := s.db.QueryRow(`SELECT credential_kind FROM target_revisions WHERE target_id='mock'`).Scan(&kind); err != nil || kind != "none" {
		t.Fatalf("migration inferred credential: %q %v", kind, err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM credential_generations`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("migration invented enrollment: %d %v", n, err)
	}
	g := CredentialGeneration{"dedicated", 1, strings.Repeat("b", 64), "workspace", "test.auth", strings.Repeat("c", 64)}
	if err := s.RegisterCredentialGeneration(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterTargetAuthorities(context.Background(), []TargetAuthority{{TargetID: "mock", TargetRevision: "r1",
		RevisionPin: strings.Repeat("a", 64), RunnerStateKind: targetmanifest.RunnerStateNone,
		Credential: &CredentialRef{g.SlotRef, g.Generation}}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("historical target acquired a credential: %v", err)
	}
}
