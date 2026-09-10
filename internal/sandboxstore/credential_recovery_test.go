package sandboxstore

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
)

func TestOccupiedCredentialRetirementIsAtomicDurableAndSelective(t *testing.T) {
	ctx := context.Background()
	s, path := openTestStore(t)
	var requests []executionwire.StartRunRequest
	var generations []CredentialGeneration
	for i := range 4 {
		r := startRequest(fmt.Sprintf("recovery-run-%d", i), "synthetic input")
		r.TargetID, r.ExpectedRevision = fmt.Sprintf("recovery-target-%d", i), "recovery-r1"
		g := CredentialGeneration{SlotRef: fmt.Sprintf("recovery-slot-%d", i), Generation: 1,
			SourceDigest: fmt.Sprintf("%064x", i+1), WorkspaceRef: "workspace",
			AuthProfileRef: "synthetic.auth", ScopeDigest: r.SessionScopeDigest}
		if err := s.RegisterCredentialGeneration(ctx, g); err != nil {
			t.Fatal(err)
		}
		bindCredentialTarget(t, s, r, g)
		if i < 3 {
			if _, _, err := admitCredential(s, r, false); err != nil {
				t.Fatal(err)
			}
		}
		requests, generations = append(requests, r), append(generations, g)
	}
	if _, _, err := s.BeginRuntimeIntent(ctx, requests[1].RunID, testBootID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeCredentialGeneration(ctx, CredentialRef{generations[2].SlotRef, 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StageTerminal(ctx, executionwire.RunEvent{RunID: requests[2].RunID,
		Seq: 1, Type: executionwire.RunEventCancelled}, nil); err != nil {
		t.Fatal(err)
	}
	before := make([]Run, 3)
	for i := range before {
		var err error
		before[i], err = s.GetRun(ctx, requests[i].RunID)
		if err != nil {
			t.Fatal(err)
		}
	}
	reopen := func() {
		t.Helper()
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		var err error
		s, err = Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
	}
	defer func() { _ = s.Close() }()
	assertRetained := func(wantRevocations int) {
		t.Helper()
		var count int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM credential_revocations`).Scan(&count); err != nil || count != wantRevocations {
			t.Fatalf("revocations = %d, want %d: %v", count, wantRevocations, err)
		}
		for i, want := range before {
			got, err := s.GetRun(ctx, requests[i].RunID)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("retirement changed retained Run %d: %#v, want %#v: %v", i, got, want, err)
			}
		}
	}
	reopen()
	assertRetained(1) // Merely opening a database must not retire credentials.
	// FAIL preserves earlier changes in this SQL statement. The enclosing
	// transaction must roll them all back, including the first new revocation.
	if _, err := s.db.Exec(`CREATE TRIGGER fail_late_retirement AFTER INSERT ON credential_revocations
WHEN (SELECT COUNT(*) FROM credential_revocations) = 3
BEGIN SELECT RAISE(FAIL, 'synthetic late retirement failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireOccupiedCredentialGenerations(ctx); err == nil {
		t.Fatal("late retirement fault not exercised")
	}
	assertRetained(1)
	reopen()
	assertRetained(1)
	if _, err := s.db.Exec(`DROP TRIGGER fail_late_retirement`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.RetireOccupiedCredentialGenerations(ctx); err != nil {
			t.Fatal(err)
		}
		assertRetained(3)
		reopen()
		assertRetained(3)
	}
	if _, created, err := admitCredential(s, requests[0], false); err != nil || created {
		t.Fatalf("retired exact replay: created=%v: %v", created, err)
	}
	if _, _, err := s.BeginRuntimeIntent(ctx, requests[0].RunID, testBootID); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("retired generation granted new Create: %v", err)
	}
	if run, err := s.SetRuntimeRef(ctx, requests[1].RunID, "synthetic-late-runtime"); err != nil ||
		run.RuntimeRef == nil || !run.CredentialLeaseHeld {
		t.Fatalf("retirement discarded previously granted Create: %#v %v", run, err)
	}
	if run, created, err := admitCredential(s, requests[3], false); err != nil || !created || !run.CredentialLeaseHeld {
		t.Fatalf("idle generation retired: %#v created=%v: %v", run, created, err)
	}
}
