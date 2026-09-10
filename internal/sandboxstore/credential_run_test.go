package sandboxstore

import (
	"context"
	"errors"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
)

func TestRunCredentialEnrollmentRequiresAdmittedUnrevokedOwnership(t *testing.T) {
	ctx := context.Background()
	s, path := openTestStore(t)
	g, proof := enrollmentFixture()
	proofMust(t, s.RegisterCredentialEnrollment(ctx, g, proof))
	r := startRequest("enrolled-run", "synthetic input")
	r.TargetID, r.ExpectedRevision, r.SessionScopeDigest = "enrolled-target", "enrolled-r1", g.ScopeDigest
	bindEnrolledCredentialTarget(t, s, r, g)
	if _, _, err := s.GetRunCredentialEnrollment(ctx, r.RunID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unadmitted Run acquired proof: %v", err)
	}
	if err := s.RevokeRunCredential(ctx, r.RunID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unadmitted Run revoked enrollment: %v", err)
	}
	_, _, err := admitCredential(s, r, false)
	proofMust(t, err)
	alias := r
	alias.RunID, alias.TargetID, alias.ExpectedRevision = "rejected-run", "alias-target", "alias-r1"
	bindEnrolledCredentialTarget(t, s, alias, g)
	if _, _, err := admitCredential(s, alias, false); !errors.Is(err, ErrCredentialBusy) {
		t.Fatalf("conflicting source admission: %v", err)
	}
	if err := s.RevokeRunCredential(ctx, alias.RunID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected contender revoked occupant: %v", err)
	}
	proofMust(t, s.Close())
	s, err = Open(ctx, path)
	proofMust(t, err)
	defer s.Close()
	got, pins, err := s.GetRunCredentialEnrollment(ctx, r.RunID)
	proofMust(t, err)
	if got != g || pins != proof {
		t.Fatal("Run-derived read changed enrollment/proof")
	}
	_, _, err = s.BeginRuntimeIntent(ctx, r.RunID, testBootID)
	proofMust(t, err)
	if _, _, err := s.GetRunCredentialEnrollment(ctx, r.RunID); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("pending Create allowed a new acquisition: %v", err)
	}
	for range 2 {
		proofMust(t, s.RevokeRunCredential(ctx, r.RunID))
	}
	run, err := s.SetRuntimeRef(ctx, r.RunID, "synthetic-late-result")
	proofMust(t, err)
	if !run.CredentialLeaseHeld || run.RuntimeRef == nil {
		t.Fatal("revocation discarded granted cleanup authority")
	}
	_, err = s.StageTerminal(ctx, executionwire.RunEvent{RunID: r.RunID, Seq: 1, Type: executionwire.RunEventCancelled}, nil)
	proofMust(t, err)
	_, err = s.ConfirmRuntimeStopped(ctx, r.RunID) // Synthetic exact cleanup.
	proofMust(t, err)
	if err := s.RevokeRunCredential(ctx, r.RunID); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("released Run retained revocation authority: %v", err)
	}
	if _, _, err := s.GetRunCredentialEnrollment(ctx, r.RunID); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("completed Run regained acquisition authority: %v", err)
	}
}

func TestRunCredentialReadAndRevocationRejectMismatchedOccupancy(t *testing.T) {
	ctx := context.Background()
	s, _ := openTestStore(t)
	g, r := credentialFixture(t, s, "proofless-target")
	_, _, err := admitCredential(s, r, false)
	proofMust(t, err)
	if _, _, err := s.GetRunCredentialEnrollment(ctx, r.RunID); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("proofless generation gained real acquisition authority: %v", err)
	}
	// Corrupt the occupant only after removing its immutable guard. Both APIs
	// must join the original target rather than trust a slot found by Run ID.
	other := g
	other.SlotRef, other.SourceDigest = "other-slot", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	proofMust(t, s.RegisterCredentialGeneration(ctx, other))
	_, err = s.db.Exec(`DROP TRIGGER credential_occupancy_immutable`)
	proofMust(t, err)
	_, err = s.db.Exec(`UPDATE credential_occupancy SET slot_ref=?,source_digest=? WHERE run_id=?`, other.SlotRef, other.SourceDigest, r.RunID)
	proofMust(t, err)
	if _, _, err := s.GetRunCredentialEnrollment(ctx, r.RunID); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("mismatched occupancy read accepted: %v", err)
	}
	if err := s.RevokeRunCredential(ctx, r.RunID); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("mismatched occupancy revoked another source: %v", err)
	}
	var revocations int
	proofMust(t, s.db.QueryRow(`SELECT COUNT(*) FROM credential_revocations`).Scan(&revocations))
	if revocations != 0 {
		t.Fatal("failed ownership check wrote revocation")
	}
}
