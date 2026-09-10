package sandboxstore

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func enrolledTargetFixture(g CredentialGeneration) EnrolledTargetAuthority {
	return EnrolledTargetAuthority{
		Target: TargetAuthority{TargetID: "enrolled-target", TargetRevision: "enrolled-r1", RevisionPin: strings.Repeat("a", 64),
			RunnerStateKind: targetmanifest.RunnerStateNone, Credential: &CredentialRef{g.SlotRef, g.Generation}},
		Scope: &CredentialTargetScope{g.WorkspaceRef, g.AuthProfileRef, g.ScopeDigest},
	}
}

func bindEnrolledCredentialTarget(t *testing.T, s *Store, r executionwire.StartRunRequest, g CredentialGeneration) {
	t.Helper()
	a := enrolledTargetFixture(g)
	a.Target.TargetID, a.Target.TargetRevision = r.TargetID, r.ExpectedRevision
	proofMust(t, s.RegisterEnrolledTargetAuthorities(context.Background(), []EnrolledTargetAuthority{a}))
}

func storedTargetPin(t *testing.T, s *Store, a TargetAuthority) string {
	t.Helper()
	var pin string
	proofMust(t, s.db.QueryRow(`SELECT semantic_fingerprint FROM target_revisions WHERE target_id=? AND revision=?`,
		a.TargetID, a.TargetRevision).Scan(&pin))
	return pin
}

func TestEnrolledTargetFingerprintBindsEveryAuthorityField(t *testing.T) {
	g, proof := enrollmentFixture()
	base := strings.Repeat("a", 64)
	// Independently encoded with Python struct.pack('>Q', len(utf8_bytes)).
	const want = "a5d835db77f7eed9acc1a79901a276306431e1660545d2005213d19e5b4735f6"
	if got := fingerprintEnrolledTarget(base, g, proof); got != want {
		t.Fatalf("credential target vector: got %s want %s", got, want)
	}
	for _, field := range []string{"base", "slot-ref", "generation", "scheme", "source", "root", "slot-object", "locator", "workspace", "auth", "scope"} {
		t.Run(field, func(t *testing.T) {
			pin, changed, pins := base, g, proof
			switch field {
			case "base":
				pin = strings.Repeat("0", 64)
			case "slot-ref":
				changed.SlotRef += "-other"
			case "generation":
				changed.Generation++
			case "scheme":
				pins.Scheme += "-other" // Hash coverage only; enrollment rejects unknown schemes.
			case "source":
				changed.SourceDigest = strings.Repeat("0", 64)
			case "root":
				pins.RootObjectDigest = strings.Repeat("0", 64)
			case "slot-object":
				pins.SlotObjectDigest = strings.Repeat("0", 64)
			case "locator":
				pins.LocatorDigest = strings.Repeat("0", 64)
			case "workspace":
				changed.WorkspaceRef += "-other"
			case "auth":
				changed.AuthProfileRef += "-other"
			case "scope":
				changed.ScopeDigest = strings.Repeat("0", 64)
			}
			if fingerprintEnrolledTarget(pin, changed, pins) == want {
				t.Fatal("authority change retained the old pin")
			}
		})
	}
	left, right := g, g
	left.WorkspaceRef, left.AuthProfileRef = "ab", "c"
	right.WorkspaceRef, right.AuthProfileRef = "a", "bc"
	if fingerprintEnrolledTarget(base, left, proof) == fingerprintEnrolledTarget(base, right, proof) {
		t.Fatal("field boundary collision")
	}
}

func TestEnrolledTargetPinPersistsReplayAndRejectsChangedAuthority(t *testing.T) {
	s, path := openTestStore(t)
	ctx := context.Background()
	g, proof := enrollmentFixture()
	proofMust(t, s.RegisterCredentialEnrollment(ctx, g, proof))
	a := enrolledTargetFixture(g)
	for range 2 {
		proofMust(t, s.RegisterEnrolledTargetAuthorities(ctx, []EnrolledTargetAuthority{a}))
	}
	if a.Target.RevisionPin != strings.Repeat("a", 64) {
		t.Fatal("registration mutated caller's base pin")
	}
	if got := storedTargetPin(t, s, a.Target); got != fingerprintEnrolledTarget(a.Target.RevisionPin, g, proof) {
		t.Fatal("stored pin omitted enrollment")
	}
	proofMust(t, s.Close())
	s, err := Open(ctx, path)
	proofMust(t, err)
	defer s.Close()
	proofMust(t, s.RegisterEnrolledTargetAuthorities(ctx, []EnrolledTargetAuthority{a}))
	changed := a
	changed.Target.RevisionPin = strings.Repeat("0", 64)
	if err := s.RegisterEnrolledTargetAuthorities(ctx, []EnrolledTargetAuthority{changed}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed non-credential authority reused revision: %v", err)
	}
	proofMust(t, s.RevokeCredentialGeneration(ctx, *a.Target.Credential))
	proofMust(t, s.RegisterEnrolledTargetAuthorities(ctx, []EnrolledTargetAuthority{a}))
	r := startRequest("revoked-target-run", "synthetic input")
	r.TargetID, r.ExpectedRevision, r.SessionScopeDigest = a.Target.TargetID, a.Target.TargetRevision, g.ScopeDigest
	if _, _, err := admitCredential(s, r, false); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("target replay revived a revoked generation: %v", err)
	}
	changed = a
	changed.Target.TargetRevision = "new-revision-on-retired-generation"
	if err := s.RegisterEnrolledTargetAuthorities(ctx, []EnrolledTargetAuthority{changed}); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("new target bound revoked generation: %v", err)
	}
	next := g
	next.Generation++
	proofMust(t, s.RegisterCredentialEnrollment(ctx, next, proof))
	changed = enrolledTargetFixture(next)
	if err := s.RegisterEnrolledTargetAuthorities(ctx, []EnrolledTargetAuthority{changed}); !errors.Is(err, ErrConflict) {
		t.Fatalf("rotation reused the old target revision: %v", err)
	}
	changed.Target.TargetRevision = "enrolled-r2"
	proofMust(t, s.RegisterEnrolledTargetAuthorities(ctx, []EnrolledTargetAuthority{changed}))
	if storedTargetPin(t, s, a.Target) == storedTargetPin(t, s, changed.Target) {
		t.Fatal("rotation did not change the durable pin")
	}
}

func TestEnrolledTargetRegistrationRejectsMissingOrMismatchedAuthority(t *testing.T) {
	for _, failure := range []string{"missing-generation", "proofless", "missing-scope", "workspace", "auth", "scope", "empty-workspace", "invalid-scope", "unknown-proof"} {
		t.Run(failure, func(t *testing.T) {
			s, _ := openTestStore(t)
			before := targetAuthorityCounts(t, s)
			ctx := context.Background()
			g, proof := enrollmentFixture()
			a := enrolledTargetFixture(g)
			switch failure {
			case "missing-generation":
			case "proofless":
				proofMust(t, s.RegisterCredentialGeneration(ctx, g))
			default:
				proofMust(t, s.RegisterCredentialEnrollment(ctx, g, proof))
			}
			want := ErrCredentialAuthority
			switch failure {
			case "missing-scope":
				a.Scope = nil
			case "workspace":
				a.Scope.WorkspaceRef = "other-workspace"
			case "auth":
				a.Scope.AuthProfileRef = "other.auth"
			case "scope":
				a.Scope.ScopeDigest = strings.Repeat("0", 64)
			case "empty-workspace":
				a.Scope.WorkspaceRef, want = "", ErrInvalidArgument
			case "invalid-scope":
				a.Scope.ScopeDigest, want = strings.Repeat("A", 64), ErrInvalidArgument
			case "unknown-proof":
				// Simulate corrupted storage after dropping the history guard.
				_, err := s.db.Exec(`DROP TRIGGER credential_generation_immutable`)
				proofMust(t, err)
				_, err = s.db.Exec(`PRAGMA ignore_check_constraints=ON`)
				proofMust(t, err)
				_, err = s.db.Exec(`UPDATE credential_generations SET proof_scheme='unknown/v1'`)
				proofMust(t, err)
			}
			if err := s.RegisterEnrolledTargetAuthorities(ctx, []EnrolledTargetAuthority{a}); !errors.Is(err, want) {
				t.Fatalf("registration: %v, want %v", err, want)
			}
			if after := targetAuthorityCounts(t, s); after != before {
				t.Fatalf("failed registration changed authority rows: %v -> %v", before, after)
			}
		})
	}
}

func targetAuthorityCounts(t *testing.T, s *Store) [3]int {
	t.Helper()
	var counts [3]int
	proofMust(t, s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM target_revisions),
(SELECT COUNT(*) FROM target_credentials), (SELECT COUNT(*) FROM runner_state_owners)`).Scan(&counts[0], &counts[1], &counts[2]))
	return counts
}

func TestEnrolledTargetMixedBatchRollsBackLateFailure(t *testing.T) {
	for _, failure := range []string{"scope", "credential-insert", "revoked"} {
		t.Run(failure, func(t *testing.T) {
			s, _ := openTestStore(t)
			before := targetAuthorityCounts(t, s)
			ctx := context.Background()
			g, proof := enrollmentFixture()
			proofMust(t, s.RegisterCredentialEnrollment(ctx, g, proof))
			a, b := enrolledTargetFixture(g), enrolledTargetFixture(g)
			b.Target.TargetID = "enrolled-b"
			free := EnrolledTargetAuthority{Target: TargetAuthority{TargetID: "free", TargetRevision: "free-r1",
				RevisionPin: strings.Repeat("1", 64), RunnerStateKind: targetmanifest.RunnerStatePersistent,
				RunnerStateRef: "synthetic-state", RunnerStatePathDigest: strings.Repeat("2", 64), StatePathAbsent: true}}
			switch failure {
			case "scope":
				b.Scope.AuthProfileRef = "wrong.auth"
			case "credential-insert":
				_, err := s.db.Exec(`CREATE TRIGGER enrolled_batch_fail BEFORE INSERT ON target_credentials
WHEN NEW.target_id='enrolled-b' BEGIN SELECT RAISE(FAIL,'synthetic failure'); END`)
				proofMust(t, err)
			case "revoked":
				other := g
				other.SlotRef, other.SourceDigest = "other-slot", strings.Repeat("0", 64)
				proofMust(t, s.RegisterCredentialEnrollment(ctx, other, proof))
				b.Target.Credential = &CredentialRef{other.SlotRef, other.Generation}
				proofMust(t, s.RevokeCredentialGeneration(ctx, *b.Target.Credential))
			}
			err := s.RegisterEnrolledTargetAuthorities(ctx, []EnrolledTargetAuthority{free, a, b})
			if failure == "credential-insert" {
				if err == nil || !strings.Contains(err.Error(), "synthetic failure") {
					t.Fatalf("did not reach the final credential INSERT: %v", err)
				}
			} else if !errors.Is(err, ErrCredentialAuthority) {
				t.Fatalf("final authority rejection: %v", err)
			}
			if after := targetAuthorityCounts(t, s); after != before {
				t.Fatalf("failed batch changed authority rows: %v -> %v", before, after)
			}
			got, pins, err := s.GetCredentialEnrollment(ctx, *a.Target.Credential)
			proofMust(t, err)
			if got != g || pins != proof {
				t.Fatal("failed target batch changed enrollment")
			}
			// Clear only the injected failure. The same mixed batch must now
			// commit its two bound targets and one credential-free state owner.
			if failure == "credential-insert" {
				_, err := s.db.Exec(`DROP TRIGGER enrolled_batch_fail`)
				proofMust(t, err)
			}
			b = enrolledTargetFixture(g)
			b.Target.TargetID = "enrolled-b"
			proofMust(t, s.RegisterEnrolledTargetAuthorities(ctx, []EnrolledTargetAuthority{free, a, b}))
			want := [3]int{before[0] + 3, before[1] + 2, before[2] + 1}
			if got := targetAuthorityCounts(t, s); got != want {
				t.Fatalf("successful batch rows: %v, want %v", got, want)
			}
			if storedTargetPin(t, s, free.Target) != free.Target.RevisionPin {
				t.Fatal("mixed registration changed credential-free pin")
			}
		})
	}
}

func TestEnrolledTargetRegistrationPreservesLegacyAndRejectsImplicitUpgrade(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	g, proof := enrollmentFixture()
	proofMust(t, s.RegisterCredentialEnrollment(ctx, g, proof))
	a := enrolledTargetFixture(g)
	free := EnrolledTargetAuthority{Target: TargetAuthority{TargetID: "free", TargetRevision: "free-r1",
		RevisionPin: strings.Repeat("1", 64), RunnerStateKind: targetmanifest.RunnerStateNone}}
	proofMust(t, s.RegisterTargetAuthorities(ctx, []TargetAuthority{free.Target, a.Target})) // Old synthetic form.
	proofMust(t, s.RegisterEnrolledTargetAuthorities(ctx, []EnrolledTargetAuthority{free}))
	if storedTargetPin(t, s, free.Target) != free.Target.RevisionPin || storedTargetPin(t, s, a.Target) != a.Target.RevisionPin {
		t.Fatal("historical pin was rewritten")
	}
	if err := s.RegisterEnrolledTargetAuthorities(ctx, []EnrolledTargetAuthority{a}); !errors.Is(err, ErrConflict) {
		t.Fatalf("implicit upgrade reused synthetic revision: %v", err)
	}
	a.Target.TargetRevision = "explicit-enrolled-revision"
	proofMust(t, s.RegisterEnrolledTargetAuthorities(ctx, []EnrolledTargetAuthority{a}))
	if err := s.RegisterTargetAuthorities(ctx, []TargetAuthority{a.Target}); !errors.Is(err, ErrConflict) {
		t.Fatalf("downgrade reused enrolled revision: %v", err)
	}
	free.Scope = a.Scope
	if err := s.RegisterEnrolledTargetAuthorities(ctx, []EnrolledTargetAuthority{free}); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("credential-free target smuggled a scope: %v", err)
	}
}
