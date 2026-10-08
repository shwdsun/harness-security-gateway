package sandboxstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// These digests are constructed synthetic authority, not filesystem evidence.
func enrollmentFixture() (CredentialGeneration, credentialsource.Proof) {
	return CredentialGeneration{"dedicated", 1, strings.Repeat("b", 64), "workspace", "test.auth", strings.Repeat("c", 64)},
		credentialsource.Proof{Scheme: credentialsource.EnrollmentScheme, RootObjectDigest: strings.Repeat("d", 64),
			SlotObjectDigest: strings.Repeat("e", 64), LocatorDigest: strings.Repeat("f", 64)}
}

func proofMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func credentialRowCounts(t *testing.T, s *Store, sources, generations int) {
	t.Helper()
	var a, b int
	proofMust(t, s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM credential_sources),
(SELECT COUNT(*) FROM credential_generations)`).Scan(&a, &b))
	if a != sources || b != generations {
		t.Fatalf("partial registration: sources=%d generations=%d, want %d/%d", a, b, sources, generations)
	}
}

func TestCredentialEnrollmentExactReplayAndRevocationSurviveReopen(t *testing.T) {
	s, path := openTestStore(t)
	ctx := context.Background()
	g, proof := enrollmentFixture()
	ref := CredentialRef{g.SlotRef, g.Generation}
	if _, _, err := s.GetCredentialEnrollment(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing registration: %v", err)
	}
	proofMust(t, s.RegisterCredentialEnrollment(ctx, g, proof))
	proofMust(t, s.RegisterCredentialEnrollment(ctx, g, proof))
	r := startRequest("enrolled-run", "synthetic input")
	r.TargetID, r.ExpectedRevision, r.SessionScopeDigest = "enrolled-target", "enrolled-r1", g.ScopeDigest
	bindEnrolledCredentialTarget(t, s, r, g)
	proofMust(t, s.RevokeCredentialGeneration(ctx, ref))
	proofMust(t, s.Close())
	reopened, err := Open(ctx, path)
	proofMust(t, err)
	defer reopened.Close()
	// Lost registration response is resolved by exact immutable read-back.
	got, pins, err := reopened.GetCredentialEnrollment(ctx, ref)
	proofMust(t, err)
	if got != g || pins != proof {
		t.Fatal("reopen changed the generation/proof pair")
	}
	proofMust(t, reopened.RegisterCredentialEnrollment(ctx, g, proof))
	credentialRowCounts(t, reopened, 1, 1)
	if _, _, err := admitCredential(reopened, r, false); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("replay revived revoked enrollment: %v", err)
	}
	if err := reopened.RegisterCredentialGeneration(ctx, g); !errors.Is(err, ErrConflict) {
		t.Fatalf("proofless replay downgraded enrollment: %v", err)
	}
}

func TestCredentialEnrollmentReplayComparesEveryPinAndScope(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	g, proof := enrollmentFixture()
	proofMust(t, s.RegisterCredentialEnrollment(ctx, g, proof))
	for _, field := range []string{"source", "workspace", "auth", "scope", "root", "slot", "locator"} {
		t.Run(field, func(t *testing.T) {
			changed, pins := g, proof
			switch field {
			case "source":
				changed.SourceDigest = strings.Repeat("a", 64)
			case "workspace":
				changed.WorkspaceRef = "other-workspace"
			case "auth":
				changed.AuthProfileRef = "other.auth"
			case "scope":
				changed.ScopeDigest = strings.Repeat("a", 64)
			case "root":
				pins.RootObjectDigest = strings.Repeat("a", 64)
			case "slot":
				pins.SlotObjectDigest = strings.Repeat("a", 64)
			case "locator":
				pins.LocatorDigest = strings.Repeat("a", 64)
			}
			if err := s.RegisterCredentialEnrollment(ctx, changed, pins); !errors.Is(err, ErrConflict) {
				t.Fatalf("changed registration accepted: %v", err)
			}
		})
	}
	got, pins, err := s.GetCredentialEnrollment(ctx, CredentialRef{g.SlotRef, g.Generation})
	proofMust(t, err)
	if got != g || pins != proof {
		t.Fatal("conflict changed existing evidence")
	}
	credentialRowCounts(t, s, 1, 1)
}

func TestCredentialEnrollmentRejectsMalformedInputWithoutSourceOwnership(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	g, proof := enrollmentFixture()
	for _, change := range []func(*CredentialGeneration, *credentialsource.Proof){
		func(_ *CredentialGeneration, p *credentialsource.Proof) { *p = credentialsource.Proof{} },
		func(_ *CredentialGeneration, p *credentialsource.Proof) { p.Scheme = "unknown/v1" },
		func(_ *CredentialGeneration, p *credentialsource.Proof) { p.RootObjectDigest = "" },
		func(_ *CredentialGeneration, p *credentialsource.Proof) { p.SlotObjectDigest = strings.Repeat("A", 64) },
		func(_ *CredentialGeneration, p *credentialsource.Proof) { p.LocatorDigest = strings.Repeat("z", 64) },
		func(g *CredentialGeneration, _ *credentialsource.Proof) { g.SourceDigest = strings.Repeat("B", 64) },
		func(g *CredentialGeneration, _ *credentialsource.Proof) { g.ScopeDigest = "" },
	} {
		changed, pins := g, proof
		change(&changed, &pins)
		if err := s.RegisterCredentialEnrollment(ctx, changed, pins); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("malformed registration: %v", err)
		}
	}
	credentialRowCounts(t, s, 0, 0)
}

func TestCredentialEnrollmentLateFailureRollsBackEntireRegistration(t *testing.T) {
	s, path := openTestStore(t)
	ctx := context.Background()
	g, proof := enrollmentFixture()
	_, err := s.db.Exec(`CREATE TRIGGER fail_enrollment AFTER INSERT ON credential_generations
BEGIN SELECT RAISE(ABORT,'synthetic late registration failure'); END`)
	proofMust(t, err)
	if err := s.RegisterCredentialEnrollment(ctx, g, proof); err == nil {
		t.Fatal("late failure not exercised")
	}
	credentialRowCounts(t, s, 0, 0)
	proofMust(t, s.Close())
	reopened, err := Open(ctx, path)
	proofMust(t, err)
	defer reopened.Close()
	credentialRowCounts(t, reopened, 0, 0)
	if _, _, err := reopened.GetCredentialEnrollment(ctx, CredentialRef{g.SlotRef, 1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed registration acquired a proof: %v", err)
	}
	_, err = reopened.db.Exec(`DROP TRIGGER fail_enrollment`)
	proofMust(t, err)
	g.SlotRef = "different-owner"
	proofMust(t, reopened.RegisterCredentialEnrollment(ctx, g, proof))
	credentialRowCounts(t, reopened, 1, 1) // The failed transaction reserved no source owner.
}

func TestCredentialEnrollmentSchemaRejectsPartialProofAndMutation(t *testing.T) {
	s, _ := openTestStore(t)
	g, proof := enrollmentFixture()
	_, err := s.db.Exec(`INSERT INTO credential_sources VALUES (?,?)`, g.SourceDigest, g.SlotRef)
	proofMust(t, err)
	good := [4]any{proof.Scheme, proof.RootObjectDigest, proof.SlotObjectDigest, proof.LocatorDigest}
	insert := func(pins [4]any) error {
		_, err := s.db.Exec(`INSERT INTO credential_generations (`+credentialGenerationColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?)`,
			g.SlotRef, g.Generation, g.SourceDigest, g.WorkspaceRef, g.AuthProfileRef, g.ScopeDigest,
			pins[0], pins[1], pins[2], pins[3])
		return err
	}
	// Every partial presence mask must reject, including SQL's NULL cases.
	for mask := 1; mask < 15; mask++ {
		pins := good
		for field := range pins {
			if mask&(1<<field) == 0 {
				pins[field] = nil
			}
		}
		if err := insert(pins); err == nil {
			t.Fatalf("partial proof mask %d accepted", mask)
		}
	}
	for field := range good {
		for _, bad := range []string{"", "unknown/v1", strings.Repeat("A", 64), strings.Repeat("f", 63), strings.Repeat("z", 64), strings.Repeat("f", 64) + "\x00suffix", strings.Repeat("f", 63) + "\x00"} {
			pins := good
			pins[field] = bad
			if err := insert(pins); err == nil {
				t.Fatalf("invalid proof field %d accepted", field)
			}
		}
	}
	credentialRowCounts(t, s, 1, 0)
	proofMust(t, insert(good))
	for _, q := range []string{
		`UPDATE credential_generations SET root_object_digest='` + strings.Repeat("a", 64) + `'`,
		`UPDATE credential_generations SET proof_scheme=NULL,root_object_digest=NULL,slot_object_digest=NULL,locator_digest=NULL`,
		`DELETE FROM credential_generations`,
		`INSERT OR REPLACE INTO credential_generations SELECT * FROM credential_generations`,
	} {
		if _, err := s.db.Exec(q); err == nil {
			t.Fatal("SQL mutated immutable proof")
		}
	}
	// SQLite text length can stop at NUL; canonical source bytes must not.
	g.SourceDigest += "\x00suffix"
	g.SlotRef = "nul-source"
	_, err = s.db.Exec(`INSERT INTO credential_sources VALUES (?,?)`, g.SourceDigest, g.SlotRef)
	proofMust(t, err) // Historical source table has only its old text-length check.
	if err := insert(good); err == nil {
		t.Fatal("NUL-suffixed source gained a proof")
	}
}

func TestCredentialEnrollmentRequiresRetirementCleanupAndPermanentOwner(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	g, proof := enrollmentFixture()
	proofMust(t, s.RegisterCredentialEnrollment(ctx, g, proof))
	r := startRequest("proof-occupant", "synthetic input")
	r.TargetID, r.ExpectedRevision, r.SessionScopeDigest = "proof-target", "proof-r1", g.ScopeDigest
	bindEnrolledCredentialTarget(t, s, r, g)
	next := g
	next.Generation++
	if err := s.RegisterCredentialEnrollment(ctx, next, proof); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("unretired rotation: %v", err)
	}
	_, _, err := admitCredential(s, r, false)
	proofMust(t, err)
	proofMust(t, s.RevokeCredentialGeneration(ctx, CredentialRef{g.SlotRef, g.Generation}))
	if err := s.RegisterCredentialEnrollment(ctx, next, proof); !errors.Is(err, ErrCredentialBusy) {
		t.Fatalf("occupied rotation: %v", err)
	}
	proofMust(t, s.RegisterCredentialEnrollment(ctx, g, proof)) // Exact historical replay is harmless while occupied.
	_, err = s.StageTerminal(ctx, executionwire.RunEvent{RunID: r.RunID, Seq: 1, Type: executionwire.RunEventCancelled}, nil)
	proofMust(t, err)
	_, err = s.ConfirmRuntimeStopped(ctx, r.RunID) // Synthetic pre-Create cleanup, no real runtime.
	proofMust(t, err)
	proof.LocatorDigest = strings.Repeat("a", 64)
	proofMust(t, s.RegisterCredentialEnrollment(ctx, next, proof))
	alias := next
	alias.SlotRef = "other-slot"
	if err := s.RegisterCredentialEnrollment(ctx, alias, proof); !errors.Is(err, ErrConflict) {
		t.Fatalf("source reassigned: %v", err)
	}
}

func TestCredentialEnrollmentConcurrentRegistrationCannotSplitProof(t *testing.T) {
	for _, mode := range []string{"same", "different", "proofless"} {
		t.Run(mode, func(t *testing.T) {
			s, path := openTestStore(t)
			ctx := context.Background()
			other, err := Open(ctx, path)
			proofMust(t, err)
			defer other.Close()
			g, proof := enrollmentFixture()
			second := proof
			if mode == "different" {
				second.LocatorDigest = strings.Repeat("a", 64)
			}
			attempts := []func() error{
				func() error { return s.RegisterCredentialEnrollment(ctx, g, proof) },
				func() error {
					if mode == "proofless" {
						return other.RegisterCredentialGeneration(ctx, g)
					}
					return other.RegisterCredentialEnrollment(ctx, g, second)
				},
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			errs := make([]error, 2)
			for i, attempt := range attempts {
				wg.Go(func() { <-start; errs[i] = attempt() })
			}
			close(start)
			wg.Wait()
			successes, conflicts := 0, 0
			for i, err := range errs {
				var sqlErr *sqlite.Error
				if errors.As(err, &sqlErr) && sqlErr.Code()&0xff == sqlite3.SQLITE_BUSY {
					err = attempts[i]()
				}
				if err == nil {
					successes++
				} else if errors.Is(err, ErrConflict) {
					conflicts++
				} else {
					t.Fatal(err)
				}
			}
			if mode == "same" {
				if successes != 2 || conflicts != 0 {
					t.Fatal("exact concurrent replay failed")
				}
			} else if successes != 1 || conflicts != 1 {
				t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
			}
			credentialRowCounts(t, s, 1, 1)
			got, pins, err := loadCredentialGeneration(ctx, s.db, CredentialRef{g.SlotRef, g.Generation})
			proofMust(t, err)
			if got != g || (pins == nil && mode != "proofless") || (pins != nil && *pins != proof && *pins != second) {
				t.Fatal("split registration evidence")
			}
		})
	}
}

func TestMigrationElevenPreservesProoflessOccupancyWithoutUpgrade(t *testing.T) {
	if fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(migrations[:10], "\x00")))) != "34e2d05fae7ada68a57a2339565d0b454acc9a62066648db3158014478c0edce" {
		t.Fatal("earlier migration bytes changed")
	}
	path := filepath.Join(t.TempDir(), "v10.sqlite3")
	db := createLegacySandboxDatabase(t, path, 10)
	ctx := context.Background()
	g, proof := enrollmentFixture()
	_, err := db.Exec(`INSERT INTO credential_sources VALUES (?,?)`, g.SourceDigest, g.SlotRef)
	proofMust(t, err)
	_, err = db.Exec(`INSERT INTO credential_generations VALUES (?,?,?,?,?,?)`, g.SlotRef, g.Generation, g.SourceDigest, g.WorkspaceRef, g.AuthProfileRef, g.ScopeDigest)
	proofMust(t, err)
	old := &Store{db: db}
	r := startRequest("legacy-credential-run", "synthetic input")
	r.TargetID, r.ExpectedRevision, r.SessionScopeDigest = "legacy-credential", "legacy-r1", g.ScopeDigest
	bindCredentialTarget(t, old, r, g)
	_, _, err = admitCredential(old, r, false)
	proofMust(t, err)
	proofMust(t, old.RevokeCredentialGeneration(ctx, CredentialRef{g.SlotRef, g.Generation}))
	proofMust(t, db.Close())
	s, err := Open(ctx, path)
	proofMust(t, err)
	defer s.Close()
	if _, _, err := s.GetCredentialEnrollment(ctx, CredentialRef{g.SlotRef, g.Generation}); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("migration invented proof: %v", err)
	}
	proofMust(t, s.RegisterCredentialGeneration(ctx, g))
	if err := s.RegisterCredentialEnrollment(ctx, g, proof); !errors.Is(err, ErrConflict) {
		t.Fatalf("implicit proof upgrade: %v", err)
	}
	_, err = s.db.Exec(`UPDATE credential_generations SET proof_scheme=?,root_object_digest=?,slot_object_digest=?,locator_digest=?`, proof.Scheme, proof.RootObjectDigest, proof.SlotObjectDigest, proof.LocatorDigest)
	if err == nil {
		t.Fatal("SQL upgraded old generation")
	}
	run, err := s.GetRun(ctx, r.RunID)
	proofMust(t, err)
	if !run.CredentialLeaseHeld || run.State != executionwire.RunStateAccepted {
		t.Fatal("migration changed retained Run occupancy")
	}
	if _, created, err := admitCredential(s, r, false); err != nil || created {
		t.Fatalf("migration lost revoked exact Run replay: %v", err)
	}
	if _, _, err := s.BeginRuntimeIntent(ctx, r.RunID, testBootID); !errors.Is(err, ErrCredentialAuthority) {
		t.Fatalf("migration lost revocation: %v", err)
	}
}

func TestCredentialEnrollmentCorruptProofFailsReadAndReopen(t *testing.T) {
	s, path := openTestStore(t)
	ctx := context.Background()
	g, proof := enrollmentFixture()
	proofMust(t, s.RegisterCredentialEnrollment(ctx, g, proof))
	// Deliberately corrupt only this synthetic database, bypassing SQL guards.
	for _, q := range []string{`DROP TRIGGER credential_generation_immutable`, `PRAGMA ignore_check_constraints=ON`, `UPDATE credential_generations SET slot_object_digest=NULL`} {
		_, err := s.db.Exec(q)
		proofMust(t, err)
	}
	if got, pins, err := s.GetCredentialEnrollment(ctx, CredentialRef{g.SlotRef, g.Generation}); !errors.Is(err, ErrCredentialAuthority) || got != (CredentialGeneration{}) || pins != (credentialsource.Proof{}) {
		t.Fatalf("corrupt proof read: %v", err)
	}
	proofMust(t, s.Close())
	if reopened, err := Open(ctx, path); err == nil {
		reopened.Close()
		t.Fatal("corrupt proof accepted on reopen")
	}
}
