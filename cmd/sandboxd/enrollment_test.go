package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
)

func startupCodexConfig(t *testing.T) sandboxconfig.Config {
	t.Helper()
	base := runnerStateOwnershipConfig(t)
	data, err := os.ReadFile("../../config/sandboxd.codex.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var c sandboxconfig.Config
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	c.Runtime = base.Runtime
	c.Socket, c.StateDatabase, c.WorkspaceRoot, c.RunnerStateRoot = base.Socket, base.StateDatabase, base.WorkspaceRoot, base.RunnerStateRoot
	root := filepath.Dir(c.WorkspaceRoot)
	c.Codex.Credential.Root = filepath.Join(root, "credentials")
	c.Codex.ProviderRoot = filepath.Join(root, "provider")
	c.Codex.ToolPackage = filepath.Join(root, "tool-package")
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

func enrollmentDB(t *testing.T, c sandboxconfig.Config) *sandboxstore.Store {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(c.StateDatabase), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sandboxstore.Open(context.Background(), c.StateDatabase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

type enrollmentFixture struct {
	proofErr, validateErr, closeErr error
	closed                          bool
	source                          string
}

func (f *enrollmentFixture) CaptureProof() (string, credentialsource.Proof, error) {
	return f.source, credentialsource.Proof{Scheme: credentialsource.EnrollmentScheme, RootObjectDigest: strings.Repeat("b", 64), SlotObjectDigest: strings.Repeat("c", 64), LocatorDigest: strings.Repeat("d", 64)}, f.proofErr
}
func (f *enrollmentFixture) Validate() error { return f.validateErr }
func (f *enrollmentFixture) Close() error    { f.closed = true; return f.closeErr }

func TestEnrollmentIsExactExplicitAndDoesNotRotate(t *testing.T) {
	ctx := context.Background()
	c := startupCodexConfig(t)
	db := enrollmentDB(t, c)
	b, scope := c.Codex.Credential, c.Codex.Scope.SessionScope()
	run := func(source string) error {
		f := &enrollmentFixture{source: source}
		err := enrollSource(ctx, db, b, scope, func(context.Context) (bool, error) { return true, nil }, func(root, dir string) (enrollmentSource, error) {
			if root != b.Root || dir != b.Directory {
				t.Fatal("enrollment changed locator")
			}
			return f, nil
		})
		if !f.closed {
			t.Fatal("enrollment retained source handle")
		}
		return err
	}
	if err := run(strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := run(strings.Repeat("a", 64)); err != nil {
		t.Fatal("exact replay failed", err)
	}
	if err := run(strings.Repeat("f", 64)); err == nil {
		t.Fatal("replacement source adopted")
	}
	g, _, err := db.GetCredentialEnrollment(ctx, sandboxstore.CredentialRef{SlotRef: b.SlotRef, Generation: 1})
	if err != nil || g.SourceDigest != strings.Repeat("a", 64) {
		t.Fatal("original enrollment changed", err)
	}
	b.Generation = 2
	if err := run(strings.Repeat("a", 64)); err == nil {
		t.Fatal("unretired history rotated automatically")
	}
	if _, _, err := db.GetCredentialEnrollment(ctx, sandboxstore.CredentialRef{SlotRef: b.SlotRef, Generation: 2}); !errors.Is(err, sandboxstore.ErrNotFound) {
		t.Fatal("rejected rotation left generation", err)
	}
}

func TestEnrollmentRefusesRetainedRuntimeBeforeOpeningSource(t *testing.T) {
	c := startupCodexConfig(t)
	db := enrollmentDB(t, c)
	for _, inventoryErr := range []error{nil, errors.New("unverified runtime")} {
		err := enrollSource(context.Background(), db, c.Codex.Credential, c.Codex.Scope.SessionScope(),
			func(context.Context) (bool, error) { return false, inventoryErr }, func(string, string) (enrollmentSource, error) {
				t.Fatal("opened source while runtime was unresolved")
				return nil, nil
			})
		if err == nil {
			t.Fatal("enrollment ignored unresolved runtime")
		}
	}
}

func TestEnrollmentObservationFailureDoesNotRegister(t *testing.T) {
	for _, field := range []string{"proof", "validation"} {
		t.Run(field, func(t *testing.T) {
			c := startupCodexConfig(t)
			db := enrollmentDB(t, c)
			f := &enrollmentFixture{source: strings.Repeat("a", 64)}
			if field == "proof" {
				f.proofErr = errors.New("observation failed")
			} else {
				f.validateErr = errors.New("changed object")
			}
			err := enrollSource(context.Background(), db, c.Codex.Credential, c.Codex.Scope.SessionScope(), func(context.Context) (bool, error) { return true, nil }, func(string, string) (enrollmentSource, error) { return f, nil })
			if err == nil || !f.closed {
				t.Fatal("failed observation accepted or handle leaked")
			}
			if _, _, err := db.GetCredentialEnrollment(context.Background(), sandboxstore.CredentialRef{SlotRef: c.Codex.Credential.SlotRef, Generation: 1}); !errors.Is(err, sandboxstore.ErrNotFound) {
				t.Fatal("failed observation registered", err)
			}
		})
	}
}

func TestEnrollmentCloseFailureRetiresCommittedGeneration(t *testing.T) {
	ctx := context.Background()
	c := startupCodexConfig(t)
	db := enrollmentDB(t, c)
	b, scope := c.Codex.Credential, c.Codex.Scope.SessionScope()
	f := &enrollmentFixture{source: strings.Repeat("a", 64), closeErr: errors.New("failed close")}
	enroll := func() error {
		return enrollSource(ctx, db, b, scope, func(context.Context) (bool, error) { return true, nil }, func(string, string) (enrollmentSource, error) { return f, nil })
	}
	if err := enroll(); err == nil || !f.closed {
		t.Fatal("failed close reported success or leaked owner")
	}
	if _, _, err := db.GetCredentialEnrollment(ctx, sandboxstore.CredentialRef{SlotRef: b.SlotRef, Generation: 1}); err != nil {
		t.Fatal("committed enrollment evidence was discarded", err)
	}
	// A separately explicit higher generation can register only after retirement.
	b.Generation = 2
	f.closeErr = nil
	if err := enroll(); err != nil {
		t.Fatal("failed close did not retire committed generation", err)
	}
}

func TestCodexStartupRejectsUnavailableBuildOrArtifactsBeforeMutation(t *testing.T) {
	c := startupCodexConfig(t)
	if err := serve(context.Background(), c); err == nil {
		t.Fatal("unprovisioned Codex startup succeeded")
	}
	for _, path := range []string{c.Socket, c.StateDatabase, c.WorkspaceRoot, c.Codex.ProviderRoot, c.Codex.Credential.Root} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("failed preparation changed %s: %v", path, err)
		}
	}
}
