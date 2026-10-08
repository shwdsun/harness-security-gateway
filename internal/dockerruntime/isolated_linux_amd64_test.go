//go:build linux && amd64 && codexintegration

package dockerruntime

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
)

func TestIsolatedSeedContentAndOwnerAreIndependent(t *testing.T) {
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private root")
	}
	dir := filepath.Join(root, "local")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("private slot")
	}
	path := filepath.Join(dir, "auth.json")
	data := []byte("random-local-auth-only")
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("seed")
	}
	held, err := credentialsource.Hold(root, "local")
	if err != nil {
		t.Fatal(err)
	}
	seed, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := &isolatedRun{held: held, seed: seed, initial: sha256.Sum256(data)}
	defer p.Finalize()
	if p.VerifyInitial() != nil {
		t.Fatal("valid initial seed denied")
	}
	if _, err := seed.WriteAt([]byte("changed"), 0); err != nil {
		t.Fatal(err)
	}
	if p.VerifyInitial() == nil || held.Validate() != nil {
		t.Fatal("same-inode content substitution escaped digest check")
	}
}

type heldSeedEndpoint struct{ runProvider }

func (*heldSeedEndpoint) InitialAuth() ([]byte, error)  { return nil, ErrCredentialUnavailable }
func (*heldSeedEndpoint) Prepare(context.Context) error { return nil }
func (*heldSeedEndpoint) Close(context.Context) error   { return nil }

func TestIsolatedCloseJoinsPreparationBeforeFinalization(t *testing.T) {
	done := make(chan struct{})
	p := &isolatedRun{endpoint: &heldSeedEndpoint{}, prepared: true, prepareDone: done}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if p.Close(ctx) == nil {
		t.Fatal("preparation obligation not retained")
	}
	close(done)
	if p.Close(context.Background()) != nil || p.Finalize() != nil {
		t.Fatal("joined preparation could not finalize")
	}
	if err := p.Prepare(context.Background()); err == nil {
		t.Fatal("closed preparation restarted")
	}
}

func TestIsolatedStaticArtifactOwnershipDiffersFromMutableStorage(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root runtime required")
	}
	if validateInstalledArtifact("/usr", true) != nil {
		t.Fatal("root-controlled static artifact directory rejected")
	}
	if validateDirectory("/usr", "/usr") == nil {
		t.Fatal("static artifact directory incorrectly accepted as mutable service storage")
	}
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("fixture")
	}
	if validateDirectory(dir, dir) != nil || validateInstalledArtifact(dir, true) == nil {
		t.Fatal("service-owned storage accepted as immutable installation")
	}
}
