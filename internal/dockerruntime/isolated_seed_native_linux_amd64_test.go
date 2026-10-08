//go:build linux && amd64 && codexintegration

package dockerruntime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"golang.org/x/sys/unix"
)

// Only readiness/transport is a fake. This fixture uses the actual wrapper,
// original owner capability and ext4 proof backend; it grants no native helper,
// service-gate, container receiver, provider or model acceptance.
type seedLifecycleEndpoint struct {
	runtime    *Runtime
	runID      string
	resource   *isolatedRun
	entered    chan struct{}
	mode       string
	prepareErr error
	closeErr   error
	registered bool
}

var localSeedFixture = []byte(`{"auth_mode":"chatgpt","tokens":{"access_token":"synthetic-local-only"}}`)

func (*seedLifecycleEndpoint) InitialAuth() ([]byte, error) {
	return bytes.Clone(localSeedFixture), nil
}
func (e *seedLifecycleEndpoint) Prepare(ctx context.Context) error {
	e.registered = e.runtime.runProvider(e.runID) == e.resource
	handoff, binding := e.resource.ClientCredential()
	if !e.registered || handoff == nil || handoff.Validate(e.runID, e.resource.fingerprint, binding) != nil || e.resource.VerifyInitial() != nil {
		return errors.New("native seed was not ready under registered ownership")
	}
	close(e.entered)
	if e.mode == "canceled" {
		<-ctx.Done()
		return ctx.Err()
	}
	return e.prepareErr
}
func (e *seedLifecycleEndpoint) Paths() (string, string) {
	return filepath.Join(e.resource.directory, "owner.sock"), filepath.Join(e.resource.directory, "ca.pem")
}
func (*seedLifecycleEndpoint) VerifyMounted(int) error       { return ErrCredentialUnavailable }
func (*seedLifecycleEndpoint) Open() error                   { return ErrCredentialUnavailable }
func (e *seedLifecycleEndpoint) Close(context.Context) error { return e.closeErr }

func TestIsolatedNativeSeedLifecycle(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged ext4 witness required")
	}
	// This test needs an ext4 TMPDIR with trusted ancestors. A group-writable
	// checkout is intentionally not accepted as a credential-root ancestor.
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Skip("native seed composition requires ext4 private temporary storage")
	}
	fingerprint, err := codexprofile.V4().Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"ready", "readiness-failure", "canceled", "unjoined"} {
		t.Run(mode, func(t *testing.T) {
			mustDir := func(path string) {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			fixture := filepath.Join(root, mode)
			mustDir(fixture)
			ownerRoot, providerRoot := filepath.Join(fixture, "owner"), filepath.Join(fixture, "provider")
			mustDir(ownerRoot)
			mustDir(filepath.Join(ownerRoot, "enrolled"))
			mustDir(providerRoot)
			canary := []byte("synthetic-owner-secret-" + mode)
			ownerPath := filepath.Join(ownerRoot, "enrolled", "auth.json")
			if err := os.WriteFile(ownerPath, canary, 0600); err != nil {
				t.Fatal(err)
			}
			held, err := credentialsource.Hold(ownerRoot, "enrolled")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := held.Close(); err != nil {
					t.Error("original held-source cleanup", err)
				}
			})
			source, proof, err := held.CaptureProof()
			if err != nil {
				t.Fatal("actual original proof", err)
			}
			binding := credentialsource.Binding{Root: ownerRoot, Directory: "enrolled", SlotRef: "fixture-slot", Generation: 7, WorkspaceRef: "fixture-workspace", AuthProfileRef: codexprofile.AuthProfileRefV4}
			runID := "native-seed-" + mode
			owner, err := held.BorrowForOwner(runID, fingerprint, binding, source, proof)
			if err != nil || owner.Claim(runID, fingerprint, binding) != nil {
				t.Fatal("actual owner claim", err)
			}
			runtime := &Runtime{}
			endpoint := &seedLifecycleEndpoint{runtime: runtime, runID: runID, mode: mode, entered: make(chan struct{})}
			if mode == "readiness-failure" {
				endpoint.prepareErr = ErrCredentialUnavailable
			}
			if mode == "unjoined" {
				endpoint.closeErr = ErrCredentialUnavailable
			}
			var resource *isolatedRun
			spec := targetSpec{fingerprint: fingerprint, credential: &credentialSpec{ownerOnly: true, binding: binding, provider: &providerSpec{root: providerRoot, createOwner: func(_ context.Context, dir, run, fp string, original *credentialsource.OwnerAccess) (runProvider, error) {
				seedBinding := binding
				seedBinding.Root, seedBinding.Directory = filepath.Join(dir, "client-seed"), "local"
				resource = &isolatedRun{endpoint: endpoint, owner: original, runID: run, fingerprint: fp, directory: dir, binding: seedBinding}
				endpoint.resource = resource
				return resource, nil
			}}}}
			t.Cleanup(func() {
				endpoint.closeErr = nil
				if err := runtime.CloseRunResources(context.Background(), runID); err != nil {
					t.Error("fixture join/finalization", err)
				}
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				go func() {
					select {
					case <-endpoint.entered:
						cancel()
					case <-ctx.Done():
					}
				}()
			}
			mounted, err := runtime.prepareProviderOwner(ctx, runID, spec, owner)
			if (err != nil) != (mode == "readiness-failure" || mode == "canceled") || !endpoint.registered || runtime.runProvider(runID) != resource {
				t.Fatal("native seed/preparation ownership lost", err)
			}
			if mode == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation attribution lost")
			}
			handoff, seedBinding := resource.ClientCredential()
			if handoff.Validate(runID, fingerprint, seedBinding) != nil || handoff.Validate(runID, fingerprint, binding) == nil || owner.ValidateClaimed(runID, fingerprint, seedBinding) == nil || owner.ValidateClaimed(runID, fingerprint, binding) != nil {
				t.Fatal("native owner/seed bindings were interchangeable")
			}
			launch := &credentialLaunch{source: handoff, owner: owner, binding: seedBinding, runID: runID}
			if launch.validate(spec) != nil || launch.validate(spec) != nil {
				t.Fatal("attach rejected independent valid owner and seed capabilities")
			}
			for _, wrong := range []credentialLaunch{
				{source: handoff, binding: seedBinding, runID: runID},
				{owner: owner, binding: seedBinding, runID: runID},
				{source: handoff, owner: owner, binding: binding, runID: runID},
				{source: handoff, owner: owner, binding: seedBinding, runID: runID + "-other"},
			} {
				if wrong.validate(spec) == nil {
					t.Fatal("attach accepted missing or mismatched native capability")
				}
			}
			wrongSpec := spec
			wrongCredential := *spec.credential
			wrongSpec.credential = &wrongCredential
			wrongCredential.binding = seedBinding
			if launch.validate(wrongSpec) == nil {
				t.Fatal("seed binding replaced original owner authority")
			}
			wrongCredential.binding, wrongCredential.ownerOnly = binding, false
			if launch.validate(wrongSpec) == nil {
				t.Fatal("legacy attach accepted an owner capability")
			}
			legacy := *launch
			legacy.owner = nil
			if legacy.validate(wrongSpec) == nil {
				t.Fatal("legacy attach used the disposable binding instead of its configured source")
			}
			wrongCredential.binding = seedBinding
			if legacy.validate(wrongSpec) != nil {
				t.Fatal("valid legacy source rejected")
			}
			legacy.binding = binding
			if legacy.validate(wrongSpec) != nil {
				t.Fatal("legacy validation depended on the owner-only seed field")
			}
			if err == nil && (mounted.credential.binding != seedBinding || strings.Contains(strings.Join(mounted.credential.arguments(), " "), ownerRoot)) {
				t.Fatal("owner source entered Runner mount arguments")
			}
			seedBytes, err := os.ReadFile(filepath.Join(seedBinding.Root, seedBinding.Directory, "auth.json"))
			if err != nil || !bytes.Equal(seedBytes, localSeedFixture) || bytes.Contains(seedBytes, canary) {
				t.Fatal("seed contents include owner canary or changed local fixture")
			}
			if err := runtime.stopRunProvider(context.Background(), runID); (err != nil) != (mode == "unjoined") {
				t.Fatal("stop/join result", err)
			}
			if runtime.runProvider(runID) != resource || handoff.Validate(runID, fingerprint, seedBinding) != nil || owner.ValidateClaimed(runID, fingerprint, binding) != nil {
				t.Fatal("pre-absence stop finalized native capabilities")
			}
			if mode == "unjoined" {
				if runtime.CloseRunResources(context.Background(), runID) == nil || runtime.runProvider(runID) != resource || owner.ValidateClaimed(runID, fingerprint, binding) != nil {
					t.Fatal("unjoined seed/owner ownership forgotten")
				}
				endpoint.closeErr = nil
			}
			// No Create was dispatched in this fixture: certain non-dispatch.
			if runtime.CloseRunResources(context.Background(), runID) != nil || runtime.runProvider(runID) != nil || handoff.Validate(runID, fingerprint, seedBinding) == nil || owner.ValidateClaimed(runID, fingerprint, binding) == nil || held.Validate() != nil {
				t.Fatal("finalization confused borrowed capability and original health")
			}
			if launch.validate(spec) == nil {
				t.Fatal("finalized owner and seed could authorize attach")
			}
			if again, err := credentialsource.Hold(ownerRoot, "enrolled"); !errors.Is(err, credentialsource.ErrBusy) {
				if again != nil {
					_ = again.Close()
				}
				t.Fatal("finalization released controller's original lock", err)
			}
			ownerBytes, err := os.ReadFile(ownerPath)
			if err != nil || !bytes.Equal(ownerBytes, canary) {
				t.Fatal("local seed preparation changed original auth")
			}
		})
	}
}
