package dockerruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
)

type preparingResource struct {
	runtime                        *Runtime
	runID                          string
	directory                      string
	prepareErr, closeErr, finalErr error
	registered, stopped, finalized bool
}

func (p *preparingResource) Paths() (string, string) {
	return filepath.Join(p.directory, "owner.sock"), filepath.Join(p.directory, "ca.pem")
}
func (*preparingResource) VerifyMounted(int) error { return nil }
func (*preparingResource) Open() error             { return nil }
func (p *preparingResource) Prepare(context.Context) error {
	p.registered = p.runtime.runProvider(p.runID) == p
	return p.prepareErr
}
func (p *preparingResource) Close(context.Context) error { p.stopped = true; return p.closeErr }
func (p *preparingResource) ClientCredential() (*credentialsource.Handoff, credentialsource.Binding) {
	return &credentialsource.Handoff{}, credentialsource.Binding{Root: filepath.Join(p.directory, "seed"), Directory: "local"}
}
func (*preparingResource) VerifyInitial() error { return nil }
func (p *preparingResource) Finalize() error {
	if !p.stopped {
		return errors.New("finalized before join")
	}
	p.finalized = true
	return p.finalErr
}

func TestProviderRegistersBeforePreparationAndRetainsEveryFailure(t *testing.T) {
	for _, fault := range []string{"prepare", "join", "finalize", "none"} {
		t.Run(fault, func(t *testing.T) {
			r := &Runtime{}
			resource := &preparingResource{runtime: r, runID: "prepared-run"}
			root := t.TempDir()
			if os.Chmod(root, 0700) != nil {
				t.Fatal("private fixture")
			}
			if fault == "prepare" {
				resource.prepareErr = ErrCredentialUnavailable
			}
			if fault == "join" {
				resource.closeErr = ErrCredentialUnavailable
			}
			if fault == "finalize" {
				resource.finalErr = ErrCredentialUnavailable
			}
			spec := targetSpec{credential: &credentialSpec{ownerOnly: true, provider: &providerSpec{root: root, createOwner: func(_ context.Context, dir, _, _ string, _ *credentialsource.OwnerAccess) (runProvider, error) {
				resource.directory = dir
				return resource, nil
			}}}}
			mounted, err := r.prepareProviderOwner(context.Background(), resource.runID, spec, &credentialsource.OwnerAccess{})
			if !resource.registered || r.runProvider(resource.runID) != resource || (err != nil) != (fault == "prepare") {
				t.Fatal("preparation lost resource ownership", err)
			}
			if err == nil && (mounted.credential.binding.Root == spec.credential.binding.Root || strings.Contains(strings.Join(mounted.credential.arguments(), " "), "src=/auth.json")) {
				t.Fatal("mounted owner binding instead of distinct seed")
			}
			if _, err := r.prepareProviderOwner(context.Background(), resource.runID, spec, &credentialsource.OwnerAccess{}); err == nil {
				t.Fatal("duplicate preparation reused path/resource")
			}
			if err := r.stopRunProvider(context.Background(), resource.runID); (err != nil) != (fault == "join") {
				t.Fatal("join result lost")
			}
			if resource.finalized || r.runProvider(resource.runID) != resource {
				t.Fatal("pre-removal join released seed")
			}
			err = r.CloseRunResources(context.Background(), resource.runID)
			bad := fault == "join" || fault == "finalize"
			if (err != nil) != bad || (r.runProvider(resource.runID) != nil) != bad {
				t.Fatal("finalization forgot a failed resource", err)
			}
			if fault == "join" && resource.finalized {
				t.Fatal("unjoined provider finalized")
			}
		})
	}
}
