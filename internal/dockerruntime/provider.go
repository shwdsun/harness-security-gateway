package dockerruntime

import (
	"context"
	"os"
	"path/filepath"

	"github.com/shwdsun/harness-security-gateway/internal/codexprovider"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
)

type runProvider interface {
	Paths() (string, string)
	VerifyMounted(int) error
	Open() error
	Close(context.Context) error
}

// Only the opt-in fixed candidate constructor populates this local factory.
// Neither the factory nor its paths are serializable Run authority.
type providerSpec struct {
	root        string
	create      func(context.Context, string) (runProvider, error)
	createOwner func(context.Context, string, string, string, *credentialsource.OwnerAccess) (runProvider, error)
}

type clientAuthProvider interface {
	runProvider
	ClientCredential() (*credentialsource.Handoff, credentialsource.Binding)
	VerifyInitial() error
	Finalize() error
}

func (r *Runtime) prepareProvider(ctx context.Context, runID string, spec targetSpec) (targetSpec, error) {
	return r.prepareProviderOwner(ctx, runID, spec, nil)
}

func (r *Runtime) prepareProviderOwner(ctx context.Context, runID string, spec targetSpec, owner *credentialsource.OwnerAccess) (targetSpec, error) {
	if spec.credential == nil || spec.credential.provider == nil {
		return spec, nil
	}
	p := spec.credential.provider
	if validateDirectory(p.root, p.root) != nil || validatePrivateDirectory(p.root) != nil {
		return spec, ErrInvalidStorage
	}
	r.credentialMu.Lock()
	if r.providers[runID] != nil {
		r.credentialMu.Unlock()
		return spec, ErrCredentialUnavailable
	}
	directory := filepath.Join(p.root, deterministicName(runID))
	// Never reuse a stale path after owner replacement or failed construction.
	if os.Mkdir(directory, 0o700) != nil {
		r.credentialMu.Unlock()
		return spec, ErrCredentialUnavailable
	}
	var endpoint runProvider
	var err error
	if spec.credential.ownerOnly && owner != nil && p.createOwner != nil {
		endpoint, err = p.createOwner(ctx, directory, runID, spec.fingerprint, owner)
	} else if !spec.credential.ownerOnly && owner == nil && p.create != nil {
		endpoint, err = p.create(ctx, directory)
	} else {
		err = ErrCredentialUnavailable
	}
	if r.providers == nil {
		r.providers = make(map[string]runProvider)
	}
	if endpoint != nil {
		r.providers[runID] = endpoint
	}
	r.credentialMu.Unlock()
	if err != nil || endpoint == nil {
		return spec, ErrCredentialUnavailable
	}
	// Registration precedes native work; do not hold the registry lock through
	// Prepare, so cancellation/cleanup can reach the resource while it blocks.
	if prepared, ok := endpoint.(interface{ Prepare(context.Context) error }); ok {
		if prepared.Prepare(ctx) != nil {
			return spec, credentialError(ctx.Err())
		}
	}
	return providerMounts(spec, endpoint), nil
}

func providerMounts(spec targetSpec, endpoint runProvider) targetSpec {
	c := *spec.credential
	c.binds = append([]credentialBind(nil), c.binds...)
	socket, ca := endpoint.Paths()
	c.binds = append(c.binds, credentialBind{socket, codexprovider.SocketPath}, credentialBind{ca, codexprovider.CAPath})
	if client, ok := endpoint.(clientAuthProvider); ok {
		_, c.binding = client.ClientCredential()
	}
	spec.credential = &c
	return spec
}

func (r *Runtime) runProvider(runID string) runProvider {
	r.credentialMu.Lock()
	defer r.credentialMu.Unlock()
	return r.providers[runID]
}

// CloseRunResources retains a failed join for reconciliation. A replacement
// owner has no old endpoint descriptors and never recreates one during cleanup.
// Durable runtime intent and credential occupancy remain the cross-process fence.
func (r *Runtime) stopRunProvider(ctx context.Context, runID string) error {
	if r == nil || ctx == nil || validateRunID(runID) != nil {
		return ErrInvalidArgument
	}
	r.credentialMu.Lock()
	endpoint := r.providers[runID]
	r.credentialMu.Unlock()
	if endpoint == nil {
		return nil
	}
	if err := endpoint.Close(ctx); err != nil {
		return err
	}
	return nil
}

// Call only after verified container absence or a certain non-dispatch proof.
// RemoveStopped uses stopRunProvider first and keeps this finalization later.
func (r *Runtime) CloseRunResources(ctx context.Context, runID string) error {
	if err := r.stopRunProvider(ctx, runID); err != nil {
		return err
	}
	endpoint := r.runProvider(runID)
	if endpoint == nil {
		return nil
	}
	if client, ok := endpoint.(clientAuthProvider); ok {
		if err := client.Finalize(); err != nil {
			return err
		}
	}
	r.credentialMu.Lock()
	if r.providers[runID] == endpoint {
		delete(r.providers, runID)
	}
	r.credentialMu.Unlock()
	return nil
}
