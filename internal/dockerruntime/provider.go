package dockerruntime

import (
	"context"
	"os"
	"path/filepath"

	"github.com/shwdsun/harness-security-gateway/internal/codexprovider"
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
	root   string
	create func(context.Context, string) (runProvider, error)
}

func (r *Runtime) prepareProvider(ctx context.Context, runID string, spec targetSpec) (targetSpec, error) {
	if spec.credential == nil || spec.credential.provider == nil {
		return spec, nil
	}
	p := spec.credential.provider
	if validateDirectory(p.root, p.root) != nil || validatePrivateDirectory(p.root) != nil {
		return spec, ErrInvalidStorage
	}
	r.credentialMu.Lock()
	defer r.credentialMu.Unlock()
	if r.providers[runID] != nil {
		return spec, ErrCredentialUnavailable
	}
	directory := filepath.Join(p.root, deterministicName(runID))
	// Never reuse a stale path after owner replacement or failed construction.
	if os.Mkdir(directory, 0o700) != nil {
		return spec, ErrCredentialUnavailable
	}
	endpoint, err := p.create(ctx, directory)
	if err != nil {
		return spec, ErrCredentialUnavailable
	}
	if r.providers == nil {
		r.providers = make(map[string]runProvider)
	}
	r.providers[runID] = endpoint
	return providerMounts(spec, endpoint), nil
}

func providerMounts(spec targetSpec, endpoint runProvider) targetSpec {
	c := *spec.credential
	c.binds = append([]credentialBind(nil), c.binds...)
	socket, ca := endpoint.Paths()
	c.binds = append(c.binds, credentialBind{socket, codexprovider.SocketPath}, credentialBind{ca, codexprovider.CAPath})
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
func (r *Runtime) CloseRunResources(ctx context.Context, runID string) error {
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
	r.credentialMu.Lock()
	if r.providers[runID] == endpoint {
		delete(r.providers, runID)
	}
	r.credentialMu.Unlock()
	return nil
}
