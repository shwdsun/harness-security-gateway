//go:build linux && amd64 && codexintegration

package dockerruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/codexprovider"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
)

type isolatedEndpoint interface {
	runProvider
	InitialAuth() ([]byte, error)
	Prepare(context.Context) error
}

type isolatedRun struct {
	endpoint                      isolatedEndpoint
	owner                         *credentialsource.OwnerAccess
	runID, fingerprint, directory string
	binding                       credentialsource.Binding
	mu                            sync.Mutex
	seed                          *os.File
	held                          *credentialsource.HeldSource
	handoff                       *credentialsource.Handoff
	initial                       [32]byte
	prepared, finalized           bool
	stopped                       bool
	prepareDone                   chan struct{}
	finalErr                      error
}

func newConfiguredIsolated(config sandboxconfig.Config) (*Runtime, string, error) {
	if config.Schema != sandboxconfig.SchemaCodexV2 || config.Validate() != nil {
		return nil, "", ErrInvalidConfig
	}
	p := config.Codex
	service, err := codexprovider.NewOwnerService(p.OwnerLauncher.Path, filepath.Join(p.ToolPackage, "bin/codex"))
	if err != nil {
		return nil, "", ErrCredentialUnavailable
	}
	r, pin, err := configuredCodex(config, func(c ProviderCanaryConfig) (*Runtime, string, error) {
		if validateLiveProvider(c) != nil {
			return nil, "", ErrInvalidConfig
		}
		base, basePin, err := newToolRuntime(c.Runtime, codexprofile.V4(), "harness-security-gateway.isolated-tool-runtime/v1")
		if err != nil {
			return nil, "", err
		}
		if validateDirectory(c.ProviderRoot, c.ProviderRoot) != nil || validatePrivateDirectory(c.ProviderRoot) != nil {
			return nil, "", ErrInvalidStorage
		}
		f, err := os.Open("/proc/self/exe")
		if err != nil {
			return nil, "", ErrInvalidConfig
		}
		h := sha256.New()
		n, readErr := io.Copy(h, io.LimitReader(f, (512<<20)+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || n <= 0 || n > 512<<20 || hex.EncodeToString(h.Sum(nil)) != c.OwnerSHA256 {
			return nil, "", ErrInvalidConfig
		}
		profilePin, _ := codexprofile.V4().Fingerprint()
		bytes, err := json.Marshal(struct {
			BasePin, ProfilePin string
			Config              ProviderCanaryConfig
			Launcher            sandboxconfig.Artifact
		}{basePin, profilePin, c, *p.OwnerLauncher})
		if err != nil {
			return nil, "", ErrInvalidConfig
		}
		digest := sha256.Sum256(append([]byte("harness-security-gateway.isolated-owner-runtime/v1\x00"), bytes...))
		ownerPin := hex.EncodeToString(digest[:])
		for key, spec := range base.targets {
			spec.credential.ownerOnly, spec.credential.pin = true, ownerPin
			spec.credential.provider = &providerSpec{root: c.ProviderRoot, createOwner: func(ctx context.Context, dir, runID, fingerprint string, owner *credentialsource.OwnerAccess) (runProvider, error) {
				endpoint, err := service.NewProvider(ctx, dir, localidentity.UID(os.Geteuid()), owner)
				if err != nil {
					return nil, err
				}
				binding := c.Runtime.Credential
				binding.Root, binding.Directory = filepath.Join(dir, "client-seed"), "local"
				return &isolatedRun{endpoint: endpoint, owner: owner, runID: runID, fingerprint: fingerprint, directory: dir, binding: binding}, nil
			}}
			base.targets[key] = spec
		}
		return base, ownerPin, nil
	})
	if err != nil {
		_ = service.Close()
		return nil, "", err
	}
	r.ownerStartup, r.ownerArtifactsClose = service.Activate, service.Close
	return r, pin, nil
}

func (p *isolatedRun) Prepare(ctx context.Context) error {
	p.mu.Lock()
	if p.prepared || p.finalized || p.stopped {
		p.mu.Unlock()
		return ErrCredentialUnavailable
	}
	p.prepared = true
	p.prepareDone = make(chan struct{})
	p.mu.Unlock()
	defer close(p.prepareDone)
	data, err := p.endpoint.InitialAuth()
	if err != nil {
		return ErrCredentialUnavailable
	}
	defer clear(data)
	if os.Mkdir(p.binding.Root, 0700) != nil || os.Mkdir(filepath.Join(p.binding.Root, p.binding.Directory), 0700) != nil {
		return ErrCredentialUnavailable
	}
	seed, err := os.OpenFile(filepath.Join(p.binding.Root, p.binding.Directory, "auth.json"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return ErrCredentialUnavailable
	}
	p.mu.Lock()
	p.seed = seed
	p.mu.Unlock()
	if n, err := seed.Write(data); err != nil || n != len(data) || seed.Sync() != nil {
		return ErrCredentialUnavailable
	}
	p.initial = sha256.Sum256(data)
	held, err := credentialsource.Hold(p.binding.Root, p.binding.Directory)
	p.mu.Lock()
	p.held = held
	p.mu.Unlock()
	if err != nil {
		return ErrCredentialUnavailable
	}
	source, proof, err := held.CaptureProof()
	if err != nil {
		return ErrCredentialUnavailable
	}
	handoff, err := held.Handoff(p.runID, p.fingerprint, p.binding, source, proof)
	p.mu.Lock()
	p.handoff = handoff
	p.mu.Unlock()
	if err != nil || handoff.Claim(p.runID, p.fingerprint, p.binding) != nil {
		return ErrCredentialUnavailable
	}
	return p.endpoint.Prepare(ctx)
}

func (p *isolatedRun) ClientCredential() (*credentialsource.Handoff, credentialsource.Binding) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.handoff, p.binding
}
func (p *isolatedRun) Paths() (string, string)     { return p.endpoint.Paths() }
func (p *isolatedRun) VerifyMounted(pid int) error { return p.endpoint.VerifyMounted(pid) }
func (p *isolatedRun) Open() error                 { return p.endpoint.Open() }
func (p *isolatedRun) Close(ctx context.Context) error {
	p.mu.Lock()
	p.stopped = true
	done := p.prepareDone
	p.mu.Unlock()
	err := p.endpoint.Close(ctx)
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return codexprovider.ErrCleanup
		}
	}
	return err
}

func (p *isolatedRun) VerifyInitial() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finalized || p.stopped || p.held == nil || p.seed == nil || p.held.Validate() != nil {
		return ErrCredentialUnavailable
	}
	data, err := io.ReadAll(io.NewSectionReader(p.seed, 0, credentialsource.MaxOwnerBytes+1))
	defer clear(data)
	if err != nil || len(data) > credentialsource.MaxOwnerBytes || sha256.Sum256(data) != p.initial || p.held.Validate() != nil {
		return ErrCredentialUnavailable
	}
	return nil
}

// Only runtime's absence/non-dispatch finalization calls this, after Close joins
// provider/native work. It never closes the controller's original HeldSource.
func (p *isolatedRun) Finalize() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finalized {
		return p.finalErr
	}
	p.finalized = true
	p.handoff.Close()
	if p.held != nil && p.held.Close() != nil {
		p.finalErr = ErrCredentialUnavailable
	}
	if p.seed != nil && p.seed.Close() != nil {
		p.finalErr = ErrCredentialUnavailable
	}
	if p.finalErr == nil {
		p.owner.Close()
	}
	return p.finalErr
}
