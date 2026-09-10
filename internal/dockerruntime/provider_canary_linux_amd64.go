//go:build linux && amd64 && codexintegration

package dockerruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/shwdsun/harness-security-gateway/internal/codexprovider"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
)

// ProviderCanaryConfig freezes a local experiment, not a production V3
// resolution. The owner executable hash binds enforcement and synthetic code;
// the existing artifact tuple binds the exact Runner/overlay and tool package.
type ProviderCanaryConfig struct {
	Runtime      SyntheticV3Config
	ProviderRoot string
	OwnerSHA256  string
}

// NewProviderCanary is opt-in and absent from normal builds. Construction only
// checks local files. Provider I/O needs a separately admitted held-credential
// Run, mounted-object verification and the bootstrap permit.
func NewProviderCanary(config ProviderCanaryConfig) (*Runtime, string, func() *codexprovider.Diagnostics, error) {
	// The first controlled canary reuses this measured cached image/template.
	// No arbitrary image or system-root override is part of this live candidate.
	if config.Runtime.Manifest.Common().Runner.Image != "golang@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd" {
		return nil, "", nil, ErrInvalidConfig
	}
	for _, name := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if _, present := os.LookupEnv(name); present {
			return nil, "", nil, ErrInvalidConfig
		}
	}
	observation := &providerObservation{}
	r, pin, err := newProviderCanary(config, "live", func(ctx context.Context, dir string) (runProvider, error) {
		endpoint, err := codexprovider.NewLive(ctx, dir, localidentity.UID(os.Geteuid()))
		if err == nil {
			observation.capture(endpoint)
		}
		return endpoint, err
	})
	return r, pin, observation.snapshot, err
}

// Retain one endpoint observation after Runtime releases its ownership entry.
// This single-Run canary has no unbounded per-Run diagnostic map. Unexpected
// multiple creations make the observation unavailable, never select a Run.
type providerObservation struct {
	mu        sync.Mutex
	endpoint  *codexprovider.Endpoint
	ambiguous bool
}

func (o *providerObservation) capture(endpoint *codexprovider.Endpoint) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.endpoint != nil || o.ambiguous {
		o.endpoint, o.ambiguous = nil, true
		return
	}
	o.endpoint = endpoint
}

func (o *providerObservation) snapshot() *codexprovider.Diagnostics {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.endpoint == nil {
		return nil
	}
	d := o.endpoint.Diagnostics()
	return &d
}

// NewSyntheticProviderCanary has a distinct pin and cannot acquire an upstream
// transport. The callback belongs to the hashed fixture owner, never a message.
func NewSyntheticProviderCanary(config ProviderCanaryConfig, respond func(context.Context, codexprovider.Request) (codexprovider.Response, error)) (*Runtime, string, error) {
	if respond == nil {
		return nil, "", ErrInvalidConfig
	}
	return newProviderCanary(config, "synthetic", func(ctx context.Context, dir string) (runProvider, error) {
		return codexprovider.NewSynthetic(ctx, dir, localidentity.UID(os.Geteuid()), respond)
	})
}

func newProviderCanary(config ProviderCanaryConfig, mode string, create func(context.Context, string) (runProvider, error)) (*Runtime, string, error) {
	r, oldPin, err := NewSyntheticV3(config.Runtime)
	if err != nil {
		return nil, "", err
	}
	if validateDirectory(config.ProviderRoot, config.ProviderRoot) != nil || validatePrivateDirectory(config.ProviderRoot) != nil || !validContainerID(config.OwnerSHA256) {
		return nil, "", ErrInvalidStorage
	}
	for _, path := range []string{config.Runtime.WorkspaceRoot, config.Runtime.Credential.Root, config.Runtime.ToolPackage} {
		if config.ProviderRoot == path || strings.HasPrefix(config.ProviderRoot+"/", path+"/") || strings.HasPrefix(path+"/", config.ProviderRoot+"/") {
			return nil, "", ErrInvalidStorage
		}
	}
	// /proc/self/exe pins the executing object, including an unlinked executable;
	// hashing a potentially replaced command pathname would not bind this owner.
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, "", ErrInvalidConfig
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (512<<20)+1))
	closeErr := f.Close()
	if err != nil || closeErr != nil || n == 0 || n > 512<<20 || hex.EncodeToString(h.Sum(nil)) != config.OwnerSHA256 {
		return nil, "", ErrInvalidConfig
	}
	data, err := json.Marshal(struct {
		Mode, BasePin, Policy string
		Config                ProviderCanaryConfig
	}{mode, oldPin, codexprovider.PolicyID, config})
	if err != nil {
		return nil, "", ErrInvalidConfig
	}
	digest := sha256.Sum256(append([]byte("harness-security-gateway.provider-canary/owner-join-v1\x00"), data...))
	pin := hex.EncodeToString(digest[:])
	for key, spec := range r.targets {
		spec.credential.pin = pin
		spec.credential.provider = &providerSpec{root: config.ProviderRoot, create: create}
		r.targets[key] = spec
	}
	r.inventoryPin = pin
	return r, pin, nil
}
