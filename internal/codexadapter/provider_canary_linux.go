//go:build linux && codexintegration

package codexadapter

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/codexprovider"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/providerrelay"
)

// ProviderCanaryLauncher is the fixed experimental HTTPS overlay. Its binary
// hash belongs to the separate owner-bound candidate pin, never the V3 pin.
// It offers no path, proxy, CA, destination or model configuration.
type ProviderCanaryLauncher struct{}

func (ProviderCanaryLauncher) Start(ctx context.Context, invocation Invocation) (Process, error) {
	if invocation.Path != codexprofile.CLIBinaryPathV3 || len(invocation.Args) == 0 || invocation.Args[len(invocation.Args)-1] != "-" || os.Geteuid() != 1000 {
		return nil, errInvalidConfig
	}
	relay, err := providerrelay.Start(ctx, codexprovider.SocketPath, localidentity.UID(1000))
	if err != nil {
		return nil, errInvalidConfig
	}
	args := append([]string(nil), invocation.Args[:len(invocation.Args)-1]...)
	invocation.Args = append(args, "--skip-git-repo-check", "--config", `model_provider="hsg-subscription-https"`,
		"--config", `model_providers.hsg-subscription-https={name="HSG subscription HTTPS",base_url="https://chatgpt.com/backend-api/codex",wire_api="responses",requires_openai_auth=true,supports_websockets=false}`,
		"--config", `features.enable_request_compression=false`, "-")
	invocation.Env = append(append([]string(nil), invocation.Env...), "HTTPS_PROXY=http://"+relay.Address(), "HTTP_PROXY=http://"+relay.Address(), "CODEX_CA_CERTIFICATE="+codexprovider.CAPath)
	process, err := (ExecLauncher{}).Start(ctx, invocation)
	if err != nil {
		return nil, errors.Join(err, relay.Close())
	}
	return &providerCanaryProcess{Process: process, relay: relay}, nil
}

type providerCanaryProcess struct {
	Process
	relay io.Closer
}

func (p *providerCanaryProcess) Wait() error {
	nativeErr := p.Process.Wait()
	relayErr := p.relay.Close()
	// Do not retain either source error or native output in the HRP result.
	if nativeErr != nil {
		nativeErr = errNativeWait
	}
	if relayErr != nil {
		relayErr = errRelayWait
	}
	return errors.Join(nativeErr, relayErr)
}
