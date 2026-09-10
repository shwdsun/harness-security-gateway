//go:build linux && codexintegration

package codexprovider

import (
	"context"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
)

// NewSynthetic is absent from normal builds. The trusted fixed responder
// performs no external I/O and must make Body.Close interrupt and join Read.
func NewSynthetic(ctx context.Context, directory string, peer localidentity.UID, respond func(context.Context, Request) (Response, error)) (*Endpoint, error) {
	return newEndpoint(ctx, directory, peer, respond)
}
