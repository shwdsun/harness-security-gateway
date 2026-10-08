package codexprovider

import (
	"errors"
	"io"
)

const SocketPath = "/run/hsg-provider.sock"
const CAPath = "/run/hsg-provider-ca.pem"

var (
	ErrConfiguration = errors.New("codexprovider: invalid fixed endpoint")
	ErrClosed        = errors.New("codexprovider: admission closed")
	ErrCleanup       = errors.New("codexprovider: cleanup incomplete")
	ErrUpstream      = errors.New("codexprovider: upstream unavailable")
)

// Response is internal transport data, never a log or public diagnostic.
// Close must interrupt Read and release all resources belonging to the body.
// MediaType is the effective fixed-route transport type, not proof of valid
// event contents or an assertion that the upstream supplied a MIME field.
type Response struct {
	Status    int
	MediaType string
	Body      io.ReadCloser
}
