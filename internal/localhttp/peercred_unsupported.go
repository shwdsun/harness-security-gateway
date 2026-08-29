//go:build !linux

package localhttp

import (
	"net"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
)

func peerCredentialsSupported() bool { return false }

func connectedPeerUID(net.Conn) (localidentity.UID, error) {
	return 0, ErrPeerUnsupported
}
