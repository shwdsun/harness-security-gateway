//go:build linux

package localhttp

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
)

func peerCredentialsSupported() bool { return true }

func connectedPeerUID(connection net.Conn) (localidentity.UID, error) {
	syscallConnection, ok := connection.(syscall.Conn)
	if !ok {
		return 0, errors.New("accepted connection has no syscall descriptor")
	}
	raw, err := syscallConnection.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("access accepted socket descriptor: %w", err)
	}
	var credentials *syscall.Ucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, credentialErr = syscall.GetsockoptUcred(
			int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED,
		)
	}); err != nil {
		return 0, fmt.Errorf("inspect accepted socket descriptor: %w", err)
	}
	if credentialErr != nil {
		return 0, fmt.Errorf("read SO_PEERCRED: %w", credentialErr)
	}
	if credentials == nil {
		return 0, errors.New("read SO_PEERCRED: empty credentials")
	}
	return localidentity.UID(credentials.Uid), nil
}
