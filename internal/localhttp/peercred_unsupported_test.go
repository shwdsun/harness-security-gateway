//go:build !linux

package localhttp

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestListenFailsClosedWithoutLinuxPeerCredentials(t *testing.T) {
	listener, err := Listen(filepath.Join(t.TempDir(), "service.sock"), 1000)
	if listener != nil || !errors.Is(err, ErrPeerUnsupported) {
		t.Fatalf("Listen() = %v, %v, want nil, ErrPeerUnsupported", listener, err)
	}
}
