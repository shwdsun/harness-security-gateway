//go:build linux && amd64 && codexintegration

package codexprovider

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOwnerServiceRequiresImmutableInstallationAndJoinedBorrows(t *testing.T) {
	file := filepath.Join(t.TempDir(), "launcher")
	if os.WriteFile(file, []byte("untrusted executable"), 0700) != nil {
		t.Fatal("fixture")
	}
	if rootInstalledExecutable(file) {
		t.Fatal("mutable/unprivileged install accepted")
	}
	if service, err := NewOwnerService(file, file); err == nil || service != nil {
		t.Fatal("unsafe artifacts passed production factory")
	}
	a, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	s := &OwnerService{files: &ownerNativeFiles{launcher: a, native: b}, refs: 1}
	if s.Close() == nil {
		t.Fatal("native FDs closed with live Run borrow")
	}
	if _, err := a.Stat(); err != nil {
		t.Fatal("failure nevertheless closed pinned FD")
	}
	s.release()
	if s.Close() != nil || s.Close() != nil {
		t.Fatal("joined borrows could not close")
	}
}
