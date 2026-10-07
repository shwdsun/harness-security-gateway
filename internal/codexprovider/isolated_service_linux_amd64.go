//go:build linux && amd64 && codexintegration

package codexprovider

import (
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"golang.org/x/sys/unix"
)

// OwnerService owns fixed executable FDs, not credentials or durable admission.
// Construction is inert. Activate is required after the process lock and before
// stores/recovery; Close cannot release FDs while a Run still borrows them.
type OwnerService struct {
	mu       sync.Mutex
	files    *ownerNativeFiles
	startup  *ownerStartup
	refs     int
	closed   bool
	closeErr error
}

func NewOwnerService(launcher, native string) (*OwnerService, error) {
	if !rootInstalledExecutable(launcher) || !rootInstalledExecutable(native) {
		return nil, ErrOwnerAuth
	}
	files, err := openOwnerNativeFiles(launcher, native, codexprofile.OwnerLauncherSHA256V4)
	if err != nil {
		return nil, err
	}
	// Recheck pinned FDs as well as the paths; FD pin alone cannot prevent
	// same-inode writes by the unprivileged owner.
	for _, f := range []*os.File{files.launcher, files.native} {
		var st unix.Stat_t
		if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			files.launcher.Close()
			files.native.Close()
			return nil, ErrOwnerAuth
		}
	}
	if !rootInstalledExecutable(launcher) || !rootInstalledExecutable(native) {
		files.launcher.Close()
		files.native.Close()
		return nil, ErrOwnerAuth
	}
	return &OwnerService{files: files}, nil
}

func rootInstalledExecutable(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 ||
		st.Mode&(0022|unix.S_ISUID|unix.S_ISGID) != 0 || st.Mode&0111 == 0 {
		return false
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		if !rootControlled(dir, true) {
			return false
		}
		if dir == "/" {
			return true
		}
	}
}

func (s *OwnerService) Activate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.startup != nil || s.refs != 0 {
		return ErrOwnerAuth
	}
	gate, err := checkOwnerStartup()
	if err != nil {
		return err
	}
	s.startup = gate
	return nil
}

// NewProvider reads no credential and starts no native process. The runtime
// registers it before calling InitialAuth/Prepare. No test responder is exposed.
func (s *OwnerService) NewProvider(ctx context.Context, dir string, peer localidentity.UID, source *credentialsource.OwnerAccess) (*isolatedProvider, error) {
	s.mu.Lock()
	if s.closed || s.startup == nil || s.startup.pid != os.Getpid() {
		s.mu.Unlock()
		return nil, ErrOwnerAuth
	}
	s.refs++
	owner, err := newOwnerNative(source, dir, s.startup, s.files)
	s.mu.Unlock()
	if err != nil {
		s.release()
		return nil, err
	}
	p, err := newIsolatedProvider(ctx, dir, peer, owner)
	if err != nil {
		s.release()
		return nil, err
	}
	p.release = s.release
	return p, nil
}

func (s *OwnerService) release() { s.mu.Lock(); s.refs--; s.mu.Unlock() }

func (s *OwnerService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refs != 0 {
		return ErrCleanup
	}
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	launcherErr := s.files.launcher.Close()
	nativeErr := s.files.native.Close()
	if launcherErr != nil || nativeErr != nil {
		s.closeErr = ErrCleanup
	}
	return s.closeErr
}
