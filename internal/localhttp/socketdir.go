package localhttp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/privatefs"
)

// PrepareSocketParent preserves owner-only development directories. For a
// different peer UID, the operator must provision a listener-owned setgid 02710
// directory and an edge-specific group first. We only inspect that layout;
// startup must never create a shared directory or change its permissions.
// The group permits traversal/connect, not authentication: Listen still checks
// the exact peer UID. Trusted provisioning must prevent concurrent replacement
// and separately establish the peer's group membership and ancestor traversal.
func PrepareSocketParent(path string, peerUID localidentity.UID) error {
	if err := peerUID.Validate(); err != nil {
		return err
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		strings.ContainsRune(path, '\x00') || path == "/" {
		return ErrNonAbsoluteSocket
	}
	if peerUID.Uint32() == uint32(os.Geteuid()) {
		return privatefs.EnsureParent(path, 0o700)
	}

	parent := filepath.Dir(path)
	for directory := parent; ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("inspect pre-provisioned socket directory: %w", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok {
			return fmt.Errorf("socket directory hierarchy must contain only non-symlink directories")
		}
		if directory == parent {
			if stat.Uid != uint32(os.Geteuid()) || info.Mode() != os.ModeDir|os.ModeSetgid|0o710 {
				return fmt.Errorf("distinct-UID socket parent must be listener-owned with mode 02710")
			}
		} else if (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) ||
			(info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return fmt.Errorf("socket ancestor must prevent replacement by other users")
		}
		if directory == "/" {
			return nil
		}
	}
}
