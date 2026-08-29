//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package corestore

import (
	"os"
	"syscall"
)

// hasSingleHardLink is an accidental-alias preflight, not an inode or mount
// identity fence. The caller must evaluate it at an existing Lstat boundary.
func hasSingleHardLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Nlink) == 1
}
