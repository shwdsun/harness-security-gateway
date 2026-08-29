//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris

package corestore

import "os"

// Fail closed where the standard FileInfo implementation does not expose a
// link count. Harness Security Gateway's supported production platform is Linux.
func hasSingleHardLink(os.FileInfo) bool {
	return false
}
