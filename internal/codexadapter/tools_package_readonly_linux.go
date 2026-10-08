//go:build linux

package codexadapter

import (
	"os"

	"golang.org/x/sys/unix"
)

// Fstatfs describes the opened file's actual mount, including a bind mount or
// nested mount, rather than permission bits or the underlying filesystem type.
func packageReadOnlyFD(fd uintptr) bool {
	var filesystem unix.Statfs_t
	return unix.Fstatfs(int(fd), &filesystem) == nil && filesystem.Flags&unix.ST_RDONLY != 0
}

func packageReadOnlyDirectory(path string, observed os.FileInfo) bool {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	f := os.NewFile(uintptr(fd), "codex-package-directory")
	opened, err := f.Stat()
	valid := err == nil && opened.IsDir() && os.SameFile(observed, opened) && packageReadOnlyFD(f.Fd())
	return f.Close() == nil && valid
}
