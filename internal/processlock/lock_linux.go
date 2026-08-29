//go:build linux

// Package processlock provides the small, persistent advisory lock used to
// fence one local daemon owner across transport-socket shutdown windows.
package processlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

var (
	ErrInvalidPath = errors.New("process lock path is invalid")
	ErrUnsafeFile  = errors.New("process lock file is unsafe")
	ErrLocked      = errors.New("process lock is already held")
)

// Lock is an exclusive non-blocking flock on a persistent private file. The
// file is intentionally never unlinked: unlinking a lock file permits two
// processes to lock different inodes under the same pathname.
type Lock struct {
	file *os.File
	once sync.Once
	err  error
}

func Acquire(path string) (*Lock, error) {
	if path == "" || !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
		return nil, ErrInvalidPath
	}
	clean := filepath.Clean(path)
	if clean == string(filepath.Separator) {
		return nil, ErrInvalidPath
	}

	flags := syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	fd, err := syscall.Open(clean, flags|syscall.O_CREAT|syscall.O_EXCL, 0o600)
	created := err == nil
	if errors.Is(err, syscall.EEXIST) {
		fd, err = syscall.Open(clean, flags, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open process lock: %w", err)
	}
	closeFD := true
	defer func() {
		if closeFD {
			_ = syscall.Close(fd)
		}
	}()
	if created {
		// Creation mode is still filtered by the caller's umask. Tighten the new
		// inode to the one exact mode without ever chmodding an existing file.
		if err := syscall.Fchmod(fd, 0o600); err != nil {
			return nil, fmt.Errorf("secure new process lock: %w", err)
		}
	}

	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("inspect process lock: %w", err)
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		stat.Mode&0o777 != 0o600 || int(stat.Uid) != os.Geteuid() {
		return nil, ErrUnsafeFile
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("acquire process lock: %w", err)
	}

	file := os.NewFile(uintptr(fd), clean)
	if file == nil {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		return nil, ErrUnsafeFile
	}
	closeFD = false
	return &Lock{file: file}, nil
}

func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.file == nil {
			return
		}
		unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
		closeErr := l.file.Close()
		switch {
		case unlockErr != nil:
			l.err = fmt.Errorf("release process lock: %w", unlockErr)
		case closeErr != nil:
			l.err = fmt.Errorf("close process lock: %w", closeErr)
		}
	})
	return l.err
}
