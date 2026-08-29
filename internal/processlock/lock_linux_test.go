//go:build linux

package processlock

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAcquireFencesIndependentOwnersUntilClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandboxd.lock")
	first, err := Acquire(path)
	if err != nil {
		t.Fatalf("Acquire(first): %v", err)
	}
	if _, err := Acquire(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("Acquire(second) error = %v, want ErrLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close(first): %v", err)
	}
	second, err := Acquire(path)
	if err != nil {
		t.Fatalf("Acquire(after close): %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("Close(second): %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode = %v, want regular 0600", info.Mode())
	}
}

func TestAcquireRejectsUnsafeFilesAndPaths(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "relaxed.lock")
	if err := os.WriteFile(regular, nil, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Acquire(regular); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("relaxed file error = %v, want ErrUnsafeFile", err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}
	symlink := filepath.Join(root, "symlink.lock")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := Acquire(symlink); err == nil {
		t.Fatal("symlink lock accepted")
	}
	for _, path := range []string{"", "relative.lock", "/"} {
		if _, err := Acquire(path); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("Acquire(%q) error = %v, want ErrInvalidPath", path, err)
		}
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	lock, err := Acquire(filepath.Join(t.TempDir(), "daemon.lock"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestNewLockModeDoesNotDependOnUmask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "umask.lock")
	previous := syscall.Umask(0o777)
	lock, err := Acquire(path)
	syscall.Umask(previous)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer lock.Close()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}
}
