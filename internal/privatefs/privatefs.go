// Package privatefs prepares daemon-owned directories without silently
// following symlinks or relaxing an existing directory's permissions.
package privatefs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var (
	ErrInvalidPath = errors.New("invalid private directory path")
	ErrSymlink     = errors.New("private directory path contains a symlink")
	ErrOwner       = errors.New("private directory has an unexpected owner")
	ErrMode        = errors.New("private directory has unexpected permissions")
)

// EnsureDir creates missing path components and verifies that the final
// directory is a non-symlink directory owned by the current effective user
// with exactly perm. Existing components are never chmodded or replaced.
func EnsureDir(path string, perm os.FileMode) error {
	if path == "" || !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') || perm.Perm() == 0 || perm.Perm()&0o077 != 0 {
		return ErrInvalidPath
	}
	clean := filepath.Clean(path)
	if clean == string(filepath.Separator) {
		return ErrInvalidPath
	}

	components := pathPrefixes(clean)
	for index, component := range components {
		info, err := os.Lstat(component)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: component %d", ErrSymlink, index)
			}
			if !info.IsDir() {
				return fmt.Errorf("%w: component %d is not a directory", ErrInvalidPath, index)
			}
		case errors.Is(err, os.ErrNotExist):
			if err := os.Mkdir(component, perm.Perm()); err != nil {
				return fmt.Errorf("create private directory component %d: %w", index, err)
			}
			info, err = os.Lstat(component)
			if err != nil {
				return fmt.Errorf("inspect new private directory component %d: %w", index, err)
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("%w: new component %d", ErrSymlink, index)
			}
		case err != nil:
			return fmt.Errorf("inspect private directory component %d: %w", index, err)
		}
	}

	info, err := os.Lstat(clean)
	if err != nil {
		return fmt.Errorf("inspect private directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return ErrOwner
	}
	if info.Mode().Perm() != perm.Perm() {
		return fmt.Errorf("%w: got %04o, want %04o", ErrMode, info.Mode().Perm(), perm.Perm())
	}
	return nil
}

// EnsureParent prepares the parent directory of an absolute file/socket path.
func EnsureParent(path string, perm os.FileMode) error {
	if path == "" || !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
		return ErrInvalidPath
	}
	return EnsureDir(filepath.Dir(filepath.Clean(path)), perm)
}

func pathPrefixes(path string) []string {
	volume := filepath.VolumeName(path)
	remainder := strings.TrimPrefix(path, volume+string(filepath.Separator))
	parts := strings.Split(remainder, string(filepath.Separator))
	current := volume + string(filepath.Separator)
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		result = append(result, current)
	}
	return result
}
