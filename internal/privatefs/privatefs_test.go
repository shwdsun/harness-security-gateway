package privatefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureDirCreatesAndReusesExactPrivateDirectory(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "runtime", "connectors", "fake")
	if err := EnsureDir(path, 0o700); err != nil {
		t.Fatalf("EnsureDir() error = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory = %#v, err = %v", info, err)
	}
	if err := EnsureDir(path, 0o700); err != nil {
		t.Fatalf("idempotent EnsureDir() error = %v", err)
	}
	if err := EnsureParent(filepath.Join(path, "agentd.sock"), 0o700); err != nil {
		t.Fatalf("EnsureParent() error = %v", err)
	}
}

func TestEnsureDirRejectsExistingLooseMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(path, 0o700); !errors.Is(err, ErrMode) {
		t.Fatalf("EnsureDir() error = %v, want ErrMode", err)
	}
}

func TestEnsureDirRejectsSymlinkAtAnyComponent(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(filepath.Join(link, "child"), 0o700); !errors.Is(err, ErrSymlink) {
		t.Fatalf("EnsureDir() error = %v, want ErrSymlink", err)
	}
}

func TestEnsureDirRejectsFileAndUnsafeInputs(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(file, 0o700); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("file error = %v", err)
	}
	for _, path := range []string{"", "relative", "/"} {
		if err := EnsureDir(path, 0o700); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("EnsureDir(%q) error = %v", path, err)
		}
	}
	if err := EnsureDir(filepath.Join(t.TempDir(), "runtime"), 0o755); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("loose requested mode error = %v", err)
	}
}
