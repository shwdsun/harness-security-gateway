//go:build linux

package localhttp

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
)

func TestSocketParentProfilesAndInheritedGroup(t *testing.T) {
	self := localidentity.UID(os.Geteuid())
	if self.Validate() != nil {
		t.Skip("requires a concrete non-root service UID")
	}
	for _, test := range []struct {
		name       string
		peer       localidentity.UID
		mode       os.FileMode
		socketMode os.FileMode
	}{
		{"same UID", self, 0o700, 0o600},
		{"distinct UID", otherPeerUID(), os.ModeSetgid | 0o710, 0o660},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			parent := filepath.Join(root, "edge")
			if test.peer != self {
				if err := os.Mkdir(parent, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(parent, test.mode); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(parent, "service.sock")
			if err := PrepareSocketParent(path, test.peer); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(parent)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := Listen(path, test.peer)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			socket, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if socket.Mode().Perm() != test.socketMode ||
				(test.peer != self && socket.Sys().(*syscall.Stat_t).Gid != before.Sys().(*syscall.Stat_t).Gid) {
				t.Fatal("socket did not retain its expected permissions and inherited edge group")
			}
			if err := PrepareSocketParent(path, test.peer); err != nil {
				t.Fatal(err)
			}
			after, err := os.Stat(parent)
			if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() {
				t.Fatal("preparation changed the provisioned directory")
			}
		})
	}
}

func TestDistinctUIDSocketParentRejectsUnsafeLayoutWithoutRepair(t *testing.T) {
	for _, mode := range []os.FileMode{0o700, 0o710, os.ModeSetgid | 0o750,
		os.ModeSetgid | 0o770, os.ModeSetgid | 0o711, os.ModeSetgid | os.ModeSticky | 0o710} {
		t.Run(mode.String(), func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, mode); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(parent)
			if err != nil {
				t.Fatal(err)
			}
			if err := PrepareSocketParent(filepath.Join(parent, "s.sock"), otherPeerUID()); err == nil {
				t.Fatal("unsafe shared directory accepted")
			}
			after, err := os.Stat(parent)
			if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() {
				t.Fatal("rejection repaired/replaced the directory")
			}
		})
	}
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	if err := PrepareSocketParent(filepath.Join(missing, "s.sock"), otherPeerUID()); err == nil {
		t.Fatal("missing shared directory accepted")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created shared directory")
	}
	if err := os.Chmod(root, os.ModeSetgid|0o710); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if err := PrepareSocketParent(filepath.Join(link, "s.sock"), otherPeerUID()); err == nil {
		t.Fatal("symlinked shared parent accepted")
	}
	ancestor := t.TempDir()
	parent := filepath.Join(ancestor, "edge")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, os.ModeSetgid|0o710); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ancestor, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := PrepareSocketParent(filepath.Join(parent, "s.sock"), otherPeerUID()); err == nil {
		t.Fatal("replaceable ancestor accepted")
	}
}
