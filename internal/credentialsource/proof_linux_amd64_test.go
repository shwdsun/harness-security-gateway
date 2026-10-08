//go:build linux && amd64

package credentialsource

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeProofOnPrivateTemporarySource(t *testing.T) {
	f := newFixture(t)
	h := holdFixture(t, f)
	var fs unix.Statfs_t
	must(t, unix.Fstatfs(int(h.file.Fd()), &fs))
	source, proof, err := h.CaptureProof()
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		if !errors.Is(err, ErrUnavailable) || source != "" || proof != (Proof{}) {
			t.Fatal("non-ext4 source gained enrollment proof")
		}
		if !errors.Is(h.Validate(), ErrChanged) {
			t.Fatal("unsupported native observation was not latched")
		}
		return
	}
	must(t, err)
	must(t, h.VerifyProof(source, proof))
}

func TestNativeProofBackendOnSyntheticExt4(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged native proof witness")
	}
	// Only this test's new fixture under the public package directory is used.
	// This tests the native backend independently of Hold's ancestor checks:
	// source checkout ancestry is not a deployment credential-root approval.
	root, err := os.MkdirTemp(".", ".hgw-proof-native-")
	must(t, err)
	t.Cleanup(func() { must(t, os.RemoveAll(root)) })
	var fs unix.Statfs_t
	must(t, unix.Statfs(root, &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Skip("package fixture is not on ext4-family storage")
	}
	slot := filepath.Join(root, "slot")
	must(t, os.Mkdir(slot, 0o700))
	auth := filepath.Join(slot, "auth.json")
	writeSynthetic(t, auth)
	var files [3]*os.File
	var ids [3]objectID
	for i, path := range []string{root, slot, auth} {
		flags := unix.O_PATH | unix.O_DIRECTORY
		if i == 2 {
			flags = unix.O_RDONLY
		}
		fd, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		must(t, err)
		files[i] = os.NewFile(uintptr(fd), "synthetic-proof-fixture")
		t.Cleanup(func() { _ = files[i].Close() })
		ids[i], err = privateObject(files[i], uint32(os.Geteuid()), i == 2)
		must(t, err)
	}
	initial, err := nativeIdentity(files, ids)
	must(t, err)
	original, err := objectDigest(initial.uuid, initial.handles[2])
	must(t, err)
	for _, handle := range initial.handles {
		if handle.kind != 1 || len(handle.data) != 8 {
			t.Fatal("unexpected native handle form")
		}
	}
	must(t, os.WriteFile(auth, []byte("synthetic-after"), 0o600))
	after, err := nativeIdentity(files, ids)
	must(t, err)
	refreshed, err := objectDigest(after.uuid, after.handles[2])
	must(t, err)
	if original != refreshed {
		t.Fatal("in-place update changed native identity")
	}
	must(t, os.Rename(auth, filepath.Join(root, "old-auth")))
	must(t, os.WriteFile(auth, []byte("synthetic-after"), 0o600))
	held, err := nativeIdentity(files, ids)
	must(t, err)
	heldDigest, err := objectDigest(held.uuid, held.handles[2])
	must(t, err)
	if heldDigest != original {
		t.Fatal("backend followed the replaced path")
	}
	newFile, err := os.Open(auth)
	must(t, err)
	defer newFile.Close()
	newFiles, newIDs := files, ids
	newFiles[2] = newFile
	newIDs[2], err = privateObject(newFile, uint32(os.Geteuid()), true)
	must(t, err)
	changed, err := nativeIdentity(newFiles, newIDs)
	must(t, err)
	changedDigest, err := objectDigest(changed.uuid, changed.handles[2])
	must(t, err)
	if changedDigest == original {
		t.Fatal("replacement shares old identity")
	}
	badIDs := ids
	badIDs[1].mount++
	if _, err := nativeIdentity(files, badIDs); !errors.Is(err, ErrUnavailable) {
		t.Fatal("mixed mount IDs accepted")
	}
	if _, err := descriptorHandle(files[2], ids[2].mount+1); !errors.Is(err, ErrUnavailable) {
		t.Fatal("handle mount mismatch accepted")
	}
	// This directory's owned fixture is removed after every owned FD closes.
}
