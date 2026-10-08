//go:build linux && amd64 && codexintegration

package codexadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A fresh disposable VM creates these fixed tiny fixtures in a private mount
// namespace. No real tool/provider runs. The source UID65534 is a deliberately
// foreign namespace-visible identity, not a host-root installation proof.
func TestIsolatedReadOnlyPackageKernel(t *testing.T) {
	if os.Getenv("HSG_V4_PACKAGE_KERNEL") != "offline-private-mount-v1" {
		t.Skip("requires the frozen dedicated kernel mount fixture")
	}
	if os.Geteuid() != 1001 || os.Getuid() != 1001 {
		t.Fatal("requires the dedicated unprivileged guest identity")
	}
	const base = "/srv/hgw-v4-acceptance/package-kernel"
	data := []byte("fixed package mount fixture\n")
	digest := sha256.Sum256(data)
	artifacts := []packageArtifact{{"bin/helper", hex.EncodeToString(digest[:]), int64(len(data)), true}}
	type observation struct {
		Case                          string
		DirectoryUID, FileUID         uint32
		RootRO, DirectoryRO, FileRO   bool
		Accepted, LegacyOwnerRejected bool
	}
	var observations []observation
	for _, tc := range []struct {
		name                        string
		rootRO, directoryRO, fileRO bool
		accept                      bool
	}{
		{"readonly", true, true, true, true},
		{"writable", false, false, false, false},
		{"writable-file", true, true, false, false},
		{"writable-directory", true, false, false, false},
		{"corrupt", true, true, true, false},
		{"extra", true, true, true, false},
		{"hardlink", true, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(base, tc.name)
			rootInfo, err := os.Lstat(root)
			if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0555 {
				t.Fatal("fixed kernel fixture root differs")
			}
			dir := filepath.Join(root, "bin")
			info, err := os.Lstat(dir)
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0555 {
				t.Fatal("fixed kernel fixture directory differs")
			}
			f, err := os.Open(filepath.Join(dir, "helper"))
			if err != nil {
				t.Fatal("fixed kernel fixture file unavailable")
			}
			defer f.Close()
			fileInfo, err := f.Stat()
			if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0555 {
				t.Fatal("fixed kernel fixture file differs")
			}
			ds, dok := info.Sys().(*syscall.Stat_t)
			fs, fok := fileInfo.Sys().(*syscall.Stat_t)
			if !dok || !fok || ds.Uid != 65534 || fs.Uid != 65534 {
				t.Fatal("foreign UID positive control missing")
			}
			o := observation{Case: tc.name, DirectoryUID: ds.Uid, FileUID: fs.Uid,
				RootRO: packageReadOnlyDirectory(root, rootInfo), DirectoryRO: packageReadOnlyDirectory(dir, info), FileRO: packageReadOnlyFD(f.Fd())}
			if o.RootRO != tc.rootRO || o.DirectoryRO != tc.directoryRO || o.FileRO != tc.fileRO {
				t.Fatal("actual mount property differs from frozen control")
			}
			err = verifyPackageArtifactsMode(root, artifacts, true)
			o.Accepted = err == nil
			if o.Accepted != tc.accept || (err != nil && !errors.Is(err, errInvalidConfig)) {
				t.Fatal("kernel readonly package acceptance mismatch")
			}
			o.LegacyOwnerRejected = errors.Is(verifyPackageArtifacts(root, artifacts), errInvalidConfig)
			if !o.LegacyOwnerRejected {
				t.Fatal("legacy package owner rule changed")
			}
			observations = append(observations, o)
		})
	}
	if t.Failed() {
		return
	}
	f, err := os.OpenFile(filepath.Join(base, "result", "kernel-result.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("kernel result unavailable")
	}
	if json.NewEncoder(f).Encode(struct {
		Passed       bool
		Observations []observation
	}{true, observations}) != nil || f.Sync() != nil {
		_ = f.Close()
		t.Fatal("kernel result could not persist")
	}
	if f.Close() != nil {
		t.Fatal("kernel result close failed")
	}
}
