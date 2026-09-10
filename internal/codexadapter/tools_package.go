package codexadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
)

type packageArtifact struct {
	path       string
	sha256     string
	bytes      int64
	executable bool
}

// verifyToolsPackage is a startup compatibility guard. It prevents the native
// CLI silently continuing without its expected tool host. Read-only image
// provenance and runtime mounts must separately prevent replacement after this
// observation; hashing mutable paths is not an atomic execution handoff.
func verifyToolsPackage(binary string) error {
	return verifyPackageArtifacts(filepath.Dir(filepath.Dir(binary)), []packageArtifact{
		{"bin/codex", codexprofile.CLIBinarySHA256V1, 270815680, true},
		{"bin/codex-code-mode-host", codexprofile.CodeModeHostSHA256V3, 69333056, true},
		{"codex-package.json", codexprofile.PackageManifestSHA256V3, 205, false},
		{"codex-path/rg", codexprofile.RipgrepSHA256V3, 5408904, true},
		{"codex-resources/bwrap", codexprofile.BubblewrapSHA256V3, 529776, true},
		{"codex-resources/zsh/bin/zsh", codexprofile.ZshSHA256V3, 898480, true},
	})
}

func verifyPackageArtifacts(root string, artifacts []packageArtifact) error {
	invalid := func(stage string) error { return fmt.Errorf("%w: native tool package %s", errInvalidConfig, stage) }
	// Native discovery adds codex-path to PATH. Extra files could introduce an
	// unpinned executable despite all six known files having matching hashes.
	allowed := map[string]bool{root: true}
	for _, artifact := range artifacts {
		path := filepath.Join(root, artifact.path)
		allowed[path] = false
		for dir := filepath.Dir(path); dir != root; dir = filepath.Dir(dir) {
			allowed[dir] = true
		}
	}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return invalid("layout unavailable")
		}
		directory, ok := allowed[path]
		if !ok || entry.Type()&os.ModeSymlink != 0 || entry.IsDir() != directory {
			return invalid("unexpected package entry")
		}
		return nil
	}); err != nil {
		return err
	}
	for _, artifact := range artifacts {
		path := filepath.Join(root, artifact.path)
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || resolved != path {
			return invalid("path mismatch")
		}
		for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
			info, err := os.Lstat(dir)
			if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !packageOwner(info) {
				return invalid("unsafe directory")
			}
			if dir == root {
				break
			}
		}
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return invalid("open failed")
		}
		file := os.NewFile(uintptr(fd), "codex-package-artifact")
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() != artifact.bytes || info.Mode().Perm()&0o022 != 0 ||
			info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || !packageOwner(info) ||
			(artifact.executable && info.Mode().Perm()&0o111 == 0) {
			_ = file.Close()
			return invalid("invalid file attributes")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 {
			_ = file.Close()
			return invalid("multiple links")
		}
		digest := sha256.New()
		n, readErr := io.Copy(digest, io.LimitReader(file, artifact.bytes+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || n != artifact.bytes || hex.EncodeToString(digest.Sum(nil)) != artifact.sha256 {
			return invalid("content mismatch")
		}
	}
	return nil
}

func packageOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid()))
}
