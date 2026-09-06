package codexcandidate

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func localCandidate(t *testing.T) (Candidate, string) {
	t.Helper()
	c, err := Decode(example(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := c.config
	cfg.Workspace.Path = filepath.Join(root, "workspace")
	cfg.Credential.Root = filepath.Join(root, "credentials")
	slot := filepath.Join(cfg.Credential.Root, cfg.Credential.Directory)
	for _, dir := range []string{cfg.Workspace.Path, cfg.Credential.Root, slot} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	auth := filepath.Join(slot, "auth.json")
	// Intentionally invalid auth JSON. Metadata inspection cannot prove login,
	// and must not parse, log, hash or otherwise consume these bytes.
	if err := os.WriteFile(auth, []byte("PRIVATE_SYNTHETIC_AUTH_SENTINEL"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(auth, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = Decode(encode(t, cfg))
	if err != nil {
		t.Fatal(err)
	}
	return c, auth
}

func TestMetadataAndRefreshNeverMeanReady(t *testing.T) {
	c, auth := localCandidate(t)
	before, _ := c.check(true, os.Geteuid(), fixtureMetadataFS{})
	if before.LocalMetadata != "matches" || before.Status != "blocked" {
		t.Fatalf("%+v", before)
	}
	if err := os.WriteFile(auth, []byte("rotated synthetic bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, _ := c.check(true, os.Geteuid(), fixtureMetadataFS{})
	if after.ConfigurationFingerprint != before.ConfigurationFingerprint || after.LocalMetadata != "matches" {
		t.Fatal("token refresh changed configuration identity")
	}
	// Replacing the inode also does not invent a binding generation. The
	// missing runtime refresh/source-handle policy stays an explicit blocker.
	replacement := filepath.Join(filepath.Dir(auth), "refresh.tmp")
	if err := os.WriteFile(replacement, []byte("replaced"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, auth); err != nil {
		t.Fatal(err)
	}
	replaced, _ := c.check(true, os.Geteuid(), fixtureMetadataFS{})
	if replaced.ConfigurationFingerprint != before.ConfigurationFingerprint || replaced.LocalMetadata != "matches" {
		t.Fatal("inode replacement changed configuration identity")
	}
	encoded := string(encode(t, replaced))
	if strings.Contains(encoded, filepath.Dir(auth)) || strings.Contains(encoded, "SENTINEL") {
		t.Fatal("report leaked private source")
	}
	if err := os.Chmod(auth, 0o644); err != nil {
		t.Fatal(err)
	}
	unsafe, _ := c.check(true, os.Geteuid(), fixtureMetadataFS{})
	if unsafe.LocalMetadata != "rejected" || unsafe.Status != "blocked" {
		t.Fatal("stale metadata reused")
	}
}

func TestRejectsUnsafeLocalMetadata(t *testing.T) {
	changes := map[string]func(*testing.T, Candidate, string){
		"missing":        func(t *testing.T, c Candidate, auth string) { must(t, os.Remove(auth)) },
		"file mode":      func(t *testing.T, c Candidate, auth string) { must(t, os.Chmod(auth, 0o644)) },
		"slot mode":      func(t *testing.T, c Candidate, auth string) { must(t, os.Chmod(filepath.Dir(auth), 0o750)) },
		"workspace mode": func(t *testing.T, c Candidate, auth string) { must(t, os.Chmod(c.config.Workspace.Path, 0o777)) },
		"file symlink": func(t *testing.T, c Candidate, auth string) {
			saved := auth + ".saved"
			must(t, os.Rename(auth, saved))
			must(t, os.Symlink(saved, auth))
		},
		"prefix symlink": func(t *testing.T, c Candidate, auth string) {
			root := c.config.Credential.Root
			must(t, os.Rename(root, root+".saved"))
			must(t, os.Symlink(root+".saved", root))
		},
		"hardlink":  func(t *testing.T, c Candidate, auth string) { must(t, os.Link(auth, auth+".link")) },
		"directory": func(t *testing.T, c Candidate, auth string) { must(t, os.Remove(auth)); must(t, os.Mkdir(auth, 0o600)) },
		"fifo": func(t *testing.T, c Candidate, auth string) {
			must(t, os.Remove(auth))
			must(t, syscall.Mkfifo(auth, 0o600))
		},
		"ambient home": func(t *testing.T, c Candidate, auth string) {
			must(t, os.WriteFile(filepath.Join(filepath.Dir(auth), "config.toml"), []byte("unapproved"), 0o600))
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c, auth := localCandidate(t)
			change(t, c, auth)
			report, err := c.check(true, os.Geteuid(), fixtureMetadataFS{})
			if err != nil || report.LocalMetadata != "rejected" || report.Status != "blocked" || len(report.Findings) == 0 {
				t.Fatalf("%+v, %v", report, err)
			}
		})
	}
}

func TestValidationOnlyAndInspectionCreateNothing(t *testing.T) {
	c, _ := localCandidate(t)
	cfg := c.config
	cfg.Credential.Root = filepath.Join(t.TempDir(), "absent-credential-root")
	c, err := Decode(encode(t, cfg))
	if err != nil {
		t.Fatal(err)
	}
	if report, err := c.Check(false); err != nil || report.LocalMetadata != "not_checked" {
		t.Fatalf("%+v, %v", report, err)
	}
	if report, err := c.Check(true); err != nil || report.LocalMetadata != "rejected" {
		t.Fatalf("%+v, %v", report, err)
	}
	if _, err := os.Lstat(cfg.Credential.Root); !os.IsNotExist(err) {
		t.Fatal("inspection created or changed source")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// This environment maps host-root-owned /tmp to uid 65534 even outside the
// command sandbox. Model that ONE system ancestor as root-owned for synthetic
// positive fixtures; all slot/workspace/file observations are real Lstat.
// Production never remaps or trusts uid 65534. This is not host PASS evidence.
type fixtureMetadataFS struct{ localMetadataFS }

type fixtureOwnerInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (f fixtureOwnerInfo) Sys() any { return &f.stat }

func (fixtureMetadataFS) Lstat(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err == nil && path == "/tmp" {
		stat := *info.Sys().(*syscall.Stat_t)
		if stat.Uid == 65534 {
			stat.Uid = 0
			return fixtureOwnerInfo{info, stat}, nil
		}
	}
	return info, err
}

type noMetadataFS struct{}

func (noMetadataFS) Lstat(string) (os.FileInfo, error)     { panic("unexpected metadata access") }
func (noMetadataFS) ReadDir(string) ([]os.DirEntry, error) { panic("unexpected directory access") }

func TestDefaultAndRootInspectionMakeNoFilesystemCalls(t *testing.T) {
	c, err := Decode(example(t))
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.check(false, 1000, noMetadataFS{})
	if err != nil || r.LocalMetadata != "not_checked" {
		t.Fatalf("%+v, %v", r, err)
	}
	r, err = c.check(true, 0, noMetadataFS{})
	if err != nil || r.LocalMetadata != "inconclusive" || r.Status != "blocked" {
		t.Fatalf("%+v, %v", r, err)
	}
}
