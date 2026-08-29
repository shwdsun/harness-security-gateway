package sandboxconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func loadedFingerprintConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	cli := executable(t, root)
	path := writeConfig(t, root, validConfigJSON(cli), 0o600)
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func cloneConfig(config Config) Config {
	cloned := config
	cloned.Workspaces = append([]StorageEntry(nil), config.Workspaces...)
	cloned.RunnerStates = append([]StorageEntry(nil), config.RunnerStates...)
	cloned.Targets = append([]targetmanifest.Manifest(nil), config.Targets...)
	for index := range cloned.Targets {
		if config.Targets[index].Runner.RequiredFeatures != nil {
			cloned.Targets[index].Runner.RequiredFeatures = make(
				[]runnerwire.Feature,
				len(config.Targets[index].Runner.RequiredFeatures),
			)
			copy(cloned.Targets[index].Runner.RequiredFeatures, config.Targets[index].Runner.RequiredFeatures)
		}
	}
	return cloned
}

func manifestFingerprint(t *testing.T, manifest targetmanifest.Manifest) string {
	t.Helper()
	fingerprint, err := manifest.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint
}

func TestRevisionSecurityFingerprintIsStableAndPinsResolvedMappings(t *testing.T) {
	config := loadedFingerprintConfig(t)
	manifest := config.Targets[0]
	fingerprint := manifestFingerprint(t, manifest)

	first, err := config.RevisionSecurityFingerprint(manifest, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	second, err := config.RevisionSecurityFingerprint(manifest, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != 64 {
		t.Fatalf("stable fingerprints = %q, %q", first, second)
	}

	tests := []struct {
		name   string
		change func(Config) Config
	}{
		{
			name: "workspace mapping",
			change: func(changed Config) Config {
				changed.Workspaces[0].Directory = "project-main-v2"
				return changed
			},
		},
		{
			name: "runner state mapping",
			change: func(changed Config) Config {
				changed.RunnerStates[0].Directory = "mock-state-v2"
				return changed
			},
		},
		{
			name: "runtime CLI",
			change: func(changed Config) Config {
				changed.Runtime.CLI = executable(t, t.TempDir())
				return changed
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := test.change(cloneConfig(config))
			got, err := changed.RevisionSecurityFingerprint(manifest, fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			if got == first {
				t.Fatalf("fingerprint did not change after %s", test.name)
			}
		})
	}

	changedManifest := manifest
	changedManifest.PolicyRef = "builtin.locked-down-v2"
	changedManifestFingerprint := manifestFingerprint(t, changedManifest)
	got, err := config.RevisionSecurityFingerprint(changedManifest, changedManifestFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if got == first {
		t.Fatal("fingerprint did not change with manifest semantics")
	}
}

func TestRunnerStateOwnershipPinsResolvedPathWithoutAdoptingIt(t *testing.T) {
	config := loadedFingerprintConfig(t)
	manifest := config.Targets[0]

	stateRef, first, absent, err := config.RunnerStateOwnership(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if stateRef != manifest.StateRef || len(first) != 64 || !absent {
		t.Fatalf("initial ownership = %q, %q, absent=%v", stateRef, first, absent)
	}
	statePath, ok := config.RunnerStatePath(manifest.StateRef)
	if !ok {
		t.Fatal("configured runner state did not resolve")
	}
	if err := os.MkdirAll(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	_, second, absent, err := config.RunnerStateOwnership(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || absent {
		t.Fatalf("existing path ownership = %q, absent=%v; want %q, false", second, absent, first)
	}

	renamed := cloneConfig(config)
	renamed.RunnerStates[0].Ref = "renamed-state-ref"
	renamedManifest := manifest
	renamedManifest.StateRef = renamed.RunnerStates[0].Ref
	renamed.Targets[0] = renamedManifest
	renamedRef, renamedDigest, renamedAbsent, err := renamed.RunnerStateOwnership(renamedManifest)
	if err != nil {
		t.Fatal(err)
	}
	if renamedRef == stateRef || renamedDigest != first || renamedAbsent {
		t.Fatalf("renamed ownership = %q, %q, absent=%v", renamedRef, renamedDigest, renamedAbsent)
	}

	moved := cloneConfig(config)
	moved.RunnerStates[0].Directory = "moved-state"
	_, movedDigest, movedAbsent, err := moved.RunnerStateOwnership(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if movedDigest == first || !movedAbsent {
		t.Fatalf("moved ownership = %q, absent=%v", movedDigest, movedAbsent)
	}
}

func TestRunnerStateOwnershipTreatsEveryExistingLeafShapeAsOwned(t *testing.T) {
	tests := []struct {
		name   string
		create func(string) error
	}{
		{
			name: "regular file",
			create: func(path string) error {
				return os.WriteFile(path, []byte("not a state directory"), 0o600)
			},
		},
		{
			name: "dangling symlink",
			create: func(path string) error {
				return os.Symlink(path+"-missing", path)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadedFingerprintConfig(t)
			manifest := config.Targets[0]
			statePath, ok := config.RunnerStatePath(manifest.StateRef)
			if !ok {
				t.Fatal("configured runner state did not resolve")
			}
			if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := test.create(statePath); err != nil {
				t.Fatal(err)
			}

			_, digest, absent, err := config.RunnerStateOwnership(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if len(digest) != 64 || absent {
				t.Fatalf("ownership digest = %q, absent=%v; want existing", digest, absent)
			}
		})
	}
}

func TestRunnerStatePathFingerprintIsLengthFramed(t *testing.T) {
	first := fingerprintRunnerStatePath("/srv/runner-state/a/bc")
	second := fingerprintRunnerStatePath("/srv/runner-state/ab/c")
	if first == second || len(first) != 64 || len(second) != 64 {
		t.Fatalf("path fingerprints = %q, %q", first, second)
	}
}

func TestRunnerStateOwnershipRejectsUnknownStateRef(t *testing.T) {
	config := loadedFingerprintConfig(t)
	manifest := config.Targets[0]
	manifest.StateRef = "missing-state"
	if _, _, _, err := config.RunnerStateOwnership(manifest); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown state ref error = %v, want ErrInvalid", err)
	}
}

func TestRevisionAuthorityFingerprintIncludesEveryLengthFramedField(t *testing.T) {
	base := revisionAuthority{
		manifestFingerprint: strings.Repeat("a", 64),
		workspacePath:       "/srv/workspaces/main",
		runnerStatePath:     "/srv/runner-state/main",
		runtimeKind:         "rootless-docker",
		runtimeEndpoint:     "unix:///run/user/1000/docker.sock",
		runtimeSocketPath:   "/run/user/1000/docker.sock",
		runtimeCLIPath:      "/usr/bin/docker",
	}
	wantDifferent := fingerprintRevisionAuthority(base)
	tests := []struct {
		name   string
		change func(*revisionAuthority)
	}{
		{"manifest fingerprint", func(value *revisionAuthority) { value.manifestFingerprint = strings.Repeat("b", 64) }},
		{"workspace path", func(value *revisionAuthority) { value.workspacePath += "-v2" }},
		{"runner state path", func(value *revisionAuthority) { value.runnerStatePath += "-v2" }},
		{"runtime kind", func(value *revisionAuthority) { value.runtimeKind = "different-runtime" }},
		{"runtime endpoint", func(value *revisionAuthority) { value.runtimeEndpoint = "unix:///run/user/2000/docker.sock" }},
		{"runtime socket", func(value *revisionAuthority) { value.runtimeSocketPath = "/run/user/2000/docker.sock" }},
		{"runtime CLI", func(value *revisionAuthority) { value.runtimeCLIPath = "/opt/docker/bin/docker" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.change(&changed)
			if got := fingerprintRevisionAuthority(changed); got == wantDifferent {
				t.Fatalf("fingerprint omitted %s", test.name)
			}
		})
	}

	first := base
	first.workspacePath = "a"
	first.runnerStatePath = "bc"
	second := base
	second.workspacePath = "ab"
	second.runnerStatePath = "c"
	if fingerprintRevisionAuthority(first) == fingerprintRevisionAuthority(second) {
		t.Fatal("adjacent authority fields were not length-framed")
	}
}

func TestRevisionSecurityFingerprintIgnoresUnreferencedConfigOrdering(t *testing.T) {
	config := loadedFingerprintConfig(t)
	manifest := config.Targets[0]
	fingerprint := manifestFingerprint(t, manifest)

	config.Workspaces = append(config.Workspaces, StorageEntry{Ref: "project-other", Directory: "project-other"})
	config.RunnerStates = append(config.RunnerStates, StorageEntry{Ref: "other-state", Directory: "other-state"})
	other := manifest
	other.ID = "project-other"
	other.Revision = "project-other-r1"
	other.WorkspaceRef = "project-other"
	other.StateRef = "other-state"
	config.Targets = append(config.Targets, other)

	first, err := config.RevisionSecurityFingerprint(manifest, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	reordered := cloneConfig(config)
	reordered.Workspaces[0], reordered.Workspaces[1] = reordered.Workspaces[1], reordered.Workspaces[0]
	reordered.RunnerStates[0], reordered.RunnerStates[1] = reordered.RunnerStates[1], reordered.RunnerStates[0]
	reordered.Targets[0], reordered.Targets[1] = reordered.Targets[1], reordered.Targets[0]
	reordered.Socket = filepath.Join(filepath.Dir(reordered.Socket), "another-sandboxd.sock")
	reordered.StateDatabase = filepath.Join(filepath.Dir(reordered.StateDatabase), "another-state.sqlite3")

	second, err := reordered.RevisionSecurityFingerprint(manifest, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("irrelevant config changed fingerprint: %q != %q", first, second)
	}
}

func TestRevisionSecurityFingerprintRejectsUnknownRefsAndBadManifestFingerprint(t *testing.T) {
	config := loadedFingerprintConfig(t)
	manifest := config.Targets[0]

	for _, test := range []struct {
		name   string
		change func(*targetmanifest.Manifest)
	}{
		{"workspace", func(value *targetmanifest.Manifest) { value.WorkspaceRef = "missing-workspace" }},
		{"runner state", func(value *targetmanifest.Manifest) { value.StateRef = "missing-state" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := manifest
			test.change(&changed)
			_, err := config.RevisionSecurityFingerprint(changed, manifestFingerprint(t, changed))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}

	for _, fingerprint := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("b", 64)} {
		if _, err := config.RevisionSecurityFingerprint(manifest, fingerprint); !errors.Is(err, ErrInvalid) {
			t.Fatalf("fingerprint %q error = %v, want ErrInvalid", fingerprint, err)
		}
	}
}
