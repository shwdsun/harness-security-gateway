// Package dockerruntime is the narrow rootless Docker CLI boundary used by
// sandboxd. It accepts only validated, operator-authored target manifests and
// never accepts argv, environment, mounts, network settings, or runtime flags
// from a Run request.
package dockerruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

const (
	LockedPolicyRef = "builtin.locked-down-v1"
	NoneProfileRef  = "builtin.none"

	containerNamePrefix = "hg-run-"
	tmpfsBytes          = 64 << 20
	stopGraceSeconds    = 5

	labelManaged           = "io.harness-gateway.managed"
	labelRunID             = "io.harness-gateway.run-id"
	labelTargetID          = "io.harness-gateway.target-id"
	labelTargetRevision    = "io.harness-gateway.target-revision"
	labelTargetFingerprint = "io.harness-gateway.target-fingerprint"
)

type ContainerRef string

func (r ContainerRef) String() string {
	return string(r)
}

type Runtime struct {
	cli      string
	endpoint string
	targets  map[targetKey]targetSpec
}

type targetKey struct {
	id       string
	revision string
}

type targetSpec struct {
	fingerprint   string
	image         string
	workspacePath string
	workspaceRoot string
	statePath     string
	stateRoot     string
	stdinLimit    int64
	stdoutLimit   int64
	stderrLimit   int64
}

func New(config sandboxconfig.Config) (*Runtime, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	workspacePaths, err := resolveStorage(config.WorkspaceRoot, config.Workspaces)
	if err != nil {
		return nil, err
	}
	statePaths, err := resolveStorage(config.RunnerStateRoot, config.RunnerStates)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateDirectory(config.RunnerStateRoot); err != nil {
		return nil, err
	}
	for _, path := range statePaths {
		if err := validatePrivateDirectory(path); err != nil {
			return nil, err
		}
	}

	targets := make(map[targetKey]targetSpec, len(config.Targets))
	for _, manifest := range config.Targets {
		if err := validateProfile(manifest); err != nil {
			return nil, err
		}
		fingerprint, err := manifest.Fingerprint()
		if err != nil {
			return nil, fmt.Errorf("%w: target manifest", ErrInvalidConfig)
		}
		workspacePath, exists := workspacePaths[manifest.WorkspaceRef]
		if !exists {
			return nil, fmt.Errorf("%w: unresolved workspace reference", ErrInvalidConfig)
		}
		statePath, exists := statePaths[manifest.StateRef]
		if !exists {
			return nil, fmt.Errorf("%w: unresolved runner-state reference", ErrInvalidConfig)
		}
		targets[targetKey{id: manifest.ID, revision: manifest.Revision}] = targetSpec{
			fingerprint:   fingerprint,
			image:         manifest.Runner.Image,
			workspacePath: workspacePath,
			workspaceRoot: config.WorkspaceRoot,
			statePath:     statePath,
			stateRoot:     config.RunnerStateRoot,
			stdinLimit:    streamInputLimit(manifest),
			stdoutLimit:   streamOutputLimit(manifest),
			stderrLimit:   int64(manifest.Limits.MaxStderrBytes),
		}
	}
	return &Runtime{
		cli:      config.Runtime.CLI,
		endpoint: config.Runtime.Endpoint,
		targets:  targets,
	}, nil
}

// Create creates one stopped, immutable runner container. The returned
// reference is a full Docker container ID, never a caller-selected name.
func (r *Runtime) Create(ctx context.Context, runID string, manifest targetmanifest.Manifest) (ContainerRef, error) {
	if err := r.ready(ctx); err != nil {
		return "", err
	}
	if err := validateRunID(runID); err != nil {
		return "", err
	}
	if err := manifest.Validate(); err != nil {
		return "", fmt.Errorf("%w: target manifest", ErrInvalidArgument)
	}
	if err := validateProfile(manifest); err != nil {
		return "", err
	}
	fingerprint, err := manifest.Fingerprint()
	if err != nil {
		return "", fmt.Errorf("%w: target fingerprint", ErrInvalidArgument)
	}
	spec, exists := r.targets[targetKey{id: manifest.ID, revision: manifest.Revision}]
	if !exists || spec.fingerprint != fingerprint || spec.image != manifest.Runner.Image {
		return "", ErrTargetNotConfigured
	}
	// Recheck immediately before passing authority-bearing paths to the CLI.
	// This narrows (but cannot eliminate) the CLI bind-mount TOCTOU window.
	if err := validateSpecStorage(spec); err != nil {
		return "", err
	}
	if err := r.attestRootless(ctx); err != nil {
		return "", err
	}

	name := deterministicName(runID)
	labels := expectedLabels(runID, manifest, fingerprint)
	arguments := createArguments(name, labels, spec, manifest)
	stdout, invoked, err := r.runObserved(ctx, "create", arguments...)
	if err == nil {
		ref, parseErr := parseContainerRef(stdout)
		if parseErr != nil {
			if adopted, found, lookupErr := r.lookupIntentAttested(ctx, runID, manifest, fingerprint); lookupErr == nil && found {
				return adopted, nil
			} else if lookupErr != nil {
				return "", uncertainCreate(parseErr, lookupErr)
			}
			return "", uncertainCreate(parseErr)
		}
		record, inspectErr := r.inspectIdentifier(ctx, string(ref))
		if inspectErr != nil {
			if adopted, found, lookupErr := r.lookupIntentAttested(ctx, runID, manifest, fingerprint); lookupErr == nil && found {
				return adopted, nil
			} else if lookupErr != nil {
				return "", uncertainCreate(inspectErr, lookupErr)
			}
			return "", uncertainCreate(inspectErr)
		}
		if record.ID != string(ref) {
			return "", uncertainCreate(ErrForeignContainer)
		}
		if verifyErr := verifyExpected(record, name, manifest.Runner.Image, labels); verifyErr != nil {
			return "", uncertainCreate(verifyErr)
		}
		return ref, nil
	}
	if !invoked {
		return "", err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		// Killing the CLI does not cancel a request already accepted by the
		// daemon. A contemporaneous absence lookup cannot close this race.
		return "", uncertainCreate(err)
	}

	// Even a normally waited non-zero exit may represent a CLI transport reset
	// after the daemon accepted the mutation. LookupIntent may close the result
	// only by finding and verifying the exact immutable container; one absence
	// observation never proves that no delayed create can still land.
	adopted, found, lookupErr := r.lookupIntentAttested(ctx, runID, manifest, fingerprint)
	if lookupErr != nil {
		return "", uncertainCreate(err, lookupErr)
	}
	if found {
		return adopted, nil
	}
	return "", uncertainCreate(err)
}

func (r *Runtime) ready(ctx context.Context) error {
	if r == nil || r.cli == "" || r.endpoint == "" || r.targets == nil {
		return ErrInvalidConfig
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidArgument)
	}
	return nil
}

func validateProfile(manifest targetmanifest.Manifest) error {
	if manifest.PolicyRef != LockedPolicyRef ||
		manifest.AuthProfileRef != NoneProfileRef ||
		manifest.SkillBundleRef != NoneProfileRef ||
		manifest.NetworkProfileRef != NoneProfileRef {
		return ErrUnsupportedProfile
	}
	return nil
}

func resolveStorage(root string, entries []sandboxconfig.StorageEntry) (map[string]string, error) {
	if err := validateDirectory(root, root); err != nil {
		return nil, err
	}
	paths := make(map[string]string, len(entries))
	for _, entry := range entries {
		path := filepath.Join(root, entry.Directory)
		if err := validateDirectory(path, root); err != nil {
			return nil, err
		}
		paths[entry.Ref] = path
	}
	return paths, nil
}

func validateDirectory(path, root string) error {
	cleanPath := filepath.Clean(path)
	cleanRoot := filepath.Clean(root)
	if !filepath.IsAbs(cleanPath) || !filepath.IsAbs(cleanRoot) || strings.ContainsAny(cleanPath, "\x00,\r\n") {
		return fmt.Errorf("%w: path syntax", ErrInvalidStorage)
	}
	relative, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: storage-root escape", ErrInvalidStorage)
	}
	info, err := os.Lstat(cleanPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: path must be a non-symlink directory", ErrInvalidStorage)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: directory must be owned by sandboxd and not writable by group or others", ErrInvalidStorage)
	}
	resolved, err := filepath.EvalSymlinks(cleanPath)
	if err != nil || resolved != cleanPath {
		return fmt.Errorf("%w: symlinked path component", ErrInvalidStorage)
	}
	return nil
}

func validatePrivateDirectory(path string) error {
	info, err := os.Lstat(filepath.Clean(path))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: runner-state directories must have mode 0700", ErrInvalidStorage)
	}
	return nil
}

func validateRunID(runID string) error {
	if err := (executionwire.GetRunRequest{RunID: runID}).Validate(); err != nil {
		return fmt.Errorf("%w: run_id", ErrInvalidArgument)
	}
	return nil
}

func deterministicName(runID string) string {
	digest := sha256.Sum256([]byte("harness-gateway/docker-name/v1\x00" + runID))
	return containerNamePrefix + hex.EncodeToString(digest[:16])
}

func expectedLabels(runID string, manifest targetmanifest.Manifest, fingerprint string) map[string]string {
	return map[string]string{
		labelManaged:           "v1",
		labelRunID:             runID,
		labelTargetID:          manifest.ID,
		labelTargetRevision:    manifest.Revision,
		labelTargetFingerprint: fingerprint,
	}
}

func createArguments(name string, labels map[string]string, spec targetSpec, manifest targetmanifest.Manifest) []string {
	arguments := []string{
		"container", "create",
		"--name", name,
		"--pull=never",
	}
	for _, key := range []string{labelManaged, labelRunID, labelTargetID, labelTargetRevision, labelTargetFingerprint} {
		arguments = append(arguments, "--label", key+"="+labels[key])
	}
	arguments = append(arguments,
		"--interactive",
		"--network", "none",
		"--read-only",
		"--restart", "no",
		"--no-healthcheck",
		"--log-driver", "none",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges=true",
		"--memory", strconv.FormatInt(manifest.Limits.MemoryBytes, 10),
		"--memory-swap", strconv.FormatInt(manifest.Limits.MemoryBytes, 10),
		"--cpus", formatCPU(manifest.Limits.CPUMillis),
		"--pids-limit", strconv.FormatInt(manifest.Limits.PIDs, 10),
		"--tmpfs", fmt.Sprintf("/tmp:rw,nosuid,nodev,noexec,size=%d,mode=1777", tmpfsBytes),
		"--workdir", "/workspace",
		// In a rootless daemon, container uid 0 maps to sandboxd's dedicated
		// host uid. This lets the runner access private 0700 binds without
		// making them group/world accessible or inheriting an image USER that
		// maps to an unrelated subordinate host uid.
		"--user", "0:0",
	)
	workspaceMount := "type=bind,src=" + spec.workspacePath + ",dst=/workspace,bind-propagation=rprivate"
	if manifest.WorkspaceMode == targetmanifest.WorkspaceReadOnly {
		workspaceMount += ",readonly"
	}
	arguments = append(arguments,
		"--mount", workspaceMount,
		"--mount", "type=bind,src="+spec.statePath+",dst=/state,bind-propagation=rprivate",
		manifest.Runner.Image,
	)
	return arguments
}

func formatCPU(millis int64) string {
	whole := millis / 1000
	fraction := millis % 1000
	return fmt.Sprintf("%d.%03d", whole, fraction)
}

func streamInputLimit(manifest targetmanifest.Manifest) int64 {
	// encoding/json may expand one input byte to a six-byte Unicode escape.
	// HRP/1 sends one start frame, so add one bounded envelope.
	return 6*int64(manifest.Limits.MaxInputBytes) + 16<<10
}

func streamOutputLimit(manifest targetmanifest.Manifest) int64 {
	// Account for JSON's worst-case six-byte string escaping, every permitted
	// event, the ready/terminal envelopes, and framing. Manifest validation
	// makes the resulting aggregate ceiling finite (about 14 MiB at HRP/1 max).
	return 6*int64(manifest.Limits.MaxOutputBytes) +
		int64(manifest.Limits.MaxEvents)*(6*int64(manifest.Limits.MaxProgressBytes)+2<<10) +
		64<<10
}
