package sandboxconfig

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"os"
	"path/filepath"

	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

const (
	revisionSecurityFingerprintDomain = "harness-gateway.sandboxconfig.revision-security/v1"
	runnerStatePathFingerprintDomain  = "harness-gateway.sandboxconfig.runner-state-path/v1"
)

type revisionAuthority struct {
	manifestFingerprint string
	workspacePath       string
	runnerStatePath     string
	runtimeKind         string
	runtimeEndpoint     string
	runtimeSocketPath   string
	runtimeCLIPath      string
}

// RevisionSecurityFingerprint binds one validated target manifest fingerprint
// to the local, operator-selected authorities that will execute it. The result
// can be supplied directly to sandboxservice.WithRevisionPin.
func (c Config) RevisionSecurityFingerprint(
	manifest targetmanifest.Manifest,
	manifestFingerprint string,
) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if err := manifest.Validate(); err != nil {
		return "", invalid("target manifest", err.Error())
	}
	if err := validateManifestFingerprint(manifestFingerprint); err != nil {
		return "", err
	}
	computed, err := manifest.Fingerprint()
	if err != nil {
		return "", invalid("target manifest fingerprint", err.Error())
	}
	if computed != manifestFingerprint {
		return "", invalid("target manifest fingerprint", "does not match the supplied target manifest")
	}

	workspacePath, ok := c.WorkspacePath(manifest.WorkspaceRef)
	if !ok {
		return "", invalid("target workspace_ref", "does not map to an approved workspace")
	}
	runnerStatePath, ok := c.RunnerStatePath(manifest.StateRef)
	if !ok {
		return "", invalid("target state_ref", "does not map to approved runner state")
	}

	authority := revisionAuthority{
		manifestFingerprint: manifestFingerprint,
		workspacePath:       filepath.Clean(workspacePath),
		runnerStatePath:     filepath.Clean(runnerStatePath),
		runtimeKind:         string(c.Runtime.Kind),
		runtimeEndpoint:     c.Runtime.Endpoint,
		runtimeSocketPath:   filepath.Clean(c.Runtime.SocketPath),
		runtimeCLIPath:      filepath.Clean(c.Runtime.CLI),
	}
	return fingerprintRevisionAuthority(authority), nil
}

// RunnerStateOwnership returns the two durable, non-path identifiers needed
// to bind one target revision to its configured runner-state directory. The
// path fingerprint is deliberately separate from the revision fingerprint so
// sandboxd can detect reuse across different targets and revisions without
// storing a host path in its database.
//
// pathAbsent is a trusted local startup observation. A missing durable owner
// may be created only when this exact path was absent before registration; an
// existing unowned path is never adopted from the current configuration.
func (c Config) RunnerStateOwnership(
	manifest targetmanifest.Manifest,
) (stateRef string, pathFingerprint string, pathAbsent bool, err error) {
	if err := c.Validate(); err != nil {
		return "", "", false, err
	}
	if err := manifest.Validate(); err != nil {
		return "", "", false, invalid("target manifest", err.Error())
	}
	runnerStatePath, ok := c.RunnerStatePath(manifest.StateRef)
	if !ok {
		return "", "", false, invalid("target state_ref", "does not map to approved runner state")
	}
	cleanPath := filepath.Clean(runnerStatePath)
	_, statErr := os.Lstat(cleanPath)
	switch {
	case statErr == nil:
		pathAbsent = false
	case os.IsNotExist(statErr):
		pathAbsent = true
	default:
		return "", "", false, invalid("target state_ref", "cannot inspect approved runner state")
	}
	return manifest.StateRef, fingerprintRunnerStatePath(cleanPath), pathAbsent, nil
}

func fingerprintRevisionAuthority(authority revisionAuthority) string {
	digest := sha256.New()
	writeFingerprintFrame(digest, revisionSecurityFingerprintDomain)
	writeFingerprintFrame(digest, authority.manifestFingerprint)
	writeFingerprintFrame(digest, authority.workspacePath)
	writeFingerprintFrame(digest, authority.runnerStatePath)
	writeFingerprintFrame(digest, authority.runtimeKind)
	writeFingerprintFrame(digest, authority.runtimeEndpoint)
	writeFingerprintFrame(digest, authority.runtimeSocketPath)
	writeFingerprintFrame(digest, authority.runtimeCLIPath)
	return hex.EncodeToString(digest.Sum(nil))
}

func fingerprintRunnerStatePath(path string) string {
	digest := sha256.New()
	writeFingerprintFrame(digest, runnerStatePathFingerprintDomain)
	writeFingerprintFrame(digest, filepath.Clean(path))
	return hex.EncodeToString(digest.Sum(nil))
}

func writeFingerprintFrame(destination hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = destination.Write(length[:])
	_, _ = destination.Write([]byte(value))
}

func validateManifestFingerprint(value string) error {
	if len(value) != sha256.Size*2 {
		return invalid("target manifest fingerprint", "must be 64 lowercase hexadecimal characters")
	}
	for index := 0; index < len(value); index++ {
		if value[index] >= '0' && value[index] <= '9' || value[index] >= 'a' && value[index] <= 'f' {
			continue
		}
		return invalid("target manifest fingerprint", "must be 64 lowercase hexadecimal characters")
	}
	return nil
}
