package sandboxconfig

import (
	"strings"
	"testing"
)

// Pinned before state-v2 integration from the unchanged v1 implementation;
// independently reproduced with explicit eight-byte big-endian framing.
func TestV1RevisionFingerprintCompatibility(t *testing.T) {
	authority := revisionAuthority{
		manifestFingerprint: strings.Repeat("a", 64),
		workspacePath:       "/srv/workspaces/main",
		runnerStatePath:     "/srv/runner-state/main",
		runtimeKind:         "rootless-docker",
		runtimeEndpoint:     "unix:///run/user/1000/docker.sock",
		runtimeSocketPath:   "/run/user/1000/docker.sock",
		runtimeCLIPath:      "/usr/bin/docker",
	}
	const want = "4e6e0b15076a18960f41893265583d683fe9d4780b663435ab76d8d3f7fa0702"
	if got := fingerprintRevisionAuthority(authority); got != want {
		t.Fatalf("legacy revision pin changed: got %s want %s", got, want)
	}
}
