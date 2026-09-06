package sandboxconfig

import (
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func TestV2ResolvedFingerprintFramesAllAuthorityAndNoInventedState(t *testing.T) {
	base := revisionAuthority{
		manifestFingerprint: strings.Repeat("a", 64), workspacePath: "/workspace/main",
		runnerStatePath: "/state/main", runtimeKind: "rootless-docker",
		runtimeEndpoint:   "unix:///run/user/1000/docker.sock",
		runtimeSocketPath: "/run/user/1000/docker.sock", runtimeCLIPath: "/usr/bin/docker",
	}
	none, persistent := targetmanifest.NoRunnerState(), targetmanifest.PersistentRunnerState("state-main")
	noneHash := fingerprintRevisionAuthorityV2(base, none)
	persistentHash := fingerprintRevisionAuthorityV2(base, persistent)
	if noneHash == persistentHash || persistentHash == fingerprintRevisionAuthority(base) {
		t.Fatal("fingerprint omitted schema or kind domain")
	}
	for _, mutation := range []func(*revisionAuthority){
		func(a *revisionAuthority) { a.manifestFingerprint += "b" },
		func(a *revisionAuthority) { a.workspacePath += "-other" },
		func(a *revisionAuthority) { a.runtimeKind += "-other" },
		func(a *revisionAuthority) { a.runtimeEndpoint += "-other" },
		func(a *revisionAuthority) { a.runtimeSocketPath += "-other" },
		func(a *revisionAuthority) { a.runtimeCLIPath += "-other" },
	} {
		changed := base
		mutation(&changed)
		if fingerprintRevisionAuthorityV2(changed, none) == noneHash ||
			fingerprintRevisionAuthorityV2(changed, persistent) == persistentHash {
			t.Fatal("unbound authority field")
		}
	}
	changed := base
	changed.runnerStatePath += "-other"
	if fingerprintRevisionAuthorityV2(changed, none) != noneHash {
		t.Fatal("none invented a state path")
	}
	if fingerprintRevisionAuthorityV2(changed, persistent) == persistentHash {
		t.Fatal("persistent omitted path")
	}
	if fingerprintRevisionAuthorityV2(base, targetmanifest.PersistentRunnerState("other")) == persistentHash {
		t.Fatal("persistent omitted ref")
	}
}

func TestV2ConfigFingerprintIgnoresUnreferencedStateButPinsPersistentMapping(t *testing.T) {
	for _, state := range []string{`{"kind":"none"}`, `{"kind":"persistent","ref":"mock-state"}`} {
		config := loadedV2Config(t, state)
		target := config.Targets[0]
		fingerprint, _ := target.Fingerprint()
		first, err := config.RevisionSecurityFingerprint(target, fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		config.RunnerStates[0].Directory += "-other"
		second, err := config.RevisionSecurityFingerprint(target, fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		if (first == second) != (target.RunnerState().Kind() == targetmanifest.RunnerStateNone) {
			t.Fatal("state mapping has incorrect fingerprint effect")
		}
	}
}
