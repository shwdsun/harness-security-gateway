package sandboxconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func v2ConfigDocument(cli, state string) string {
	document := strings.Replace(validConfigJSON(cli), `"sandboxd/v2"`, `"sandboxd/v3"`, 1)
	document = strings.Replace(document, `"harness-target/v1"`, `"harness-target/v2"`, 1)
	return strings.Replace(document, `"state_ref":"mock-state"`, `"runner_state":`+state, 1)
}

func TestV3NoStateExampleLoadsWithLocalOperatorPaths(t *testing.T) {
	data, err := os.ReadFile("../../config/sandboxd.v3-none.example.json")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	document := strings.Replace(string(data), `"/usr/bin/docker"`, quote(executable(t, root)), 1)
	document = strings.Replace(document, "unix:///run/user/1000/docker.sock", localRootlessEndpoint(), 1)
	config, err := Load(writeConfig(t, root, document, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if config.Schema != SchemaV3 || config.Targets[0].RunnerState().Kind() != targetmanifest.RunnerStateNone {
		t.Fatal("example is not v3 none")
	}
}

func loadedV2Config(t *testing.T, state string) Config {
	t.Helper()
	root := t.TempDir()
	config, err := Load(writeConfig(t, root, v2ConfigDocument(executable(t, root), state), 0o600))
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestConfigVersionGateAndRoundTrip(t *testing.T) {
	for _, state := range []string{`{"kind":"none"}`, `{"kind":"persistent","ref":"mock-state"}`} {
		config := loadedV2Config(t, state)
		fingerprint, _ := config.Targets[0].Fingerprint()
		legacy := loadedFingerprintConfig(t)
		if _, err := legacy.RevisionSecurityFingerprint(config.Targets[0], fingerprint); err == nil {
			t.Fatal("v2 bypassed legacy fingerprint resolver gate")
		}
		if _, err := legacy.RunnerStateOwnership(config.Targets[0]); err == nil {
			t.Fatal("v2 bypassed legacy ownership resolver gate")
		}
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Load(writeConfig(t, t.TempDir(), string(data), 0o600))
		if err != nil {
			t.Fatal(err)
		}
		if err := decoded.Validate(); err != nil {
			t.Fatal(err)
		}
		got, _ := decoded.Targets[0].Fingerprint()
		if got != fingerprint {
			t.Fatal("round trip changed target fingerprint")
		}
		decoded.Schema = SchemaV2
		if err := decoded.Validate(); err == nil {
			t.Fatal("v2 config accepted v2 target")
		}
		if _, err := decoded.Registry(); err == nil {
			t.Fatal("v2 target bypassed config gate through Registry")
		}
	}
	root := t.TempDir()
	document := strings.Replace(v2ConfigDocument(executable(t, root), `{"kind":"none"}`), `"sandboxd/v3"`, `"sandboxd/v2"`, 1)
	if _, err := Load(writeConfig(t, root, document, 0o600)); err == nil {
		t.Fatal("JSON bypassed version gate")
	}
}

func TestConfigV3NoneNeedsNoStateCatalogEntryOrLeaf(t *testing.T) {
	config := loadedV2Config(t, `{"kind":"none"}`)
	config.RunnerStates = []StorageEntry{}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	// A dangling root makes persistent state lookup unusable; none must not
	// stat a fabricated target path or silently treat "" as ".".
	if err := os.MkdirAll(filepath.Dir(config.RunnerStateRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/missing-hsg-test-state-root", config.RunnerStateRoot); err != nil {
		t.Fatal(err)
	}
	owner, err := config.RunnerStateOwnership(config.Targets[0])
	if err != nil {
		t.Fatal(err)
	}
	if owner.Kind != targetmanifest.RunnerStateNone || owner.Ref != "" || owner.PathDigest != "" || owner.PathAbsent {
		t.Fatalf("none fabricated ownership: %#v", owner)
	}
	config.RunnerStates = nil
	if err := config.Validate(); err == nil {
		t.Fatal("missing v3 state catalog accepted")
	}
}

func TestConfigV3MixedVersionsAndDuplicateIdentity(t *testing.T) {
	legacy := loadedFingerprintConfig(t).Targets[0]
	config := loadedV2Config(t, `{"kind":"none"}`)
	second, _ := config.Targets[0].ManifestV2()
	second.ID, second.Revision = "mock-none", "mock-none-r1"
	definition, err := targetmanifest.FromV2(second)
	if err != nil {
		t.Fatal(err)
	}
	config.Targets = []targetmanifest.Definition{legacy, definition}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	config.Targets = append(config.Targets, legacy)
	if err := config.Validate(); err == nil {
		t.Fatal("duplicate identity accepted")
	}
}

func TestConfigV3RejectsUnimplementedProfiles(t *testing.T) {
	for _, mutate := range []func(*targetmanifest.ManifestV2){
		func(m *targetmanifest.ManifestV2) { m.Runner.Family = "codex" },
		func(m *targetmanifest.ManifestV2) { m.Runner.AdapterVersion = "9.0.0" },
		func(m *targetmanifest.ManifestV2) { m.PolicyRef = "policy.custom" },
		func(m *targetmanifest.ManifestV2) { m.AuthProfileRef = "auth.personal" },
		func(m *targetmanifest.ManifestV2) { m.SkillBundleRef = "skills.custom" },
		func(m *targetmanifest.ManifestV2) { m.NetworkProfileRef = "network.internet" },
	} {
		config := loadedV2Config(t, `{"kind":"none"}`)
		original, _ := config.Targets[0].ManifestV2()
		mutate(&original)
		candidate, err := targetmanifest.FromV2(original)
		if err != nil {
			t.Fatal(err)
		}
		config.Targets[0] = candidate
		if err := config.Validate(); err == nil {
			t.Fatal("unsupported v2 profile accepted")
		}
		if _, err := config.Registry(); err == nil {
			t.Fatal("registry bypassed profile gate")
		}
	}
}
