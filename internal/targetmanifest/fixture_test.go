package targetmanifest

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
)

// Captured from the first v2 candidate and retained through strict-decoding
// corrections. The independently captured v1 hash is in v1_compatibility_test.
const pinnedV2Fingerprint = "c38543981d1e620089d97bdf9c4613167f54a5bec22869185ce70bc4a60b701b"

func TestV1CanonicalBytesPinned(t *testing.T) {
	features := []string{string(runnerwire.FeatureProgressText), string(runnerwire.FeatureSessionResume)}
	sort.Strings(features)
	want := `{"schema":"harness-target/v1","id":"project-codex","revision":"","runner":{"family":"codex","adapter_version":"0.1.0","protocol":"` + string(runnerwire.ProtocolV1) + `","image":"registry.example/runner-codex@sha256:` + imageDigest + `","required_features":["` + features[0] + `","` + features[1] + `"]},"workspace_ref":"project-main","workspace_mode":"rw","state_ref":"project-codex-state","policy_ref":"codex-reviewed-v1","auth_profile_ref":"codex-auth-proxy-v1","skill_bundle_ref":"codex-skills-v1","network_profile_ref":"model-proxy-only-v1","session_mode":"opaque_resume","limits":{"timeout_seconds":1800,"memory_bytes":2147483648,"cpu_millis":2000,"pids":256,"max_input_bytes":32768,"max_output_bytes":32768,"max_progress_bytes":4096,"max_stderr_bytes":65536,"max_events":512,"max_session_age_seconds":604800,"max_session_turns":128}}`
	normalized := validManifest()
	normalized.Revision = ""
	normalized.Runner.RequiredFeatures = sortedFeatures(normalized.Runner.RequiredFeatures)
	data, err := json.Marshal(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Fatalf("canonical v1 bytes drifted:\n got %s\nwant %s", data, want)
	}
}

func TestV2FingerprintPinnedFixture(t *testing.T) {
	got, err := validManifestV2().Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if got != pinnedV2Fingerprint {
		t.Fatalf("v2 fingerprint drifted: got %s want %s", got, pinnedV2Fingerprint)
	}
}

func TestEmptyFeaturesPreserveLegacyCanonicalNull(t *testing.T) {
	if sortedFeatures([]runnerwire.Feature{}) != nil {
		t.Fatal("empty features must retain the legacy JSON null normalization")
	}
}
