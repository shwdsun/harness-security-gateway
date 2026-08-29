package targetmanifest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
)

const imageDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validManifest() Manifest {
	return Manifest{
		Schema:   SchemaV1,
		ID:       "project-codex",
		Revision: "project-codex-r1",
		Runner: Runner{
			Family:           "codex",
			AdapterVersion:   "0.1.0",
			Protocol:         runnerwire.ProtocolV1,
			Image:            "registry.example/runner-codex@sha256:" + imageDigest,
			RequiredFeatures: []runnerwire.Feature{runnerwire.FeatureSessionResume, runnerwire.FeatureProgressText},
		},
		WorkspaceRef:      "project-main",
		WorkspaceMode:     WorkspaceReadWrite,
		StateRef:          "project-codex-state",
		PolicyRef:         "codex-reviewed-v1",
		AuthProfileRef:    "codex-auth-proxy-v1",
		SkillBundleRef:    "codex-skills-v1",
		NetworkProfileRef: "model-proxy-only-v1",
		SessionMode:       SessionOpaqueResume,
		Limits: Limits{
			TimeoutSeconds:       1800,
			MemoryBytes:          2 << 30,
			CPUMillis:            2000,
			PIDs:                 256,
			MaxInputBytes:        32 << 10,
			MaxOutputBytes:       32 << 10,
			MaxProgressBytes:     4 << 10,
			MaxStderrBytes:       64 << 10,
			MaxEvents:            512,
			MaxSessionAgeSeconds: 7 * 24 * 60 * 60,
			MaxSessionTurns:      128,
		},
	}
}

func TestSessionLifecycleLimitsAreModeBoundedAndFingerprintRelevant(t *testing.T) {
	manifest := validManifest()
	baseline, err := manifest.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Manifest){
		func(value *Manifest) { value.Limits.MaxSessionAgeSeconds = 0 },
		func(value *Manifest) { value.Limits.MaxSessionAgeSeconds = MaxSessionAgeSeconds + 1 },
		func(value *Manifest) { value.Limits.MaxSessionTurns = 0 },
		func(value *Manifest) { value.Limits.MaxSessionTurns = MaxSessionTurns + 1 },
	} {
		changed := manifest
		mutate(&changed)
		if err := changed.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid session limits error = %v", err)
		}
	}
	changed := manifest
	changed.Limits.MaxSessionTurns++
	fingerprint, err := changed.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint == baseline {
		t.Fatal("session lifecycle policy did not change fingerprint")
	}
	newOnly := manifest
	newOnly.SessionMode = SessionNewOnly
	newOnly.Runner.RequiredFeatures = []runnerwire.Feature{runnerwire.FeatureProgressText}
	if err := newOnly.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("new_only nonzero lifecycle limits error = %v", err)
	}
	newOnly.Limits.MaxSessionAgeSeconds = 0
	newOnly.Limits.MaxSessionTurns = 0
	if err := newOnly.Validate(); err != nil {
		t.Fatalf("new_only zero lifecycle limits error = %v", err)
	}
	atBoundary := manifest
	atBoundary.Limits.MaxSessionAgeSeconds = MaxSessionAgeSeconds
	atBoundary.Limits.MaxSessionTurns = MaxSessionTurns
	if err := atBoundary.Validate(); err != nil {
		t.Fatalf("maximum lifecycle limits error = %v", err)
	}
}

func TestManifestValidAndFingerprintStable(t *testing.T) {
	manifest := validManifest()
	first, err := manifest.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	manifest.Runner.RequiredFeatures[0], manifest.Runner.RequiredFeatures[1] = manifest.Runner.RequiredFeatures[1], manifest.Runner.RequiredFeatures[0]
	second, err := manifest.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != 64 {
		t.Fatalf("fingerprints = %q, %q", first, second)
	}
	manifest.PolicyRef = "codex-reviewed-v2"
	third, err := manifest.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Fatal("policy change did not change fingerprint")
	}
}

func TestManifestRequiresDigestPinnedImage(t *testing.T) {
	manifest := validManifest()
	manifest.Runner.Image = "registry.example/runner-codex:latest"
	if err := manifest.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tag-only image error = %v", err)
	}
	manifest.Runner.Image = "registry.example/runner-codex@sha256:" + strings.ToUpper(imageDigest)
	if err := manifest.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("uppercase digest error = %v", err)
	}
}

func TestResumeRequiresFeature(t *testing.T) {
	manifest := validManifest()
	manifest.Runner.RequiredFeatures = []runnerwire.Feature{runnerwire.FeatureProgressText}
	if err := manifest.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing resume feature error = %v", err)
	}
}

func TestDecodeRejectsAuthorityEscapeFields(t *testing.T) {
	manifest := validManifest()
	data, err := jsonMarshalForTest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"env", "mounts", "argv", "host_path", "provider_options", "metadata"} {
		t.Run(field, func(t *testing.T) {
			payload := strings.TrimSuffix(string(data), "}") + `,"` + field + `":{}}`
			if _, err := Decode([]byte(payload)); err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("Decode() error = %v", err)
			}
		})
	}
}

func TestLogicalRefsRejectPathDotSegments(t *testing.T) {
	for _, value := range []string{".", ".."} {
		manifest := validManifest()
		manifest.WorkspaceRef = value
		if err := manifest.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("WorkspaceRef %q error = %v, want ErrInvalid", value, err)
		}
	}
}

func jsonMarshalForTest(value any) ([]byte, error) {
	return json.Marshal(value)
}
