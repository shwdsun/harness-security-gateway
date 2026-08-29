package targetregistry

import (
	"errors"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func fixture() targetmanifest.Manifest {
	return targetmanifest.Manifest{
		Schema:   targetmanifest.SchemaV1,
		ID:       "target-one",
		Revision: "target-one-r1",
		Runner: targetmanifest.Runner{
			Family:           "mock",
			AdapterVersion:   "0.1.0",
			Protocol:         runnerwire.ProtocolV1,
			Image:            "local/mock@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			RequiredFeatures: []runnerwire.Feature{},
		},
		WorkspaceRef:      "workspace-one",
		WorkspaceMode:     targetmanifest.WorkspaceReadWrite,
		StateRef:          "state-one",
		PolicyRef:         "mock-policy-v1",
		AuthProfileRef:    "none",
		SkillBundleRef:    "none",
		NetworkProfileRef: "none",
		SessionMode:       targetmanifest.SessionNewOnly,
		Limits: targetmanifest.Limits{
			TimeoutSeconds:   30,
			MemoryBytes:      128 << 20,
			CPUMillis:        500,
			PIDs:             32,
			MaxInputBytes:    4096,
			MaxOutputBytes:   4096,
			MaxProgressBytes: 1024,
			MaxStderrBytes:   4096,
			MaxEvents:        16,
		},
	}
}

func TestResolvePinsRevision(t *testing.T) {
	manifest := fixture()
	registry, err := New([]targetmanifest.Manifest{manifest})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := registry.Resolve(manifest.ID, manifest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Manifest.ID != manifest.ID || len(entry.Fingerprint) != 64 {
		t.Fatalf("entry = %#v", entry)
	}
	if _, err := registry.Resolve(manifest.ID, "replacement"); !errors.Is(err, ErrRevisionMismatch) {
		t.Fatalf("revision error = %v", err)
	}
	if _, err := registry.Resolve("missing", "r1"); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("missing error = %v", err)
	}
}

func TestNewRejectsDuplicateID(t *testing.T) {
	manifest := fixture()
	copy := manifest
	copy.Revision = "target-one-r2"
	if _, err := New([]targetmanifest.Manifest{manifest, copy}); !errors.Is(err, ErrDuplicateTarget) {
		t.Fatalf("duplicate error = %v", err)
	}
}
