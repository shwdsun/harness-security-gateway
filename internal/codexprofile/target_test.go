package codexprofile

import (
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func matchingTarget(c Contract) targetmanifest.ManifestV2 {
	return targetmanifest.ManifestV2{
		Schema: targetmanifest.SchemaV2, ID: "codex-test", Revision: "codex-test-r1",
		Runner: targetmanifest.Runner{Family: c.Runner.Family, AdapterVersion: c.Runner.AdapterVersion,
			Protocol: c.Runner.Protocol, RequiredFeatures: []runnerwire.Feature{},
			Image: "example/codex@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		WorkspaceRef: "project", WorkspaceMode: targetmanifest.WorkspaceReadWrite,
		RunnerState: targetmanifest.NoRunnerState(), SessionMode: targetmanifest.SessionNewOnly,
		PolicyRef: c.Profiles.Policy, AuthProfileRef: c.Profiles.Auth,
		SkillBundleRef: c.Profiles.Skill, NetworkProfileRef: c.Profiles.Network,
		Limits: targetmanifest.Limits{TimeoutSeconds: 300, MemoryBytes: 512 << 20,
			CPUMillis: 1000, PIDs: 64, MaxInputBytes: 32768, MaxOutputBytes: 2000,
			MaxProgressBytes: 4096, MaxStderrBytes: 4096, MaxEvents: 16},
	}
}

func TestSealedTargetMatch(t *testing.T) {
	for _, c := range []Contract{V1(), V2()} {
		m := matchingTarget(c)
		d, err := targetmanifest.FromV2(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.MatchTarget(d); err != nil {
			t.Fatal(err)
		}
		wrong := V2()
		if c.ID == IDV2 {
			wrong = V1()
		}
		if err := wrong.MatchTarget(d); err == nil {
			t.Fatal("cross-profile adapter accepted")
		}
	}
	if err := V1().MatchTarget(targetmanifest.Definition{}); err == nil {
		t.Fatal("zero target accepted")
	}
	d, _ := targetmanifest.FromV2(matchingTarget(V1()))
	if err := (Contract{}).MatchTarget(d); err == nil {
		t.Fatal("zero contract accepted")
	}
}

func TestTargetProjectionRejectsAuthorityChanges(t *testing.T) {
	mutations := map[string]func(*targetmanifest.ManifestV2){
		"family":   func(m *targetmanifest.ManifestV2) { m.Runner.Family = "mock" },
		"adapter":  func(m *targetmanifest.ManifestV2) { m.Runner.AdapterVersion = "other" },
		"protocol": func(m *targetmanifest.ManifestV2) { m.Runner.Protocol = "hrp/2" },
		"feature": func(m *targetmanifest.ManifestV2) {
			m.Runner.RequiredFeatures = []runnerwire.Feature{runnerwire.FeatureProgressText}
		},
		"state":   func(m *targetmanifest.ManifestV2) { m.RunnerState = targetmanifest.PersistentRunnerState("state") },
		"policy":  func(m *targetmanifest.ManifestV2) { m.PolicyRef = "builtin.locked-down-v1" },
		"auth":    func(m *targetmanifest.ManifestV2) { m.AuthProfileRef = "builtin.none" },
		"skill":   func(m *targetmanifest.ManifestV2) { m.SkillBundleRef = "other" },
		"network": func(m *targetmanifest.ManifestV2) { m.NetworkProfileRef = "builtin.none" },
		"resume": func(m *targetmanifest.ManifestV2) {
			m.SessionMode = targetmanifest.SessionOpaqueResume
			m.Runner.RequiredFeatures = []runnerwire.Feature{runnerwire.FeatureSessionResume}
			m.Limits.MaxSessionTurns = 1
			m.Limits.MaxSessionAgeSeconds = 60
		},
		"invalid limit": func(m *targetmanifest.ManifestV2) { m.Limits.PIDs = 0 },
	}
	for _, c := range []Contract{V1(), V2()} {
		for name, mutate := range mutations {
			t.Run(c.ID+"/"+name, func(t *testing.T) {
				m := matchingTarget(c)
				mutate(&m)
				d, err := targetmanifest.FromV2(m)
				if err == nil && c.MatchTarget(d) == nil {
					t.Fatal("authority mutation accepted")
				}
			})
		}
	}
	// A truthful legacy target is persistent; there is no silent v1 projection.
	m := matchingTarget(V1())
	legacy, err := targetmanifest.FromV1(targetmanifest.Manifest{
		Schema: targetmanifest.SchemaV1, ID: m.ID, Revision: m.Revision, Runner: m.Runner,
		WorkspaceRef: m.WorkspaceRef, WorkspaceMode: m.WorkspaceMode, StateRef: "legacy",
		PolicyRef: m.PolicyRef, AuthProfileRef: m.AuthProfileRef, SkillBundleRef: m.SkillBundleRef,
		NetworkProfileRef: m.NetworkProfileRef, SessionMode: m.SessionMode, Limits: m.Limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	if V1().MatchTarget(legacy) == nil {
		t.Fatal("legacy persistent target accepted")
	}
}

func TestMessagingEnvelopeDoesNotChangeV1(t *testing.T) {
	for _, change := range []func(*targetmanifest.ManifestV2){
		func(m *targetmanifest.ManifestV2) { m.Limits.TimeoutSeconds = 60 },
		func(m *targetmanifest.ManifestV2) { m.Limits.MaxOutputBytes = 2001 },
		func(m *targetmanifest.ManifestV2) { m.Limits.MaxOutputBytes = 1999 },
		func(m *targetmanifest.ManifestV2) { m.WorkspaceMode = targetmanifest.WorkspaceReadOnly },
	} {
		for _, c := range []Contract{V1(), V2()} {
			m := matchingTarget(c)
			change(&m)
			d, err := targetmanifest.FromV2(m)
			if err != nil {
				t.Fatal(err)
			}
			if got := c.MatchTarget(d); (got == nil) != (c.ID == IDV1) {
				t.Fatalf("%s: %v", c.ID, got)
			}
		}
	}
}
