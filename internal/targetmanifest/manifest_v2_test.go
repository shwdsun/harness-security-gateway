package targetmanifest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
)

func validManifestV2() ManifestV2 {
	v1 := validManifest()
	return ManifestV2{
		Schema: SchemaV2, ID: v1.ID, Revision: v1.Revision, Runner: v1.Runner,
		WorkspaceRef: v1.WorkspaceRef, WorkspaceMode: v1.WorkspaceMode,
		RunnerState: PersistentRunnerState("project-codex-state"),
		PolicyRef:   v1.PolicyRef, AuthProfileRef: v1.AuthProfileRef,
		SkillBundleRef: v1.SkillBundleRef, NetworkProfileRef: v1.NetworkProfileRef,
		SessionMode: v1.SessionMode, Limits: v1.Limits,
	}
}

func newOnlyV2(state RunnerState) ManifestV2 {
	m := validManifestV2()
	m.RunnerState = state
	m.SessionMode = SessionNewOnly
	m.Runner.RequiredFeatures = []runnerwire.Feature{runnerwire.FeatureProgressText}
	m.Limits.MaxSessionAgeSeconds, m.Limits.MaxSessionTurns = 0, 0
	return m
}

const stateSegment = `,"runner_state":{"kind":"persistent","ref":"project-codex-state"}`

func v2Payload(t *testing.T, segment string) string {
	t.Helper()
	data, err := json.Marshal(validManifestV2())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), stateSegment) {
		t.Fatalf("payload lacks state segment: %s", data)
	}
	return strings.Replace(string(data), stateSegment, segment, 1)
}

func TestRunnerStateUnionProgrammatic(t *testing.T) {
	if err := (RunnerState{}).Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero state error = %v", err)
	}
	for _, ref := range []string{"", ".", "..", "bad/ref", strings.Repeat("a", MaxNameBytes+1)} {
		if err := PersistentRunnerState(ref).Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("persistent(%q) error = %v", ref, err)
		}
	}
	if err := NoRunnerState().Validate(); err != nil {
		t.Fatal(err)
	}
	if ref, ok := NoRunnerState().PersistentRef(); ok || ref != "" {
		t.Fatalf("none exposed ref %q", ref)
	}
	if ref, ok := PersistentRunnerState("s").PersistentRef(); !ok || ref != "s" {
		t.Fatalf("persistent ref = %q, %v", ref, ok)
	}
	if _, err := json.Marshal(RunnerState{}); err == nil {
		t.Fatal("zero state marshalled")
	}
	for state, want := range map[RunnerState]string{
		NoRunnerState():            `{"kind":"none"}`,
		PersistentRunnerState("s"): `{"kind":"persistent","ref":"s"}`,
	} {
		data, err := json.Marshal(state)
		if err != nil || string(data) != want {
			t.Fatalf("marshal = %s, %v; want %s", data, err, want)
		}
	}
	m := validManifestV2()
	m.RunnerState = RunnerState{}
	if err := m.Validate(); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "runner_state") {
		t.Fatalf("manifest with zero state error = %v", err)
	}
}

func TestV2NoneRequiresNewOnly(t *testing.T) {
	none := validManifestV2()
	none.RunnerState = NoRunnerState()
	if err := none.Validate(); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "new_only") {
		t.Fatalf("none+opaque_resume error = %v", err)
	}
	if err := newOnlyV2(NoRunnerState()).Validate(); err != nil {
		t.Fatalf("none+new_only error = %v", err)
	}
	if err := newOnlyV2(PersistentRunnerState("s")).Validate(); err != nil {
		t.Fatalf("persistent+new_only error = %v", err)
	}
	if err := validManifestV2().Validate(); err != nil {
		t.Fatalf("persistent+opaque_resume error = %v", err)
	}
}

func TestDecodeV2Shapes(t *testing.T) {
	for _, segment := range []string{
		`,"runner_state":{"kind":"none"}`,
		`,"runner_state":{"kind":"persistent","ref":"other-state"}`,
	} {
		payload := strings.Replace(v2Payload(t, segment), `"session_mode":"opaque_resume"`, `"session_mode":"new_only"`, 1)
		payload = strings.Replace(payload, `"max_session_age_seconds":604800,"max_session_turns":128`, `"max_session_age_seconds":0,"max_session_turns":0`, 1)
		if _, err := DecodeV2([]byte(payload)); err != nil {
			t.Fatalf("accept %s: %v", segment, err)
		}
	}
	if _, err := DecodeV2([]byte(v2Payload(t, stateSegment))); err != nil {
		t.Fatal(err)
	}
	rejected := map[string]string{
		"missing":             "",
		"null":                `,"runner_state":null`,
		"string":              `,"runner_state":"none"`,
		"empty object":        `,"runner_state":{}`,
		"null kind":           `,"runner_state":{"kind":null}`,
		"unknown kind":        `,"runner_state":{"kind":"ephemeral"}`,
		"none null ref":       `,"runner_state":{"kind":"none","ref":null}`,
		"none empty ref":      `,"runner_state":{"kind":"none","ref":""}`,
		"none with ref":       `,"runner_state":{"kind":"none","ref":"s"}`,
		"persistent no ref":   `,"runner_state":{"kind":"persistent"}`,
		"persistent null ref": `,"runner_state":{"kind":"persistent","ref":null}`,
		"persistent empty":    `,"runner_state":{"kind":"persistent","ref":""}`,
		"persistent bad ref":  `,"runner_state":{"kind":"persistent","ref":"a/b"}`,
		"persistent int ref":  `,"runner_state":{"kind":"persistent","ref":5}`,
		"extra field":         `,"runner_state":{"kind":"persistent","ref":"s","path":"/x"}`,
		"duplicate key":       `,"runner_state":{"kind":"none","kind":"none"}`,
		"state_ref alias":     stateSegment + `,"state_ref":"project-codex-state"`,
		"state_ref null":      stateSegment + `,"state_ref":null`,
		"none opaque_resume":  `,"runner_state":{"kind":"none"}`,
	}
	for name, segment := range rejected {
		t.Run(name, func(t *testing.T) {
			if m, err := DecodeV2([]byte(v2Payload(t, segment))); err == nil {
				t.Fatalf("accepted %#v", m)
			}
		})
	}
	base := v2Payload(t, stateSegment)
	for name, payload := range map[string]string{
		"v1 schema":    strings.Replace(base, SchemaV2, SchemaV1, 1),
		"trailing":     base + "{}",
		"invalid utf8": base + "\xff",
		"too deep":     strings.Repeat("[", MaxJSONDepth+1) + strings.Repeat("]", MaxJSONDepth+1),
		"too large":    base + strings.Repeat(" ", MaxManifest),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeV2([]byte(payload)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestContractsRefuseEachOther(t *testing.T) {
	v2 := v2Payload(t, stateSegment)
	if _, err := Decode([]byte(v2)); err == nil {
		t.Fatal("v1 Decode accepted v2 payload")
	}
	if _, err := Decode([]byte(strings.Replace(v2, SchemaV2, SchemaV1, 1))); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("v1 Decode mixed payload error = %v", err)
	}
	v1, err := json.Marshal(validManifest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeV2(v1); err == nil {
		t.Fatal("DecodeV2 accepted v1 payload")
	}
	mixed := strings.Replace(string(v1), SchemaV1, SchemaV2, 1)
	if _, err := DecodeV2([]byte(mixed)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("DecodeV2 mixed payload error = %v", err)
	}
}

func TestV2FingerprintBindsSemantics(t *testing.T) {
	base := validManifestV2()
	baseline, err := base.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	fp := func(m ManifestV2) string {
		t.Helper()
		got, err := m.Fingerprint()
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	for name, mutate := range map[string]func(*ManifestV2){
		"family":   func(m *ManifestV2) { m.Runner.Family = "other" },
		"adapter":  func(m *ManifestV2) { m.Runner.AdapterVersion = "0.2.0" },
		"features": func(m *ManifestV2) { m.Runner.RequiredFeatures = []runnerwire.Feature{runnerwire.FeatureSessionResume} },
		"timeout":  func(m *ManifestV2) { m.Limits.TimeoutSeconds++ },
		"memory":   func(m *ManifestV2) { m.Limits.MemoryBytes++ },
		"cpu":      func(m *ManifestV2) { m.Limits.CPUMillis++ },
		"pids":     func(m *ManifestV2) { m.Limits.PIDs++ },
		"input":    func(m *ManifestV2) { m.Limits.MaxInputBytes-- },
		"output":   func(m *ManifestV2) { m.Limits.MaxOutputBytes-- },
		"progress": func(m *ManifestV2) { m.Limits.MaxProgressBytes-- },
		"stderr":   func(m *ManifestV2) { m.Limits.MaxStderrBytes-- },
		"events":   func(m *ManifestV2) { m.Limits.MaxEvents-- },
		"age":      func(m *ManifestV2) { m.Limits.MaxSessionAgeSeconds++ },
		"session": func(m *ManifestV2) {
			m.SessionMode = SessionNewOnly
			m.Limits.MaxSessionAgeSeconds, m.Limits.MaxSessionTurns = 0, 0
		},
		"ref":       func(m *ManifestV2) { m.RunnerState = PersistentRunnerState("other-state") },
		"id":        func(m *ManifestV2) { m.ID = "x" },
		"workspace": func(m *ManifestV2) { m.WorkspaceRef = "x" },
		"ws mode":   func(m *ManifestV2) { m.WorkspaceMode = WorkspaceReadOnly },
		"policy":    func(m *ManifestV2) { m.PolicyRef = "x" },
		"auth":      func(m *ManifestV2) { m.AuthProfileRef = "x" },
		"skills":    func(m *ManifestV2) { m.SkillBundleRef = "x" },
		"network":   func(m *ManifestV2) { m.NetworkProfileRef = "x" },
		"image":     func(m *ManifestV2) { m.Runner.Image = "registry.example/other@sha256:" + imageDigest },
		"limits":    func(m *ManifestV2) { m.Limits.MaxSessionTurns++ },
	} {
		changed := base
		mutate(&changed)
		if fp(changed) == baseline {
			t.Fatalf("%s change did not alter fingerprint", name)
		}
	}
	if fp(newOnlyV2(NoRunnerState())) == fp(newOnlyV2(PersistentRunnerState("project-codex-state"))) {
		t.Fatal("state kind not bound")
	}
	revised := base
	revised.Revision = "project-codex-r2"
	if fp(revised) != baseline {
		t.Fatal("revision leaked into fingerprint")
	}
	reordered := base
	reordered.Runner.RequiredFeatures = []runnerwire.Feature{runnerwire.FeatureProgressText, runnerwire.FeatureSessionResume}
	before := append([]runnerwire.Feature(nil), reordered.Runner.RequiredFeatures...)
	if fp(reordered) != baseline {
		t.Fatal("feature order leaked into fingerprint")
	}
	for i := range before {
		if reordered.Runner.RequiredFeatures[i] != before[i] {
			t.Fatal("caller slice mutated")
		}
	}
	v1fp, err := validManifest().Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if v1fp == baseline {
		t.Fatal("v1 and v2 fingerprints collide")
	}
}
