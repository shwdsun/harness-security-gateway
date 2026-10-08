package dockerruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func fixtureV2Definition(t *testing.T, fixture testFixture, state string) targetmanifest.Definition {
	t.Helper()
	data, err := json.Marshal(fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	document := strings.Replace(string(data), `"harness-target/v1"`, `"harness-target/v2"`, 1)
	document = strings.Replace(document, `"state_ref":"`+fixture.manifest.StateRef+`"`, `"runner_state":`+state, 1)
	definition, err := targetmanifest.DecodeDefinition([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	return definition
}

func TestV2CreateStateMountIsExplicitAndNoneNeverUsesStateStorage(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(map[bool]string{false: "none", true: "persistent"}[persistent], func(t *testing.T) {
			fixture := newFixture(t)
			state := `{"kind":"none"}`
			if persistent {
				state = `{"kind":"persistent","ref":"` + fixture.manifest.StateRef + `"}`
			}
			target := fixtureV2Definition(t, fixture, state)
			fixture.config.Schema = sandboxconfig.SchemaV3
			fixture.config.Targets = []targetmanifest.Definition{target}
			if !persistent {
				fixture.config.RunnerStates = []sandboxconfig.StorageEntry{{Ref: "unused", Directory: "must-not-be-looked-up"}}
				fixture.config.RunnerStateRoot = t.TempDir()
				if err := os.Chmod(fixture.config.RunnerStateRoot, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			fingerprint, _ := target.Fingerprint()
			record, err := json.Marshal(inspectRecord{ID: testContainerID, Name: "/" + deterministicName("run-v2"),
				Image: target.Common().Runner.Image, State: StateCreated, Labels: expectedLabels("run-v2", target, fingerprint)})
			if err != nil {
				t.Fatal(err)
			}
			fixture.setPlan(t, rootlessInfoStep(), helperStep{Stdout: testContainerID + "\n"}, helperStep{Stdout: string(record) + "\n"})
			runtime, err := New(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runtime.Create(context.Background(), "run-v2", target); err != nil {
				t.Fatal(err)
			}
			calls := fixture.calls(t)
			if len(calls) != 3 {
				t.Fatalf("CLI calls: %#v", calls)
			}
			mounts, stateMounts := 0, 0
			for index, arg := range calls[1].Arguments {
				if arg == "--mount" {
					mounts++
					if strings.Contains(calls[1].Arguments[index+1], "dst=/state,") {
						stateMounts++
					}
				}
			}
			if (persistent && (mounts != 2 || stateMounts != 1)) || (!persistent && (mounts != 1 || stateMounts != 0)) {
				t.Fatalf("incorrect mounts: %#v", calls[1].Arguments)
			}
			if !persistent {
				spec := runtime.targets[targetKey{id: target.ID(), revision: target.Revision()}]
				if spec.statePath != "" || spec.stateRoot != "" {
					t.Fatalf("none resolved a path: %#v", spec)
				}
				leaves, err := os.ReadDir(fixture.config.RunnerStateRoot)
				if err != nil || len(leaves) != 0 {
					t.Fatalf("none created state leaf: %v %v", leaves, err)
				}
				spec.stateKind = ""
				if err := validateSpecStorage(spec); err == nil {
					t.Fatal("unknown state kind reached create")
				}
			}
		})
	}
}

func TestV2UnapprovedSuppliedProfileNeverReachesCLI(t *testing.T) {
	fixture := newFixture(t)
	target := fixtureV2Definition(t, fixture, `{"kind":"none"}`)
	fixture.config.Schema = sandboxconfig.SchemaV3
	fixture.config.Targets = []targetmanifest.Definition{target}
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := target.ManifestV2()
	raw.Runner.Family = "codex"
	forbidden, err := targetmanifest.FromV2(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Create(context.Background(), "run-forbidden", forbidden); !errors.Is(err, ErrUnsupportedProfile) {
		t.Fatalf("unapproved profile result: %v", err)
	}
	if calls := fixture.calls(t); len(calls) != 0 {
		t.Fatalf("unapproved profile reached CLI: %#v", calls)
	}
}
