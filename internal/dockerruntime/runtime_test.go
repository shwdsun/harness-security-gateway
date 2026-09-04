package dockerruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

const testContainerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestCreateUsesExactLockedDockerArguments(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: testContainerID + "\n"},
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateCreated)},
	)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := runtime.Create(context.Background(), "run-1", fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	if ref != ContainerRef(testContainerID) {
		t.Fatalf("unexpected ref %q", ref)
	}

	fingerprint, err := fixture.manifest.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	name := deterministicName("run-1")
	wantCreate := []string{
		"--host", fixture.config.Runtime.Endpoint,
		"container", "create",
		"--name", name,
		"--pull=never",
		"--label", labelManaged + "=v1",
		"--label", labelRunID + "=run-1",
		"--label", labelTargetID + "=" + fixture.manifest.ID,
		"--label", labelTargetRevision + "=" + fixture.manifest.Revision,
		"--label", labelTargetFingerprint + "=" + fingerprint,
		"--interactive",
		"--network", "none",
		"--read-only",
		"--restart", "no",
		"--no-healthcheck",
		"--log-driver", "none",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges=true",
		"--memory", "134217728",
		"--memory-swap", "134217728",
		"--cpus", "1.000",
		"--pids-limit", "64",
		"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=67108864,mode=1777",
		"--workdir", "/workspace",
		"--user", "0:0",
		"--mount", "type=bind,src=" + fixture.workspaceDir + ",dst=/workspace,bind-propagation=rprivate",
		"--mount", "type=bind,src=" + fixture.stateDir + ",dst=/state,bind-propagation=rprivate",
		fixture.manifest.Runner.Image,
	}
	calls := fixture.calls(t)
	if len(calls) != 3 {
		t.Fatalf("got %d calls, want 3", len(calls))
	}
	requireArguments(t, calls[0], []string{
		"--host", fixture.config.Runtime.Endpoint,
		"info", "--format", rootlessInfoFormat,
	})
	requireArguments(t, calls[1], wantCreate)
	requireArguments(t, calls[2], []string{
		"--host", fixture.config.Runtime.Endpoint,
		"container", "inspect", "--format", inspectFormat, testContainerID,
	})
	for _, forbidden := range []string{"--env", "--entrypoint", "--privileged", "--volume"} {
		for _, argument := range calls[1].Arguments {
			if argument == forbidden {
				t.Fatalf("create contained forbidden argument %q", forbidden)
			}
		}
	}
}

func TestCreateReadOnlyWorkspaceMount(t *testing.T) {
	fixture := newFixture(t)
	fixture.manifest.WorkspaceMode = targetmanifest.WorkspaceReadOnly
	fixture.config.Targets[0] = fixture.manifest
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	spec := runtime.targets[targetKey{id: fixture.manifest.ID, revision: fixture.manifest.Revision}]
	arguments := createArguments("safe-name", map[string]string{
		labelManaged: "v1", labelRunID: "run", labelTargetID: fixture.manifest.ID,
		labelTargetRevision: fixture.manifest.Revision, labelTargetFingerprint: spec.fingerprint,
	}, spec, fixture.manifest)
	workspaceMount := "type=bind,src=" + fixture.workspaceDir + ",dst=/workspace,bind-propagation=rprivate,readonly"
	if !containsAdjacent(arguments, "--mount", workspaceMount) {
		t.Fatalf("missing read-only workspace mount in %q", arguments)
	}
	stateMount := "type=bind,src=" + fixture.stateDir + ",dst=/state,bind-propagation=rprivate"
	if !containsAdjacent(arguments, "--mount", stateMount) {
		t.Fatalf("missing writable state mount in %q", arguments)
	}
}

func TestNewAndCreateRejectUnapprovedAuthority(t *testing.T) {
	t.Run("Codex V1 manifest projection remains disabled", func(t *testing.T) {
		fixture := newFixture(t)
		manifest := fixture.config.Targets[0]
		manifest.Runner.Family = codexprofile.RunnerFamilyV1
		manifest.Runner.AdapterVersion = codexprofile.AdapterVersionV1
		manifest.Runner.Protocol = codexprofile.RunnerProtocolV1
		manifest.Runner.RequiredFeatures = []runnerwire.Feature{}
		manifest.PolicyRef = codexprofile.PolicyProfileRefV1
		manifest.AuthProfileRef = codexprofile.AuthProfileRefV1
		manifest.SkillBundleRef = codexprofile.SkillBundleRefV1
		manifest.NetworkProfileRef = codexprofile.NetworkProfileRefV1
		manifest.SessionMode = targetmanifest.SessionMode(codexprofile.SessionModeV1)
		manifest.Limits.MaxSessionAgeSeconds = 0
		manifest.Limits.MaxSessionTurns = 0
		fixture.config.Targets[0] = manifest

		_, err := New(fixture.config)
		if !errors.Is(err, ErrUnsupportedProfile) {
			t.Fatalf("Codex manifest projection error = %v, want ErrUnsupportedProfile", err)
		}
		if calls := fixture.calls(t); len(calls) != 0 {
			t.Fatalf("profile validation invoked Docker: %#v", calls)
		}
	})

	t.Run("unsupported configured profile", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.config.Targets[0].NetworkProfileRef = "network.internet"
		_, err := New(fixture.config)
		if !errors.Is(err, ErrUnsupportedProfile) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("unsupported supplied profile", func(t *testing.T) {
		fixture := newFixture(t)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		manifest := fixture.manifest
		manifest.AuthProfileRef = "auth.personal"
		_, err = runtime.Create(context.Background(), "run-1", manifest)
		if !errors.Is(err, ErrUnsupportedProfile) {
			t.Fatalf("got %v", err)
		}
		if calls := fixture.calls(t); len(calls) != 0 {
			t.Fatalf("unexpected CLI calls: %#v", calls)
		}
	})

	t.Run("different manifest", func(t *testing.T) {
		fixture := newFixture(t)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		manifest := fixture.manifest
		manifest.Runner.Image = "registry.example/other@sha256:" + strings.Repeat("b", 64)
		_, err = runtime.Create(context.Background(), "run-1", manifest)
		if !errors.Is(err, ErrTargetNotConfigured) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("malicious run id", func(t *testing.T) {
		fixture := newFixture(t)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		for _, runID := range []string{"bad/id", "bad\n--help", strings.Repeat("a", 65)} {
			_, err := runtime.Create(context.Background(), runID, fixture.manifest)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("run ID %q: got %v", runID, err)
			}
		}
	})

	t.Run("comma in storage path", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.config.WorkspaceRoot = fixture.config.WorkspaceRoot + ",option"
		_, err := New(fixture.config)
		if !errors.Is(err, ErrInvalidStorage) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("newline in storage path", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.config.WorkspaceRoot = fixture.config.WorkspaceRoot + "\noption"
		_, err := New(fixture.config)
		if !errors.Is(err, ErrInvalidStorage) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("group-writable mapped directory", func(t *testing.T) {
		fixture := newFixture(t)
		if err := os.Chmod(fixture.workspaceDir, 0o770); err != nil {
			t.Fatal(err)
		}
		_, err := New(fixture.config)
		if !errors.Is(err, ErrInvalidStorage) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("non-private runner state", func(t *testing.T) {
		fixture := newFixture(t)
		if err := os.Chmod(fixture.stateDir, 0o750); err != nil {
			t.Fatal(err)
		}
		_, err := New(fixture.config)
		if !errors.Is(err, ErrInvalidStorage) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("symlinked mapped directory", func(t *testing.T) {
		fixture := newFixture(t)
		realDirectory := filepath.Join(filepath.Dir(fixture.workspaceDir), "real-workspace")
		if err := os.Rename(fixture.workspaceDir, realDirectory); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realDirectory, fixture.workspaceDir); err != nil {
			t.Fatal(err)
		}
		_, err := New(fixture.config)
		if !errors.Is(err, ErrInvalidStorage) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("post-construction symlink substitution", func(t *testing.T) {
		fixture := newFixture(t)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		realDirectory := filepath.Join(filepath.Dir(fixture.workspaceDir), "real-workspace")
		if err := os.Rename(fixture.workspaceDir, realDirectory); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realDirectory, fixture.workspaceDir); err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Create(context.Background(), "run-1", fixture.manifest)
		if !errors.Is(err, ErrInvalidStorage) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("post-construction mode relaxation", func(t *testing.T) {
		fixture := newFixture(t)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fixture.stateDir, 0o777); err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Create(context.Background(), "run-1", fixture.manifest)
		if !errors.Is(err, ErrInvalidStorage) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("post-construction root mode relaxation", func(t *testing.T) {
		fixture := newFixture(t)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fixture.config.WorkspaceRoot, 0o777); err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Create(context.Background(), "run-1", fixture.manifest)
		if !errors.Is(err, ErrInvalidStorage) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestCreateIsIdempotentOnlyForExactManagedContainer(t *testing.T) {
	t.Run("adopt exact", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.setPlan(t,
			rootlessInfoStep(),
			helperStep{Stderr: "secret daemon detail", ExitCode: 125},
			helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateCreated)},
		)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := runtime.Create(context.Background(), "run-1", fixture.manifest)
		if err != nil {
			t.Fatal(err)
		}
		if ref != ContainerRef(testContainerID) {
			t.Fatalf("unexpected ref %q", ref)
		}
		if errors.Is(err, ErrCreateUncertain) {
			t.Fatalf("exact adoption remained uncertain: %v", err)
		}
		calls := fixture.calls(t)
		if len(calls) != 3 || calls[2].Arguments[len(calls[2].Arguments)-1] != deterministicName("run-1") {
			t.Fatalf("unexpected adoption calls: %#v", calls)
		}
	})

	t.Run("refuse foreign", func(t *testing.T) {
		fixture := newFixture(t)
		var record inspectRecord
		if err := json.Unmarshal([]byte(managedRecord(t, fixture, "run-1", testContainerID, StateCreated)), &record); err != nil {
			t.Fatal(err)
		}
		record.Labels[labelTargetFingerprint] = strings.Repeat("f", 64)
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		fixture.setPlan(t,
			rootlessInfoStep(),
			helperStep{Stderr: "secret daemon detail", ExitCode: 125},
			helperStep{Stdout: string(encoded)},
		)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Create(context.Background(), "run-1", fixture.manifest)
		if !errors.Is(err, ErrForeignContainer) {
			t.Fatalf("got %v", err)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("raw stderr leaked: %v", err)
		}
	})
}

func TestCreateUncertainClassification(t *testing.T) {
	t.Run("local validation is certain", func(t *testing.T) {
		fixture := newFixture(t)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Create(context.Background(), "bad/name", fixture.manifest)
		if !errors.Is(err, ErrInvalidArgument) || errors.Is(err, ErrCreateUncertain) {
			t.Fatalf("preflight error = %v", err)
		}
		if calls := fixture.calls(t); len(calls) != 0 {
			t.Fatalf("preflight reached CLI: %#v", calls)
		}
	})

	t.Run("rootless attestation failure is certain", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.setPlan(t, helperStep{Stdout: `["name=seccomp,profile=builtin"]`})
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Create(context.Background(), "run-1", fixture.manifest)
		if !errors.Is(err, ErrRootlessRequired) || errors.Is(err, ErrCreateUncertain) {
			t.Fatalf("attestation error = %v", err)
		}
	})

	t.Run("create CLI start failure is certain", func(t *testing.T) {
		fixture := newFixture(t)
		step := rootlessInfoStep()
		step.RemoveSelf = true
		fixture.setPlan(t, step)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Create(context.Background(), "run-1", fixture.manifest)
		if !errors.Is(err, ErrCommandFailed) || errors.Is(err, ErrCreateUncertain) {
			t.Fatalf("start failure = %v", err)
		}
		if calls := fixture.calls(t); len(calls) != 1 {
			t.Fatalf("start failure calls = %#v", calls)
		}
	})

	t.Run("completed failure remains uncertain after one absence", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.setPlan(t,
			rootlessInfoStep(),
			helperStep{ExitCode: 125, Stderr: "closed daemon rejection secret"},
			helperStep{ExitCode: 1},
			helperStep{},
		)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Create(context.Background(), "run-1", fixture.manifest)
		if !errors.Is(err, ErrCommandFailed) || !errors.Is(err, ErrCreateUncertain) {
			t.Fatalf("completed failure classification = %v", err)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("stderr leaked: %v", err)
		}
	})

	t.Run("cancelled create response is uncertain", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.setPlan(t,
			rootlessInfoStep(),
			helperStep{DelayMS: 30_000, Stdout: testContainerID + "\n"},
		)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		err = cancelCreateAfterHelperStep(t, runtime, fixture, 2)
		if !errors.Is(err, ErrCreateUncertain) || !errors.Is(err, context.Canceled) {
			t.Fatalf("killed create error = %v", err)
		}
		if got := err.Error(); strings.Contains(got, fixture.helper) || strings.Contains(got, testContainerID) {
			t.Fatalf("uncertain error leaked details: %v", err)
		}
	})

	t.Run("successful malformed response remains uncertain after absence", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.setPlan(t,
			rootlessInfoStep(),
			helperStep{Stdout: "not-a-container-id\n"},
			helperStep{ExitCode: 1},
			helperStep{},
		)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Create(context.Background(), "run-1", fixture.manifest)
		if !errors.Is(err, ErrCreateUncertain) || !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("malformed successful create = %v", err)
		}
	})

	t.Run("successful create inspect cancellation is uncertain", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.setPlan(t,
			rootlessInfoStep(),
			helperStep{Stdout: testContainerID + "\n"},
			helperStep{DelayMS: 30_000},
		)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		err = cancelCreateAfterHelperStep(t, runtime, fixture, 3)
		if !errors.Is(err, ErrCreateUncertain) || !errors.Is(err, context.Canceled) {
			t.Fatalf("inspect cancellation = %v", err)
		}
	})
}

func cancelCreateAfterHelperStep(t *testing.T, runtime *Runtime, fixture testFixture, wantNext int) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := runtime.Create(ctx, "run-1", fixture.manifest)
		result <- err
	}()

	waitErr := waitForHelperPlanNext(fixture, wantNext)
	cancel()
	select {
	case err := <-result:
		if waitErr != nil {
			t.Fatal(waitErr)
		}
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Create() did not return after context cancellation")
		return nil
	}
}

func waitForHelperPlanNext(fixture testFixture, wantNext int) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(fixture.helper + ".plan")
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read helper plan: %w", err)
		}
		if err == nil {
			var plan helperPlan
			// The helper rewrites this small file before it records the call and
			// enters its configured delay. A concurrent read can observe the
			// truncate/write window, so malformed snapshots are retried.
			if json.Unmarshal(data, &plan) == nil && plan.Next >= wantNext {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("helper plan did not reach step %d", wantNext)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCommandOutputIsBoundedAndErrorsAreSanitized(t *testing.T) {
	t.Run("output bound", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.setPlan(t,
			rootlessInfoStep(),
			helperStep{
				Stdout: strings.Repeat("x", commandStdoutLimit+1),
				Stderr: "secret-output-bound-detail",
			},
		)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Create(context.Background(), "run-1", fixture.manifest)
		if !errors.Is(err, ErrOutputLimit) {
			t.Fatalf("got %v", err)
		}
		if strings.Contains(err.Error(), "secret-output-bound-detail") {
			t.Fatalf("stderr leaked: %v", err)
		}
	})

	t.Run("stderr bound", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.setPlan(t,
			rootlessInfoStep(),
			helperStep{
				Stdout: testContainerID + "\n",
				Stderr: strings.Repeat("s", commandStderrLimit+1),
			},
		)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Create(context.Background(), "run-1", fixture.manifest)
		if !errors.Is(err, ErrOutputLimit) {
			t.Fatalf("got %v", err)
		}
		if strings.Contains(err.Error(), strings.Repeat("s", 16)) {
			t.Fatalf("stderr leaked: %v", err)
		}
	})

	t.Run("failed create and inspect", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.setPlan(t,
			rootlessInfoStep(),
			helperStep{Stderr: "registry credential secret", ExitCode: 125},
			helperStep{Stderr: "daemon filesystem secret", ExitCode: 1},
		)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Create(context.Background(), "run-1", fixture.manifest)
		if !errors.Is(err, ErrCommandFailed) {
			t.Fatalf("got %v", err)
		}
		for _, secret := range []string{"registry credential", "filesystem secret"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("stderr leaked: %v", err)
			}
		}
	})
}

func TestInspectAcceptsOnlyManagedFullReferencesAndClosedStates(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateRunning)},
	)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := runtime.Inspect(context.Background(), ContainerRef(testContainerID))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Ref != ContainerRef(testContainerID) || inspection.State != StateRunning || inspection.ExitCode != 0 {
		t.Fatalf("unexpected inspection: %#v", inspection)
	}

	for _, bad := range []ContainerRef{"--help", "0123456789ab", ContainerRef(strings.ToUpper(testContainerID)), "bad\nref"} {
		_, err := runtime.Inspect(context.Background(), bad)
		if !errors.Is(err, ErrInvalidRef) {
			t.Fatalf("ref %q: got %v", bad, err)
		}
	}
	if _, err := ParseContainerRef(testContainerID); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseContainerRef("--help"); !errors.Is(err, ErrInvalidRef) {
		t.Fatalf("got %v", err)
	}
}

func TestInspectRejectsUnknownDockerStateAndUnknownJSON(t *testing.T) {
	for name, mutate := range map[string]func(string) string{
		"unknown state": func(record string) string {
			return strings.Replace(record, `"state":"running"`, `"state":"unknown"`, 1)
		},
		"unknown field": func(record string) string {
			record = strings.TrimSpace(record)
			return strings.TrimSuffix(record, `}`) + `,"host_path":"/secret"}`
		},
		"duplicate field": func(record string) string {
			record = strings.TrimSpace(record)
			return strings.TrimSuffix(record, `}`) + `,"state":"running"}`
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFixture(t)
			fixture.setPlan(t,
				rootlessInfoStep(),
				helperStep{Stdout: mutate(managedRecord(t, fixture, "run-1", testContainerID, StateRunning))},
			)
			runtime, err := New(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			_, err = runtime.Inspect(context.Background(), ContainerRef(testContainerID))
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestInspectProvesFullReferenceAbsenceAfterResponseLoss(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.setPlan(t,
			rootlessInfoStep(),
			helperStep{Stderr: "ambiguous inspect failure", ExitCode: 1},
			helperStep{},
		)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Inspect(context.Background(), ContainerRef(testContainerID))
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v", err)
		}
		calls := fixture.calls(t)
		if len(calls) != 3 {
			t.Fatalf("calls = %#v", calls)
		}
		requireArguments(t, calls[2], []string{
			"--host", fixture.config.Runtime.Endpoint,
			"container", "ls", "--all", "--no-trunc",
			"--filter", "id=" + testContainerID, "--format", "{{.ID}}",
		})
	})

	t.Run("still present preserves inspect failure", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.setPlan(t,
			rootlessInfoStep(),
			helperStep{ExitCode: 1},
			helperStep{Stdout: testContainerID + "\n"},
		)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Inspect(context.Background(), ContainerRef(testContainerID))
		if !errors.Is(err, ErrCommandFailed) || errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("ambiguous probe fails closed", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.setPlan(t,
			rootlessInfoStep(),
			helperStep{ExitCode: 1},
			helperStep{Stdout: testContainerID + "\n" + testContainerID + "\n"},
		)
		runtime, err := New(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Inspect(context.Background(), ContainerRef(testContainerID))
		if !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("got %v", err)
		}
	})
}

func containsAdjacent(arguments []string, first, second string) bool {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == first && arguments[index+1] == second {
			return true
		}
	}
	return false
}

func TestFormatCPU(t *testing.T) {
	for input, want := range map[int64]string{100: "0.100", 1000: "1.000", 64000: "64.000"} {
		if got := formatCPU(input); got != want {
			t.Fatalf("formatCPU(%d) = %q, want %q", input, got, want)
		}
	}
}

func TestErrorsNeverEchoCallerValues(t *testing.T) {
	fixture := newFixture(t)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	secret := "secret/host/path"
	_, err = runtime.Create(context.Background(), secret, fixture.manifest)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe error: %v", err)
	}
	_ = fmt.Sprintf("%v", runtime)
}
