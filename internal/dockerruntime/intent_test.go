package dockerruntime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestLookupIntentReturnsOnlyExactImmutableContainer(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateCreated)},
	)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	ref, found, err := runtime.LookupIntent(context.Background(), "run-1", fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !found || ref != ContainerRef(testContainerID) {
		t.Fatalf("LookupIntent() = (%q, %t), want (%q, true)", ref, found, testContainerID)
	}
	assertNoCreateCall(t, fixture.calls(t))
}

func TestLookupIntentProvesAbsenceWithExactNameList(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stderr: "ambiguous inspect daemon-secret", ExitCode: 1},
		helperStep{},
	)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	ref, found, err := runtime.LookupIntent(context.Background(), "run-1", fixture.manifest)
	if err != nil || found || ref != "" {
		t.Fatalf("LookupIntent() = (%q, %t, %v), want absent", ref, found, err)
	}
	calls := fixture.calls(t)
	if len(calls) != 3 {
		t.Fatalf("calls = %#v", calls)
	}
	name := deterministicName("run-1")
	requireArguments(t, calls[0], []string{
		"--host", fixture.config.Runtime.Endpoint,
		"info", "--format", rootlessInfoFormat,
	})
	requireArguments(t, calls[1], []string{
		"--host", fixture.config.Runtime.Endpoint,
		"container", "inspect", "--format", inspectFormat, name,
	})
	requireArguments(t, calls[2], []string{
		"--host", fixture.config.Runtime.Endpoint,
		"container", "ls", "--all", "--no-trunc",
		"--filter", "name=^/" + name + "$", "--format", intentListFormat,
	})
	assertNoCreateCall(t, calls)
}

func TestLookupIntentRecoversFromLostNameInspectResponse(t *testing.T) {
	fixture := newFixture(t)
	name := deterministicName("run-1")
	listed, err := json.Marshal(intentListRecord{ID: testContainerID, Name: name})
	if err != nil {
		t.Fatal(err)
	}
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stderr: "lost inspect response", ExitCode: 1},
		helperStep{Stdout: string(listed) + "\n"},
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateCreated)},
	)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	ref, found, err := runtime.LookupIntent(context.Background(), "run-1", fixture.manifest)
	if err != nil || !found || ref != ContainerRef(testContainerID) {
		t.Fatalf("LookupIntent() = (%q, %t, %v)", ref, found, err)
	}
	calls := fixture.calls(t)
	if len(calls) != 4 {
		t.Fatalf("calls = %#v", calls)
	}
	requireArguments(t, calls[3], []string{
		"--host", fixture.config.Runtime.Endpoint,
		"container", "inspect", "--format", inspectFormat, testContainerID,
	})
	assertNoCreateCall(t, calls)
}

func TestLookupIntentFailsClosedOnAmbiguousAbsence(t *testing.T) {
	tests := []struct {
		name  string
		probe helperStep
		want  error
	}{
		{
			name:  "probe command failure",
			probe: helperStep{Stderr: "socket uncertainty secret", ExitCode: 2},
			want:  ErrCommandFailed,
		},
		{
			name:  "malformed probe",
			probe: helperStep{Stdout: `{"id":"not-full","name":"wrong"}`},
			want:  ErrInvalidResponse,
		},
		{
			name:  "multiple probe records",
			probe: helperStep{Stdout: `{"id":"` + testContainerID + `","name":"one"}` + "\n" + `{"id":"` + testContainerID + `","name":"two"}`},
			want:  ErrInvalidResponse,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			fixture.setPlan(t,
				rootlessInfoStep(),
				helperStep{ExitCode: 1},
				test.probe,
			)
			runtime, err := New(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			ref, found, err := runtime.LookupIntent(context.Background(), "run-1", fixture.manifest)
			if !errors.Is(err, test.want) || found || ref != "" {
				t.Fatalf("LookupIntent() = (%q, %t, %v), want %v", ref, found, err, test.want)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("stderr leaked: %v", err)
			}
			assertNoCreateCall(t, fixture.calls(t))
		})
	}
}

func TestLookupIntentRefusesForeignContainer(t *testing.T) {
	fixture := newFixture(t)
	var record inspectRecord
	if err := json.Unmarshal([]byte(managedRecord(t, fixture, "run-1", testContainerID, StateCreated)), &record); err != nil {
		t.Fatal(err)
	}
	record.Image = "registry.example/foreign@sha256:" + strings.Repeat("f", 64)
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	fixture.setPlan(t, rootlessInfoStep(), helperStep{Stdout: string(encoded)})
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	_, found, err := runtime.LookupIntent(context.Background(), "run-1", fixture.manifest)
	if !errors.Is(err, ErrForeignContainer) || found {
		t.Fatalf("LookupIntent() = (found=%t, err=%v)", found, err)
	}
	assertNoCreateCall(t, fixture.calls(t))
}

func TestLookupIntentRejectsInvalidIntentBeforeCLI(t *testing.T) {
	fixture := newFixture(t)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	_, found, err := runtime.LookupIntent(context.Background(), "bad/name", fixture.manifest)
	if !errors.Is(err, ErrInvalidArgument) || found {
		t.Fatalf("LookupIntent() = (found=%t, err=%v)", found, err)
	}
	if calls := fixture.calls(t); len(calls) != 0 {
		t.Fatalf("unexpected CLI calls: %#v", calls)
	}
}

func TestLookupIntentRefusesUnattestedDaemonBeforeNameInspection(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t, helperStep{Stdout: `["name=seccomp,profile=builtin"]`})
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	_, found, err := runtime.LookupIntent(context.Background(), "run-1", fixture.manifest)
	if !errors.Is(err, ErrRootlessRequired) || found {
		t.Fatalf("LookupIntent() = (found=%t, err=%v), want ErrRootlessRequired", found, err)
	}
	calls := fixture.calls(t)
	if len(calls) != 1 {
		t.Fatalf("lookup reached container API: %#v", calls)
	}
	requireArguments(t, calls[0], []string{
		"--host", fixture.config.Runtime.Endpoint,
		"info", "--format", rootlessInfoFormat,
	})
}

func assertNoCreateCall(t *testing.T, calls []helperCall) {
	t.Helper()
	for _, call := range calls {
		for index := 0; index+1 < len(call.Arguments); index++ {
			if call.Arguments[index] == "container" && call.Arguments[index+1] == "create" {
				t.Fatalf("LookupIntent invoked create: %#v", call.Arguments)
			}
		}
	}
}
