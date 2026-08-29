package dockerruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestLifecycleCommandsUseOnlyVerifiedFullReference(t *testing.T) {
	tests := []struct {
		name      string
		state     ContainerState
		arguments []string
		invoke    func(*Runtime, context.Context, ContainerRef) error
	}{
		{
			name:      "stop",
			state:     StateRunning,
			arguments: []string{"container", "stop", "--timeout", "5", testContainerID},
			invoke:    (*Runtime).Stop,
		},
		{
			name:      "kill",
			state:     StateRunning,
			arguments: []string{"container", "kill", "--signal", "KILL", testContainerID},
			invoke:    (*Runtime).Kill,
		},
		{
			name:      "remove",
			state:     StateExited,
			arguments: []string{"container", "rm", "--volumes", testContainerID},
			invoke:    (*Runtime).RemoveStopped,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			fixture.setPlan(t,
				rootlessInfoStep(),
				helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, test.state)},
				helperStep{Stdout: testContainerID + "\n"},
			)
			runtime, err := New(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.invoke(runtime, context.Background(), ContainerRef(testContainerID)); err != nil {
				t.Fatal(err)
			}
			calls := fixture.calls(t)
			if len(calls) != 3 {
				t.Fatalf("got %d calls, want 3", len(calls))
			}
			requireArguments(t, calls[0], []string{
				"--host", fixture.config.Runtime.Endpoint,
				"info", "--format", rootlessInfoFormat,
			})
			requireArguments(t, calls[1], []string{
				"--host", fixture.config.Runtime.Endpoint,
				"container", "inspect", "--format", inspectFormat, testContainerID,
			})
			want := append([]string{"--host", fixture.config.Runtime.Endpoint}, test.arguments...)
			requireArguments(t, calls[2], want)
		})
	}
}

func TestRemoveStoppedRejectsLiveContainer(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateRunning)},
	)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	err = runtime.RemoveStopped(context.Background(), ContainerRef(testContainerID))
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("got %v", err)
	}
	if calls := fixture.calls(t); len(calls) != 2 {
		t.Fatalf("unexpected calls: %#v", calls)
	}
}

func TestLifecycleCommandErrorIsSanitized(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateRunning)},
		helperStep{Stderr: "daemon secret path /private", ExitCode: 9},
	)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	err = runtime.Stop(context.Background(), ContainerRef(testContainerID))
	if !errors.Is(err, ErrCommandFailed) {
		t.Fatalf("got %v", err)
	}
	var commandError *CommandError
	if !errors.As(err, &commandError) || commandError.ExitCode != 9 {
		t.Fatalf("unexpected error: %#v", err)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "/private") {
		t.Fatalf("stderr leaked: %v", err)
	}
}

func TestLifecycleRejectsOptionLikeReferenceBeforeCLI(t *testing.T) {
	fixture := newFixture(t)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	for _, invoke := range []func(context.Context, ContainerRef) error{
		runtime.Stop, runtime.Kill, runtime.RemoveStopped,
	} {
		if err := invoke(context.Background(), ContainerRef("--help")); !errors.Is(err, ErrInvalidRef) {
			t.Fatalf("got %v", err)
		}
	}
	if calls := fixture.calls(t); len(calls) != 0 {
		t.Fatalf("unexpected calls: %#v", calls)
	}
}

func TestRemoveResponseLossCanBeReconciledAsAbsent(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateExited)},
		helperStep{Stderr: "remove response was lost", ExitCode: 1},
	)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	err = runtime.RemoveStopped(context.Background(), ContainerRef(testContainerID))
	if !errors.Is(err, ErrCommandFailed) {
		t.Fatalf("remove error = %v", err)
	}

	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{ExitCode: 1},
		helperStep{},
	)
	err = runtime.RemoveStopped(context.Background(), ContainerRef(testContainerID))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("reconcile error = %v", err)
	}
}
