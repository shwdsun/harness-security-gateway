package dockerruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParseRootlessInfoIsStrictAndFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   error
	}{
		{
			name:   "rootless among security options",
			output: `["name=seccomp,profile=builtin","name=rootless","name=cgroupns"]`,
		},
		{name: "rootful", output: `["name=seccomp,profile=builtin","name=cgroupns"]`, want: ErrRootlessRequired},
		{name: "empty", output: `[]`, want: ErrInvalidResponse},
		{name: "null", output: `null`, want: ErrInvalidResponse},
		{name: "wrong shape", output: `{"security_options":["name=rootless"]}`, want: ErrInvalidResponse},
		{name: "trailing data", output: `["name=rootless"] true`, want: ErrInvalidResponse},
		{name: "duplicate rootless claim", output: `["name=rootless","name=rootless"]`, want: ErrInvalidResponse},
		{name: "too large", output: `["name=rootless","` + strings.Repeat("x", rootlessInfoMaxBytes) + `"]`, want: ErrInvalidResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := parseRootlessInfo([]byte(test.output))
			if test.want == nil && err != nil {
				t.Fatalf("parseRootlessInfo() error = %v", err)
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("parseRootlessInfo() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCreateRefusesDaemonWithoutRootlessAttestation(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t, helperStep{
		Stdout:   `["name=seccomp,profile=builtin","name=cgroupns"]`,
		Stderr:   "daemon-secret-must-not-leak",
		ExitCode: 0,
	})
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runtime.Create(context.Background(), "run-1", fixture.manifest)
	if !errors.Is(err, ErrRootlessRequired) {
		t.Fatalf("Create() error = %v, want ErrRootlessRequired", err)
	}
	if strings.Contains(err.Error(), "daemon-secret") {
		t.Fatalf("stderr leaked: %v", err)
	}
	calls := fixture.calls(t)
	if len(calls) != 1 {
		t.Fatalf("calls = %#v, want only rootless attestation", calls)
	}
	requireArguments(t, calls[0], []string{
		"--host", fixture.config.Runtime.Endpoint,
		"info", "--format", rootlessInfoFormat,
	})
}

func TestCreateReattestsRootlessDaemonEveryTime(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: testContainerID + "\n"},
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateCreated)},
		helperStep{Stdout: `["name=seccomp,profile=builtin"]`},
	)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Create(context.Background(), "run-1", fixture.manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Create(context.Background(), "run-2", fixture.manifest); !errors.Is(err, ErrRootlessRequired) {
		t.Fatalf("second Create() error = %v, want ErrRootlessRequired", err)
	}
	calls := fixture.calls(t)
	if len(calls) != 4 {
		t.Fatalf("got %d calls, want 4", len(calls))
	}
	for _, index := range []int{0, 3} {
		requireArguments(t, calls[index], []string{
			"--host", fixture.config.Runtime.Endpoint,
			"info", "--format", rootlessInfoFormat,
		})
	}
}

func TestRootlessAttestationCommandFailureIsSanitized(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t, helperStep{Stderr: "daemon-token=secret", ExitCode: 17})
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runtime.Create(context.Background(), "run-1", fixture.manifest)
	if !errors.Is(err, ErrCommandFailed) {
		t.Fatalf("Create() error = %v, want ErrCommandFailed", err)
	}
	var commandError *CommandError
	if !errors.As(err, &commandError) || commandError.ExitCode != 17 || commandError.Operation != "attest-rootless" {
		t.Fatalf("unexpected command error: %#v", err)
	}
	if strings.Contains(err.Error(), "daemon-token") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("stderr leaked: %v", err)
	}
}

func TestManagedOperationsRefuseUnattestedDaemonBeforeContainerAccess(t *testing.T) {
	tests := []struct {
		name   string
		invoke func(*Runtime) error
	}{
		{
			name: "inspect",
			invoke: func(runtime *Runtime) error {
				_, err := runtime.Inspect(context.Background(), ContainerRef(testContainerID))
				return err
			},
		},
		{
			name:   "stop",
			invoke: func(runtime *Runtime) error { return runtime.Stop(context.Background(), ContainerRef(testContainerID)) },
		},
		{
			name:   "kill",
			invoke: func(runtime *Runtime) error { return runtime.Kill(context.Background(), ContainerRef(testContainerID)) },
		},
		{
			name: "remove",
			invoke: func(runtime *Runtime) error {
				return runtime.RemoveStopped(context.Background(), ContainerRef(testContainerID))
			},
		},
		{
			name: "attach-start",
			invoke: func(runtime *Runtime) error {
				_, err := runtime.AttachStart(context.Background(), ContainerRef(testContainerID))
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			fixture.setPlan(t, helperStep{Stdout: `["name=seccomp,profile=builtin"]`})
			runtime, err := New(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.invoke(runtime); !errors.Is(err, ErrRootlessRequired) {
				t.Fatalf("operation error = %v, want ErrRootlessRequired", err)
			}
			calls := fixture.calls(t)
			if len(calls) != 1 {
				t.Fatalf("operation reached container API: %#v", calls)
			}
			requireArguments(t, calls[0], []string{
				"--host", fixture.config.Runtime.Endpoint,
				"info", "--format", rootlessInfoFormat,
			})
		})
	}
}
