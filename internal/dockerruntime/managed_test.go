package dockerruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const secondTestContainerID = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

func TestListManagedReturnsVerifiedRefsInStableOrder(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: secondTestContainerID + "\n" + testContainerID + "\n"},
		helperStep{Stdout: managedRecord(t, fixture, "run-1", testContainerID, StateRunning)},
		helperStep{Stdout: managedRecord(t, fixture, "run-2", secondTestContainerID, StateExited)},
	)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}

	refs, err := runtime.ListManaged(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []ContainerRef{testContainerID, secondTestContainerID}
	if fmt.Sprint(refs) != fmt.Sprint(want) {
		t.Fatalf("ListManaged() = %q, want %q", refs, want)
	}

	calls := fixture.calls(t)
	if len(calls) != 4 {
		t.Fatalf("calls = %#v, want attestation, list, and two inspections", calls)
	}
	requireArguments(t, calls[0], []string{
		"--host", fixture.config.Runtime.Endpoint,
		"info", "--format", rootlessInfoFormat,
	})
	requireArguments(t, calls[1], []string{
		"--host", fixture.config.Runtime.Endpoint,
		"container", "ls", "--all", "--no-trunc",
		"--filter", "label=" + labelManaged + "=v1",
		"--format", managedListFormat,
	})
	for index, ref := range want {
		requireArguments(t, calls[index+2], []string{
			"--host", fixture.config.Runtime.Endpoint,
			"container", "inspect", "--format", inspectFormat, string(ref),
		})
	}
}

func TestListManagedAcceptsEmptyExactList(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t, rootlessInfoStep(), helperStep{})
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}

	refs, err := runtime.ListManaged(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if refs == nil || len(refs) != 0 {
		t.Fatalf("ListManaged() = %#v, want non-nil empty result", refs)
	}
	if calls := fixture.calls(t); len(calls) != 2 {
		t.Fatalf("calls = %#v, want no inspect", calls)
	}
}

func TestListManagedRejectsMalformedOrDuplicateListings(t *testing.T) {
	tooMany := make([]string, 0, managedListLimit+1)
	for index := 0; index <= managedListLimit; index++ {
		tooMany = append(tooMany, fmt.Sprintf("%064x", index))
	}
	tests := []struct {
		name   string
		output string
	}{
		{name: "missing final LF", output: testContainerID},
		{name: "CRLF", output: testContainerID + "\r\n"},
		{name: "empty line", output: testContainerID + "\n\n"},
		{name: "short ID", output: "0123456789abcdef\n"},
		{name: "uppercase ID", output: strings.Repeat("A", 64) + "\n"},
		{name: "duplicate ID", output: testContainerID + "\n" + testContainerID + "\n"},
		{name: "over count limit", output: strings.Join(tooMany, "\n") + "\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			fixture.setPlan(t, rootlessInfoStep(), helperStep{Stdout: test.output})
			runtime, err := New(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			refs, err := runtime.ListManaged(context.Background())
			if !errors.Is(err, ErrInvalidResponse) || refs != nil {
				t.Fatalf("ListManaged() = (%#v, %v), want ErrInvalidResponse", refs, err)
			}
			if calls := fixture.calls(t); len(calls) != 2 {
				t.Fatalf("malformed listing reached inspect: %#v", calls)
			}
		})
	}
}

func TestListManagedFailsClosedOnUnverifiedCandidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*inspectRecord)
	}{
		{
			name: "listed ref mismatch",
			mutate: func(record *inspectRecord) {
				record.ID = secondTestContainerID
			},
		},
		{
			name: "foreign managed label",
			mutate: func(record *inspectRecord) {
				record.Labels[labelManaged] = "v2"
			},
		},
		{
			name: "invalid run label",
			mutate: func(record *inspectRecord) {
				record.Labels[labelRunID] = "bad/run"
			},
		},
		{
			name: "unconfigured target",
			mutate: func(record *inspectRecord) {
				record.Labels[labelTargetID] = "target-unknown"
			},
		},
		{
			name: "unconfigured revision",
			mutate: func(record *inspectRecord) {
				record.Labels[labelTargetRevision] = "target-main-r2"
			},
		},
		{
			name: "foreign image",
			mutate: func(record *inspectRecord) {
				record.Image = "registry.example/foreign@sha256:" + strings.Repeat("f", 64)
			},
		},
		{
			name: "foreign name",
			mutate: func(record *inspectRecord) {
				record.Name = "/" + deterministicName("run-2")
			},
		},
		{
			name: "foreign fingerprint",
			mutate: func(record *inspectRecord) {
				record.Labels[labelTargetFingerprint] = strings.Repeat("f", 64)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			record := decodeManagedRecord(t, fixture, "run-1", testContainerID)
			test.mutate(&record)
			fixture.setPlan(t,
				rootlessInfoStep(),
				helperStep{Stdout: testContainerID + "\n"},
				helperStep{Stdout: encodeInspectRecord(t, record)},
			)
			runtime, err := New(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			refs, err := runtime.ListManaged(context.Background())
			if !errors.Is(err, ErrForeignContainer) || refs != nil {
				t.Fatalf("ListManaged() = (%#v, %v), want ErrForeignContainer", refs, err)
			}
		})
	}
}

func TestListManagedFailsBeforeInventoryWithoutRootlessAttestation(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t, helperStep{Stdout: `["name=seccomp,profile=builtin"]`})
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}

	refs, err := runtime.ListManaged(context.Background())
	if !errors.Is(err, ErrRootlessRequired) || refs != nil {
		t.Fatalf("ListManaged() = (%#v, %v), want ErrRootlessRequired", refs, err)
	}
	if calls := fixture.calls(t); len(calls) != 1 {
		t.Fatalf("unattested daemon reached inventory: %#v", calls)
	}
}

func TestListManagedSanitizesListAndInspectFailures(t *testing.T) {
	tests := []struct {
		name  string
		steps []helperStep
		op    string
	}{
		{
			name:  "list failure",
			steps: []helperStep{rootlessInfoStep(), {Stderr: "daemon-secret", ExitCode: 17}},
			op:    "list-managed",
		},
		{
			name: "inspect failure",
			steps: []helperStep{
				rootlessInfoStep(),
				{Stdout: testContainerID + "\n"},
				{Stderr: "daemon-secret", ExitCode: 18},
			},
			op: "inspect",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			fixture.setPlan(t, test.steps...)
			runtime, err := New(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			refs, err := runtime.ListManaged(context.Background())
			if !errors.Is(err, ErrCommandFailed) || refs != nil {
				t.Fatalf("ListManaged() = (%#v, %v), want ErrCommandFailed", refs, err)
			}
			var commandError *CommandError
			if !errors.As(err, &commandError) || commandError.Operation != test.op {
				t.Fatalf("unexpected command error: %#v", err)
			}
			if strings.Contains(err.Error(), "daemon-secret") {
				t.Fatalf("stderr leaked: %v", err)
			}
		})
	}
}

func TestListManagedKeepsCommandOutputBound(t *testing.T) {
	fixture := newFixture(t)
	fixture.setPlan(t,
		rootlessInfoStep(),
		helperStep{Stdout: strings.Repeat("a", commandStdoutLimit+1)},
	)
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}

	refs, err := runtime.ListManaged(context.Background())
	if !errors.Is(err, ErrOutputLimit) || refs != nil {
		t.Fatalf("ListManaged() = (%#v, %v), want ErrOutputLimit", refs, err)
	}
	if calls := fixture.calls(t); len(calls) != 2 {
		t.Fatalf("over-limit listing reached inspect: %#v", calls)
	}
}

func decodeManagedRecord(t *testing.T, fixture testFixture, runID, id string) inspectRecord {
	t.Helper()
	var record inspectRecord
	if err := json.Unmarshal([]byte(managedRecord(t, fixture, runID, id, StateCreated)), &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func encodeInspectRecord(t *testing.T, record inspectRecord) string {
	t.Helper()
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded) + "\n"
}
