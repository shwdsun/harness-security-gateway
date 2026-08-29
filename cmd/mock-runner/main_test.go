package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
)

func TestRunEmitsOneValidDeterministicLifecycle(t *testing.T) {
	start := validStart()
	start.Input.Text = "do not echo this input"

	var stdin bytes.Buffer
	if err := runnerwire.NewEncoder(&stdin).Encode(start); err != nil {
		t.Fatalf("encode start: %v", err)
	}
	// A second start is deliberately left unread. One process has exactly one
	// Run capability and exits after its first lifecycle.
	second := validStart()
	second.RunID = "run-ignored"
	if err := runnerwire.NewEncoder(&stdin).Encode(second); err != nil {
		t.Fatalf("encode second start: %v", err)
	}

	var stdout bytes.Buffer
	if err := run(&stdin, &stdout); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	decoder := runnerwire.NewDecoder(&stdout)
	readyFrame, err := decoder.DecodeRunnerFrame()
	if err != nil {
		t.Fatalf("decode ready: %v", err)
	}
	ready, ok := readyFrame.(*runnerwire.RunnerReady)
	if !ok {
		t.Fatalf("first frame = %T, want *RunnerReady", readyFrame)
	}
	if ready.Adapter.Family != adapterFamily || ready.Adapter.Version != adapterVersion {
		t.Fatalf("adapter = %#v", ready.Adapter)
	}
	if !ready.Supports(runnerwire.FeatureSessionResume) || !ready.Supports(runnerwire.FeatureProgressText) {
		t.Fatalf("features = %#v", ready.Features)
	}

	sequence, err := runnerwire.NewSequence(start.RunID)
	if err != nil {
		t.Fatalf("NewSequence() error = %v", err)
	}
	var completed *runnerwire.RunCompleted
	for index := 0; index < 3; index++ {
		frame, decodeErr := decoder.DecodeRunnerFrame()
		if decodeErr != nil {
			t.Fatalf("decode event %d: %v", index, decodeErr)
		}
		event, eventOK := frame.(runnerwire.RunEvent)
		if !eventOK {
			t.Fatalf("frame %d = %T, want RunEvent", index, frame)
		}
		if acceptErr := sequence.Accept(event); acceptErr != nil {
			t.Fatalf("accept event %d: %v", index, acceptErr)
		}
		if terminal, completedOK := event.(*runnerwire.RunCompleted); completedOK {
			completed = terminal
		}
	}
	if err := sequence.Finalize(); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if _, err := decoder.Decode(); !errors.Is(err, io.EOF) {
		t.Fatalf("extra stdout frame error = %v, want EOF", err)
	}
	if completed == nil {
		t.Fatal("missing completed frame")
	}

	digest := sha256.Sum256([]byte(start.Input.Text))
	wantOutput := "mock completed: input_sha256=" + hex.EncodeToString(digest[:])
	if completed.Output.Text != wantOutput {
		t.Fatalf("output = %q, want %q", completed.Output.Text, wantOutput)
	}
	if strings.Contains(completed.Output.Text, start.Input.Text) {
		t.Fatalf("output unexpectedly contains raw input: %q", completed.Output.Text)
	}
	if completed.SessionToken == "" || !strings.HasPrefix(completed.SessionToken, "mock-") {
		t.Fatalf("session token = %q", completed.SessionToken)
	}
	if err := completed.Validate(); err != nil {
		t.Fatalf("completed frame failed validation: %v", err)
	}
}

func TestRunResumeEchoesValidatedSessionToken(t *testing.T) {
	start := validStart()
	start.Session = runnerwire.Session{
		Mode:  runnerwire.SessionModeResume,
		Token: "mock-existing_42",
	}

	frames := execute(t, start)
	completed, ok := frames[len(frames)-1].(*runnerwire.RunCompleted)
	if !ok {
		t.Fatalf("last frame = %T, want *RunCompleted", frames[len(frames)-1])
	}
	if completed.SessionToken != start.Session.Token {
		t.Fatalf("session token = %q, want %q", completed.SessionToken, start.Session.Token)
	}
}

func TestRunRejectsNonStartControllerInputWithoutStdoutDiagnostics(t *testing.T) {
	invalidInput := strings.NewReader(`{"protocol":"hrp/1","type":"run.started","run_id":"run-1","seq":1}` + "\n")
	var stdout bytes.Buffer
	if err := run(invalidInput, &stdout); err == nil {
		t.Fatal("run() error = nil")
	}

	decoder := runnerwire.NewDecoder(&stdout)
	if frame, err := decoder.DecodeRunnerFrame(); err != nil {
		t.Fatalf("decode ready: %v", err)
	} else if _, ok := frame.(*runnerwire.RunnerReady); !ok {
		t.Fatalf("first frame = %T, want *RunnerReady", frame)
	}
	if _, err := decoder.Decode(); !errors.Is(err, io.EOF) {
		t.Fatalf("stdout after ready error = %v, want EOF", err)
	}
}

func TestRunRejectsNilStreams(t *testing.T) {
	if err := run(nil, io.Discard); err == nil {
		t.Fatal("run(nil, output) error = nil")
	}
	if err := run(strings.NewReader(""), nil); err == nil {
		t.Fatal("run(input, nil) error = nil")
	}
}

func validStart() *runnerwire.RunStart {
	return &runnerwire.RunStart{
		Protocol:       runnerwire.ProtocolV1,
		Type:           runnerwire.TypeRunStart,
		RunID:          "run-1",
		TargetRevision: "mock-target-r1",
		Input: runnerwire.TextContent{
			MediaType: runnerwire.MediaTypeTextPlain,
			Text:      "inspect project",
		},
		Session:        runnerwire.Session{Mode: runnerwire.SessionModeNew},
		DeadlineUnixMS: 1786900000000,
	}
}

func execute(t *testing.T, start *runnerwire.RunStart) []runnerwire.RunnerFrame {
	t.Helper()
	var stdin bytes.Buffer
	if err := runnerwire.NewEncoder(&stdin).Encode(start); err != nil {
		t.Fatalf("encode start: %v", err)
	}
	var stdout bytes.Buffer
	if err := run(&stdin, &stdout); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	decoder := runnerwire.NewDecoder(&stdout)
	frames := make([]runnerwire.RunnerFrame, 0, 4)
	for {
		frame, err := decoder.DecodeRunnerFrame()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode output: %v", err)
		}
		frames = append(frames, frame)
	}
	return frames
}
