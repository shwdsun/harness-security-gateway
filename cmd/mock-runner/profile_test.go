package main

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
)

func TestFixedNewOnlyProfileEmitsNoResumeFeatureOrToken(t *testing.T) {
	start := validStart()
	var input, output bytes.Buffer
	if err := runnerwire.NewEncoder(&input).Encode(start); err != nil {
		t.Fatal(err)
	}
	if err := runProfile(&input, &output, "new_only"); err != nil {
		t.Fatal(err)
	}
	decoder := runnerwire.NewDecoder(&output)
	frame, err := decoder.DecodeRunnerFrame()
	if err != nil {
		t.Fatal(err)
	}
	ready := frame.(*runnerwire.RunnerReady)
	if ready.Supports(runnerwire.FeatureSessionResume) {
		t.Fatal("new-only advertised resume")
	}
	sequence, err := runnerwire.NewSequence(start.RunID)
	if err != nil {
		t.Fatal(err)
	}
	var completed bool
	for {
		frame, err := decoder.DecodeRunnerFrame()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		event := frame.(runnerwire.RunEvent)
		if err := sequence.Accept(event); err != nil {
			t.Fatal(err)
		}
		if terminal, ok := frame.(*runnerwire.RunCompleted); ok {
			completed = true
			if terminal.SessionToken != "" {
				t.Fatal("new-only returned token")
			}
		}
	}
	if err := sequence.Finalize(); err != nil || !completed {
		t.Fatalf("lifecycle incomplete: %v", err)
	}
}

func TestFixedProfileRejectsUnknownBuildValueAndResume(t *testing.T) {
	var output bytes.Buffer
	if err := runProfile(bytes.NewReader(nil), &output, "unknown"); err == nil || output.Len() != 0 {
		t.Fatal("unknown profile emitted readiness")
	}
	start := validStart()
	start.Session = runnerwire.Session{Mode: runnerwire.SessionModeResume, Token: "synthetic"}
	var input bytes.Buffer
	if err := runnerwire.NewEncoder(&input).Encode(start); err != nil {
		t.Fatal(err)
	}
	if err := runProfile(&input, &output, "new_only"); err != nil {
		t.Fatal(err)
	}
	decoder := runnerwire.NewDecoder(&output)
	for index := 0; index < 2; index++ {
		if _, err := decoder.DecodeRunnerFrame(); err != nil {
			t.Fatal(err)
		}
	}
	frame, err := decoder.DecodeRunnerFrame()
	if err != nil {
		t.Fatal(err)
	}
	failed, ok := frame.(*runnerwire.RunFailed)
	if !ok || failed.Seq != 2 || failed.Error.Code != runnerwire.ErrorCodePolicyDenied {
		t.Fatalf("resume was not denied: %#v", frame)
	}
	if _, err := decoder.DecodeRunnerFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("extra frame: %v", err)
	}
}
