package runnerbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func TestRunHandshakeOrderingNewSessionAndTranslation(t *testing.T) {
	manifest := validManifest(targetmanifest.SessionNewOnly)
	request := validRequest(manifest)
	output := encodeRunnerFrames(t,
		validReady(manifest),
		&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: request.RunID, Seq: 1},
		&runnerwire.RunProgress{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunProgress, RunID: request.RunID, Seq: 2, Kind: runnerwire.ProgressKindOutputDelta, Text: "working"},
		&runnerwire.RunCompleted{
			Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunCompleted, RunID: request.RunID, Seq: 3,
			Output: runnerwire.TextContent{MediaType: runnerwire.MediaTypeTextPlain, Text: "done"},
		},
	)

	var runnerInput bytes.Buffer
	observed := &orderingReader{reader: bytes.NewReader(output), runnerInput: &runnerInput}
	emissions := make([]Emission, 0, 3)
	err := Run(context.Background(), request, manifest, nil, observed, &runnerInput, func(_ context.Context, emission Emission) error {
		emissions = append(emissions, emission)
		return nil
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if observed.writtenBeforeFirstRead() {
		t.Fatal("run.start was written before runner.ready was read")
	}

	start := decodeStart(t, runnerInput.Bytes())
	if bytes.Contains(runnerInput.Bytes(), []byte(request.SessionScopeDigest)) {
		t.Fatal("session scope digest crossed into the untrusted runner protocol")
	}
	if start.RunID != request.RunID || start.TargetRevision != request.ExpectedRevision || start.Input.Text != request.Input.Text {
		t.Fatalf("run.start = %#v", start)
	}
	if start.Session.Mode != runnerwire.SessionModeNew || start.Session.Token != "" {
		t.Fatalf("run.start session = %#v", start.Session)
	}
	if start.DeadlineUnixMS != request.Deadline.UnixMilli() {
		t.Fatalf("deadline = %d, want %d", start.DeadlineUnixMS, request.Deadline.UnixMilli())
	}

	if len(emissions) != 3 {
		t.Fatalf("emissions = %d, want 3", len(emissions))
	}
	if emissions[0].Event.Type != executionwire.RunEventStarted || emissions[0].Event.Seq != 1 {
		t.Fatalf("started = %#v", emissions[0])
	}
	if emissions[1].Event.Type != executionwire.RunEventProgress ||
		emissions[1].Event.Progress == nil ||
		emissions[1].Event.Progress.Kind != executionwire.ProgressOutputDelta ||
		emissions[1].Event.Progress.Text != "working" {
		t.Fatalf("progress = %#v", emissions[1])
	}
	if emissions[2].Event.Type != executionwire.RunEventCompleted ||
		emissions[2].Event.Result == nil ||
		emissions[2].Event.Result.Output.Text != "done" ||
		emissions[2].Event.Result.SessionRef != nil ||
		emissions[2].VendorSessionToken != nil {
		t.Fatalf("completed = %#v", emissions[2])
	}
}

func TestRunOpaqueSessionNewAndResumeKeepVendorTokenOutOfExecutionWire(t *testing.T) {
	manifest := validManifest(targetmanifest.SessionOpaqueResume)

	t.Run("new session returns side token", func(t *testing.T) {
		request := validRequest(manifest)
		output := successfulOutput(t, manifest, request.RunID, "vendor-new-token")
		emissions, runnerInput, err := runBuffered(request, manifest, nil, output)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if start := decodeStart(t, runnerInput); start.Session.Mode != runnerwire.SessionModeNew || start.Session.Token != "" {
			t.Fatalf("start session = %#v", start.Session)
		}
		terminal := emissions[len(emissions)-1]
		if terminal.VendorSessionToken == nil || *terminal.VendorSessionToken != "vendor-new-token" {
			t.Fatalf("side token = %#v", terminal.VendorSessionToken)
		}
		if terminal.Event.Result == nil || terminal.Event.Result.SessionRef != nil {
			t.Fatalf("execution result = %#v", terminal.Event.Result)
		}
		encoded, marshalErr := json.Marshal(terminal)
		if marshalErr != nil {
			t.Fatalf("json.Marshal() error = %v", marshalErr)
		}
		if bytes.Contains(encoded, []byte("vendor-new-token")) || bytes.Contains(encoded, []byte("VendorSessionToken")) {
			t.Fatalf("serialized emission leaked vendor token: %s", encoded)
		}
	})

	t.Run("resume receives resolved token", func(t *testing.T) {
		request := validRequest(manifest)
		sessionRef := "session_ref_1"
		request.SessionRef = &sessionRef
		resolved := "vendor-existing-token"
		output := successfulOutput(t, manifest, request.RunID, "vendor-next-token")
		emissions, runnerInput, err := runBuffered(request, manifest, &resolved, output)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		start := decodeStart(t, runnerInput)
		if start.Session.Mode != runnerwire.SessionModeResume || start.Session.Token != resolved {
			t.Fatalf("start session = %#v", start.Session)
		}
		terminal := emissions[len(emissions)-1]
		if terminal.VendorSessionToken == nil || *terminal.VendorSessionToken != "vendor-next-token" {
			t.Fatalf("side token = %#v", terminal.VendorSessionToken)
		}
	})
}

func TestRunEnforcesSessionPolicyFailClosed(t *testing.T) {
	t.Run("opaque resume token is required", func(t *testing.T) {
		manifest := validManifest(targetmanifest.SessionOpaqueResume)
		request := validRequest(manifest)
		ref := "session_ref_1"
		request.SessionRef = &ref
		var runnerInput bytes.Buffer
		err := Run(context.Background(), request, manifest, nil, bytes.NewReader(nil), &runnerInput, discardSink)
		assertBridgeClass(t, err, ErrorInvalidSession)
		if runnerInput.Len() != 0 {
			t.Fatalf("runner input = %q", runnerInput.Bytes())
		}
	})

	t.Run("resolved token without session ref is rejected", func(t *testing.T) {
		manifest := validManifest(targetmanifest.SessionOpaqueResume)
		request := validRequest(manifest)
		token := "vendor-token"
		err := Run(context.Background(), request, manifest, &token, bytes.NewReader(nil), io.Discard, discardSink)
		assertBridgeClass(t, err, ErrorInvalidSession)
	})

	t.Run("new_only request cannot resume", func(t *testing.T) {
		manifest := validManifest(targetmanifest.SessionNewOnly)
		request := validRequest(manifest)
		ref := "session_ref_1"
		request.SessionRef = &ref
		token := "vendor-token"
		err := Run(context.Background(), request, manifest, &token, bytes.NewReader(nil), io.Discard, discardSink)
		assertBridgeClass(t, err, ErrorPolicyDenied)
	})

	t.Run("new_only runner cannot create hidden session", func(t *testing.T) {
		manifest := validManifest(targetmanifest.SessionNewOnly)
		request := validRequest(manifest)
		output := successfulOutput(t, manifest, request.RunID, "unexpected-vendor-token")
		emissions, _, err := runBuffered(request, manifest, nil, output)
		assertBridgeClass(t, err, ErrorPolicyDenied)
		if len(emissions) != 1 || emissions[0].Event.Type != executionwire.RunEventStarted {
			t.Fatalf("emissions = %#v, want only started", emissions)
		}
	})

	t.Run("opaque resume completion requires successor token", func(t *testing.T) {
		manifest := validManifest(targetmanifest.SessionOpaqueResume)
		request := validRequest(manifest)
		output := successfulOutput(t, manifest, request.RunID, "")
		emissions, _, err := runBuffered(request, manifest, nil, output)
		assertBridgeClass(t, err, ErrorProtocolViolation)
		if len(emissions) != 1 || emissions[0].Event.Type != executionwire.RunEventStarted {
			t.Fatalf("emissions = %#v, want only started", emissions)
		}
	})

	t.Run("invalid resolved vendor token", func(t *testing.T) {
		manifest := validManifest(targetmanifest.SessionOpaqueResume)
		request := validRequest(manifest)
		ref := "session_ref_1"
		request.SessionRef = &ref
		resolved := "unsafe?token"
		output := encodeRunnerFrames(t, validReady(manifest))
		_, runnerInput, err := runBuffered(request, manifest, &resolved, output)
		assertBridgeClass(t, err, ErrorInvalidSession)
		if len(runnerInput) != 0 {
			t.Fatalf("invalid start was written: %q", runnerInput)
		}
	})
}

func TestRunMapsEveryClosedRunnerFailureAndAcceptsCancelled(t *testing.T) {
	tests := []struct {
		code runnerwire.ErrorCode
		want executionwire.FailureCode
	}{
		{runnerwire.ErrorCodeInputRejected, executionwire.FailureRunnerFailed},
		{runnerwire.ErrorCodeInvalidSession, executionwire.FailureInvalidSession},
		{runnerwire.ErrorCodePolicyDenied, executionwire.FailurePolicyDenied},
		{runnerwire.ErrorCodeHarnessError, executionwire.FailureRunnerFailed},
		{runnerwire.ErrorCodeRunnerInternal, executionwire.FailureRunnerFailed},
	}
	for _, test := range tests {
		t.Run(string(test.code), func(t *testing.T) {
			manifest := validManifest(targetmanifest.SessionNewOnly)
			request := validRequest(manifest)
			output := encodeRunnerFrames(t,
				validReady(manifest),
				&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: request.RunID, Seq: 1},
				&runnerwire.RunFailed{
					Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunFailed, RunID: request.RunID, Seq: 2,
					Error: runnerwire.Failure{Code: test.code, Message: "sanitized runner failure"},
				},
			)
			emissions, _, err := runBuffered(request, manifest, nil, output)
			if err != nil {
				t.Fatalf("Run() after valid run.failed error = %v", err)
			}
			failure := emissions[len(emissions)-1].Event
			if failure.Type != executionwire.RunEventFailed || failure.Failure == nil ||
				failure.Failure.Code != test.want || failure.Failure.Message != "sanitized runner failure" {
				t.Fatalf("failure = %#v", failure)
			}
		})
	}

	t.Run("cancelled terminal is protocol success", func(t *testing.T) {
		manifest := validManifest(targetmanifest.SessionNewOnly)
		request := validRequest(manifest)
		output := encodeRunnerFrames(t,
			validReady(manifest),
			&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: request.RunID, Seq: 1},
			&runnerwire.RunCancelled{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunCancelled, RunID: request.RunID, Seq: 2},
		)
		emissions, _, err := runBuffered(request, manifest, nil, output)
		if err != nil {
			t.Fatalf("Run() after valid cancelled error = %v", err)
		}
		if emissions[len(emissions)-1].Event.Type != executionwire.RunEventCancelled {
			t.Fatalf("terminal = %#v", emissions[len(emissions)-1])
		}
	})
}

func TestRunRejectsHandshakeAndEventProtocolViolations(t *testing.T) {
	tests := []struct {
		name          string
		mutate        func(targetmanifest.Manifest, executionwire.StartRunRequest) []byte
		wantEmissions int
	}{
		{
			name: "wrong first frame",
			mutate: func(_ targetmanifest.Manifest, request executionwire.StartRunRequest) []byte {
				return encodeRunnerFrames(t, &runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: request.RunID, Seq: 1})
			},
		},
		{
			name: "wrong adapter family",
			mutate: func(manifest targetmanifest.Manifest, _ executionwire.StartRunRequest) []byte {
				ready := validReady(manifest)
				ready.Adapter.Family = "other"
				return encodeRunnerFrames(t, ready)
			},
		},
		{
			name: "wrong adapter version",
			mutate: func(manifest targetmanifest.Manifest, _ executionwire.StartRunRequest) []byte {
				ready := validReady(manifest)
				ready.Adapter.Version = "9.9.9"
				return encodeRunnerFrames(t, ready)
			},
		},
		{
			name: "missing required feature",
			mutate: func(manifest targetmanifest.Manifest, _ executionwire.StartRunRequest) []byte {
				ready := validReady(manifest)
				ready.Features = []runnerwire.Feature{}
				return encodeRunnerFrames(t, ready)
			},
		},
		{
			name: "wrong run ID",
			mutate: func(manifest targetmanifest.Manifest, _ executionwire.StartRunRequest) []byte {
				return encodeRunnerFrames(t,
					validReady(manifest),
					&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: "other-run", Seq: 1},
				)
			},
		},
		{
			name: "sequence gap",
			mutate: func(manifest targetmanifest.Manifest, request executionwire.StartRunRequest) []byte {
				return encodeRunnerFrames(t,
					validReady(manifest),
					&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: request.RunID, Seq: 1},
					&runnerwire.RunProgress{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunProgress, RunID: request.RunID, Seq: 3, Kind: runnerwire.ProgressKindStatus, Text: "gap"},
				)
			},
			wantEmissions: 1,
		},
		{
			name: "ready repeated after start",
			mutate: func(manifest targetmanifest.Manifest, _ executionwire.StartRunRequest) []byte {
				return encodeRunnerFrames(t, validReady(manifest), validReady(manifest))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validManifest(targetmanifest.SessionNewOnly)
			request := validRequest(manifest)
			emissions, _, err := runBuffered(request, manifest, nil, test.mutate(manifest, request))
			assertBridgeClass(t, err, ErrorProtocolViolation)
			if len(emissions) != test.wantEmissions {
				t.Fatalf("emissions = %d, want %d", len(emissions), test.wantEmissions)
			}
		})
	}
}

func TestRunRejectsUnknownDuplicateAndEOF(t *testing.T) {
	manifest := validManifest(targetmanifest.SessionNewOnly)
	request := validRequest(manifest)
	ready := encodeRunnerFrames(t, validReady(manifest))

	tests := []struct {
		name   string
		output []byte
	}{
		{
			name:   "duplicate ready key",
			output: []byte(`{"protocol":"hrp/1","type":"runner.ready","adapter":{"family":"mock","family":"other","version":"0.1.0"},"features":["progress.text"]}` + "\n"),
		},
		{
			name:   "unknown event field",
			output: append(append([]byte(nil), ready...), []byte(`{"protocol":"hrp/1","type":"run.started","run_id":"run_1","seq":1,"raw_stderr":"secret prompt"}`+"\n")...),
		},
		{name: "EOF before ready", output: nil},
		{name: "EOF before terminal", output: ready},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := runBuffered(request, manifest, nil, test.output)
			assertBridgeClass(t, err, ErrorProtocolViolation)
			if strings.Contains(err.Error(), "secret prompt") || strings.Contains(err.Error(), request.Input.Text) {
				t.Fatalf("BridgeError leaked runner/prompt text: %v", err)
			}
		})
	}
}

func TestRunEnforcesTargetSpecificBounds(t *testing.T) {
	t.Run("input", func(t *testing.T) {
		manifest := validManifest(targetmanifest.SessionNewOnly)
		manifest.Limits.MaxInputBytes = 4
		request := validRequest(manifest)
		request.Input.Text = "12345"
		err := Run(context.Background(), request, manifest, nil, bytes.NewReader(nil), io.Discard, discardSink)
		assertBridgeClass(t, err, ErrorPolicyDenied)
	})

	t.Run("progress", func(t *testing.T) {
		manifest := validManifest(targetmanifest.SessionNewOnly)
		manifest.Limits.MaxProgressBytes = 3
		request := validRequest(manifest)
		output := encodeRunnerFrames(t,
			validReady(manifest),
			&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: request.RunID, Seq: 1},
			&runnerwire.RunProgress{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunProgress, RunID: request.RunID, Seq: 2, Kind: runnerwire.ProgressKindStatus, Text: "four"},
		)
		emissions, _, err := runBuffered(request, manifest, nil, output)
		assertBridgeClass(t, err, ErrorOutputLimit)
		if len(emissions) != 1 {
			t.Fatalf("emissions = %d, want started only", len(emissions))
		}
	})

	t.Run("output", func(t *testing.T) {
		manifest := validManifest(targetmanifest.SessionNewOnly)
		manifest.Limits.MaxOutputBytes = 3
		request := validRequest(manifest)
		output := encodeRunnerFrames(t,
			validReady(manifest),
			&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: request.RunID, Seq: 1},
			&runnerwire.RunCompleted{
				Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunCompleted, RunID: request.RunID, Seq: 2,
				Output: runnerwire.TextContent{MediaType: runnerwire.MediaTypeTextPlain, Text: "four"},
			},
		)
		emissions, _, err := runBuffered(request, manifest, nil, output)
		assertBridgeClass(t, err, ErrorOutputLimit)
		if len(emissions) != 1 {
			t.Fatalf("emissions = %d, want started only", len(emissions))
		}
	})

	t.Run("event count", func(t *testing.T) {
		manifest := validManifest(targetmanifest.SessionNewOnly)
		manifest.Limits.MaxEvents = 2
		request := validRequest(manifest)
		output := encodeRunnerFrames(t,
			validReady(manifest),
			&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: request.RunID, Seq: 1},
			&runnerwire.RunProgress{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunProgress, RunID: request.RunID, Seq: 2, Kind: runnerwire.ProgressKindStatus, Text: "working"},
			&runnerwire.RunCompleted{
				Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunCompleted, RunID: request.RunID, Seq: 3,
				Output: runnerwire.TextContent{MediaType: runnerwire.MediaTypeTextPlain, Text: "done"},
			},
		)
		emissions, _, err := runBuffered(request, manifest, nil, output)
		assertBridgeClass(t, err, ErrorOutputLimit)
		if len(emissions) != 2 {
			t.Fatalf("emissions = %d, want 2", len(emissions))
		}
	})
}

func TestRunStopsAtFirstTerminal(t *testing.T) {
	manifest := validManifest(targetmanifest.SessionNewOnly)
	request := validRequest(manifest)
	output := encodeRunnerFrames(t,
		validReady(manifest),
		&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: request.RunID, Seq: 1},
		&runnerwire.RunCompleted{
			Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunCompleted, RunID: request.RunID, Seq: 2,
			Output: runnerwire.TextContent{MediaType: runnerwire.MediaTypeTextPlain, Text: "done"},
		},
		&runnerwire.RunProgress{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunProgress, RunID: request.RunID, Seq: 3, Kind: runnerwire.ProgressKindStatus, Text: "must not be read"},
	)
	emissions, _, err := runBuffered(request, manifest, nil, output)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(emissions) != 2 || emissions[1].Event.Type != executionwire.RunEventCompleted {
		t.Fatalf("emissions = %#v", emissions)
	}
}

func TestRunContextCancellationAndDeadline(t *testing.T) {
	t.Run("already cancelled", func(t *testing.T) {
		manifest := validManifest(targetmanifest.SessionNewOnly)
		request := validRequest(manifest)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := Run(ctx, request, manifest, nil, bytes.NewReader(nil), io.Discard, discardSink)
		assertBridgeClass(t, err, ErrorCancelled)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	})

	t.Run("cancel while waiting for ready", func(t *testing.T) {
		manifest := validManifest(targetmanifest.SessionNewOnly)
		request := validRequest(manifest)
		outputReader, outputWriter := io.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			result <- Run(ctx, request, manifest, nil, outputReader, io.Discard, discardSink)
		}()
		cancel()
		select {
		case err := <-result:
			assertBridgeClass(t, err, ErrorCancelled)
		case <-time.After(time.Second):
			t.Fatal("Run() did not return after cancellation")
		}
		_ = outputWriter.Close()
		_ = outputReader.Close()
	})

	t.Run("deadline while waiting for ready", func(t *testing.T) {
		manifest := validManifest(targetmanifest.SessionNewOnly)
		request := validRequest(manifest)
		request.Deadline = time.Now().Add(30 * time.Millisecond)
		outputReader, outputWriter := io.Pipe()
		err := Run(context.Background(), request, manifest, nil, outputReader, io.Discard, discardSink)
		assertBridgeClass(t, err, ErrorDeadline)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want DeadlineExceeded", err)
		}
		_ = outputWriter.Close()
		_ = outputReader.Close()
	})
}

func TestRunTerminalCommitWinsCancellationRace(t *testing.T) {
	manifest := validManifest(targetmanifest.SessionNewOnly)
	request := validRequest(manifest)
	output := encodeRunnerFrames(t,
		validReady(manifest),
		&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: request.RunID, Seq: 1},
		&runnerwire.RunCompleted{
			Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunCompleted, RunID: request.RunID, Seq: 2,
			Output: runnerwire.TextContent{MediaType: runnerwire.MediaTypeTextPlain, Text: "done"},
		},
	)
	ctx, cancel := context.WithCancel(context.Background())
	emitted := 0
	err := Run(ctx, request, manifest, nil, bytes.NewReader(output), io.Discard, func(_ context.Context, emission Emission) error {
		emitted++
		if emission.Event.Type == executionwire.RunEventCompleted {
			cancel()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Run() after committed terminal error = %v", err)
	}
	if emitted != 2 {
		t.Fatalf("emitted = %d, want 2", emitted)
	}
}

func TestRunSinkAndWriterFailuresAreTyped(t *testing.T) {
	manifest := validManifest(targetmanifest.SessionNewOnly)
	request := validRequest(manifest)

	t.Run("sink", func(t *testing.T) {
		output := encodeRunnerFrames(t,
			validReady(manifest),
			&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: request.RunID, Seq: 1},
		)
		err := Run(context.Background(), request, manifest, nil, bytes.NewReader(output), io.Discard, func(context.Context, Emission) error {
			return errors.New("database secret")
		})
		assertBridgeClass(t, err, ErrorInternal)
		if strings.Contains(err.Error(), "database secret") {
			t.Fatalf("BridgeError leaked sink cause: %v", err)
		}
	})

	t.Run("writer", func(t *testing.T) {
		output := encodeRunnerFrames(t, validReady(manifest))
		err := Run(context.Background(), request, manifest, nil, bytes.NewReader(output), failingWriter{}, discardSink)
		assertBridgeClass(t, err, ErrorRunnerFailed)
	})
}

type orderingReader struct {
	reader      io.Reader
	runnerInput *bytes.Buffer
	mu          sync.Mutex
	checked     bool
	written     bool
}

func (reader *orderingReader) Read(buffer []byte) (int, error) {
	reader.mu.Lock()
	if !reader.checked {
		reader.checked = true
		reader.written = reader.runnerInput.Len() != 0
	}
	reader.mu.Unlock()
	return reader.reader.Read(buffer)
}

func (reader *orderingReader) writtenBeforeFirstRead() bool {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.written
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("runner pipe closed")
}

func discardSink(context.Context, Emission) error { return nil }

func validManifest(mode targetmanifest.SessionMode) targetmanifest.Manifest {
	features := []runnerwire.Feature{runnerwire.FeatureProgressText}
	if mode == targetmanifest.SessionOpaqueResume {
		features = append(features, runnerwire.FeatureSessionResume)
	}
	manifest := targetmanifest.Manifest{
		Schema:   targetmanifest.SchemaV1,
		ID:       "mock-target",
		Revision: "mock-target-r1",
		Runner: targetmanifest.Runner{
			Family: "mock", AdapterVersion: "0.1.0", Protocol: runnerwire.ProtocolV1,
			Image:            "registry.example/mock@sha256:" + strings.Repeat("a", 64),
			RequiredFeatures: features,
		},
		WorkspaceRef: "workspace", WorkspaceMode: targetmanifest.WorkspaceReadWrite,
		StateRef: "state", PolicyRef: "policy", AuthProfileRef: "auth",
		SkillBundleRef: "skills", NetworkProfileRef: "network", SessionMode: mode,
		Limits: targetmanifest.Limits{
			TimeoutSeconds: 30, MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 16,
			MaxInputBytes: 1024, MaxOutputBytes: 1024, MaxProgressBytes: 1024,
			MaxStderrBytes: 1024, MaxEvents: 10,
		},
	}
	if mode == targetmanifest.SessionOpaqueResume {
		manifest.Limits.MaxSessionAgeSeconds = 24 * 60 * 60
		manifest.Limits.MaxSessionTurns = 32
	}
	return manifest
}

func validRequest(manifest targetmanifest.Manifest) executionwire.StartRunRequest {
	return executionwire.StartRunRequest{
		RunID: "run_1", TargetID: manifest.ID, ExpectedRevision: manifest.Revision,
		SessionScopeDigest: strings.Repeat("a", 64),
		Input:              executionwire.TextInput{MediaType: executionwire.MediaTypeTextPlain, Text: "inspect project"},
		Deadline:           time.Now().Add(time.Minute).UTC().Truncate(time.Millisecond),
	}
}

func validReady(manifest targetmanifest.Manifest) *runnerwire.RunnerReady {
	features := append([]runnerwire.Feature(nil), manifest.Runner.RequiredFeatures...)
	return &runnerwire.RunnerReady{
		Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunnerReady,
		Adapter:  runnerwire.Adapter{Family: manifest.Runner.Family, Version: manifest.Runner.AdapterVersion},
		Features: features,
	}
}

func successfulOutput(t *testing.T, manifest targetmanifest.Manifest, runID, token string) []byte {
	t.Helper()
	return encodeRunnerFrames(t,
		validReady(manifest),
		&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: runID, Seq: 1},
		&runnerwire.RunCompleted{
			Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunCompleted, RunID: runID, Seq: 2,
			Output:       runnerwire.TextContent{MediaType: runnerwire.MediaTypeTextPlain, Text: "done"},
			SessionToken: token,
		},
	)
}

func encodeRunnerFrames(t *testing.T, frames ...runnerwire.Frame) []byte {
	t.Helper()
	var output bytes.Buffer
	encoder := runnerwire.NewEncoder(&output)
	for _, frame := range frames {
		if err := encoder.Encode(frame); err != nil {
			t.Fatalf("encode %T: %v", frame, err)
		}
	}
	return output.Bytes()
}

func decodeStart(t *testing.T, data []byte) *runnerwire.RunStart {
	t.Helper()
	decoder := runnerwire.NewDecoder(bytes.NewReader(data))
	frame, err := decoder.DecodeControllerFrame()
	if err != nil {
		t.Fatalf("decode run.start: %v; data %q", err, data)
	}
	start, ok := frame.(*runnerwire.RunStart)
	if !ok {
		t.Fatalf("controller frame = %T, want *RunStart", frame)
	}
	if _, err := decoder.Decode(); !errors.Is(err, io.EOF) {
		t.Fatalf("extra controller frame error = %v, want EOF", err)
	}
	return start
}

func runBuffered(
	request executionwire.StartRunRequest,
	manifest targetmanifest.Manifest,
	resolvedToken *string,
	runnerOutput []byte,
) ([]Emission, []byte, error) {
	var runnerInput bytes.Buffer
	emissions := make([]Emission, 0, 4)
	err := Run(
		context.Background(), request, manifest, resolvedToken,
		bytes.NewReader(runnerOutput), &runnerInput,
		func(_ context.Context, emission Emission) error {
			emissions = append(emissions, emission)
			return nil
		},
	)
	return emissions, append([]byte(nil), runnerInput.Bytes()...), err
}

func assertBridgeClass(t *testing.T, err error, class ErrorClass) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", class)
	}
	var bridge *BridgeError
	if !errors.As(err, &bridge) || bridge.Class != class {
		t.Fatalf("error = %#v, want BridgeError %s", err, class)
	}
	if err.Error() != "runner bridge: "+string(class) {
		t.Fatalf("Error() = %q, want closed classification", err.Error())
	}
}
