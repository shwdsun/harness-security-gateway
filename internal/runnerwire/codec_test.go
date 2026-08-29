package runnerwire

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

func TestDecodeFrameExamples(t *testing.T) {
	tests := []struct {
		name string
		json string
		want Frame
	}{
		{
			name: "ready",
			json: `{"protocol":"hrp/1","type":"runner.ready","adapter":{"family":"codex","version":"0.1.0"},"features":["session.resume","progress.text"]}`,
			want: &RunnerReady{
				Protocol: ProtocolV1,
				Type:     TypeRunnerReady,
				Adapter:  Adapter{Family: "codex", Version: "0.1.0"},
				Features: []Feature{FeatureSessionResume, FeatureProgressText},
			},
		},
		{
			name: "start new session",
			json: `{"protocol":"hrp/1","type":"run.start","run_id":"01JEXAMPLE","target_revision":"project-codex-r1","input":{"media_type":"text/plain","text":"Inspect the project"},"session":{"mode":"new"},"deadline_unix_ms":1786900000000}`,
			want: &RunStart{
				Protocol:       ProtocolV1,
				Type:           TypeRunStart,
				RunID:          "01JEXAMPLE",
				TargetRevision: "project-codex-r1",
				Input:          TextContent{MediaType: MediaTypeTextPlain, Text: "Inspect the project"},
				Session:        Session{Mode: SessionModeNew},
				DeadlineUnixMS: 1786900000000,
			},
		},
		{
			name: "start resumed session",
			json: `{"protocol":"hrp/1","type":"run.start","run_id":"run-2","target_revision":"project-claude-r1","input":{"media_type":"text/plain","text":"Continue"},"session":{"mode":"resume","token":"vendor-token"},"deadline_unix_ms":1786900000000}`,
			want: &RunStart{
				Protocol:       ProtocolV1,
				Type:           TypeRunStart,
				RunID:          "run-2",
				TargetRevision: "project-claude-r1",
				Input:          TextContent{MediaType: MediaTypeTextPlain, Text: "Continue"},
				Session:        Session{Mode: SessionModeResume, Token: "vendor-token"},
				DeadlineUnixMS: 1786900000000,
			},
		},
		{
			name: "started",
			json: `{"protocol":"hrp/1","type":"run.started","run_id":"01JEXAMPLE","seq":1}`,
			want: &RunStarted{Protocol: ProtocolV1, Type: TypeRunStarted, RunID: "01JEXAMPLE", Seq: 1},
		},
		{
			name: "progress",
			json: `{"protocol":"hrp/1","type":"run.progress","run_id":"01JEXAMPLE","seq":2,"kind":"status","text":"Inspecting the project"}`,
			want: &RunProgress{Protocol: ProtocolV1, Type: TypeRunProgress, RunID: "01JEXAMPLE", Seq: 2, Kind: ProgressKindStatus, Text: "Inspecting the project"},
		},
		{
			name: "completed",
			json: `{"protocol":"hrp/1","type":"run.completed","run_id":"01JEXAMPLE","seq":3,"output":{"media_type":"text/plain","text":"Inspection complete"},"session_token":"opaque-vendor-token"}`,
			want: &RunCompleted{
				Protocol: ProtocolV1, Type: TypeRunCompleted, RunID: "01JEXAMPLE", Seq: 3,
				Output: TextContent{MediaType: MediaTypeTextPlain, Text: "Inspection complete"}, SessionToken: "opaque-vendor-token",
			},
		},
		{
			name: "failed",
			json: `{"protocol":"hrp/1","type":"run.failed","run_id":"01JEXAMPLE","seq":3,"error":{"code":"harness_error","message":"Sanitized bounded message"}}`,
			want: &RunFailed{
				Protocol: ProtocolV1, Type: TypeRunFailed, RunID: "01JEXAMPLE", Seq: 3,
				Error: Failure{Code: ErrorCodeHarnessError, Message: "Sanitized bounded message"},
			},
		},
		{
			name: "cancelled",
			json: `{"protocol":"hrp/1","type":"run.cancelled","run_id":"01JEXAMPLE","seq":3}`,
			want: &RunCancelled{Protocol: ProtocolV1, Type: TypeRunCancelled, RunID: "01JEXAMPLE", Seq: 3},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := DecodeFrame([]byte(test.json))
			if err != nil {
				t.Fatalf("DecodeFrame() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("DecodeFrame() = %#v, want %#v", got, test.want)
			}

			encoded, err := MarshalFrame(got)
			if err != nil {
				t.Fatalf("MarshalFrame() error = %v", err)
			}
			roundTrip, err := DecodeFrame(encoded)
			if err != nil {
				t.Fatalf("DecodeFrame(MarshalFrame()) error = %v", err)
			}
			if !reflect.DeepEqual(roundTrip, test.want) {
				t.Fatalf("round trip = %#v, want %#v", roundTrip, test.want)
			}
		})
	}
}

func TestDecodeFrameRejectsStructurallyUnsafeJSON(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		is     error
		needle string
	}{
		{
			name: "duplicate top-level key",
			data: []byte(`{"protocol":"hrp/1","type":"run.started","run_id":"first","run_id":"second","seq":1}`),
			is:   strictjson.ErrDuplicateKey,
		},
		{
			name: "duplicate nested key",
			data: []byte(`{"protocol":"hrp/1","type":"run.completed","run_id":"r","seq":1,"output":{"media_type":"text/plain","text":"first","text":"second"}}`),
			is:   strictjson.ErrDuplicateKey,
		},
		{
			name:   "unknown field",
			data:   []byte(`{"protocol":"hrp/1","type":"run.started","run_id":"r","seq":1,"image":"forbidden"}`),
			needle: "unknown field",
		},
		{
			name:   "unknown nested field",
			data:   []byte(`{"protocol":"hrp/1","type":"run.start","run_id":"r","target_revision":"rev","input":{"media_type":"text/plain","text":"hi","path":"/host"},"session":{"mode":"new"},"deadline_unix_ms":1}`),
			needle: "unknown field",
		},
		{
			name: "trailing value",
			data: []byte(`{"protocol":"hrp/1","type":"run.started","run_id":"r","seq":1} {}`),
			is:   strictjson.ErrTrailingData,
		},
		{
			name: "invalid UTF-8",
			data: append([]byte(`{"protocol":"hrp/1","type":"run.progress","run_id":"r","seq":1,"kind":"status","text":"`),
				append([]byte{0xff}, []byte(`"}`)...)...),
			is: strictjson.ErrInvalidUTF8,
		},
		{
			name: "excessive depth",
			data: []byte(`{"protocol":"hrp/1","type":"run.started","run_id":"r","seq":1,"extra":[[[[[[[[0]]]]]]]]}`),
			is:   strictjson.ErrTooDeep,
		},
		{
			name: "unknown type",
			data: []byte(`{"protocol":"hrp/1","type":"run.shell","run_id":"r","seq":1}`),
			is:   ErrUnexpectedFrameType,
		},
		{
			name:   "wrong protocol",
			data:   []byte(`{"protocol":"hrp/2","type":"run.started","run_id":"r","seq":1}`),
			needle: "protocol",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeFrame(test.data)
			if err == nil {
				t.Fatal("DecodeFrame() error = nil")
			}
			if !errors.Is(err, ErrInvalidFrame) {
				t.Fatalf("DecodeFrame() error = %v, want ErrInvalidFrame", err)
			}
			if test.is != nil && !errors.Is(err, test.is) {
				t.Fatalf("DecodeFrame() error = %v, want errors.Is(%v)", err, test.is)
			}
			if test.needle != "" && !strings.Contains(err.Error(), test.needle) {
				t.Fatalf("DecodeFrame() error = %v, want substring %q", err, test.needle)
			}
		})
	}
}

func TestFrameValidationRejectsOutOfContractValues(t *testing.T) {
	validStart := func() *RunStart {
		return &RunStart{
			Protocol: ProtocolV1, Type: TypeRunStart, RunID: "run-1", TargetRevision: "target-r1",
			Input:   TextContent{MediaType: MediaTypeTextPlain, Text: "hello"},
			Session: Session{Mode: SessionModeNew}, DeadlineUnixMS: 1786900000000,
		}
	}
	validReady := func() *RunnerReady {
		return &RunnerReady{
			Protocol: ProtocolV1, Type: TypeRunnerReady,
			Adapter: Adapter{Family: "codex", Version: "0.1.0"}, Features: []Feature{},
		}
	}

	tests := []struct {
		name  string
		frame Frame
	}{
		{name: "mismatched discriminator", frame: func() Frame { f := validStart(); f.Type = TypeRunStarted; return f }()},
		{name: "unsafe run id", frame: func() Frame { f := validStart(); f.RunID = "run id"; return f }()},
		{name: "oversized revision", frame: func() Frame {
			f := validStart()
			f.TargetRevision = strings.Repeat("r", MaxTargetRevisionBytes+1)
			return f
		}()},
		{name: "unknown media type", frame: func() Frame { f := validStart(); f.Input.MediaType = "text/html"; return f }()},
		{name: "oversized input", frame: func() Frame { f := validStart(); f.Input.Text = strings.Repeat("x", MaxInputTextBytes+1); return f }()},
		{name: "blank input", frame: func() Frame { f := validStart(); f.Input.Text = " \n\t"; return f }()},
		{name: "NUL in input", frame: func() Frame { f := validStart(); f.Input.Text = "hello\x00world"; return f }()},
		{name: "unknown session mode", frame: func() Frame { f := validStart(); f.Session.Mode = "automatic"; return f }()},
		{name: "token on new session", frame: func() Frame { f := validStart(); f.Session.Token = "token"; return f }()},
		{name: "missing resume token", frame: func() Frame { f := validStart(); f.Session.Mode = SessionModeResume; return f }()},
		{name: "control in resume token", frame: func() Frame {
			f := validStart()
			f.Session = Session{Mode: SessionModeResume, Token: "bad\ntoken"}
			return f
		}()},
		{name: "invalid deadline", frame: func() Frame { f := validStart(); f.DeadlineUnixMS = 0; return f }()},
		{name: "missing features array", frame: func() Frame { f := validReady(); f.Features = nil; return f }()},
		{name: "unknown feature", frame: func() Frame { f := validReady(); f.Features = []Feature{"network.full"}; return f }()},
		{name: "duplicate feature", frame: func() Frame {
			f := validReady()
			f.Features = []Feature{FeatureProgressText, FeatureProgressText}
			return f
		}()},
		{name: "adapter whitespace", frame: func() Frame { f := validReady(); f.Adapter.Family = "claude code"; return f }()},
		{name: "zero sequence", frame: &RunStarted{Protocol: ProtocolV1, Type: TypeRunStarted, RunID: "r", Seq: 0}},
		{name: "sequence over event limit", frame: &RunStarted{Protocol: ProtocolV1, Type: TypeRunStarted, RunID: "r", Seq: MaxEvents + 1}},
		{name: "unknown progress kind", frame: &RunProgress{Protocol: ProtocolV1, Type: TypeRunProgress, RunID: "r", Seq: 1, Kind: "trace", Text: "detail"}},
		{name: "oversized progress", frame: &RunProgress{Protocol: ProtocolV1, Type: TypeRunProgress, RunID: "r", Seq: 1, Kind: ProgressKindStatus, Text: strings.Repeat("p", MaxProgressTextBytes+1)}},
		{name: "blank progress", frame: &RunProgress{Protocol: ProtocolV1, Type: TypeRunProgress, RunID: "r", Seq: 1, Kind: ProgressKindStatus, Text: "\n\t"}},
		{name: "unknown error code", frame: &RunFailed{Protocol: ProtocolV1, Type: TypeRunFailed, RunID: "r", Seq: 1, Error: Failure{Code: "container_exit", Message: "no"}}},
		{name: "empty error message", frame: &RunFailed{Protocol: ProtocolV1, Type: TypeRunFailed, RunID: "r", Seq: 1, Error: Failure{Code: ErrorCodeHarnessError}}},
		{name: "blank error message", frame: &RunFailed{Protocol: ProtocolV1, Type: TypeRunFailed, RunID: "r", Seq: 1, Error: Failure{Code: ErrorCodeHarnessError, Message: " \n"}}},
		{name: "oversized output", frame: &RunCompleted{Protocol: ProtocolV1, Type: TypeRunCompleted, RunID: "r", Seq: 1, Output: TextContent{MediaType: MediaTypeTextPlain, Text: strings.Repeat("o", MaxOutputTextBytes+1)}}},
		{name: "NUL in output", frame: &RunCompleted{Protocol: ProtocolV1, Type: TypeRunCompleted, RunID: "r", Seq: 1, Output: TextContent{MediaType: MediaTypeTextPlain, Text: "done\x00"}}},
		{name: "control in session token", frame: &RunCompleted{Protocol: ProtocolV1, Type: TypeRunCompleted, RunID: "r", Seq: 1, Output: TextContent{MediaType: MediaTypeTextPlain}, SessionToken: "bad\ttoken"}},
		{name: "unsafe ASCII in session token", frame: &RunCompleted{Protocol: ProtocolV1, Type: TypeRunCompleted, RunID: "r", Seq: 1, Output: TextContent{MediaType: MediaTypeTextPlain}, SessionToken: "bad?token"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := MarshalFrame(test.frame); !errors.Is(err, ErrInvalidFrame) {
				t.Fatalf("MarshalFrame() error = %v, want ErrInvalidFrame", err)
			}
		})
	}

	var nilReady *RunnerReady
	if _, err := MarshalFrame(nilReady); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("MarshalFrame(typed nil) error = %v, want ErrInvalidFrame", err)
	}
}

func TestDirectionalDecoders(t *testing.T) {
	start := []byte(`{"protocol":"hrp/1","type":"run.start","run_id":"r","target_revision":"rev","input":{"media_type":"text/plain","text":"hi"},"session":{"mode":"new"},"deadline_unix_ms":1}`)
	started := []byte(`{"protocol":"hrp/1","type":"run.started","run_id":"r","seq":1}`)

	if _, err := DecodeControllerFrame(start); err != nil {
		t.Fatalf("DecodeControllerFrame(start) error = %v", err)
	}
	if _, err := DecodeRunnerFrame(start); !errors.Is(err, ErrUnexpectedFrameType) {
		t.Fatalf("DecodeRunnerFrame(start) error = %v, want ErrUnexpectedFrameType", err)
	}
	if _, err := DecodeRunnerFrame(started); err != nil {
		t.Fatalf("DecodeRunnerFrame(started) error = %v", err)
	}
	if _, err := DecodeControllerFrame(started); !errors.Is(err, ErrUnexpectedFrameType) {
		t.Fatalf("DecodeControllerFrame(started) error = %v, want ErrUnexpectedFrameType", err)
	}
}

func TestCompletedOutputMayBeEmpty(t *testing.T) {
	frame := &RunCompleted{
		Protocol: ProtocolV1, Type: TypeRunCompleted, RunID: "r", Seq: 1,
		Output: TextContent{MediaType: MediaTypeTextPlain},
	}
	if _, err := MarshalFrame(frame); err != nil {
		t.Fatalf("MarshalFrame(empty output) error = %v", err)
	}
}

func TestJSONLStream(t *testing.T) {
	ready := &RunnerReady{
		Protocol: ProtocolV1, Type: TypeRunnerReady,
		Adapter:  Adapter{Family: "codex", Version: "0.1.0"},
		Features: []Feature{FeatureProgressText},
	}
	started := &RunStarted{Protocol: ProtocolV1, Type: TypeRunStarted, RunID: "run-1", Seq: 1}

	var wire bytes.Buffer
	encoder := NewEncoder(&wire)
	if err := encoder.Encode(ready); err != nil {
		t.Fatalf("Encode(ready) error = %v", err)
	}
	if err := encoder.Encode(started); err != nil {
		t.Fatalf("Encode(started) error = %v", err)
	}
	if got := bytes.Count(wire.Bytes(), []byte{'\n'}); got != 2 {
		t.Fatalf("wire newline count = %d, want 2", got)
	}

	decoder := NewDecoder(&wire)
	first, err := decoder.DecodeRunnerFrame()
	if err != nil || !reflect.DeepEqual(first, ready) {
		t.Fatalf("first frame = %#v, %v; want %#v", first, err, ready)
	}
	second, err := decoder.DecodeRunnerFrame()
	if err != nil || !reflect.DeepEqual(second, started) {
		t.Fatalf("second frame = %#v, %v; want %#v", second, err, started)
	}
	if _, err := decoder.Decode(); !errors.Is(err, io.EOF) {
		t.Fatalf("Decode() after stream error = %v, want EOF", err)
	}
}

func TestJSONLDecoderFramingLimits(t *testing.T) {
	if _, err := NewDecoder(strings.NewReader("\n")).Decode(); !errors.Is(err, ErrEmptyFrame) {
		t.Fatalf("empty line error = %v, want ErrEmptyFrame", err)
	}
	tooLarge := strings.Repeat("x", MaxFrameBytes+1) + "\n"
	if _, err := NewDecoder(strings.NewReader(tooLarge)).Decode(); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized line error = %v, want ErrFrameTooLarge", err)
	}
}

type shortWriter struct {
	buffer bytes.Buffer
}

func (w *shortWriter) Write(data []byte) (int, error) {
	if len(data) > 7 {
		data = data[:7]
	}
	return w.buffer.Write(data)
}

func TestEncoderHandlesShortWrites(t *testing.T) {
	writer := &shortWriter{}
	frame := &RunStarted{Protocol: ProtocolV1, Type: TypeRunStarted, RunID: "r", Seq: 1}
	if err := NewEncoder(writer).Encode(frame); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if !bytes.HasSuffix(writer.buffer.Bytes(), []byte{'\n'}) {
		t.Fatalf("encoded bytes = %q, want LF suffix", writer.buffer.Bytes())
	}
	if _, err := DecodeFrame(bytes.TrimSuffix(writer.buffer.Bytes(), []byte{'\n'})); err != nil {
		t.Fatalf("DecodeFrame(encoded) error = %v", err)
	}
}
