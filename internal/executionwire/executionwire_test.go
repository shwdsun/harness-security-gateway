package executionwire

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

func validStartRunJSON() string {
	return `{"run_id":"run_01","target_id":"demo-codex","expected_revision":"demo-r1","session_scope_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","session_ref":"session_01","input":{"media_type":"text/plain","text":"Inspect the project"},"deadline":"2026-08-16T12:00:00Z"}`
}

func TestDecodeStartRunRequest(t *testing.T) {
	request, err := DecodeStartRunRequest([]byte(validStartRunJSON()))
	if err != nil {
		t.Fatalf("DecodeStartRunRequest() error = %v", err)
	}
	if request.RunID != "run_01" || request.TargetID != "demo-codex" {
		t.Fatalf("DecodeStartRunRequest() = %#v", request)
	}
	if request.SessionRef == nil || *request.SessionRef != "session_01" {
		t.Fatalf("SessionRef = %#v", request.SessionRef)
	}
	if got := request.Deadline.Format(time.RFC3339); got != "2026-08-16T12:00:00Z" {
		t.Fatalf("Deadline = %q", got)
	}
}

func TestDecodeStartRunRejectsDuplicateKey(t *testing.T) {
	payload := `{"run_id":"run_01","run_id":"run_02","target_id":"demo","expected_revision":"r1","input":{"media_type":"text/plain","text":"hello"},"deadline":"2026-08-16T12:00:00Z"}`
	_, err := DecodeStartRunRequest([]byte(payload))
	if !errors.Is(err, strictjson.ErrDuplicateKey) {
		t.Fatalf("error = %v, want ErrDuplicateKey", err)
	}
}

func TestDecodeStartRunRejectsForbiddenAuthorityFields(t *testing.T) {
	fields := []string{"image", "path", "argv", "env", "mount", "network", "runtime"}
	base := strings.TrimSuffix(validStartRunJSON(), "}")
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			payload := base + `,"` + field + `":{}}`
			_, err := DecodeStartRunRequest([]byte(payload))
			if err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("error = %v, want unknown-field rejection", err)
			}
		})
	}
}

func TestStartRunValidationRejectsUnboundedOrUnsafeData(t *testing.T) {
	request, err := DecodeStartRunRequest([]byte(validStartRunJSON()))
	if err != nil {
		t.Fatal(err)
	}

	tooLarge := request
	tooLarge.Input.Text = strings.Repeat("x", MaxInputTextBytes+1)
	if err := tooLarge.Validate(); err == nil {
		t.Fatal("oversized input accepted")
	}

	unsafeSession := request
	value := "../../state/session"
	unsafeSession.SessionRef = &value
	if err := unsafeSession.Validate(); err == nil {
		t.Fatal("path-like session ref accepted")
	}

	for name, digest := range map[string]string{
		"absent": "",
		"short":  strings.Repeat("a", 63),
		"upper":  strings.Repeat("A", 64),
		"nonhex": strings.Repeat("g", 64),
	} {
		t.Run("scope digest "+name, func(t *testing.T) {
			changed := request
			changed.SessionScopeDigest = digest
			if err := changed.Validate(); err == nil {
				t.Fatal("invalid session scope digest accepted")
			}
		})
	}

	unsupportedMedia := request
	unsupportedMedia.Input.MediaType = "application/json"
	if err := unsupportedMedia.Validate(); err == nil {
		t.Fatal("unsupported media type accepted")
	}

	nulInput := request
	nulInput.Input.Text = "unsafe\x00text"
	if err := nulInput.Validate(); err == nil {
		t.Fatal("NUL input accepted")
	}
}

func TestStartRunFingerprintIsDeterministicAndSemantic(t *testing.T) {
	request, err := DecodeStartRunRequest([]byte(validStartRunJSON()))
	if err != nil {
		t.Fatal(err)
	}
	first, err := StartRunFingerprint(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := StartRunFingerprint(request)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != sha256HexLength {
		t.Fatalf("fingerprints = %q, %q", first, second)
	}

	sameInstant := request
	sameInstant.Deadline = time.Date(2026, 8, 16, 14, 0, 0, 0, time.FixedZone("plus-two", 2*60*60))
	normalized, err := StartRunFingerprint(sameInstant)
	if err != nil {
		t.Fatal(err)
	}
	if normalized != first {
		t.Fatalf("equivalent deadlines differ: %q != %q", normalized, first)
	}

	changed := request
	changed.Input.Text = "Inspect another project"
	different, err := StartRunFingerprint(changed)
	if err != nil {
		t.Fatal(err)
	}
	if different == first {
		t.Fatal("different request produced the same fingerprint")
	}
	changed = request
	changed.SessionScopeDigest = strings.Repeat("b", 64)
	different, err = StartRunFingerprint(changed)
	if err != nil || different == first {
		t.Fatalf("scope digest was not fingerprinted: %q, %v", different, err)
	}
}

const sha256HexLength = 64

func TestRunEventDiscriminatedUnion(t *testing.T) {
	valid := RunEvent{
		RunID: "run_01",
		Seq:   2,
		Type:  RunEventProgress,
		Progress: &RunProgress{
			Kind: ProgressStatus,
			Text: "Inspecting",
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}

	invalid := valid
	invalid.Result = &RunResult{Output: TextOutput{MediaType: MediaTypeTextPlain}}
	if err := invalid.Validate(); err == nil {
		t.Fatal("event with conflicting payloads accepted")
	}

	unknown := valid
	unknown.Progress = &RunProgress{Kind: "vendor_detail", Text: "unsafe"}
	if err := unknown.Validate(); err == nil {
		t.Fatal("unknown progress kind accepted")
	}
}

func TestDecodeRunEventRejectsUnknownAndDuplicateNestedFields(t *testing.T) {
	unknown := `{"run_id":"run_01","seq":1,"type":"progress","progress":{"kind":"status","text":"working","provider":"x"}}`
	if _, err := DecodeRunEvent([]byte(unknown)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}

	duplicate := `{"run_id":"run_01","seq":1,"type":"progress","progress":{"kind":"status","text":"one","text":"two"}}`
	if _, err := DecodeRunEvent([]byte(duplicate)); !errors.Is(err, strictjson.ErrDuplicateKey) {
		t.Fatalf("duplicate field error = %v", err)
	}
}

func TestGetRunResponseValidatesSequenceAndTerminalState(t *testing.T) {
	response := GetRunResponse{
		Status: RunStatus{RunID: "run_01", State: RunStateCompleted, LastEventSeq: 3},
		Events: []RunEvent{
			{RunID: "run_01", Seq: 1, Type: RunEventStarted},
			{RunID: "run_01", Seq: 2, Type: RunEventProgress, Progress: &RunProgress{Kind: ProgressStatus, Text: "Working"}},
			{RunID: "run_01", Seq: 3, Type: RunEventCompleted, Result: &RunResult{Output: TextOutput{MediaType: MediaTypeTextPlain, Text: "Done"}}},
		},
	}
	if err := response.Validate(); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	encoded, err := Marshal(&response)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeGetRunResponse(encoded)
	if err != nil {
		t.Fatalf("round-trip decode error = %v", err)
	}
	if len(decoded.Events) != 3 {
		t.Fatalf("event count = %d", len(decoded.Events))
	}

	wrongState := response
	wrongState.Status.State = RunStateRunning
	if err := wrongState.Validate(); err == nil {
		t.Fatal("terminal event with running state accepted")
	}

	outOfOrder := response
	outOfOrder.Events = append([]RunEvent(nil), response.Events...)
	outOfOrder.Events[1].Seq = 1
	if err := outOfOrder.Validate(); err == nil {
		t.Fatal("non-increasing event sequence accepted")
	}

	skipped := response
	skipped.Events = append([]RunEvent(nil), response.Events...)
	skipped.Events[1].Seq = 3
	skipped.Events[2].Seq = 4
	skipped.Status.LastEventSeq = 4
	if err := skipped.Validate(); err == nil {
		t.Fatal("gapped event sequence accepted")
	}
}

func TestCancellingBeforeRunnerStartHasNoInventedEvent(t *testing.T) {
	response := GetRunResponse{
		Status: RunStatus{RunID: "run_01", State: RunStateCancelling, LastEventSeq: 0},
		Events: []RunEvent{},
	}
	if err := response.Validate(); err != nil {
		t.Fatalf("pre-start cancelling response rejected: %v", err)
	}

	running := response
	running.Status.State = RunStateRunning
	if err := running.Validate(); err == nil {
		t.Fatal("running response without run.started event accepted")
	}

	completed := response
	completed.Status.State = RunStateCompleted
	if err := completed.Validate(); err == nil {
		t.Fatal("completed response without terminal event accepted")
	}
}

func TestFailureEnumsAreClosed(t *testing.T) {
	event := RunEvent{
		RunID:   "run_01",
		Seq:     2,
		Type:    RunEventFailed,
		Failure: &RunFailure{Code: "vendor_error", Message: "failed"},
	}
	if err := event.Validate(); err == nil {
		t.Fatal("unknown failure code accepted")
	}

	event.Type = RunEventInterrupted
	event.Failure.Code = FailureRuntimeInterrupted
	if err := event.Validate(); err != nil {
		t.Fatalf("valid interrupted event rejected: %v", err)
	}
}

func TestCancelAndGetHaveOnlyRunID(t *testing.T) {
	if _, err := DecodeCancelRunRequest([]byte(`{"run_id":"run_01","reason":"user text"}`)); err == nil {
		t.Fatal("cancel reason unexpectedly accepted")
	}
	if _, err := DecodeGetRunRequest([]byte(`{"run_id":"run_01","include":"raw_stderr"}`)); err == nil {
		t.Fatal("get-run option unexpectedly accepted")
	}
}

func TestMarshalRejectsTypedNil(t *testing.T) {
	var request *StartRunRequest
	if _, err := Marshal(request); err == nil {
		t.Fatal("typed nil unexpectedly marshalled")
	}
}
