// Package runnerwire implements Harness Runner Protocol v1 (HRP/1).
//
// HRP/1 is a deliberately closed JSON Lines protocol between sandboxd and one
// ephemeral harness runner. The types in this package are the complete v1 wire
// surface; vendor-specific flags and open-ended extension objects do not belong
// here.
package runnerwire

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	ProtocolV1 = "hrp/1"

	// MaxFrameBytes is the absolute HRP/1 JSON value limit, before the newline.
	// Target manifests can and should impose smaller per-target limits.
	MaxFrameBytes = 256 * 1024
	MaxJSONDepth  = 8

	MaxRunIDBytes          = 64
	MaxTargetRevisionBytes = 160
	MaxAdapterFamilyBytes  = 64
	MaxAdapterVersionBytes = 64
	MaxFeatures            = 16
	MaxEvents              = 512
	MaxInputTextBytes      = 32 * 1024
	MaxOutputTextBytes     = 32 * 1024
	MaxProgressTextBytes   = 4 * 1024
	MaxErrorMessageBytes   = 4 * 1024
	MaxSessionTokenBytes   = 1024

	// MaxDeadlineUnixMS is the last millisecond representable in year 9999.
	MaxDeadlineUnixMS int64 = 253402300799999
)

var ErrInvalidFrame = errors.New("invalid HRP/1 frame")

// FrameType is the closed set of HRP/1 frame discriminators.
type FrameType string

const (
	TypeRunnerReady  FrameType = "runner.ready"
	TypeRunStart     FrameType = "run.start"
	TypeRunStarted   FrameType = "run.started"
	TypeRunProgress  FrameType = "run.progress"
	TypeRunCompleted FrameType = "run.completed"
	TypeRunFailed    FrameType = "run.failed"
	TypeRunCancelled FrameType = "run.cancelled"
)

// Feature is a protocol behavior a runner can advertise. Features describe
// compatibility only and never grant authority.
type Feature string

const (
	FeatureSessionResume Feature = "session.resume"
	FeatureProgressText  Feature = "progress.text"
)

// MediaType is closed in HRP/1; typed artifacts are intentionally deferred.
type MediaType string

const MediaTypeTextPlain MediaType = "text/plain"

type SessionMode string

const (
	SessionModeNew    SessionMode = "new"
	SessionModeResume SessionMode = "resume"
)

type ProgressKind string

const (
	ProgressKindStatus      ProgressKind = "status"
	ProgressKindOutputDelta ProgressKind = "output_delta"
)

// ErrorCode is the closed set of failures a runner is allowed to claim.
// Runtime exits, deadlines, malformed protocol, and output-limit failures are
// classified independently by sandboxd.
type ErrorCode string

const (
	ErrorCodeInputRejected  ErrorCode = "input_rejected"
	ErrorCodeInvalidSession ErrorCode = "invalid_session"
	ErrorCodePolicyDenied   ErrorCode = "policy_denied"
	ErrorCodeHarnessError   ErrorCode = "harness_error"
	ErrorCodeRunnerInternal ErrorCode = "runner_internal"
)

type Adapter struct {
	Family  string `json:"family"`
	Version string `json:"version"`
}

type TextContent struct {
	MediaType MediaType `json:"media_type"`
	Text      string    `json:"text"`
}

type Session struct {
	Mode  SessionMode `json:"mode"`
	Token string      `json:"token,omitempty"`
}

type Failure struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

// Frame is sealed so every value accepted by MarshalFrame has a reviewed,
// closed HRP/1 schema.
type Frame interface {
	Validate() error
	FrameType() FrameType
	hrpFrame()
}

// RunnerFrame is a frame sent by a runner to sandboxd.
type RunnerFrame interface {
	Frame
	runnerFrame()
}

// ControllerFrame is a frame sent by sandboxd to a runner.
type ControllerFrame interface {
	Frame
	controllerFrame()
}

// RunEvent is a sequenced frame emitted after run.start.
type RunEvent interface {
	RunnerFrame
	EventRunID() string
	EventSequence() uint64
	Terminal() bool
	runEvent()
}

type RunnerReady struct {
	Protocol string    `json:"protocol"`
	Type     FrameType `json:"type"`
	Adapter  Adapter   `json:"adapter"`
	Features []Feature `json:"features"`
}

type RunStart struct {
	Protocol       string      `json:"protocol"`
	Type           FrameType   `json:"type"`
	RunID          string      `json:"run_id"`
	TargetRevision string      `json:"target_revision"`
	Input          TextContent `json:"input"`
	Session        Session     `json:"session"`
	DeadlineUnixMS int64       `json:"deadline_unix_ms"`
}

type RunStarted struct {
	Protocol string    `json:"protocol"`
	Type     FrameType `json:"type"`
	RunID    string    `json:"run_id"`
	Seq      uint64    `json:"seq"`
}

type RunProgress struct {
	Protocol string       `json:"protocol"`
	Type     FrameType    `json:"type"`
	RunID    string       `json:"run_id"`
	Seq      uint64       `json:"seq"`
	Kind     ProgressKind `json:"kind"`
	Text     string       `json:"text"`
}

type RunCompleted struct {
	Protocol     string      `json:"protocol"`
	Type         FrameType   `json:"type"`
	RunID        string      `json:"run_id"`
	Seq          uint64      `json:"seq"`
	Output       TextContent `json:"output"`
	SessionToken string      `json:"session_token,omitempty"`
}

type RunFailed struct {
	Protocol string    `json:"protocol"`
	Type     FrameType `json:"type"`
	RunID    string    `json:"run_id"`
	Seq      uint64    `json:"seq"`
	Error    Failure   `json:"error"`
}

// RunCancelled has no runner-selected reason field. Cancellation truth comes
// from sandboxd's runtime reconciliation, not from untrusted runner prose.
type RunCancelled struct {
	Protocol string    `json:"protocol"`
	Type     FrameType `json:"type"`
	RunID    string    `json:"run_id"`
	Seq      uint64    `json:"seq"`
}

func (*RunnerReady) hrpFrame()     {}
func (*RunStart) hrpFrame()        {}
func (*RunStarted) hrpFrame()      {}
func (*RunProgress) hrpFrame()     {}
func (*RunCompleted) hrpFrame()    {}
func (*RunFailed) hrpFrame()       {}
func (*RunCancelled) hrpFrame()    {}
func (*RunnerReady) runnerFrame()  {}
func (*RunStarted) runnerFrame()   {}
func (*RunProgress) runnerFrame()  {}
func (*RunCompleted) runnerFrame() {}
func (*RunFailed) runnerFrame()    {}
func (*RunCancelled) runnerFrame() {}
func (*RunStart) controllerFrame() {}
func (*RunStarted) runEvent()      {}
func (*RunProgress) runEvent()     {}
func (*RunCompleted) runEvent()    {}
func (*RunFailed) runEvent()       {}
func (*RunCancelled) runEvent()    {}

func (*RunnerReady) FrameType() FrameType  { return TypeRunnerReady }
func (*RunStart) FrameType() FrameType     { return TypeRunStart }
func (*RunStarted) FrameType() FrameType   { return TypeRunStarted }
func (*RunProgress) FrameType() FrameType  { return TypeRunProgress }
func (*RunCompleted) FrameType() FrameType { return TypeRunCompleted }
func (*RunFailed) FrameType() FrameType    { return TypeRunFailed }
func (*RunCancelled) FrameType() FrameType { return TypeRunCancelled }

func (f *RunnerReady) Validate() error {
	if f == nil {
		return invalid("frame", "must not be null")
	}
	if err := validateEnvelope(f.Protocol, f.Type, TypeRunnerReady); err != nil {
		return err
	}
	if err := validateVisibleASCII("adapter.family", f.Adapter.Family, 1, MaxAdapterFamilyBytes); err != nil {
		return err
	}
	if err := validateVisibleASCII("adapter.version", f.Adapter.Version, 1, MaxAdapterVersionBytes); err != nil {
		return err
	}
	if f.Features == nil {
		return invalid("features", "must be an array")
	}
	if len(f.Features) > MaxFeatures {
		return invalid("features", fmt.Sprintf("must contain at most %d entries", MaxFeatures))
	}
	seen := make(map[Feature]struct{}, len(f.Features))
	for i, feature := range f.Features {
		if !validFeature(feature) {
			return invalid(fmt.Sprintf("features[%d]", i), "is not supported by HRP/1")
		}
		if _, exists := seen[feature]; exists {
			return invalid(fmt.Sprintf("features[%d]", i), "is duplicated")
		}
		seen[feature] = struct{}{}
	}
	return nil
}

func (f *RunnerReady) Supports(feature Feature) bool {
	if f == nil {
		return false
	}
	for _, advertised := range f.Features {
		if advertised == feature {
			return true
		}
	}
	return false
}

func (f *RunStart) Validate() error {
	if f == nil {
		return invalid("frame", "must not be null")
	}
	if err := validateEnvelope(f.Protocol, f.Type, TypeRunStart); err != nil {
		return err
	}
	if err := validateIdentifier("run_id", f.RunID, MaxRunIDBytes); err != nil {
		return err
	}
	if err := validateIdentifier("target_revision", f.TargetRevision, MaxTargetRevisionBytes); err != nil {
		return err
	}
	if err := validateTextContent("input", f.Input, MaxInputTextBytes); err != nil {
		return err
	}
	if strings.TrimSpace(f.Input.Text) == "" {
		return invalid("input.text", "must not be blank")
	}
	if err := validateSession(f.Session); err != nil {
		return err
	}
	if f.DeadlineUnixMS <= 0 || f.DeadlineUnixMS > MaxDeadlineUnixMS {
		return invalid("deadline_unix_ms", "must be a positive Unix millisecond through year 9999")
	}
	return nil
}

func (f *RunStarted) Validate() error {
	if f == nil {
		return invalid("frame", "must not be null")
	}
	return validateEvent(f.Protocol, f.Type, TypeRunStarted, f.RunID, f.Seq)
}

func (f *RunProgress) Validate() error {
	if f == nil {
		return invalid("frame", "must not be null")
	}
	if err := validateEvent(f.Protocol, f.Type, TypeRunProgress, f.RunID, f.Seq); err != nil {
		return err
	}
	if f.Kind != ProgressKindStatus && f.Kind != ProgressKindOutputDelta {
		return invalid("kind", "must be status or output_delta")
	}
	if err := validateUTF8Text("text", f.Text, MaxProgressTextBytes); err != nil {
		return err
	}
	if strings.TrimSpace(f.Text) == "" {
		return invalid("text", "must not be blank")
	}
	return nil
}

func (f *RunCompleted) Validate() error {
	if f == nil {
		return invalid("frame", "must not be null")
	}
	if err := validateEvent(f.Protocol, f.Type, TypeRunCompleted, f.RunID, f.Seq); err != nil {
		return err
	}
	if err := validateTextContent("output", f.Output, MaxOutputTextBytes); err != nil {
		return err
	}
	if f.SessionToken != "" {
		if err := validateOpaqueToken("session_token", f.SessionToken, MaxSessionTokenBytes); err != nil {
			return err
		}
	}
	return nil
}

func (f *RunFailed) Validate() error {
	if f == nil {
		return invalid("frame", "must not be null")
	}
	if err := validateEvent(f.Protocol, f.Type, TypeRunFailed, f.RunID, f.Seq); err != nil {
		return err
	}
	if !validErrorCode(f.Error.Code) {
		return invalid("error.code", "is not supported by HRP/1")
	}
	if strings.TrimSpace(f.Error.Message) == "" {
		return invalid("error.message", "must not be blank")
	}
	return validateUTF8Text("error.message", f.Error.Message, MaxErrorMessageBytes)
}

func (f *RunCancelled) Validate() error {
	if f == nil {
		return invalid("frame", "must not be null")
	}
	return validateEvent(f.Protocol, f.Type, TypeRunCancelled, f.RunID, f.Seq)
}

func (f *RunStarted) EventRunID() string      { return f.RunID }
func (f *RunProgress) EventRunID() string     { return f.RunID }
func (f *RunCompleted) EventRunID() string    { return f.RunID }
func (f *RunFailed) EventRunID() string       { return f.RunID }
func (f *RunCancelled) EventRunID() string    { return f.RunID }
func (f *RunStarted) EventSequence() uint64   { return f.Seq }
func (f *RunProgress) EventSequence() uint64  { return f.Seq }
func (f *RunCompleted) EventSequence() uint64 { return f.Seq }
func (f *RunFailed) EventSequence() uint64    { return f.Seq }
func (f *RunCancelled) EventSequence() uint64 { return f.Seq }
func (*RunStarted) Terminal() bool            { return false }
func (*RunProgress) Terminal() bool           { return false }
func (*RunCompleted) Terminal() bool          { return true }
func (*RunFailed) Terminal() bool             { return true }
func (*RunCancelled) Terminal() bool          { return true }

func validateEnvelope(protocol string, got, want FrameType) error {
	if protocol != ProtocolV1 {
		return invalid("protocol", fmt.Sprintf("must be %q", ProtocolV1))
	}
	if got != want {
		return invalid("type", fmt.Sprintf("must be %q", want))
	}
	return nil
}

func validateEvent(protocol string, got, want FrameType, runID string, seq uint64) error {
	if err := validateEnvelope(protocol, got, want); err != nil {
		return err
	}
	if err := validateIdentifier("run_id", runID, MaxRunIDBytes); err != nil {
		return err
	}
	if seq == 0 {
		return invalid("seq", "must be greater than zero")
	}
	if seq > MaxEvents {
		return invalid("seq", fmt.Sprintf("must not exceed %d", MaxEvents))
	}
	return nil
}

func validateSession(session Session) error {
	switch session.Mode {
	case SessionModeNew:
		if session.Token != "" {
			return invalid("session.token", "must be absent when mode is new")
		}
	case SessionModeResume:
		if session.Token == "" {
			return invalid("session.token", "is required when mode is resume")
		}
		if err := validateOpaqueToken("session.token", session.Token, MaxSessionTokenBytes); err != nil {
			return err
		}
	default:
		return invalid("session.mode", "must be new or resume")
	}
	return nil
}

func validateTextContent(field string, content TextContent, maxBytes int) error {
	if content.MediaType != MediaTypeTextPlain {
		return invalid(field+".media_type", fmt.Sprintf("must be %q", MediaTypeTextPlain))
	}
	return validateUTF8Text(field+".text", content.Text, maxBytes)
}

func validateIdentifier(field, value string, maxBytes int) error {
	if len(value) == 0 {
		return invalid(field, "must not be empty")
	}
	if len(value) > maxBytes {
		return invalid(field, fmt.Sprintf("must contain at most %d bytes", maxBytes))
	}
	for _, char := range []byte(value) {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("-_.:/@", rune(char)) {
			continue
		}
		return invalid(field, "must contain only ASCII letters, digits, and -_.:/@")
	}
	return nil
}

func validateVisibleASCII(field, value string, minBytes, maxBytes int) error {
	if len(value) < minBytes || len(value) > maxBytes {
		return invalid(field, fmt.Sprintf("must contain between %d and %d bytes", minBytes, maxBytes))
	}
	for _, char := range []byte(value) {
		if char < 0x21 || char > 0x7e {
			return invalid(field, "must contain only visible ASCII without spaces")
		}
	}
	return nil
}

func validateOpaqueToken(field, value string, maxBytes int) error {
	if len(value) == 0 || len(value) > maxBytes {
		return invalid(field, fmt.Sprintf("must contain between 1 and %d bytes", maxBytes))
	}
	for _, char := range []byte(value) {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("-._~:/@+=", rune(char)) {
			continue
		}
		return invalid(field, "must contain only safe ASCII token characters")
	}
	return nil
}

func validateUTF8Text(field, value string, maxBytes int) error {
	if !utf8.ValidString(value) {
		return invalid(field, "must be valid UTF-8")
	}
	if strings.ContainsRune(value, '\x00') {
		return invalid(field, "must not contain NUL")
	}
	if len(value) > maxBytes {
		return invalid(field, fmt.Sprintf("must contain at most %d bytes", maxBytes))
	}
	return nil
}

func validFeature(feature Feature) bool {
	return feature == FeatureSessionResume || feature == FeatureProgressText
}

func validErrorCode(code ErrorCode) bool {
	switch code {
	case ErrorCodeInputRejected, ErrorCodeInvalidSession, ErrorCodePolicyDenied,
		ErrorCodeHarnessError, ErrorCodeRunnerInternal:
		return true
	default:
		return false
	}
}

func invalid(field, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidFrame, field, reason)
}
