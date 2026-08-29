// Package runnerbridge implements the synchronous, trusted HRP/1 boundary
// between sandboxd and one already-started runner. It does not launch, signal,
// or otherwise control a process or container.
package runnerbridge

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// ErrorClass is the closed set of failures for which the bridge could not
// commit one trustworthy terminal runner event. A valid run.failed or
// run.cancelled event is a successful protocol exchange and is represented in
// the event sink, not returned again as a BridgeError.
type ErrorClass string

const (
	ErrorProtocolViolation ErrorClass = "protocol_violation"
	ErrorRunnerFailed      ErrorClass = "runner_failed"
	ErrorInvalidSession    ErrorClass = "invalid_session"
	ErrorPolicyDenied      ErrorClass = "policy_denied"
	ErrorDeadline          ErrorClass = "deadline"
	ErrorOutputLimit       ErrorClass = "output_limit"
	ErrorCancelled         ErrorClass = "cancelled"
	ErrorInternal          ErrorClass = "internal"
)

// BridgeError deliberately prints only its closed classification. Its wrapped
// cause is available for trusted local diagnostics, but raw runner frames and
// prompts are never incorporated into Error().
type BridgeError struct {
	Class ErrorClass
	cause error
}

func (e *BridgeError) Error() string {
	if e == nil || !validErrorClass(e.Class) {
		return "runner bridge: internal"
	}
	return "runner bridge: " + string(e.Class)
}

func (e *BridgeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Emission keeps a vendor token in an explicitly sandbox-domain-only side
// field. The json:"-" defense prevents accidental serialization alongside the
// vendor-neutral execution event. The sink can atomically persist the event
// and bind the token to a newly minted SessionRef.
type Emission struct {
	Event              executionwire.RunEvent `json:"event"`
	VendorSessionToken *string                `json:"-"`
}

type Sink func(context.Context, Emission) error

// Run bridges one already-started runner. runnerOutput is the runner's stdout;
// runnerInput is its stdin. On cancellation/error the caller remains
// responsible for closing/reconciling the process pipes and runtime.
func Run(
	ctx context.Context,
	request executionwire.StartRunRequest,
	manifest targetmanifest.Manifest,
	resolvedVendorToken *string,
	runnerOutput io.Reader,
	runnerInput io.Writer,
	sink Sink,
) error {
	if ctx == nil {
		return bridgeError(ErrorInternal, errors.New("nil context"))
	}
	if runnerOutput == nil || runnerInput == nil || sink == nil {
		return bridgeError(ErrorInternal, errors.New("missing runner stream or event sink"))
	}
	if err := request.Validate(); err != nil {
		return bridgeError(ErrorInternal, err)
	}
	if err := manifest.Validate(); err != nil {
		return bridgeError(ErrorInternal, err)
	}
	if request.TargetID != manifest.ID || request.ExpectedRevision != manifest.Revision {
		return bridgeError(ErrorInternal, errors.New("request target does not match resolved manifest"))
	}
	if len(request.Input.Text) > manifest.Limits.MaxInputBytes {
		return bridgeError(ErrorPolicyDenied, errors.New("input exceeds target limit"))
	}

	session, err := resolveSession(request, manifest, resolvedVendorToken)
	if err != nil {
		return err
	}

	runCtx, cancel := withRunDeadline(ctx, request.Deadline, manifest.Limits.TimeoutSeconds)
	defer cancel()
	if err := contextBridgeError(runCtx.Err()); err != nil {
		return err
	}

	decoder := runnerwire.NewDecoder(runnerOutput)
	first, err := decodeFrame(runCtx, decoder)
	if err != nil {
		return classifyReadError(runCtx, err)
	}
	ready, ok := first.(*runnerwire.RunnerReady)
	if !ok {
		return bridgeError(ErrorProtocolViolation, errors.New("first runner frame is not runner.ready"))
	}
	if ready.Adapter.Family != manifest.Runner.Family || ready.Adapter.Version != manifest.Runner.AdapterVersion {
		return bridgeError(ErrorProtocolViolation, errors.New("runner adapter does not match target manifest"))
	}
	for _, required := range manifest.Runner.RequiredFeatures {
		if !ready.Supports(required) {
			return bridgeError(ErrorProtocolViolation, errors.New("runner omitted a required feature"))
		}
	}

	start := &runnerwire.RunStart{
		Protocol:       runnerwire.ProtocolV1,
		Type:           runnerwire.TypeRunStart,
		RunID:          request.RunID,
		TargetRevision: request.ExpectedRevision,
		Input: runnerwire.TextContent{
			MediaType: runnerwire.MediaTypeTextPlain,
			Text:      request.Input.Text,
		},
		Session:        session,
		DeadlineUnixMS: request.Deadline.UnixMilli(),
	}
	if err := start.Validate(); err != nil {
		class := ErrorInternal
		if session.Mode == runnerwire.SessionModeResume {
			class = ErrorInvalidSession
		}
		return bridgeError(class, err)
	}
	if err := encodeFrame(runCtx, runnerwire.NewEncoder(runnerInput), start); err != nil {
		if contextErr := contextBridgeError(runCtx.Err()); contextErr != nil {
			return contextErr
		}
		return bridgeError(ErrorRunnerFailed, err)
	}

	sequence, err := runnerwire.NewSequence(request.RunID)
	if err != nil {
		return bridgeError(ErrorInternal, err)
	}
	for {
		frame, readErr := decodeFrame(runCtx, decoder)
		if readErr != nil {
			return classifyReadError(runCtx, readErr)
		}
		event, ok := frame.(runnerwire.RunEvent)
		if !ok {
			return bridgeError(ErrorProtocolViolation, errors.New("runner emitted a non-event after start"))
		}
		if event.EventSequence() > uint64(manifest.Limits.MaxEvents) {
			return bridgeError(ErrorOutputLimit, errors.New("runner exceeded target event limit"))
		}
		if err := sequence.Accept(event); err != nil {
			return bridgeError(ErrorProtocolViolation, err)
		}
		if progress, ok := event.(*runnerwire.RunProgress); ok {
			if !ready.Supports(runnerwire.FeatureProgressText) {
				return bridgeError(ErrorProtocolViolation, errors.New("runner emitted unadvertised text progress"))
			}
			if len(progress.Text) > manifest.Limits.MaxProgressBytes {
				return bridgeError(ErrorOutputLimit, errors.New("runner exceeded target progress limit"))
			}
		}
		if completed, ok := event.(*runnerwire.RunCompleted); ok {
			if len(completed.Output.Text) > manifest.Limits.MaxOutputBytes {
				return bridgeError(ErrorOutputLimit, errors.New("runner exceeded target output limit"))
			}
			if manifest.SessionMode == targetmanifest.SessionNewOnly && completed.SessionToken != "" {
				// new_only targets cannot create hidden resumable state. Reject the
				// terminal before it reaches durable execution events.
				return bridgeError(ErrorPolicyDenied, errors.New("new_only runner returned a session token"))
			}
			if manifest.SessionMode == targetmanifest.SessionOpaqueResume && completed.SessionToken == "" {
				return bridgeError(ErrorProtocolViolation, errors.New("opaque_resume runner omitted the successor session token"))
			}
		}

		emission, err := translateEvent(event, manifest.SessionMode)
		if err != nil {
			return err
		}
		if err := emit(runCtx, sink, emission); err != nil {
			return err
		}
		if event.Terminal() {
			if err := sequence.Finalize(); err != nil {
				return bridgeError(ErrorProtocolViolation, err)
			}
			return nil
		}
	}
}

func resolveSession(
	request executionwire.StartRunRequest,
	manifest targetmanifest.Manifest,
	resolvedVendorToken *string,
) (runnerwire.Session, error) {
	switch manifest.SessionMode {
	case targetmanifest.SessionNewOnly:
		if request.SessionRef != nil || resolvedVendorToken != nil {
			return runnerwire.Session{}, bridgeError(ErrorPolicyDenied, errors.New("new_only target cannot resume a session"))
		}
		return runnerwire.Session{Mode: runnerwire.SessionModeNew}, nil
	case targetmanifest.SessionOpaqueResume:
		if request.SessionRef == nil {
			if resolvedVendorToken != nil {
				return runnerwire.Session{}, bridgeError(ErrorInvalidSession, errors.New("vendor token has no requested session ref"))
			}
			return runnerwire.Session{Mode: runnerwire.SessionModeNew}, nil
		}
		if resolvedVendorToken == nil || *resolvedVendorToken == "" {
			return runnerwire.Session{}, bridgeError(ErrorInvalidSession, errors.New("requested session token was not resolved"))
		}
		return runnerwire.Session{Mode: runnerwire.SessionModeResume, Token: *resolvedVendorToken}, nil
	default:
		return runnerwire.Session{}, bridgeError(ErrorInternal, errors.New("unsupported manifest session mode"))
	}
}

func translateEvent(event runnerwire.RunEvent, sessionMode targetmanifest.SessionMode) (Emission, error) {
	translated := executionwire.RunEvent{
		RunID: event.EventRunID(),
		Seq:   event.EventSequence(),
	}
	emission := Emission{Event: translated}

	switch frame := event.(type) {
	case *runnerwire.RunStarted:
		emission.Event.Type = executionwire.RunEventStarted
	case *runnerwire.RunProgress:
		emission.Event.Type = executionwire.RunEventProgress
		kind := executionwire.ProgressStatus
		if frame.Kind == runnerwire.ProgressKindOutputDelta {
			kind = executionwire.ProgressOutputDelta
		}
		emission.Event.Progress = &executionwire.RunProgress{Kind: kind, Text: frame.Text}
	case *runnerwire.RunCompleted:
		emission.Event.Type = executionwire.RunEventCompleted
		emission.Event.Result = &executionwire.RunResult{
			Output: executionwire.TextOutput{
				MediaType: executionwire.MediaTypeTextPlain,
				Text:      frame.Output.Text,
			},
		}
		if sessionMode == targetmanifest.SessionOpaqueResume && frame.SessionToken != "" {
			token := frame.SessionToken
			emission.VendorSessionToken = &token
		}
	case *runnerwire.RunFailed:
		emission.Event.Type = executionwire.RunEventFailed
		emission.Event.Failure = &executionwire.RunFailure{
			Code:    mapFailureCode(frame.Error.Code),
			Message: frame.Error.Message,
		}
	case *runnerwire.RunCancelled:
		emission.Event.Type = executionwire.RunEventCancelled
	default:
		return Emission{}, bridgeError(ErrorProtocolViolation, errors.New("unknown runner event type"))
	}
	if err := emission.Event.Validate(); err != nil {
		return Emission{}, bridgeError(ErrorProtocolViolation, err)
	}
	return emission, nil
}

func mapFailureCode(code runnerwire.ErrorCode) executionwire.FailureCode {
	switch code {
	case runnerwire.ErrorCodeInvalidSession:
		return executionwire.FailureInvalidSession
	case runnerwire.ErrorCodePolicyDenied:
		return executionwire.FailurePolicyDenied
	case runnerwire.ErrorCodeInputRejected, runnerwire.ErrorCodeHarnessError, runnerwire.ErrorCodeRunnerInternal:
		return executionwire.FailureRunnerFailed
	default:
		return executionwire.FailureRunnerFailed
	}
}

type decodeResult struct {
	frame runnerwire.RunnerFrame
	err   error
}

func decodeFrame(ctx context.Context, decoder *runnerwire.Decoder) (runnerwire.RunnerFrame, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make(chan decodeResult, 1)
	go func() {
		frame, err := decoder.DecodeRunnerFrame()
		result <- decodeResult{frame: frame, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case decoded := <-result:
		return decoded.frame, decoded.err
	}
}

func encodeFrame(ctx context.Context, encoder *runnerwire.Encoder, frame runnerwire.Frame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	result := make(chan error, 1)
	go func() {
		result <- encoder.Encode(frame)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-result:
		return err
	}
}

func emit(ctx context.Context, sink Sink, emission Emission) error {
	if err := ctx.Err(); err != nil {
		return contextBridgeError(err)
	}
	if err := sink(ctx, emission); err != nil {
		if contextErr := contextBridgeError(ctx.Err()); contextErr != nil {
			return contextErr
		}
		return bridgeError(ErrorInternal, err)
	}
	// A nil sink result means the event was committed. In particular, a
	// terminal event must remain authoritative if cancellation races just after
	// that commit; returning a bridge error would invite a duplicate terminal.
	return nil
}

func withRunDeadline(parent context.Context, requested time.Time, timeoutSeconds int64) (context.Context, context.CancelFunc) {
	effective := requested
	manifestDeadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
	if manifestDeadline.Before(effective) {
		effective = manifestDeadline
	}
	return context.WithDeadline(parent, effective)
}

func classifyReadError(ctx context.Context, err error) error {
	if contextErr := contextBridgeError(ctx.Err()); contextErr != nil {
		return contextErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return contextBridgeError(err)
	}
	if errors.Is(err, io.EOF) {
		return bridgeError(ErrorProtocolViolation, errors.New("runner stream ended before a terminal event"))
	}
	if errors.Is(err, runnerwire.ErrInvalidFrame) ||
		errors.Is(err, runnerwire.ErrUnexpectedFrameType) ||
		errors.Is(err, runnerwire.ErrEmptyFrame) ||
		errors.Is(err, runnerwire.ErrFrameTooLarge) {
		return bridgeError(ErrorProtocolViolation, err)
	}
	return bridgeError(ErrorRunnerFailed, err)
}

func contextBridgeError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return bridgeError(ErrorCancelled, err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return bridgeError(ErrorDeadline, err)
	}
	return bridgeError(ErrorInternal, err)
}

func bridgeError(class ErrorClass, cause error) *BridgeError {
	if !validErrorClass(class) {
		class = ErrorInternal
	}
	return &BridgeError{Class: class, cause: cause}
}

func validErrorClass(class ErrorClass) bool {
	switch class {
	case ErrorProtocolViolation, ErrorRunnerFailed, ErrorInvalidSession,
		ErrorPolicyDenied, ErrorDeadline, ErrorOutputLimit,
		ErrorCancelled, ErrorInternal:
		return true
	default:
		return false
	}
}

// Compile-time compatibility checks for the trusted callback boundary.
var _ error = (*BridgeError)(nil)
