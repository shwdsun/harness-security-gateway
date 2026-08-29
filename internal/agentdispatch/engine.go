package agentdispatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
)

const (
	// This frozen domain-separation label participates in persisted delivery IDs.
	// It is not an import path and deliberately retains the prototype namespace.
	deliveryIDDomain = "harnessgateway.local/core/agentdispatch/text-delivery/v1"
	maxRunTimeout    = 24 * time.Hour
)

const (
	textCompletedWithoutOutput = "Run completed without text output."
	textCancelled              = "Run cancelled."
	textInterrupted            = "Run interrupted; it was not automatically retried."
)

// Store is the narrow part of corestore.Operations needed to advance Runs.
// It deliberately excludes ingest, arbitrary outbox writes, and connector
// delivery operations.
type Store interface {
	ClaimQueuedRun(context.Context, time.Duration) (corestore.Run, bool, error)
	GetRun(context.Context, string) (corestore.Run, error)
	ListRunningRuns(context.Context, int) ([]corestore.Run, error)
	GetSession(context.Context, corestore.SessionKey) (corestore.Session, bool, error)
	PrepareRunStart(context.Context, corestore.PrepareRunStartInput) (corestore.PreparedRunStart, error)
	MarkRunRunning(context.Context, string, string) error
	FinishRun(context.Context, corestore.FinishRunInput, *corestore.TextDeliveryInput) error
}

// Sandbox is the narrow idempotent execution surface used by agentd. Runtime
// configuration is intentionally impossible to express through this view.
type Sandbox interface {
	StartRun(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error)
	GetRun(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error)
}

type Clock func() time.Time

type Option func(*options) error

type options struct {
	clock Clock
}

// WithClock injects the proposal clock. PrepareRunStart durably normalizes and
// freezes the actual deadline, so the clock never becomes sandbox authority.
func WithClock(clock Clock) Option {
	return func(config *options) error {
		if clock == nil {
			return errors.New("agentdispatch: nil clock")
		}
		config.clock = clock
		return nil
	}
}

// ErrorCode is a closed operational classification. Raw store, transport, and
// sandbox causes remain available through Unwrap but are never rendered by
// Error.
type ErrorCode string

const (
	ErrorInvalidState       ErrorCode = "invalid_state"
	ErrorDispatchLost       ErrorCode = "dispatch_lost"
	ErrorStoreUnavailable   ErrorCode = "store_unavailable"
	ErrorSandboxUnavailable ErrorCode = "sandbox_unavailable"
	ErrorConflict           ErrorCode = "conflict"
	ErrorProtocolViolation  ErrorCode = "protocol_violation"
	ErrorContextDone        ErrorCode = "context_done"
)

type Error struct {
	Code  ErrorCode
	Cause error
}

func (e *Error) Error() string {
	if e == nil {
		return "agent dispatch error: invalid_state"
	}
	return "agent dispatch error: " + string(e.Code)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Result describes one durable advancement. SandboxState is the last closed
// state observed from sandboxd; CoreState is the state committed in agentd.
type Result struct {
	RunID        string
	SandboxState executionwire.RunState
	CoreState    corestore.RunState
	Finished     bool
}

// ReconcileItem lets one broken Run avoid starving later running Runs. Err is
// always a closed *Error. Reconcile itself returns an error only when listing
// cannot begin or when the caller's context ends.
type ReconcileItem struct {
	Result Result
	Err    error
}

// Engine is a synchronous, crash-safe state-machine composer.
type Engine struct {
	store         Store
	sandbox       Sandbox
	dispatchLease time.Duration
	runTimeout    time.Duration
	clock         Clock
}

func New(
	store Store,
	sandbox Sandbox,
	dispatchLease time.Duration,
	runTimeout time.Duration,
	supplied ...Option,
) (*Engine, error) {
	if nilInterface(store) {
		return nil, errors.New("agentdispatch: nil store")
	}
	if nilInterface(sandbox) {
		return nil, errors.New("agentdispatch: nil sandbox")
	}
	if dispatchLease < time.Second || dispatchLease > time.Duration(agentconfig.MaxLeaseSeconds)*time.Second {
		return nil, errors.New("agentdispatch: dispatch lease must be between one second and ten minutes")
	}
	if runTimeout < time.Second || runTimeout > maxRunTimeout {
		return nil, errors.New("agentdispatch: run timeout must be between one second and twenty-four hours")
	}
	config := options{clock: func() time.Time { return time.Now().UTC() }}
	for index, option := range supplied {
		if option == nil {
			return nil, fmt.Errorf("agentdispatch: option %d is nil", index)
		}
		if err := option(&config); err != nil {
			return nil, fmt.Errorf("agentdispatch: apply option %d: %w", index, err)
		}
	}
	return &Engine{
		store:         store,
		sandbox:       sandbox,
		dispatchLease: dispatchLease,
		runTimeout:    runTimeout,
		clock:         config.clock,
	}, nil
}

// DispatchOne claims at most one queued Run and advances it once. claimed is
// true even when advancement fails, allowing the daemon to log the Run ID and
// wait for the durable lease before trying the same Run again.
func (e *Engine) DispatchOne(ctx context.Context) (result Result, claimed bool, err error) {
	if err := e.ready(ctx); err != nil {
		return Result{}, false, err
	}
	run, claimed, err := e.store.ClaimQueuedRun(ctx, e.dispatchLease)
	if err != nil {
		return Result{}, false, mapStoreError(ctx, err)
	}
	if !claimed {
		return Result{}, false, nil
	}
	result = resultForRun(run)
	if err := validateStoreRun(run, corestore.RunDispatching); err != nil {
		return result, true, dispatchError(ErrorInvalidState, err)
	}
	advanced, err := e.advanceDispatching(ctx, run)
	if advanced.RunID != "" {
		result = advanced
	}
	return result, true, err
}

// Advance advances one known Run by ID. Dispatching Runs safely re-offer the
// exact prepared StartRun; running Runs are poll-only and are never started as
// a fresh execution.
func (e *Engine) Advance(ctx context.Context, runID string) (Result, error) {
	if err := e.ready(ctx); err != nil {
		return Result{}, err
	}
	run, err := e.store.GetRun(ctx, runID)
	if err != nil {
		return Result{RunID: runID}, mapStoreError(ctx, err)
	}
	if run.ID != runID {
		return Result{RunID: runID}, dispatchError(ErrorInvalidState, errors.New("store returned a different Run ID"))
	}
	switch run.State {
	case corestore.RunDispatching:
		if err := validateStoreRun(run, corestore.RunDispatching); err != nil {
			return resultForRun(run), dispatchError(ErrorInvalidState, err)
		}
		return e.advanceDispatching(ctx, run)
	case corestore.RunRunning:
		if err := validateStoreRun(run, corestore.RunRunning); err != nil {
			return resultForRun(run), dispatchError(ErrorInvalidState, err)
		}
		return e.advanceRunning(ctx, run)
	case corestore.RunCompleted, corestore.RunFailed, corestore.RunCancelled, corestore.RunInterrupted:
		result := resultForRun(run)
		result.Finished = true
		result.SandboxState = sandboxStateFromCore(run.State)
		return result, nil
	default:
		return resultForRun(run), dispatchError(ErrorInvalidState, corestore.ErrInvalidTransition)
	}
}

// Reconcile polls every bounded running Run returned by corestore. Individual
// failures are reported per item so one bad sandbox response cannot starve the
// rest of the deterministic reconciliation batch.
func (e *Engine) Reconcile(ctx context.Context, limit int) ([]ReconcileItem, error) {
	if err := e.ready(ctx); err != nil {
		return nil, err
	}
	runs, err := e.store.ListRunningRuns(ctx, limit)
	if err != nil {
		return nil, mapStoreError(ctx, err)
	}
	items := make([]ReconcileItem, 0, len(runs))
	for _, run := range runs {
		result := resultForRun(run)
		var advanceErr error
		if err := validateStoreRun(run, corestore.RunRunning); err != nil {
			advanceErr = dispatchError(ErrorInvalidState, err)
		} else {
			result, advanceErr = e.advanceRunning(ctx, run)
		}
		items = append(items, ReconcileItem{Result: result, Err: advanceErr})
		if advanceErr != nil && callerContextError(ctx, advanceErr) {
			return items, advanceErr
		}
	}
	return items, nil
}

func (e *Engine) advanceDispatching(ctx context.Context, run corestore.Run) (Result, error) {
	result := resultForRun(run)
	scopeDigest, err := sessionauth.Digest(sessionScopeForRun(run))
	if err != nil {
		return result, dispatchError(ErrorInvalidState, err)
	}
	sessionRef, err := e.currentSession(ctx, run)
	if err != nil {
		return result, err
	}
	proposalNow := e.clock().UTC()
	if proposalNow.IsZero() {
		return result, dispatchError(ErrorInvalidState, errors.New("clock returned zero time"))
	}
	prepared, err := e.store.PrepareRunStart(ctx, corestore.PrepareRunStartInput{
		RunID:         run.ID,
		DispatchToken: run.DispatchToken,
		SessionRef:    sessionRef,
		Deadline:      proposalNow.Add(e.runTimeout),
	})
	if err != nil {
		return result, mapStoreError(ctx, err)
	}
	applyPreparedStart(&run, prepared)
	request := startRequest(run, prepared, scopeDigest)
	if err := request.Validate(); err != nil {
		finished, finishErr := e.finishFailure(ctx, run, corestore.RunFailureProtocolViolation)
		if finishErr != nil {
			return result, finishErr
		}
		return finished, dispatchError(ErrorProtocolViolation, err)
	}

	status, err := e.sandbox.StartRun(ctx, request)
	if err != nil {
		if callerContextError(ctx, err) {
			return result, mapSandboxError(ctx, err)
		}
		if failure, handled := terminalStartFailure(err); handled {
			// sandboxservice performs trusted target/deadline checks before its
			// idempotent durable lookup. After an earlier Start response was lost,
			// those checks may now fail (most notably because the frozen deadline
			// expired) even though this exact Run already exists. Prove absence
			// before converting the Start error into an agentd terminal state.
			if !sandboxErrorIs(err, executionhttp.ErrorConflict) {
				snapshot, getErr := e.sandbox.GetRun(ctx, executionwire.GetRunRequest{RunID: run.ID})
				switch {
				case getErr == nil:
					return e.applySnapshot(ctx, run, snapshot)
				case !sandboxErrorIs(getErr, executionhttp.ErrorRunNotFound):
					return result, mapSandboxError(ctx, getErr)
				}
			}
			finished, finishErr := e.finishFailure(ctx, run, failure)
			if finishErr != nil {
				return result, finishErr
			}
			if sandboxErrorIs(err, executionhttp.ErrorConflict) {
				return finished, dispatchError(ErrorConflict, err)
			}
			return finished, nil
		}
		return result, mapSandboxError(ctx, err)
	}
	if err := validateStatus(run.ID, status); err != nil {
		finished, finishErr := e.finishFailure(ctx, run, corestore.RunFailureProtocolViolation)
		if finishErr != nil {
			return result, finishErr
		}
		return finished, dispatchError(ErrorProtocolViolation, err)
	}
	result.SandboxState = status.State
	if status.State == executionwire.RunStateRunning {
		if err := e.store.MarkRunRunning(ctx, run.ID, run.DispatchToken); err != nil {
			return result, mapStoreError(ctx, err)
		}
		run.State = corestore.RunRunning
		result.CoreState = corestore.RunRunning
	}

	// Poll once after StartRun. A fast runner may already be terminal, while an
	// accepted snapshot remains safely re-offerable with the same fingerprint.
	snapshot, err := e.sandbox.GetRun(ctx, executionwire.GetRunRequest{RunID: run.ID})
	if err != nil {
		return result, mapSandboxError(ctx, err)
	}
	if snapshot.Validate() == nil && snapshot.Status.RunID == run.ID &&
		!sandboxStateProgresses(status.State, snapshot.Status.State) {
		finished, finishErr := e.finishFailure(ctx, run, corestore.RunFailureProtocolViolation)
		if finishErr != nil {
			return result, finishErr
		}
		return finished, dispatchError(
			ErrorProtocolViolation,
			errors.New("sandbox state regressed between StartRun and GetRun"),
		)
	}
	return e.applySnapshot(ctx, run, snapshot)
}

func (e *Engine) advanceRunning(ctx context.Context, run corestore.Run) (Result, error) {
	result := resultForRun(run)
	snapshot, err := e.sandbox.GetRun(ctx, executionwire.GetRunRequest{RunID: run.ID})
	if err != nil {
		if sandboxErrorIs(err, executionhttp.ErrorRunNotFound) {
			return e.finishInterrupted(ctx, run)
		}
		return result, mapSandboxError(ctx, err)
	}
	return e.applySnapshot(ctx, run, snapshot)
}

func (e *Engine) applySnapshot(ctx context.Context, run corestore.Run, snapshot executionwire.GetRunResponse) (Result, error) {
	result := resultForRun(run)
	if err := snapshot.Validate(); err != nil || snapshot.Status.RunID != run.ID {
		if err == nil {
			err = errors.New("sandbox snapshot Run ID does not match")
		}
		finished, finishErr := e.finishFailure(ctx, run, corestore.RunFailureProtocolViolation)
		if finishErr != nil {
			return result, finishErr
		}
		return finished, dispatchError(ErrorProtocolViolation, err)
	}
	result.SandboxState = snapshot.Status.State
	switch snapshot.Status.State {
	case executionwire.RunStateAccepted:
		if run.State == corestore.RunRunning {
			finished, err := e.finishInterrupted(ctx, run)
			if err != nil {
				return result, err
			}
			return finished, dispatchError(ErrorProtocolViolation, errors.New("sandbox state regressed from running to accepted"))
		}
		return result, nil
	case executionwire.RunStateRunning:
		if run.State == corestore.RunDispatching {
			if err := e.store.MarkRunRunning(ctx, run.ID, run.DispatchToken); err != nil {
				return result, mapStoreError(ctx, err)
			}
		}
		result.CoreState = corestore.RunRunning
		return result, nil
	case executionwire.RunStateCancelling:
		return result, nil
	case executionwire.RunStateCompleted, executionwire.RunStateFailed,
		executionwire.RunStateCancelled, executionwire.RunStateInterrupted:
		return e.finishTerminalSnapshot(ctx, run, snapshot)
	default:
		// Validate already rejects this path; retain a defensive closed result.
		return result, dispatchError(ErrorProtocolViolation, errors.New("unsupported sandbox state"))
	}
}

func (e *Engine) finishTerminalSnapshot(
	ctx context.Context,
	run corestore.Run,
	snapshot executionwire.GetRunResponse,
) (Result, error) {
	final := snapshot.Events[len(snapshot.Events)-1]
	finish := corestore.FinishRunInput{RunID: run.ID, DispatchToken: run.DispatchToken}
	var replyText string
	switch snapshot.Status.State {
	case executionwire.RunStateCompleted:
		finish.State = corestore.RunCompleted
		finish.OutputText = final.Result.Output.Text
		if final.Result.SessionRef != nil {
			finish.ResultSessionRef = *final.Result.SessionRef
		}
		replyText = finish.OutputText
		if strings.TrimSpace(replyText) == "" {
			replyText = textCompletedWithoutOutput
		}
	case executionwire.RunStateFailed:
		finish.State = corestore.RunFailed
		finish.FailureCode = mapFailureCode(final.Failure.Code)
		replyText = safeFailureText(finish.FailureCode)
	case executionwire.RunStateCancelled:
		finish.State = corestore.RunCancelled
		replyText = textCancelled
	case executionwire.RunStateInterrupted:
		finish.State = corestore.RunInterrupted
		finish.FailureCode = corestore.RunFailureRuntimeInterrupted
		replyText = textInterrupted
	default:
		return resultForRun(run), dispatchError(ErrorProtocolViolation, errors.New("non-terminal snapshot passed to finish"))
	}
	return e.commitFinish(ctx, run, snapshot.Status.State, finish, replyText)
}

func (e *Engine) finishFailure(ctx context.Context, run corestore.Run, code corestore.RunFailureCode) (Result, error) {
	return e.commitFinish(ctx, run, executionwire.RunStateFailed, corestore.FinishRunInput{
		RunID: run.ID, DispatchToken: run.DispatchToken,
		State: corestore.RunFailed, FailureCode: code,
	}, safeFailureText(code))
}

func (e *Engine) finishInterrupted(ctx context.Context, run corestore.Run) (Result, error) {
	return e.commitFinish(ctx, run, executionwire.RunStateInterrupted, corestore.FinishRunInput{
		RunID: run.ID, DispatchToken: run.DispatchToken,
		State: corestore.RunInterrupted, FailureCode: corestore.RunFailureRuntimeInterrupted,
	}, textInterrupted)
}

func (e *Engine) commitFinish(
	ctx context.Context,
	run corestore.Run,
	sandboxState executionwire.RunState,
	finish corestore.FinishRunInput,
	replyText string,
) (Result, error) {
	reply := &corestore.TextDeliveryInput{
		ID:   deliveryIDForRun(run.ID),
		Text: replyText,
	}
	if err := e.store.FinishRun(ctx, finish, reply); err != nil {
		result := resultForRun(run)
		result.SandboxState = sandboxState
		return result, mapStoreError(ctx, err)
	}
	return Result{
		RunID: run.ID, SandboxState: sandboxState,
		CoreState: finish.State, Finished: true,
	}, nil
}

func (e *Engine) currentSession(ctx context.Context, run corestore.Run) (*string, error) {
	key := sessionKeyFromRun(run)
	session, found, err := e.store.GetSession(ctx, key)
	if err != nil {
		return nil, mapStoreError(ctx, err)
	}
	if !found {
		return nil, nil
	}
	if session.SessionKey != key || session.Ref == "" {
		return nil, dispatchError(ErrorProtocolViolation, errors.New("store returned a mismatched scoped session"))
	}
	ref := session.Ref
	return &ref, nil
}

func applyPreparedStart(run *corestore.Run, prepared corestore.PreparedRunStart) {
	run.StartPrepared = true
	run.StartDeadline = prepared.Deadline
	run.StartSessionRef = nil
	if prepared.SessionRef != nil {
		ref := *prepared.SessionRef
		run.StartSessionRef = &ref
	}
}

func sessionKeyFromRun(run corestore.Run) corestore.SessionKey {
	return corestore.SessionKey{
		BindingFingerprint: run.BindingFingerprint,
		ConnectorID:        run.ConnectorID,
		ActorRef:           run.ActorRef,
		ConversationRef:    run.ConversationRef,
		TargetID:           run.TargetID,
		TargetRevision:     run.TargetRevision,
	}
}

func sessionScopeForRun(run corestore.Run) sessionauth.Scope {
	return sessionauth.Scope{
		BindingFingerprint: run.BindingFingerprint,
		ConnectorID:        run.ConnectorID,
		ActorRef:           run.ActorRef,
		ConversationRef:    run.ConversationRef,
		TargetID:           run.TargetID,
		TargetRevision:     run.TargetRevision,
	}
}

func startRequest(run corestore.Run, prepared corestore.PreparedRunStart, scopeDigest string) executionwire.StartRunRequest {
	var sessionRef *string
	if prepared.SessionRef != nil {
		copy := *prepared.SessionRef
		sessionRef = &copy
	}
	return executionwire.StartRunRequest{
		RunID: run.ID, TargetID: run.TargetID, ExpectedRevision: run.TargetRevision,
		SessionScopeDigest: scopeDigest, SessionRef: sessionRef,
		Input: executionwire.TextInput{
			MediaType: executionwire.MediaTypeTextPlain,
			Text:      run.InputText,
		},
		Deadline: prepared.Deadline,
	}
}

func validateStatus(runID string, status executionwire.RunStatus) error {
	if err := status.Validate(); err != nil {
		return err
	}
	if status.RunID != runID {
		return errors.New("sandbox status Run ID does not match")
	}
	return nil
}

func sandboxStateProgresses(from, to executionwire.RunState) bool {
	terminal := func(state executionwire.RunState) bool {
		switch state {
		case executionwire.RunStateCompleted, executionwire.RunStateFailed,
			executionwire.RunStateCancelled, executionwire.RunStateInterrupted:
			return true
		default:
			return false
		}
	}
	switch from {
	case executionwire.RunStateAccepted:
		return to == executionwire.RunStateAccepted || to == executionwire.RunStateRunning ||
			to == executionwire.RunStateCancelling || terminal(to)
	case executionwire.RunStateRunning:
		return to == executionwire.RunStateRunning || to == executionwire.RunStateCancelling || terminal(to)
	case executionwire.RunStateCancelling:
		return to == executionwire.RunStateCancelling || terminal(to)
	case executionwire.RunStateCompleted, executionwire.RunStateFailed,
		executionwire.RunStateCancelled, executionwire.RunStateInterrupted:
		return to == from
	default:
		return false
	}
}

func terminalStartFailure(err error) (corestore.RunFailureCode, bool) {
	switch {
	case sandboxErrorIs(err, executionhttp.ErrorTargetNotFound):
		return corestore.RunFailureTargetUnavailable, true
	case sandboxErrorIs(err, executionhttp.ErrorRevisionMismatch):
		return corestore.RunFailureRevisionMismatch, true
	case sandboxErrorIs(err, executionhttp.ErrorInvalidSession):
		return corestore.RunFailureInvalidSession, true
	case sandboxErrorIs(err, executionhttp.ErrorInvalidState):
		return corestore.RunFailureDeadlineExceeded, true
	case sandboxErrorIs(err, executionhttp.ErrorConflict):
		return corestore.RunFailureProtocolViolation, true
	default:
		return "", false
	}
}

func mapFailureCode(code executionwire.FailureCode) corestore.RunFailureCode {
	switch code {
	case executionwire.FailureTargetUnavailable:
		return corestore.RunFailureTargetUnavailable
	case executionwire.FailureRevisionMismatch:
		return corestore.RunFailureRevisionMismatch
	case executionwire.FailureInvalidSession:
		return corestore.RunFailureInvalidSession
	case executionwire.FailurePolicyDenied:
		return corestore.RunFailurePolicyDenied
	case executionwire.FailureDeadlineExceeded:
		return corestore.RunFailureDeadlineExceeded
	case executionwire.FailureOutputLimit:
		return corestore.RunFailureOutputLimit
	case executionwire.FailureRunnerFailed:
		return corestore.RunFailureRunnerFailed
	case executionwire.FailureProtocolViolation:
		return corestore.RunFailureProtocolViolation
	case executionwire.FailureRuntimeInterrupted:
		return corestore.RunFailureRuntimeInterrupted
	case executionwire.FailureInternal:
		return corestore.RunFailureInternal
	default:
		return corestore.RunFailureProtocolViolation
	}
}

func safeFailureText(code corestore.RunFailureCode) string {
	switch code {
	case corestore.RunFailureTargetUnavailable:
		return "Run failed: target unavailable."
	case corestore.RunFailureRevisionMismatch:
		return "Run failed: target revision mismatch."
	case corestore.RunFailureInvalidSession:
		return "Run failed: saved session is no longer valid."
	case corestore.RunFailurePolicyDenied:
		return "Run failed: execution was denied by policy."
	case corestore.RunFailureDeadlineExceeded:
		return "Run failed: deadline exceeded."
	case corestore.RunFailureOutputLimit:
		return "Run failed: output limit exceeded."
	case corestore.RunFailureRunnerFailed:
		return "Run failed in the runner."
	case corestore.RunFailureProtocolViolation:
		return "Run failed: protocol violation."
	default:
		return "Run failed due to an internal error."
	}
}

func deliveryIDForRun(runID string) string {
	digest := sha256.Sum256([]byte(deliveryIDDomain + "\x00" + runID))
	return "delivery_" + hex.EncodeToString(digest[:])
}

func resultForRun(run corestore.Run) Result {
	return Result{RunID: run.ID, CoreState: run.State}
}

func validateStoreRun(run corestore.Run, expected corestore.RunState) error {
	if run.ID == "" {
		return errors.New("store returned a Run without an ID")
	}
	if run.State != expected {
		return errors.New("store returned a Run in an unexpected state")
	}
	if run.DispatchToken == "" {
		return errors.New("store returned a Run without its dispatch capability")
	}
	if expected == corestore.RunRunning && !run.StartPrepared {
		return errors.New("store returned an unprepared running Run")
	}
	return nil
}

func sandboxStateFromCore(state corestore.RunState) executionwire.RunState {
	switch state {
	case corestore.RunCompleted:
		return executionwire.RunStateCompleted
	case corestore.RunFailed:
		return executionwire.RunStateFailed
	case corestore.RunCancelled:
		return executionwire.RunStateCancelled
	case corestore.RunInterrupted:
		return executionwire.RunStateInterrupted
	default:
		return ""
	}
}

func mapStoreError(ctx context.Context, err error) error {
	switch {
	case callerContextError(ctx, err):
		return dispatchError(ErrorContextDone, err)
	case errors.Is(err, corestore.ErrDispatchLost):
		return dispatchError(ErrorDispatchLost, err)
	case errors.Is(err, corestore.ErrConflict):
		return dispatchError(ErrorConflict, err)
	case errors.Is(err, corestore.ErrInvalid), errors.Is(err, corestore.ErrNotFound),
		errors.Is(err, corestore.ErrStartUnprepared), errors.Is(err, corestore.ErrInvalidTransition):
		return dispatchError(ErrorInvalidState, err)
	default:
		return dispatchError(ErrorStoreUnavailable, err)
	}
}

func mapSandboxError(ctx context.Context, err error) error {
	if callerContextError(ctx, err) {
		return dispatchError(ErrorContextDone, err)
	}
	if sandboxErrorIs(err, executionhttp.ErrorConflict) {
		return dispatchError(ErrorConflict, err)
	}
	if sandboxErrorIs(err, executionhttp.ErrorInvalidState) {
		return dispatchError(ErrorInvalidState, err)
	}
	return dispatchError(ErrorSandboxUnavailable, err)
}

func callerContextError(ctx context.Context, err error) bool {
	if ctx == nil || err == nil {
		return false
	}
	contextErr := ctx.Err()
	return contextErr != nil && errors.Is(err, contextErr)
}

func sandboxErrorIs(err error, code executionhttp.ErrorCode) bool {
	var serviceError *executionhttp.ServiceError
	if errors.As(err, &serviceError) && serviceError != nil {
		return serviceError.Code == code
	}
	var remoteError *executionhttp.RemoteError
	return errors.As(err, &remoteError) && remoteError != nil && remoteError.Code == string(code)
}

func dispatchError(code ErrorCode, cause error) error {
	switch code {
	case ErrorInvalidState, ErrorDispatchLost, ErrorStoreUnavailable,
		ErrorSandboxUnavailable, ErrorConflict, ErrorProtocolViolation, ErrorContextDone:
	default:
		code = ErrorInvalidState
	}
	return &Error{Code: code, Cause: cause}
}

func (e *Engine) ready(ctx context.Context) error {
	if e == nil || nilInterface(e.store) || nilInterface(e.sandbox) || e.clock == nil {
		return dispatchError(ErrorInvalidState, errors.New("agentdispatch: engine is not initialized"))
	}
	if ctx == nil {
		return dispatchError(ErrorInvalidState, errors.New("agentdispatch: nil context"))
	}
	if err := ctx.Err(); err != nil {
		return dispatchError(ErrorContextDone, err)
	}
	return nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var (
	_ Store   = (corestore.Operations)(nil)
	_ Sandbox = (*executionhttp.Client)(nil)
)
