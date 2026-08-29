package agentdispatch

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
)

var baseTime = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

type tokenSequence struct {
	mu   sync.Mutex
	next int
}

func (s *tokenSequence) Next() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	return fmt.Sprintf("lease_test_%d", s.next), nil
}

type fakeSandbox struct {
	mu      sync.Mutex
	startFn func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error)
	getFn   func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error)
	starts  []executionwire.StartRunRequest
	gets    []executionwire.GetRunRequest
}

func (s *fakeSandbox) StartRun(ctx context.Context, request executionwire.StartRunRequest) (executionwire.RunStatus, error) {
	s.mu.Lock()
	s.starts = append(s.starts, cloneStart(request))
	fn := s.startFn
	s.mu.Unlock()
	if fn == nil {
		return acceptedStatus(request.RunID), nil
	}
	return fn(ctx, request)
}

func (s *fakeSandbox) GetRun(ctx context.Context, request executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
	s.mu.Lock()
	s.gets = append(s.gets, request)
	fn := s.getFn
	s.mu.Unlock()
	if fn == nil {
		return acceptedSnapshot(request.RunID), nil
	}
	return fn(ctx, request)
}

func (s *fakeSandbox) Starts() []executionwire.StartRunRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]executionwire.StartRunRequest, len(s.starts))
	for index := range s.starts {
		result[index] = cloneStart(s.starts[index])
	}
	return result
}

func (s *fakeSandbox) StartCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.starts)
}

func cloneStart(request executionwire.StartRunRequest) executionwire.StartRunRequest {
	copy := request
	if request.SessionRef != nil {
		ref := *request.SessionRef
		copy.SessionRef = &ref
	}
	return copy
}

func acceptedStatus(runID string) executionwire.RunStatus {
	return executionwire.RunStatus{RunID: runID, State: executionwire.RunStateAccepted}
}

func runningStatus(runID string) executionwire.RunStatus {
	return executionwire.RunStatus{RunID: runID, State: executionwire.RunStateRunning, LastEventSeq: 1}
}

func acceptedSnapshot(runID string) executionwire.GetRunResponse {
	return executionwire.GetRunResponse{Status: acceptedStatus(runID), Events: []executionwire.RunEvent{}}
}

func runningSnapshot(runID string) executionwire.GetRunResponse {
	return executionwire.GetRunResponse{
		Status: runningStatus(runID),
		Events: []executionwire.RunEvent{
			{RunID: runID, Seq: 1, Type: executionwire.RunEventStarted},
		},
	}
}

func completedSnapshot(runID, output string, sessionRef *string) executionwire.GetRunResponse {
	return executionwire.GetRunResponse{
		Status: executionwire.RunStatus{
			RunID: runID, State: executionwire.RunStateCompleted, LastEventSeq: 2,
		},
		Events: []executionwire.RunEvent{
			{RunID: runID, Seq: 1, Type: executionwire.RunEventStarted},
			{
				RunID: runID, Seq: 2, Type: executionwire.RunEventCompleted,
				Result: &executionwire.RunResult{
					Output:     executionwire.TextOutput{MediaType: executionwire.MediaTypeTextPlain, Text: output},
					SessionRef: sessionRef,
				},
			},
		},
	}
}

func failedSnapshot(runID string, code executionwire.FailureCode, message string) executionwire.GetRunResponse {
	return executionwire.GetRunResponse{
		Status: executionwire.RunStatus{RunID: runID, State: executionwire.RunStateFailed, LastEventSeq: 1},
		Events: []executionwire.RunEvent{
			{
				RunID: runID, Seq: 1, Type: executionwire.RunEventFailed,
				Failure: &executionwire.RunFailure{Code: code, Message: message},
			},
		},
	}
}

func interruptedSnapshot(runID, privateMessage string) executionwire.GetRunResponse {
	return executionwire.GetRunResponse{
		Status: executionwire.RunStatus{RunID: runID, State: executionwire.RunStateInterrupted, LastEventSeq: 1},
		Events: []executionwire.RunEvent{
			{
				RunID: runID, Seq: 1, Type: executionwire.RunEventInterrupted,
				Failure: &executionwire.RunFailure{
					Code: executionwire.FailureRuntimeInterrupted, Message: privateMessage,
				},
			},
		},
	}
}

func cancelledSnapshot(runID string) executionwire.GetRunResponse {
	return executionwire.GetRunResponse{
		Status: executionwire.RunStatus{RunID: runID, State: executionwire.RunStateCancelled, LastEventSeq: 1},
		Events: []executionwire.RunEvent{
			{RunID: runID, Seq: 1, Type: executionwire.RunEventCancelled},
		},
	}
}

type testCoreStore struct {
	*corestore.Store
	path string
}

// PutSession is a test-only direct-SQL fixture. Production corestore exposes no
// arbitrary session mint operation; FinishRun is its sole creation path.
func (s *testCoreStore) PutSession(ctx context.Context, session corestore.Session) error {
	db, err := sql.Open("sqlite", s.path+"?_txlock=immediate&_pragma=foreign_keys(1)")
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, `INSERT INTO sessions(
        binding_fingerprint, connector_id, actor_ref, conversation_ref,
        target_id, target_revision, session_ref, updated_at_ms
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(binding_fingerprint, connector_id, actor_ref, conversation_ref,
                target_id, target_revision)
    DO UPDATE SET session_ref = excluded.session_ref, updated_at_ms = excluded.updated_at_ms`,
		session.BindingFingerprint, session.ConnectorID, session.ActorRef,
		session.ConversationRef, session.TargetID, session.TargetRevision,
		session.Ref, baseTime.UnixMilli())
	return err
}

func openCoreStore(t *testing.T, clock *fakeClock, tokens *tokenSequence) (*testCoreStore, string, corestore.Options) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agentd.sqlite3")
	options := corestore.Options{
		Clock: clock.Now, NewLeaseToken: tokens.Next,
		Admission: corestore.AdmissionOptions{
			AcceptWindow: time.Hour, ReceiptWindow: 24 * time.Hour, FutureSkew: 5 * time.Minute,
			MaxReceiptsPerConnector: 1_000, MaxQueuedRunsPerConnector: 1_000,
			MaxNonTerminalRunsPerConnector: 1_000, MaxPendingDeliveriesPerConnector: 1_000,
			MaxRetainedInputBytesPerConnector: 32 << 20, MaxDatabasePages: 100_000,
		},
	}
	store, err := corestore.Open(context.Background(), path, options)
	if err != nil {
		t.Fatalf("corestore.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return &testCoreStore{Store: store, path: path}, path, options
}

func seedRunningRun(t *testing.T, path, runID string, now time.Time) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open fixture database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("close fixture database: %v", err)
		}
	}()
	result, err := db.ExecContext(context.Background(), `
UPDATE runs
SET state = 'running', dispatch_token = ?, dispatch_attempt_count = 1,
    start_prepared = 1, start_deadline_ms = ?, updated_at_ms = ?
WHERE id = ? AND state = 'queued'`,
		"fixture_token_"+runID, now.Add(time.Hour).UnixMilli(), now.UnixMilli(), runID)
	if err != nil {
		t.Fatalf("seed running Run %s: %v", runID, err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		t.Fatalf("seed running Run %s affected %d rows, err=%v", runID, affected, err)
	}
}

type ingestStore interface {
	IngestTextRun(context.Context, corestore.IngestTextRunInput, corestore.TextRunAuthorizer, corestore.RunIDSource) (corestore.IngestResult, error)
}

func ingestRun(t *testing.T, store ingestStore, runID, eventID, revision string) corestore.Run {
	t.Helper()
	var payload corestore.PayloadHash
	copy(payload[:], []byte(eventID))
	result, err := store.IngestTextRun(context.Background(), corestore.IngestTextRunInput{
		ConnectorID:      "discord-main",
		EventID:          eventID,
		PayloadHash:      payload,
		ActorRef:         "discord:user:" + eventID,
		ConversationRef:  "discord:channel:200",
		MessageRef:       "discord:message:" + eventID,
		OccurredAtUnixMS: baseTime.UnixMilli(),
		Text:             "inspect the workspace",
	}, func() (corestore.TextRunAuthorization, error) {
		return corestore.TextRunAuthorization{
			TargetID: "codex-project", TargetRevision: revision,
			BindingFingerprint: strings.Repeat("a", corestore.SHA256HexBytes),
			PolicyRevision:     strings.Repeat("b", corestore.SHA256HexBytes),
		}, nil
	}, func() (string, error) { return runID, nil })
	if err != nil {
		t.Fatalf("IngestTextRun(%s): %v", runID, err)
	}
	return result.Run
}

func newEngine(t *testing.T, store Store, sandbox Sandbox, clock *fakeClock) *Engine {
	t.Helper()
	engine, err := New(store, sandbox, 10*time.Second, time.Hour, WithClock(clock.Now))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return engine
}

func requireDispatchCode(t *testing.T, err error, want ErrorCode) *Error {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %q error, got nil", want)
	}
	var dispatchErr *Error
	if !errors.As(err, &dispatchErr) || dispatchErr == nil {
		t.Fatalf("error = %T %v, want *agentdispatch.Error", err, err)
	}
	if dispatchErr.Code != want {
		t.Fatalf("error code = %q, want %q", dispatchErr.Code, want)
	}
	if got, expected := dispatchErr.Error(), "agent dispatch error: "+string(want); got != expected {
		t.Fatalf("closed error = %q, want %q", got, expected)
	}
	return dispatchErr
}

type deliveryClaimStore interface {
	ClaimTextDeliveries(context.Context, string, int, time.Duration) ([]corestore.TextDelivery, error)
}

func claimOneDelivery(t *testing.T, store deliveryClaimStore) corestore.TextDelivery {
	t.Helper()
	deliveries, err := store.ClaimTextDeliveries(context.Background(), "discord-main", 10, 30*time.Second)
	if err != nil {
		t.Fatalf("ClaimTextDeliveries: %v", err)
	}
	if len(deliveries) != 1 {
		t.Fatalf("deliveries = %#v, want exactly one", deliveries)
	}
	return deliveries[0]
}

func TestCrashBoundaryAReclaimsBeforeStart(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	tokens := &tokenSequence{}
	store, _, _ := openCoreStore(t, clock, tokens)
	ingestRun(t, store, "run_a_boundary", "event_a_boundary", "revision-1")

	// Simulate agentd dying after ClaimQueuedRun but before Prepare/Start.
	first, claimed, err := store.ClaimQueuedRun(context.Background(), 10*time.Second)
	if err != nil || !claimed {
		t.Fatalf("initial claim = %#v, %v, %v", first, claimed, err)
	}
	clock.Advance(11 * time.Second)
	sandbox := &fakeSandbox{}
	engine := newEngine(t, store, sandbox, clock)
	result, claimed, err := engine.DispatchOne(context.Background())
	if err != nil || !claimed {
		t.Fatalf("reclaimed DispatchOne = %#v, %v, %v", result, claimed, err)
	}
	if result.RunID != first.ID || result.CoreState != corestore.RunDispatching || result.SandboxState != executionwire.RunStateAccepted {
		t.Fatalf("reclaimed result = %#v", result)
	}
	if sandbox.StartCount() != 1 {
		t.Fatalf("StartRun calls = %d, want 1", sandbox.StartCount())
	}
	stored, err := store.GetRun(context.Background(), first.ID)
	if err != nil || !stored.StartPrepared || stored.DispatchAttemptCount != 2 {
		t.Fatalf("stored reclaimed Run = %#v, err = %v", stored, err)
	}
}

func TestCrashBoundaryBResponseLossAndAcceptedRepostUseOriginalFingerprint(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	tokens := &tokenSequence{}
	store, _, _ := openCoreStore(t, clock, tokens)
	run := ingestRun(t, store, "run_b_boundary", "event_b_boundary", "revision-1")
	key := sessionKeyForRun(run)
	if err := store.PutSession(context.Background(), corestore.Session{SessionKey: key, Ref: "session_original"}); err != nil {
		t.Fatal(err)
	}

	privateTransportError := errors.New("write response lost after sandbox commit: private socket detail")
	sandbox := &fakeSandbox{}
	sandbox.startFn = func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
		if sandbox.StartCount() == 1 {
			return executionwire.RunStatus{}, privateTransportError
		}
		return acceptedStatus(run.ID), nil
	}
	sandbox.getFn = func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
		return acceptedSnapshot(run.ID), nil
	}
	engine := newEngine(t, store, sandbox, clock)

	firstResult, claimed, err := engine.DispatchOne(context.Background())
	if !claimed || firstResult.RunID != run.ID {
		t.Fatalf("first dispatch = %#v, claimed=%v", firstResult, claimed)
	}
	closed := requireDispatchCode(t, err, ErrorSandboxUnavailable)
	if strings.Contains(closed.Error(), "socket") {
		t.Fatal("closed error leaked transport detail")
	}

	// Session authority can advance after the first preparation. Reclaim must
	// still use the original returned session and deadline.
	if err := store.PutSession(context.Background(), corestore.Session{SessionKey: key, Ref: "session_newer"}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(11 * time.Second)
	second, claimed, err := engine.DispatchOne(context.Background())
	if err != nil || !claimed || second.SandboxState != executionwire.RunStateAccepted {
		t.Fatalf("second dispatch = %#v, claimed=%v, err=%v", second, claimed, err)
	}
	// The daemon may also re-offer accepted work immediately through Advance,
	// without waiting for another lease cycle after a sandbox process restart.
	third, err := engine.Advance(context.Background(), run.ID)
	if err != nil || third.SandboxState != executionwire.RunStateAccepted {
		t.Fatalf("accepted repost = %#v, err=%v", third, err)
	}

	starts := sandbox.Starts()
	if len(starts) != 3 {
		t.Fatalf("StartRun calls = %d, want 3", len(starts))
	}
	wantFingerprint, err := executionwire.StartRunFingerprint(starts[0])
	if err != nil {
		t.Fatal(err)
	}
	for index, request := range starts {
		fingerprint, fingerprintErr := executionwire.StartRunFingerprint(request)
		if fingerprintErr != nil || fingerprint != wantFingerprint {
			t.Fatalf("StartRun[%d] fingerprint = %q, err=%v, want %q", index, fingerprint, fingerprintErr, wantFingerprint)
		}
		if request.SessionRef == nil || *request.SessionRef != "session_original" {
			t.Fatalf("StartRun[%d] session = %#v, want immutable original", index, request.SessionRef)
		}
	}
}

func TestRestartGatesNewerQueueBehindLiveDispatchCapability(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	store, _, _ := openCoreStore(t, clock, &tokenSequence{})
	first := ingestRun(t, store, "run_restart_gate_a", "event_restart_gate_a", "revision-1")
	second := ingestRun(t, store, "run_restart_gate_b", "event_restart_gate_b", "revision-1")
	sandbox := &fakeSandbox{}
	beforeCrash := newEngine(t, store, sandbox, clock)
	result, claimed, err := beforeCrash.DispatchOne(context.Background())
	if err != nil || !claimed || result.RunID != first.ID || result.SandboxState != executionwire.RunStateAccepted {
		t.Fatalf("initial accepted dispatch = %#v, claimed=%v, err=%v", result, claimed, err)
	}
	activeBefore, err := store.GetRun(context.Background(), first.ID)
	if err != nil {
		t.Fatal(err)
	}

	// A new Engine models agentd restart with no in-memory activeDispatch ID.
	// The live durable capability gates the newer queued Run without being
	// exposed or stolen.
	afterCrash := newEngine(t, store, sandbox, clock)
	for attempt := 0; attempt < 3; attempt++ {
		if result, claimed, err := afterCrash.DispatchOne(context.Background()); err != nil || claimed || result.RunID != "" {
			t.Fatalf("gated post-restart claim %d = %#v, claimed=%v, err=%v", attempt, result, claimed, err)
		}
	}
	activeAfter, err := store.GetRun(context.Background(), first.ID)
	if err != nil || activeAfter.DispatchToken != activeBefore.DispatchToken ||
		activeAfter.DispatchAttemptCount != activeBefore.DispatchAttemptCount {
		t.Fatalf("gating mutated live dispatch = %#v, err=%v", activeAfter, err)
	}
	queued, err := store.GetRun(context.Background(), second.ID)
	if err != nil || queued.State != corestore.RunQueued || queued.DispatchAttemptCount != 0 {
		t.Fatalf("newer Run bypassed live dispatch = %#v, err=%v", queued, err)
	}

	clock.Advance(11 * time.Second)
	reclaimed, claimed, err := afterCrash.DispatchOne(context.Background())
	if err != nil || !claimed || reclaimed.RunID != first.ID {
		t.Fatalf("expired original reclaim = %#v, claimed=%v, err=%v", reclaimed, claimed, err)
	}
	starts := sandbox.Starts()
	if len(starts) != 2 || starts[0].RunID != first.ID || starts[1].RunID != first.ID {
		t.Fatalf("restart StartRun order = %#v", starts)
	}
}

func TestExpiredReofferRecoversExistingSandboxRunBeforeDeadlineFailure(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	store, _, _ := openCoreStore(t, clock, &tokenSequence{})
	run := ingestRun(t, store, "run_expired_reoffer", "event_expired_reoffer", "revision-1")
	sandbox := &fakeSandbox{}
	responseLost := errors.New("StartRun response lost after durable sandbox acceptance")
	sandbox.startFn = func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
		if sandbox.StartCount() == 1 {
			return executionwire.RunStatus{}, responseLost
		}
		// sandboxservice currently checks the frozen deadline before its
		// idempotent store lookup, so the re-offer can receive invalid_state.
		return executionwire.RunStatus{}, &executionhttp.RemoteError{
			StatusCode: 409, Code: string(executionhttp.ErrorInvalidState),
		}
	}
	sandbox.getFn = func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
		return completedSnapshot(run.ID, "real sandbox result", nil), nil
	}
	engine, err := New(store, sandbox, 10*time.Second, 5*time.Second, WithClock(clock.Now))
	if err != nil {
		t.Fatal(err)
	}

	first, claimed, err := engine.DispatchOne(context.Background())
	if !claimed || first.RunID != run.ID {
		t.Fatalf("first lost response = %#v, claimed=%v", first, claimed)
	}
	requireDispatchCode(t, err, ErrorSandboxUnavailable)
	clock.Advance(11 * time.Second)
	second, claimed, err := engine.DispatchOne(context.Background())
	if err != nil || !claimed || !second.Finished || second.CoreState != corestore.RunCompleted {
		t.Fatalf("expired re-offer recovery = %#v, claimed=%v, err=%v", second, claimed, err)
	}
	stored, err := store.GetRun(context.Background(), run.ID)
	if err != nil || stored.State != corestore.RunCompleted || stored.OutputText == nil || *stored.OutputText != "real sandbox result" {
		t.Fatalf("recovered durable sandbox result = %#v, err=%v", stored, err)
	}
	if delivery := claimOneDelivery(t, store); delivery.Text != "real sandbox result" {
		t.Fatalf("recovered delivery = %#v", delivery)
	}
	starts := sandbox.Starts()
	if len(starts) != 2 {
		t.Fatalf("StartRun requests = %#v", starts)
	}
	firstFingerprint, _ := executionwire.StartRunFingerprint(starts[0])
	secondFingerprint, _ := executionwire.StartRunFingerprint(starts[1])
	if firstFingerprint != secondFingerprint {
		t.Fatalf("expired re-offer changed fingerprint: %q != %q", firstFingerprint, secondFingerprint)
	}
}

func TestRunningIsMarkedOnlyAfterSandboxReportsRunning(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	store, _, _ := openCoreStore(t, clock, &tokenSequence{})
	run := ingestRun(t, store, "run_running", "event_running", "revision-1")
	sandbox := &fakeSandbox{
		startFn: func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
			return acceptedStatus(run.ID), nil
		},
		getFn: func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
			return runningSnapshot(run.ID), nil
		},
	}
	engine := newEngine(t, store, sandbox, clock)
	result, claimed, err := engine.DispatchOne(context.Background())
	if err != nil || !claimed {
		t.Fatalf("DispatchOne = %#v, %v, %v", result, claimed, err)
	}
	if result.CoreState != corestore.RunRunning || result.SandboxState != executionwire.RunStateRunning {
		t.Fatalf("running result = %#v", result)
	}
	stored, err := store.GetRun(context.Background(), run.ID)
	if err != nil || stored.State != corestore.RunRunning || !stored.DispatchExpiresAt.IsZero() {
		t.Fatalf("stored running Run = %#v, err=%v", stored, err)
	}
}

func TestStaleDispatchCannotCrossRunningBoundary(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	store, _, _ := openCoreStore(t, clock, &tokenSequence{})
	run := ingestRun(t, store, "run_stale", "event_stale", "revision-1")
	sandbox := &fakeSandbox{}
	sandbox.startFn = func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
		if sandbox.StartCount() == 1 {
			clock.Advance(11 * time.Second)
		}
		return runningStatus(run.ID), nil
	}
	sandbox.getFn = func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
		return runningSnapshot(run.ID), nil
	}
	engine := newEngine(t, store, sandbox, clock)

	first, claimed, err := engine.DispatchOne(context.Background())
	if !claimed || first.RunID != run.ID {
		t.Fatalf("first stale dispatch = %#v, claimed=%v", first, claimed)
	}
	requireDispatchCode(t, err, ErrorDispatchLost)
	stored, err := store.GetRun(context.Background(), run.ID)
	if err != nil || stored.State != corestore.RunDispatching {
		t.Fatalf("stale worker changed Run = %#v, err=%v", stored, err)
	}

	second, claimed, err := engine.DispatchOne(context.Background())
	if err != nil || !claimed || second.CoreState != corestore.RunRunning {
		t.Fatalf("reclaimed running dispatch = %#v, claimed=%v, err=%v", second, claimed, err)
	}
	starts := sandbox.Starts()
	if len(starts) != 2 {
		t.Fatalf("StartRun count = %d", len(starts))
	}
	firstFingerprint, _ := executionwire.StartRunFingerprint(starts[0])
	secondFingerprint, _ := executionwire.StartRunFingerprint(starts[1])
	if firstFingerprint != secondFingerprint {
		t.Fatalf("reclaim fingerprint changed: %q != %q", firstFingerprint, secondFingerprint)
	}
}

func TestTerminalBeforeRunningFinishesAtomically(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	store, _, _ := openCoreStore(t, clock, &tokenSequence{})
	run := ingestRun(t, store, "run_terminal_early", "event_terminal_early", "revision-1")
	resultSession := "session_result"
	snapshot := completedSnapshot(run.ID, "inspection complete", &resultSession)
	sandbox := &fakeSandbox{
		startFn: func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
			return snapshot.Status, nil
		},
		getFn: func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
			return snapshot, nil
		},
	}
	engine := newEngine(t, store, sandbox, clock)
	result, claimed, err := engine.DispatchOne(context.Background())
	if err != nil || !claimed || !result.Finished || result.CoreState != corestore.RunCompleted {
		t.Fatalf("terminal-before-running = %#v, claimed=%v, err=%v", result, claimed, err)
	}
	stored, err := store.GetRun(context.Background(), run.ID)
	if err != nil || stored.State != corestore.RunCompleted || stored.OutputText == nil || *stored.OutputText != "inspection complete" {
		t.Fatalf("completed Run = %#v, err=%v", stored, err)
	}
	key := sessionKeyForRun(run)
	session, found, err := store.GetSession(context.Background(), key)
	if err != nil || !found || session.Ref != resultSession {
		t.Fatalf("result session = %#v, found=%v, err=%v", session, found, err)
	}
	delivery := claimOneDelivery(t, store)
	if delivery.ID != deliveryIDForRun(run.ID) || delivery.Text != "inspection complete" || delivery.ReplyToRef != run.MessageRef {
		t.Fatalf("terminal delivery = %#v", delivery)
	}
}

func TestStartAndGetStateRegressionFailsClosedAsProtocolViolation(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	store, _, _ := openCoreStore(t, clock, &tokenSequence{})
	run := ingestRun(t, store, "run_state_regression", "event_state_regression", "revision-1")
	terminal := completedSnapshot(run.ID, "unconfirmed terminal output", nil)
	sandbox := &fakeSandbox{
		startFn: func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
			return terminal.Status, nil
		},
		getFn: func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
			return acceptedSnapshot(run.ID), nil
		},
	}
	engine := newEngine(t, store, sandbox, clock)
	result, claimed, err := engine.DispatchOne(context.Background())
	if !claimed || !result.Finished || result.CoreState != corestore.RunFailed {
		t.Fatalf("regressed state result = %#v, claimed=%v", result, claimed)
	}
	requireDispatchCode(t, err, ErrorProtocolViolation)
	stored, err := store.GetRun(context.Background(), run.ID)
	if err != nil || stored.FailureCode == nil || *stored.FailureCode != corestore.RunFailureProtocolViolation {
		t.Fatalf("regressed state stored Run = %#v, err=%v", stored, err)
	}
}

func TestSandboxStateProgressionIsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		from, to executionwire.RunState
		allowed  bool
	}{
		{executionwire.RunStateAccepted, executionwire.RunStateCompleted, true},
		{executionwire.RunStateRunning, executionwire.RunStateCancelling, true},
		{executionwire.RunStateCancelling, executionwire.RunStateInterrupted, true},
		{executionwire.RunStateRunning, executionwire.RunStateAccepted, false},
		{executionwire.RunStateCancelling, executionwire.RunStateRunning, false},
		{executionwire.RunStateCompleted, executionwire.RunStateAccepted, false},
		{executionwire.RunStateFailed, executionwire.RunStateCompleted, false},
	}
	for _, test := range tests {
		if got := sandboxStateProgresses(test.from, test.to); got != test.allowed {
			t.Errorf("sandboxStateProgresses(%q, %q) = %v, want %v", test.from, test.to, got, test.allowed)
		}
	}
}

type finishResponseLossStore struct {
	Store
	mu   sync.Mutex
	lost bool
}

func (s *finishResponseLossStore) FinishRun(ctx context.Context, input corestore.FinishRunInput, reply *corestore.TextDeliveryInput) error {
	err := s.Store.FinishRun(ctx, input, reply)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lost {
		s.lost = true
		return errors.New("commit succeeded but response was lost: private database detail")
	}
	return nil
}

func TestCrashBoundariesCAfterRunningAndDAfterTerminalReconcileOnRestart(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{now: baseTime}
	tokens := &tokenSequence{}
	store, path, options := openCoreStore(t, clock, tokens)
	run := ingestRun(t, store, "run_restart", "event_restart", "revision-1")
	sandbox := &fakeSandbox{
		startFn: func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
			return runningStatus(run.ID), nil
		},
		getFn: func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
			return runningSnapshot(run.ID), nil
		},
	}
	engine := newEngine(t, store, sandbox, clock)
	result, claimed, err := engine.DispatchOne(ctx)
	if err != nil || !claimed || result.CoreState != corestore.RunRunning {
		t.Fatalf("initial running dispatch = %#v, %v, %v", result, claimed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := corestore.Open(ctx, path, options)
	if err != nil {
		t.Fatalf("reopen corestore: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	sandbox.getFn = func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
		return completedSnapshot(run.ID, "durable result", nil), nil
	}
	lossy := &finishResponseLossStore{Store: reopened}
	restarted := newEngine(t, lossy, sandbox, clock)
	items, err := restarted.Reconcile(ctx, corestore.MaxReconcileRuns)
	if err != nil {
		t.Fatalf("Reconcile list error: %v", err)
	}
	if len(items) != 1 || items[0].Result.RunID != run.ID {
		t.Fatalf("reconcile items = %#v", items)
	}
	requireDispatchCode(t, items[0].Err, ErrorStoreUnavailable)

	// The error simulated response loss after the transaction committed. A
	// restart sees no running Run, while the deterministic outbox row exists.
	stored, err := reopened.GetRun(ctx, run.ID)
	if err != nil || stored.State != corestore.RunCompleted {
		t.Fatalf("Run after lost Finish response = %#v, err=%v", stored, err)
	}
	items, err = restarted.Reconcile(ctx, corestore.MaxReconcileRuns)
	if err != nil || len(items) != 0 {
		t.Fatalf("second Reconcile = %#v, err=%v", items, err)
	}
	delivery := claimOneDelivery(t, reopened)
	if delivery.ID != deliveryIDForRun(run.ID) || delivery.Text != "durable result" {
		t.Fatalf("durable deterministic delivery = %#v", delivery)
	}
	if sandbox.StartCount() != 1 {
		t.Fatalf("restart started running Run again %d times", sandbox.StartCount())
	}
}

func TestScopedSessionResumeAndNewSessionProposal(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	store, _, _ := openCoreStore(t, clock, &tokenSequence{})
	first := ingestRun(t, store, "run_session_a", "event_session_a", "revision-1")
	second := ingestRun(t, store, "run_session_b", "event_session_b", "revision-2")
	key := sessionKeyForRun(first)
	if err := store.PutSession(context.Background(), corestore.Session{SessionKey: key, Ref: "session_exact"}); err != nil {
		t.Fatal(err)
	}
	sandbox := &fakeSandbox{getFn: func(_ context.Context, request executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
		return completedSnapshot(request.RunID, "done", nil), nil
	}}
	engine := newEngine(t, store, sandbox, clock)
	for range 2 {
		if _, claimed, err := engine.DispatchOne(context.Background()); err != nil || !claimed {
			t.Fatalf("DispatchOne session fixture: claimed=%v err=%v", claimed, err)
		}
	}
	starts := sandbox.Starts()
	if len(starts) != 2 || starts[0].RunID != first.ID || starts[1].RunID != second.ID {
		t.Fatalf("session StartRun order = %#v", starts)
	}
	if starts[0].SessionRef == nil || *starts[0].SessionRef != "session_exact" {
		t.Fatalf("exact scoped resume = %#v", starts[0].SessionRef)
	}
	wantDigest, err := sessionauth.Digest(sessionScopeForRun(first))
	if err != nil || starts[0].SessionScopeDigest != wantDigest {
		t.Fatalf("first scope digest = %q, err=%v, want %q", starts[0].SessionScopeDigest, err, wantDigest)
	}
	if starts[1].SessionRef != nil {
		t.Fatalf("different revision reused session: %#v", starts[1].SessionRef)
	}
}

func sessionKeyForRun(run corestore.Run) corestore.SessionKey {
	return corestore.SessionKey{
		BindingFingerprint: run.BindingFingerprint,
		ConnectorID:        run.ConnectorID, ActorRef: run.ActorRef,
		ConversationRef: run.ConversationRef, TargetID: run.TargetID,
		TargetRevision: run.TargetRevision,
	}
}

func invalidSessionRemoteError() error {
	return &executionhttp.RemoteError{StatusCode: 409, Code: string(executionhttp.ErrorInvalidSession)}
}

func sandboxRunNotFound(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
	return executionwire.GetRunResponse{}, &executionhttp.RemoteError{
		StatusCode: 404, Code: string(executionhttp.ErrorRunNotFound),
	}
}

func TestInvalidSessionDoesNotAutomaticallyClearPreparedSession(t *testing.T) {
	tests := []struct {
		name          string
		terminalEvent bool
	}{
		{name: "StartRun closed error"},
		{name: "terminal failure event", terminalEvent: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &fakeClock{now: baseTime}
			store, _, _ := openCoreStore(t, clock, &tokenSequence{})
			run := ingestRun(t, store, "run_invalid_session_"+fmt.Sprint(test.terminalEvent), "event_invalid_session_"+fmt.Sprint(test.terminalEvent), "revision-1")
			key := sessionKeyForRun(run)
			if err := store.PutSession(context.Background(), corestore.Session{SessionKey: key, Ref: "session_poisoned"}); err != nil {
				t.Fatal(err)
			}
			otherKey := key
			otherKey.TargetRevision = "revision-2"
			if err := store.PutSession(context.Background(), corestore.Session{SessionKey: otherKey, Ref: "session_other_scope"}); err != nil {
				t.Fatal(err)
			}

			sandbox := &fakeSandbox{}
			if test.terminalEvent {
				snapshot := failedSnapshot(run.ID, executionwire.FailureInvalidSession, "private invalid-session detail")
				sandbox.startFn = func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
					return snapshot.Status, nil
				}
				sandbox.getFn = func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
					return snapshot, nil
				}
			} else {
				sandbox.startFn = func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
					return executionwire.RunStatus{}, invalidSessionRemoteError()
				}
				sandbox.getFn = sandboxRunNotFound
			}
			engine := newEngine(t, store, sandbox, clock)
			result, claimed, err := engine.DispatchOne(context.Background())
			if err != nil || !claimed || !result.Finished || result.CoreState != corestore.RunFailed {
				t.Fatalf("invalid session result = %#v, claimed=%v, err=%v", result, claimed, err)
			}
			starts := sandbox.Starts()
			if len(starts) != 1 || starts[0].SessionRef == nil || *starts[0].SessionRef != "session_poisoned" {
				t.Fatalf("prepared session request = %#v", starts)
			}
			current, found, err := store.GetSession(context.Background(), key)
			if err != nil || !found || current.Ref != "session_poisoned" {
				t.Fatalf("prepared session changed = %#v, found=%v err=%v", current, found, err)
			}
			other, found, err := store.GetSession(context.Background(), otherKey)
			if err != nil || !found || other.Ref != "session_other_scope" {
				t.Fatalf("cross-scope session changed = %#v, found=%v, err=%v", other, found, err)
			}
			stored, err := store.GetRun(context.Background(), run.ID)
			if err != nil || stored.FailureCode == nil || *stored.FailureCode != corestore.RunFailureInvalidSession {
				t.Fatalf("stored invalid-session failure = %#v, err=%v", stored, err)
			}
		})
	}
}

func TestInvalidSessionNeverClearsNewerConcurrentSession(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	store, _, _ := openCoreStore(t, clock, &tokenSequence{})
	run := ingestRun(t, store, "run_session_newer", "event_session_newer", "revision-1")
	key := sessionKeyForRun(run)
	if err := store.PutSession(context.Background(), corestore.Session{SessionKey: key, Ref: "session_prepared"}); err != nil {
		t.Fatal(err)
	}
	sandbox := &fakeSandbox{}
	sandbox.startFn = func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
		// This models another completed Run publishing a newer scoped session
		// after this Run was prepared but before invalid_session is observed.
		if err := store.PutSession(context.Background(), corestore.Session{SessionKey: key, Ref: "session_newer"}); err != nil {
			t.Fatalf("publish newer session: %v", err)
		}
		return executionwire.RunStatus{}, invalidSessionRemoteError()
	}
	sandbox.getFn = sandboxRunNotFound
	engine := newEngine(t, store, sandbox, clock)
	result, claimed, err := engine.DispatchOne(context.Background())
	if err != nil || !claimed || !result.Finished {
		t.Fatalf("invalid-session dispatch = %#v, claimed=%v, err=%v", result, claimed, err)
	}
	current, found, err := store.GetSession(context.Background(), key)
	if err != nil || !found || current.Ref != "session_newer" {
		t.Fatalf("newer session was cleared = %#v, found=%v, err=%v", current, found, err)
	}
}

type failFinishBeforeCommitStore struct {
	Store
	mu       sync.Mutex
	failed   bool
	replyIDs []string
}

func (s *failFinishBeforeCommitStore) FinishRun(ctx context.Context, input corestore.FinishRunInput, reply *corestore.TextDeliveryInput) error {
	s.mu.Lock()
	if reply != nil {
		s.replyIDs = append(s.replyIDs, reply.ID)
	}
	if !s.failed {
		s.failed = true
		s.mu.Unlock()
		return errors.New("Finish response unknown before commit")
	}
	s.mu.Unlock()
	return s.Store.FinishRun(ctx, input, reply)
}

func (s *failFinishBeforeCommitStore) ReplyIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.replyIDs...)
}

func TestInvalidSessionFinishFailureRetryPreservesPreparedSession(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	store, _, _ := openCoreStore(t, clock, &tokenSequence{})
	run := ingestRun(t, store, "run_clear_crash", "event_clear_crash", "revision-1")
	key := sessionKeyForRun(run)
	if err := store.PutSession(context.Background(), corestore.Session{SessionKey: key, Ref: "session_poisoned"}); err != nil {
		t.Fatal(err)
	}
	lossy := &failFinishBeforeCommitStore{Store: store}
	sandbox := &fakeSandbox{
		startFn: func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
			return executionwire.RunStatus{}, invalidSessionRemoteError()
		},
		getFn: sandboxRunNotFound,
	}
	engine := newEngine(t, lossy, sandbox, clock)

	first, claimed, err := engine.DispatchOne(context.Background())
	if !claimed || first.Finished {
		t.Fatalf("first Finish failure = %#v, claimed=%v", first, claimed)
	}
	requireDispatchCode(t, err, ErrorStoreUnavailable)
	current, found, err := store.GetSession(context.Background(), key)
	if err != nil || !found || current.Ref != "session_poisoned" {
		t.Fatalf("prepared session changed after failed Finish: %#v found=%v err=%v", current, found, err)
	}

	second, err := engine.Advance(context.Background(), run.ID)
	if err != nil || !second.Finished || second.CoreState != corestore.RunFailed {
		t.Fatalf("retry after failed Finish = %#v, err=%v", second, err)
	}
	starts := sandbox.Starts()
	if len(starts) != 2 || starts[0].SessionRef == nil || starts[1].SessionRef == nil ||
		*starts[0].SessionRef != "session_poisoned" || *starts[1].SessionRef != "session_poisoned" {
		t.Fatalf("immutable prepared session was not retried = %#v", starts)
	}
	firstFingerprint, _ := executionwire.StartRunFingerprint(starts[0])
	secondFingerprint, _ := executionwire.StartRunFingerprint(starts[1])
	if firstFingerprint != secondFingerprint {
		t.Fatalf("retry StartRun fingerprint changed: %q != %q", firstFingerprint, secondFingerprint)
	}
	replyIDs := lossy.ReplyIDs()
	if len(replyIDs) != 2 || replyIDs[0] != replyIDs[1] || replyIDs[0] != deliveryIDForRun(run.ID) {
		t.Fatalf("Finish retry delivery IDs = %#v", replyIDs)
	}
}

func TestFailureMessagesAreRedactedAndCodesRemainClosed(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	store, _, _ := openCoreStore(t, clock, &tokenSequence{})
	run := ingestRun(t, store, "run_redaction", "event_redaction", "revision-1")
	private := "SECRET harness stderr /home/operator/token model-provider-detail"
	snapshot := failedSnapshot(run.ID, executionwire.FailureRunnerFailed, private)
	sandbox := &fakeSandbox{
		startFn: func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
			return snapshot.Status, nil
		},
		getFn: func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
			return snapshot, nil
		},
	}
	engine := newEngine(t, store, sandbox, clock)
	result, claimed, err := engine.DispatchOne(context.Background())
	if err != nil || !claimed || !result.Finished || result.CoreState != corestore.RunFailed {
		t.Fatalf("failed dispatch = %#v, claimed=%v, err=%v", result, claimed, err)
	}
	stored, err := store.GetRun(context.Background(), run.ID)
	if err != nil || stored.FailureCode == nil || *stored.FailureCode != corestore.RunFailureRunnerFailed {
		t.Fatalf("stored failure = %#v, err=%v", stored, err)
	}
	delivery := claimOneDelivery(t, store)
	if delivery.Text != safeFailureText(corestore.RunFailureRunnerFailed) {
		t.Fatalf("safe failure text = %q", delivery.Text)
	}
	if strings.Contains(fmt.Sprintf("%#v %#v", stored, delivery), private) {
		t.Fatal("private sandbox failure message reached agentd persistence")
	}
}

func TestEveryFailureCodeMapsExactly(t *testing.T) {
	t.Parallel()
	tests := []struct {
		wire executionwire.FailureCode
		core corestore.RunFailureCode
	}{
		{executionwire.FailureTargetUnavailable, corestore.RunFailureTargetUnavailable},
		{executionwire.FailureRevisionMismatch, corestore.RunFailureRevisionMismatch},
		{executionwire.FailureInvalidSession, corestore.RunFailureInvalidSession},
		{executionwire.FailurePolicyDenied, corestore.RunFailurePolicyDenied},
		{executionwire.FailureDeadlineExceeded, corestore.RunFailureDeadlineExceeded},
		{executionwire.FailureOutputLimit, corestore.RunFailureOutputLimit},
		{executionwire.FailureRunnerFailed, corestore.RunFailureRunnerFailed},
		{executionwire.FailureProtocolViolation, corestore.RunFailureProtocolViolation},
		{executionwire.FailureRuntimeInterrupted, corestore.RunFailureRuntimeInterrupted},
		{executionwire.FailureInternal, corestore.RunFailureInternal},
	}
	for _, test := range tests {
		if got := mapFailureCode(test.wire); got != test.core {
			t.Errorf("mapFailureCode(%q) = %q, want %q", test.wire, got, test.core)
		}
	}
}

func TestInterruptedOrUnknownRunningRunIsNeverStartedFresh(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	store, _, _ := openCoreStore(t, clock, &tokenSequence{})
	run := ingestRun(t, store, "run_unknown", "event_unknown", "revision-1")
	sandbox := &fakeSandbox{
		startFn: func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
			return runningStatus(run.ID), nil
		},
		getFn: func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
			return runningSnapshot(run.ID), nil
		},
	}
	engine := newEngine(t, store, sandbox, clock)
	if result, claimed, err := engine.DispatchOne(context.Background()); err != nil || !claimed || result.CoreState != corestore.RunRunning {
		t.Fatalf("initial running = %#v, %v, %v", result, claimed, err)
	}
	sandbox.getFn = func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
		return executionwire.GetRunResponse{}, &executionhttp.RemoteError{
			StatusCode: 404, Code: string(executionhttp.ErrorRunNotFound),
		}
	}
	items, err := engine.Reconcile(context.Background(), 10)
	if err != nil || len(items) != 1 || items[0].Err != nil || items[0].Result.CoreState != corestore.RunInterrupted {
		t.Fatalf("unknown running reconcile = %#v, err=%v", items, err)
	}
	if sandbox.StartCount() != 1 {
		t.Fatalf("unknown running Run was restarted; StartRun count=%d", sandbox.StartCount())
	}
	stored, err := store.GetRun(context.Background(), run.ID)
	if err != nil || stored.State != corestore.RunInterrupted || stored.FailureCode == nil || *stored.FailureCode != corestore.RunFailureRuntimeInterrupted {
		t.Fatalf("interrupted stored Run = %#v, err=%v", stored, err)
	}
	if _, claimed, err := engine.DispatchOne(context.Background()); err != nil || claimed {
		t.Fatalf("terminal Run was requeued: claimed=%v err=%v", claimed, err)
	}
	delivery := claimOneDelivery(t, store)
	if delivery.Text != textInterrupted {
		t.Fatalf("interrupted delivery = %q", delivery.Text)
	}
}

func TestSandboxInterruptedAndCancelledTerminalMappings(t *testing.T) {
	tests := []struct {
		name      string
		snapshot  func(string) executionwire.GetRunResponse
		wantState corestore.RunState
		wantText  string
	}{
		{
			name: "interrupted",
			snapshot: func(runID string) executionwire.GetRunResponse {
				return interruptedSnapshot(runID, "private runtime reason")
			},
			wantState: corestore.RunInterrupted,
			wantText:  textInterrupted,
		},
		{
			name:      "cancelled",
			snapshot:  cancelledSnapshot,
			wantState: corestore.RunCancelled,
			wantText:  textCancelled,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &fakeClock{now: baseTime}
			store, _, _ := openCoreStore(t, clock, &tokenSequence{})
			run := ingestRun(t, store, "run_"+test.name, "event_"+test.name, "revision-1")
			snapshot := test.snapshot(run.ID)
			sandbox := &fakeSandbox{
				startFn: func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
					return snapshot.Status, nil
				},
				getFn: func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
					return snapshot, nil
				},
			}
			engine := newEngine(t, store, sandbox, clock)
			result, claimed, err := engine.DispatchOne(context.Background())
			if err != nil || !claimed || !result.Finished || result.CoreState != test.wantState {
				t.Fatalf("terminal result = %#v, claimed=%v, err=%v", result, claimed, err)
			}
			if delivery := claimOneDelivery(t, store); delivery.Text != test.wantText {
				t.Fatalf("delivery text = %q, want %q", delivery.Text, test.wantText)
			}
			if sandbox.StartCount() != 1 {
				t.Fatalf("terminal Run Start count = %d", sandbox.StartCount())
			}
		})
	}
}

func TestStartClosedFailuresBecomeSafeTerminalRuns(t *testing.T) {
	tests := []struct {
		name string
		code executionhttp.ErrorCode
		want corestore.RunFailureCode
	}{
		{"target", executionhttp.ErrorTargetNotFound, corestore.RunFailureTargetUnavailable},
		{"revision", executionhttp.ErrorRevisionMismatch, corestore.RunFailureRevisionMismatch},
		{"session", executionhttp.ErrorInvalidSession, corestore.RunFailureInvalidSession},
		{"deadline", executionhttp.ErrorInvalidState, corestore.RunFailureDeadlineExceeded},
		{"fingerprint conflict", executionhttp.ErrorConflict, corestore.RunFailureProtocolViolation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &fakeClock{now: baseTime}
			store, _, _ := openCoreStore(t, clock, &tokenSequence{})
			run := ingestRun(t, store, "run_start_"+strings.ReplaceAll(test.name, " ", "_"), "event_start_"+strings.ReplaceAll(test.name, " ", "_"), "revision-1")
			sandbox := &fakeSandbox{
				startFn: func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
					return executionwire.RunStatus{}, &executionhttp.RemoteError{StatusCode: 409, Code: string(test.code)}
				},
				getFn: sandboxRunNotFound,
			}
			engine := newEngine(t, store, sandbox, clock)
			result, claimed, err := engine.DispatchOne(context.Background())
			if test.code == executionhttp.ErrorConflict {
				requireDispatchCode(t, err, ErrorConflict)
			} else if err != nil {
				t.Fatalf("unexpected operational error: %v", err)
			}
			if !claimed || !result.Finished || result.CoreState != corestore.RunFailed {
				t.Fatalf("closed Start failure = %#v, claimed=%v, err=%v", result, claimed, err)
			}
			stored, err := store.GetRun(context.Background(), run.ID)
			if err != nil || stored.FailureCode == nil || *stored.FailureCode != test.want {
				t.Fatalf("mapped Start failure = %#v, err=%v", stored, err)
			}
			if delivery := claimOneDelivery(t, store); delivery.Text != safeFailureText(test.want) {
				t.Fatalf("safe failure delivery = %q", delivery.Text)
			}
		})
	}
}

func TestDeliveryIDIsStableDomainSeparatedAndOpaque(t *testing.T) {
	t.Parallel()
	first := deliveryIDForRun("run_1")
	if first != deliveryIDForRun("run_1") {
		t.Fatal("delivery ID is not stable")
	}
	if first == deliveryIDForRun("run_2") {
		t.Fatal("different Run IDs produced the same delivery ID")
	}
	if strings.Contains(first, "run_1") || !strings.HasPrefix(first, "delivery_") {
		t.Fatalf("delivery ID is not opaque and typed: %q", first)
	}
	if len(first) > corestore.MaxIDBytes {
		t.Fatalf("delivery ID length = %d", len(first))
	}
}

func TestReconcileContinuesAfterPerRunFailure(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	store, path, _ := openCoreStore(t, clock, &tokenSequence{})
	first := ingestRun(t, store, "run_batch_a", "event_batch_a", "revision-1")
	second := ingestRun(t, store, "run_batch_b", "event_batch_b", "revision-1")
	sandbox := &fakeSandbox{
		startFn: func(_ context.Context, request executionwire.StartRunRequest) (executionwire.RunStatus, error) {
			return runningStatus(request.RunID), nil
		},
		getFn: func(_ context.Context, request executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
			return runningSnapshot(request.RunID), nil
		},
	}
	engine := newEngine(t, store, sandbox, clock)
	if result, claimed, err := engine.DispatchOne(context.Background()); err != nil || !claimed || result.CoreState != corestore.RunRunning {
		t.Fatalf("running fixture = %#v, claimed=%v, err=%v", result, claimed, err)
	}
	// The store now enforces one global active Run. Seed a second historical
	// running row directly so restart reconciliation remains defensive against a
	// database produced before that invariant while ClaimQueuedRun stays strict.
	seedRunningRun(t, path, second.ID, clock.Now())
	// A context-shaped sandbox cause under a live caller is not the caller's
	// cancellation and must not starve the rest of the batch.
	private := context.Canceled
	sandbox.getFn = func(_ context.Context, request executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
		if request.RunID == first.ID {
			return executionwire.GetRunResponse{}, private
		}
		return completedSnapshot(second.ID, "second done", nil), nil
	}
	items, err := engine.Reconcile(context.Background(), 10)
	if err != nil || len(items) != 2 {
		t.Fatalf("Reconcile = %#v, err=%v", items, err)
	}
	requireDispatchCode(t, items[0].Err, ErrorSandboxUnavailable)
	if items[1].Err != nil || !items[1].Result.Finished || items[1].Result.CoreState != corestore.RunCompleted {
		t.Fatalf("second reconciliation was starved: %#v", items[1])
	}
}

func TestClosedErrorsAndContextPropagation(t *testing.T) {
	clock := &fakeClock{now: baseTime}
	store, _, _ := openCoreStore(t, clock, &tokenSequence{})
	ingestRun(t, store, "run_closed", "event_closed", "revision-1")
	private := errors.New("dial /private/socket: credential-like detail")
	sandbox := &fakeSandbox{startFn: func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
		return executionwire.RunStatus{}, private
	}}
	engine := newEngine(t, store, sandbox, clock)
	_, claimed, err := engine.DispatchOne(context.Background())
	if !claimed {
		t.Fatal("transport failure did not report claimed Run")
	}
	dispatchErr := requireDispatchCode(t, err, ErrorSandboxUnavailable)
	if strings.Contains(dispatchErr.Error(), "private") || !errors.Is(dispatchErr, private) {
		t.Fatalf("closed/local cause behavior = %v", dispatchErr)
	}
	sandbox.startFn = func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
		return executionwire.RunStatus{}, context.Canceled
	}
	_, err = engine.Advance(context.Background(), "run_closed")
	requireDispatchCode(t, err, ErrorSandboxUnavailable)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("live caller lost sandbox cancellation cause: %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = engine.DispatchOne(cancelled)
	requireDispatchCode(t, err, ErrorContextDone)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("context cancellation was not preserved: %v", err)
	}
}

func TestNewValidatesDependenciesAndDurations(t *testing.T) {
	t.Parallel()
	store := &stubStore{}
	sandbox := &fakeSandbox{}
	var typedNilStore *stubStore
	var typedNilSandbox *fakeSandbox
	tests := []struct {
		name    string
		store   Store
		sandbox Sandbox
		lease   time.Duration
		timeout time.Duration
		options []Option
	}{
		{name: "nil store", sandbox: sandbox, lease: time.Second, timeout: time.Second},
		{name: "typed nil store", store: typedNilStore, sandbox: sandbox, lease: time.Second, timeout: time.Second},
		{name: "nil sandbox", store: store, lease: time.Second, timeout: time.Second},
		{name: "typed nil sandbox", store: store, sandbox: typedNilSandbox, lease: time.Second, timeout: time.Second},
		{name: "short lease", store: store, sandbox: sandbox, lease: time.Second - 1, timeout: time.Second},
		{name: "long lease", store: store, sandbox: sandbox, lease: 10*time.Minute + 1, timeout: time.Second},
		{name: "short timeout", store: store, sandbox: sandbox, lease: time.Second, timeout: time.Second - 1},
		{name: "long timeout", store: store, sandbox: sandbox, lease: time.Second, timeout: 24*time.Hour + 1},
		{name: "nil option", store: store, sandbox: sandbox, lease: time.Second, timeout: time.Second, options: []Option{nil}},
		{name: "nil clock", store: store, sandbox: sandbox, lease: time.Second, timeout: time.Second, options: []Option{WithClock(nil)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(test.store, test.sandbox, test.lease, test.timeout, test.options...); err == nil {
				t.Fatal("New accepted invalid input")
			}
		})
	}
}

// stubStore is used only for constructor validation; its methods must never be
// called by those tests.
type stubStore struct{}

func (*stubStore) ClaimQueuedRun(context.Context, time.Duration) (corestore.Run, bool, error) {
	return corestore.Run{}, false, nil
}
func (*stubStore) GetRun(context.Context, string) (corestore.Run, error) {
	return corestore.Run{}, nil
}
func (*stubStore) ListRunningRuns(context.Context, int) ([]corestore.Run, error) {
	return nil, nil
}
func (*stubStore) GetSession(context.Context, corestore.SessionKey) (corestore.Session, bool, error) {
	return corestore.Session{}, false, nil
}
func (*stubStore) PrepareRunStart(context.Context, corestore.PrepareRunStartInput) (corestore.PreparedRunStart, error) {
	return corestore.PreparedRunStart{}, nil
}
func (*stubStore) MarkRunRunning(context.Context, string, string) error { return nil }
func (*stubStore) FinishRun(context.Context, corestore.FinishRunInput, *corestore.TextDeliveryInput) error {
	return nil
}
