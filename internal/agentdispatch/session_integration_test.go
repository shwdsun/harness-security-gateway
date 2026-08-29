package agentdispatch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/runnerbridge"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
)

const (
	sessionIntegrationTargetID       = "codex-project"
	sessionIntegrationTargetRevision = "revision-1"
)

type committedServiceSandbox struct {
	service *sandboxservice.Service

	mu        sync.Mutex
	starts    []executionwire.StartRunRequest
	afterSave func(context.Context, executionwire.StartRunRequest, executionwire.RunStatus) (executionwire.RunStatus, error)
}

func (s *committedServiceSandbox) StartRun(
	ctx context.Context,
	request executionwire.StartRunRequest,
) (executionwire.RunStatus, error) {
	s.mu.Lock()
	s.starts = append(s.starts, cloneStart(request))
	hook := s.afterSave
	s.mu.Unlock()

	status, err := s.service.StartRun(ctx, request)
	if err != nil || hook == nil {
		return status, err
	}
	return hook(ctx, request, status)
}

func (s *committedServiceSandbox) GetRun(
	ctx context.Context,
	request executionwire.GetRunRequest,
) (executionwire.GetRunResponse, error) {
	return s.service.GetRun(ctx, request)
}

func (s *committedServiceSandbox) Starts() []executionwire.StartRunRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]executionwire.StartRunRequest, len(s.starts))
	for index := range s.starts {
		result[index] = cloneStart(s.starts[index])
	}
	return result
}

func sessionIntegrationManifest() targetmanifest.Manifest {
	return targetmanifest.Manifest{
		Schema:   targetmanifest.SchemaV1,
		ID:       sessionIntegrationTargetID,
		Revision: sessionIntegrationTargetRevision,
		Runner: targetmanifest.Runner{
			Family:           "mock",
			AdapterVersion:   "0.1.0",
			Protocol:         runnerwire.ProtocolV1,
			Image:            "registry.example/mock@sha256:" + strings.Repeat("a", 64),
			RequiredFeatures: []runnerwire.Feature{runnerwire.FeatureSessionResume},
		},
		WorkspaceRef:      "workspace-session-integration",
		WorkspaceMode:     targetmanifest.WorkspaceReadOnly,
		StateRef:          "state-session-integration",
		PolicyRef:         "policy-session-integration",
		AuthProfileRef:    "auth-session-integration",
		SkillBundleRef:    "skills-session-integration",
		NetworkProfileRef: "network-session-integration",
		SessionMode:       targetmanifest.SessionOpaqueResume,
		Limits: targetmanifest.Limits{
			TimeoutSeconds:       3_600,
			MemoryBytes:          64 << 20,
			CPUMillis:            100,
			PIDs:                 16,
			MaxInputBytes:        executionwire.MaxInputTextBytes,
			MaxOutputBytes:       executionwire.MaxOutputTextBytes,
			MaxProgressBytes:     runnerwire.MaxProgressTextBytes,
			MaxStderrBytes:       4 << 10,
			MaxEvents:            executionwire.MaxEvents,
			MaxSessionAgeSeconds: 24 * 60 * 60,
			MaxSessionTurns:      8,
		},
	}
}

func openSessionIntegrationSandbox(
	t *testing.T,
	path string,
	clock *fakeClock,
) (*sandboxstore.Store, *sandboxservice.Service) {
	t.Helper()
	store, err := sandboxstore.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("sandboxstore.Open: %v", err)
	}
	manifest := sessionIntegrationManifest()
	registry, err := targetregistry.New([]targetmanifest.Manifest{manifest})
	if err != nil {
		_ = store.Close()
		t.Fatalf("targetregistry.New: %v", err)
	}
	service, err := sandboxservice.New(
		context.Background(), registry, store,
		func(candidate targetmanifest.Manifest) (string, string, bool, error) {
			fingerprint, fingerprintErr := candidate.Fingerprint()
			return candidate.StateRef, fingerprint, true, fingerprintErr
		},
		sandboxservice.WithClock(clock.Now),
	)
	if err != nil {
		_ = store.Close()
		t.Fatalf("sandboxservice.New: %v", err)
	}
	return store, service
}

func ingestSessionIntegrationRun(
	t *testing.T,
	store ingestStore,
	runID string,
	eventID string,
) corestore.Run {
	t.Helper()
	return ingestSessionIntegrationRunAt(t, store, runID, eventID, baseTime)
}

func ingestSessionIntegrationRunAt(
	t *testing.T,
	store ingestStore,
	runID string,
	eventID string,
	occurredAt time.Time,
) corestore.Run {
	t.Helper()
	payload := sha256.Sum256([]byte("session-integration:" + eventID))
	result, err := store.IngestTextRun(
		context.Background(),
		corestore.IngestTextRunInput{
			ConnectorID:      "discord-main",
			EventID:          eventID,
			PayloadHash:      payload,
			ActorRef:         "discord:user:session-integration",
			ConversationRef:  "discord:channel:session-integration",
			MessageRef:       "discord:message:" + eventID,
			OccurredAtUnixMS: occurredAt.UnixMilli(),
			Text:             "continue the durable session",
		},
		func() (corestore.TextRunAuthorization, error) {
			return corestore.TextRunAuthorization{
				TargetID:           sessionIntegrationTargetID,
				TargetRevision:     sessionIntegrationTargetRevision,
				BindingFingerprint: strings.Repeat("a", corestore.SHA256HexBytes),
				PolicyRevision:     strings.Repeat("b", corestore.SHA256HexBytes),
			}, nil
		},
		func() (string, error) { return runID, nil },
	)
	if err != nil {
		t.Fatalf("IngestTextRun(%s): %v", runID, err)
	}
	if result.Duplicate {
		t.Fatalf("IngestTextRun(%s) unexpectedly replayed", runID)
	}
	return result.Run
}

func seedSessionIntegrationParent(
	t *testing.T,
	service *sandboxservice.Service,
	store *sandboxstore.Store,
	run corestore.Run,
	ref string,
	vendorToken string,
) {
	t.Helper()
	digest, err := sessionauth.Digest(sessionScopeForRun(run))
	if err != nil {
		t.Fatal(err)
	}
	request := executionwire.StartRunRequest{
		RunID:              "sandbox-parent-" + run.ID,
		TargetID:           run.TargetID,
		ExpectedRevision:   run.TargetRevision,
		SessionScopeDigest: digest,
		Input: executionwire.TextInput{
			MediaType: executionwire.MediaTypeTextPlain,
			Text:      "establish parent",
		},
		Deadline: baseTime.Add(time.Hour),
	}
	if _, err := service.StartRun(context.Background(), request); err != nil {
		t.Fatalf("seed StartRun: %v", err)
	}
	if _, err := store.AppendEvent(context.Background(), executionwire.RunEvent{
		RunID: request.RunID, Seq: 1, Type: executionwire.RunEventStarted,
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendEvent(context.Background(), executionwire.RunEvent{
		RunID: request.RunID,
		Seq:   2,
		Type:  executionwire.RunEventCompleted,
		Result: &executionwire.RunResult{
			Output:     executionwire.TextOutput{MediaType: executionwire.MediaTypeTextPlain, Text: "parent ready"},
			SessionRef: &ref,
		},
	}, &sandboxstore.SessionMapping{Ref: ref, VendorToken: vendorToken}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmRuntimeStopped(context.Background(), request.RunID); err != nil {
		t.Fatal(err)
	}
}

func appendSessionIntegrationCompleted(
	t *testing.T,
	store *sandboxstore.Store,
	runID string,
	ref string,
	vendorToken string,
) executionwire.RunStatus {
	t.Helper()
	ctx := context.Background()
	if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
		RunID: runID, Seq: 1, Type: executionwire.RunEventStarted,
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
		RunID: runID,
		Seq:   2,
		Type:  executionwire.RunEventCompleted,
		Result: &executionwire.RunResult{
			Output:     executionwire.TextOutput{MediaType: executionwire.MediaTypeTextPlain, Text: "resumed"},
			SessionRef: &ref,
		},
	}, &sandboxstore.SessionMapping{Ref: ref, VendorToken: vendorToken}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmRuntimeStopped(ctx, runID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.GetSnapshot(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.Status
}

func appendSessionIntegrationBridgeCompleted(
	t *testing.T,
	store *sandboxstore.Store,
	request executionwire.StartRunRequest,
	resolvedVendorToken *string,
	ref string,
	vendorToken string,
) executionwire.RunStatus {
	t.Helper()
	manifest := sessionIntegrationManifest()
	var runnerOutput bytes.Buffer
	encoder := runnerwire.NewEncoder(&runnerOutput)
	for _, frame := range []runnerwire.Frame{
		&runnerwire.RunnerReady{
			Protocol: runnerwire.ProtocolV1,
			Type:     runnerwire.TypeRunnerReady,
			Adapter: runnerwire.Adapter{
				Family: manifest.Runner.Family, Version: manifest.Runner.AdapterVersion,
			},
			Features: []runnerwire.Feature{runnerwire.FeatureSessionResume},
		},
		&runnerwire.RunStarted{
			Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted,
			RunID: request.RunID, Seq: 1,
		},
		&runnerwire.RunCompleted{
			Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunCompleted,
			RunID: request.RunID, Seq: 2,
			Output: runnerwire.TextContent{
				MediaType: runnerwire.MediaTypeTextPlain, Text: "resumed",
			},
			SessionToken: vendorToken,
		},
	} {
		if err := encoder.Encode(frame); err != nil {
			t.Fatal(err)
		}
	}
	var runnerInput bytes.Buffer
	if err := runnerbridge.Run(
		context.Background(), request, manifest, resolvedVendorToken,
		&runnerOutput, &runnerInput,
		func(ctx context.Context, emission runnerbridge.Emission) error {
			var mapping *sandboxstore.SessionMapping
			if emission.VendorSessionToken != nil {
				emission.Event.Result.SessionRef = &ref
				mapping = &sandboxstore.SessionMapping{
					Ref: ref, VendorToken: *emission.VendorSessionToken,
				}
			}
			_, err := store.AppendEvent(ctx, emission.Event, mapping)
			return err
		},
	); err != nil {
		t.Fatalf("runnerbridge.Run(%s): %v", request.RunID, err)
	}
	frame, err := runnerwire.NewDecoder(bytes.NewReader(runnerInput.Bytes())).DecodeControllerFrame()
	if err != nil {
		t.Fatalf("decode runner start for %s: %v", request.RunID, err)
	}
	start, ok := frame.(*runnerwire.RunStart)
	if !ok {
		t.Fatalf("runner input for %s = %T, want *runnerwire.RunStart", request.RunID, frame)
	}
	if request.SessionRef == nil {
		if start.Session.Mode != runnerwire.SessionModeNew || start.Session.Token != "" {
			t.Fatalf("fresh runner session for %s = %#v", request.RunID, start.Session)
		}
	} else if resolvedVendorToken == nil || start.Session.Mode != runnerwire.SessionModeResume ||
		start.Session.Token != *resolvedVendorToken {
		t.Fatalf("resumed runner session for %s = %#v, resolved=%v",
			request.RunID, start.Session, resolvedVendorToken)
	}
	if _, err := store.ConfirmRuntimeStopped(context.Background(), request.RunID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.GetSnapshot(context.Background(), request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.Status
}

func appendSessionIntegrationInvalidFailure(
	t *testing.T,
	store *sandboxstore.Store,
	runID string,
) executionwire.RunStatus {
	t.Helper()
	ctx := context.Background()
	if _, err := store.AppendEvent(ctx, executionwire.RunEvent{
		RunID: runID,
		Seq:   1,
		Type:  executionwire.RunEventFailed,
		Failure: &executionwire.RunFailure{
			Code: executionwire.FailureInvalidSession, Message: "closed invalid session",
		},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmRuntimeStopped(ctx, runID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.GetSnapshot(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.Status
}

func assertSessionIntegrationCounts(
	t *testing.T,
	path string,
	parentRef string,
	runID string,
	successorRef string,
) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var uses, successors, completions int
	if err := db.QueryRow(`SELECT COUNT(*) FROM session_uses
	    WHERE session_ref = ? AND run_id = ?`, parentRef, runID).Scan(&uses); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions
	    WHERE session_ref = ? AND created_by_run_id = ?`, successorRef, runID).Scan(&successors); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM run_events
	    WHERE run_id = ? AND event_type = 'completed' AND result_session_ref = ?`,
		runID, successorRef).Scan(&completions); err != nil {
		t.Fatal(err)
	}
	if uses != 1 || successors != 1 || completions != 1 {
		t.Fatalf("durable session counts = uses:%d successors:%d completions:%d, want 1/1/1",
			uses, successors, completions)
	}
}

func TestRealStoresLostCommittedStartRetryPublishesSuccessorExactlyOnce(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{now: baseTime}
	core, corePath, coreOptions := openCoreStore(t, clock, &tokenSequence{})
	sandboxPath := filepath.Join(t.TempDir(), "sandbox.sqlite3")
	sandboxStore, service := openSessionIntegrationSandbox(t, sandboxPath, clock)
	t.Cleanup(func() { _ = sandboxStore.Close() })

	run := ingestSessionIntegrationRun(t, core, "run_real_lost_start", "event_real_lost_start")
	const parentRef = "session_real_parent"
	const parentToken = "vendor-real-parent"
	seedSessionIntegrationParent(t, service, sandboxStore, run, parentRef, parentToken)
	if err := core.PutSession(ctx, corestore.Session{
		SessionKey: sessionKeyForRun(run), Ref: parentRef,
	}); err != nil {
		t.Fatal(err)
	}

	lost := &committedServiceSandbox{service: service}
	lost.afterSave = func(
		_ context.Context,
		_ executionwire.StartRunRequest,
		_ executionwire.RunStatus,
	) (executionwire.RunStatus, error) {
		return executionwire.RunStatus{}, errors.New("response lost after durable StartRun commit")
	}
	firstEngine := newEngine(t, core, lost, clock)
	first, claimed, err := firstEngine.DispatchOne(ctx)
	if !claimed || first.RunID != run.ID {
		t.Fatalf("lost StartRun dispatch = %#v, claimed=%v", first, claimed)
	}
	requireDispatchCode(t, err, ErrorSandboxUnavailable)
	digest, err := sessionauth.Digest(sessionScopeForRun(run))
	if err != nil {
		t.Fatal(err)
	}
	if token, err := sandboxStore.ResolveSessionForRun(
		ctx, run.ID, parentRef, run.TargetID, run.TargetRevision, digest,
	); err != nil || token != parentToken {
		t.Fatalf("committed consumed parent = %q, %v", token, err)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sandboxStore.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedCoreStore, err := corestore.Open(ctx, corePath, coreOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedCoreStore.Close()
	core = &testCoreStore{Store: reopenedCoreStore, path: corePath}
	sandboxStore, service = openSessionIntegrationSandbox(t, sandboxPath, clock)

	const successorRef = "session_real_successor"
	retry := &committedServiceSandbox{service: service}
	retry.afterSave = func(
		_ context.Context,
		request executionwire.StartRunRequest,
		_ executionwire.RunStatus,
	) (executionwire.RunStatus, error) {
		return appendSessionIntegrationCompleted(
			t, sandboxStore, request.RunID, successorRef, "vendor-real-successor",
		), nil
	}
	restartedEngine := newEngine(t, core, retry, clock)
	second, err := restartedEngine.Advance(ctx, run.ID)
	if err != nil || !second.Finished || second.CoreState != corestore.RunCompleted {
		t.Fatalf("retry recovery = %#v, err=%v", second, err)
	}
	if _, err := restartedEngine.Advance(ctx, run.ID); err != nil {
		t.Fatalf("terminal Core retry: %v", err)
	}

	lostStarts, retryStarts := lost.Starts(), retry.Starts()
	if len(lostStarts) != 1 || len(retryStarts) != 1 {
		t.Fatalf("StartRun calls = lost:%d retry:%d, want 1/1", len(lostStarts), len(retryStarts))
	}
	firstFingerprint, _ := executionwire.StartRunFingerprint(lostStarts[0])
	secondFingerprint, _ := executionwire.StartRunFingerprint(retryStarts[0])
	if firstFingerprint != secondFingerprint || lostStarts[0].SessionRef == nil ||
		retryStarts[0].SessionRef == nil || *lostStarts[0].SessionRef != parentRef ||
		*retryStarts[0].SessionRef != parentRef {
		t.Fatalf("retry changed prepared resume: lost=%#v retry=%#v", lostStarts, retryStarts)
	}
	current, found, err := core.GetSession(ctx, sessionKeyForRun(run))
	if err != nil || !found || current.Ref != successorRef {
		t.Fatalf("Core successor pointer = %#v, found=%v, err=%v", current, found, err)
	}
	coreDB, err := sql.Open("sqlite", corePath)
	if err != nil {
		t.Fatal(err)
	}
	defer coreDB.Close()
	var deliveries int
	if err := coreDB.QueryRow(`SELECT COUNT(*) FROM text_deliveries WHERE run_id = ?`,
		run.ID).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 {
		t.Fatalf("Core delivery count = %d, want exactly 1", deliveries)
	}
	assertSessionIntegrationCounts(t, sandboxPath, parentRef, run.ID, successorRef)
}

func TestRealStoresThreeTurnSessionLineageCompletesExactlyOnce(t *testing.T) {
	ctx := context.Background()
	startedAt := time.Now().UTC().Truncate(time.Millisecond)
	clock := &fakeClock{now: startedAt}
	core, corePath, _ := openCoreStore(t, clock, &tokenSequence{})
	sandboxPath := filepath.Join(t.TempDir(), "sandbox.sqlite3")
	sandboxStore, service := openSessionIntegrationSandbox(t, sandboxPath, clock)
	defer sandboxStore.Close()

	runIDs := []string{"run_real_turn_1", "run_real_turn_2", "run_real_turn_3"}
	sessionRefs := []string{"session_real_turn_1", "session_real_turn_2", "session_real_turn_3"}
	vendorTokens := []string{"vendor-real-turn-1", "vendor-real-turn-2", "vendor-real-turn-3"}
	successorByRun := make(map[string]string, len(runIDs))
	tokenByRef := make(map[string]string, len(sessionRefs))
	for index := range runIDs {
		successorByRun[runIDs[index]] = sessionRefs[index]
		tokenByRef[sessionRefs[index]] = vendorTokens[index]
	}

	sandbox := &committedServiceSandbox{service: service}
	sandbox.afterSave = func(
		_ context.Context,
		request executionwire.StartRunRequest,
		_ executionwire.RunStatus,
	) (executionwire.RunStatus, error) {
		var resolvedToken *string
		if request.SessionRef != nil {
			wantToken := tokenByRef[*request.SessionRef]
			resolved, err := sandboxStore.ResolveSessionForRun(
				ctx, request.RunID, *request.SessionRef, request.TargetID,
				request.ExpectedRevision, request.SessionScopeDigest,
			)
			if err != nil || resolved != wantToken {
				t.Fatalf("turn %s resolved token = %q, err=%v, want %q",
					request.RunID, resolved, err, wantToken)
			}
			resolvedToken = &resolved
		}
		ref := successorByRun[request.RunID]
		return appendSessionIntegrationBridgeCompleted(
			t, sandboxStore, request, resolvedToken, ref, tokenByRef[ref],
		), nil
	}
	engine := newEngine(t, core, sandbox, clock)

	for index, runID := range runIDs {
		run := ingestSessionIntegrationRunAt(
			t, core, runID, "event_real_turn_"+string(rune('1'+index)), startedAt,
		)
		result, claimed, err := engine.DispatchOne(ctx)
		if err != nil || !claimed || !result.Finished || result.RunID != runID ||
			result.CoreState != corestore.RunCompleted {
			t.Fatalf("turn %d dispatch = %#v, claimed=%v, err=%v",
				index+1, result, claimed, err)
		}
		current, found, err := core.GetSession(ctx, sessionKeyForRun(run))
		if err != nil || !found || current.Ref != sessionRefs[index] {
			t.Fatalf("turn %d Core pointer = %#v, found=%v, err=%v",
				index+1, current, found, err)
		}
		clock.Advance(time.Minute)
	}

	starts := sandbox.Starts()
	if len(starts) != len(runIDs) {
		t.Fatalf("StartRun calls = %d, want %d", len(starts), len(runIDs))
	}
	for index := range starts {
		if index == 0 {
			if starts[index].SessionRef != nil {
				t.Fatalf("turn 1 unexpectedly resumed %q", *starts[index].SessionRef)
			}
			continue
		}
		if starts[index].SessionRef == nil || *starts[index].SessionRef != sessionRefs[index-1] {
			t.Fatalf("turn %d parent = %#v, want %q",
				index+1, starts[index].SessionRef, sessionRefs[index-1])
		}
	}

	sandboxDB, err := sql.Open("sqlite", sandboxPath)
	if err != nil {
		t.Fatal(err)
	}
	defer sandboxDB.Close()
	var lineageStart, lineageExpiry int64
	for index, ref := range sessionRefs {
		var parent sql.NullString
		var createdBy string
		var startedAt, expiresAt, turn int64
		if err := sandboxDB.QueryRow(`SELECT parent_session_ref, created_by_run_id,
            lineage_started_at_unix_ms, expires_at_unix_ms, turn_number
            FROM sessions WHERE session_ref = ?`, ref).Scan(
			&parent, &createdBy, &startedAt, &expiresAt, &turn,
		); err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			lineageStart, lineageExpiry = startedAt, expiresAt
			if parent.Valid {
				t.Fatalf("turn 1 parent = %q, want NULL", parent.String)
			}
		} else if !parent.Valid || parent.String != sessionRefs[index-1] {
			t.Fatalf("turn %d lineage parent = %#v, want %q",
				index+1, parent, sessionRefs[index-1])
		}
		if createdBy != runIDs[index] || startedAt != lineageStart ||
			expiresAt != lineageExpiry || turn != int64(index+1) {
			t.Fatalf("turn %d lineage = creator:%q start:%d expiry:%d turn:%d",
				index+1, createdBy, startedAt, expiresAt, turn)
		}
		var successors, completions int
		if err := sandboxDB.QueryRow(`SELECT COUNT(*) FROM sessions
            WHERE created_by_run_id = ?`, runIDs[index]).Scan(&successors); err != nil {
			t.Fatal(err)
		}
		if err := sandboxDB.QueryRow(`SELECT COUNT(*) FROM run_events
            WHERE run_id = ? AND event_type = 'completed' AND result_session_ref = ?`,
			runIDs[index], ref).Scan(&completions); err != nil {
			t.Fatal(err)
		}
		if successors != 1 || completions != 1 {
			t.Fatalf("turn %d durable successor/completion = %d/%d, want 1/1",
				index+1, successors, completions)
		}
	}
	for index := 0; index < len(sessionRefs)-1; index++ {
		var uses int
		if err := sandboxDB.QueryRow(`SELECT COUNT(*) FROM session_uses
            WHERE session_ref = ? AND run_id = ?`, sessionRefs[index], runIDs[index+1]).Scan(&uses); err != nil {
			t.Fatal(err)
		}
		if uses != 1 {
			t.Fatalf("turn %d parent use = %d, want exactly 1", index+1, uses)
		}
	}
	var allUses int
	if err := sandboxDB.QueryRow(`SELECT COUNT(*) FROM session_uses`).Scan(&allUses); err != nil {
		t.Fatal(err)
	}
	if allUses != 2 {
		t.Fatalf("session use count = %d, want exactly 2", allUses)
	}

	coreDB, err := sql.Open("sqlite", corePath)
	if err != nil {
		t.Fatal(err)
	}
	defer coreDB.Close()
	var deliveries, distinctRuns int
	if err := coreDB.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT run_id)
        FROM text_deliveries`).Scan(&deliveries, &distinctRuns); err != nil {
		t.Fatal(err)
	}
	if deliveries != 3 || distinctRuns != 3 {
		t.Fatalf("Core deliveries = %d across %d Runs, want exactly 3/3",
			deliveries, distinctRuns)
	}
}

func TestRealStoresConsumedFailedResumeReopenClosedFailsWithoutFreshFallback(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{now: baseTime}
	core, corePath, coreOptions := openCoreStore(t, clock, &tokenSequence{})
	sandboxPath := filepath.Join(t.TempDir(), "sandbox.sqlite3")
	sandboxStore, service := openSessionIntegrationSandbox(t, sandboxPath, clock)

	firstRun := ingestSessionIntegrationRun(t, core, "run_real_failed_resume", "event_real_failed_resume")
	const parentRef = "session_real_failed_parent"
	seedSessionIntegrationParent(t, service, sandboxStore, firstRun, parentRef, "vendor-real-failed-parent")
	if err := core.PutSession(ctx, corestore.Session{
		SessionKey: sessionKeyForRun(firstRun), Ref: parentRef,
	}); err != nil {
		t.Fatal(err)
	}

	failing := &committedServiceSandbox{service: service}
	failing.afterSave = func(
		_ context.Context,
		request executionwire.StartRunRequest,
		_ executionwire.RunStatus,
	) (executionwire.RunStatus, error) {
		return appendSessionIntegrationInvalidFailure(t, sandboxStore, request.RunID), nil
	}
	firstEngine := newEngine(t, core, failing, clock)
	first, claimed, err := firstEngine.DispatchOne(ctx)
	if err != nil || !claimed || !first.Finished || first.CoreState != corestore.RunFailed {
		t.Fatalf("consumed failed resume = %#v, claimed=%v, err=%v", first, claimed, err)
	}
	storedFirst, err := core.GetRun(ctx, firstRun.ID)
	if err != nil || storedFirst.FailureCode == nil ||
		*storedFirst.FailureCode != corestore.RunFailureInvalidSession {
		t.Fatalf("first Core failure = %#v, err=%v", storedFirst, err)
	}
	current, found, err := core.GetSession(ctx, sessionKeyForRun(firstRun))
	if err != nil || !found || current.Ref != parentRef {
		t.Fatalf("retained failed parent = %#v, found=%v, err=%v", current, found, err)
	}

	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sandboxStore.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedCoreStore, err := corestore.Open(ctx, corePath, coreOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedCoreStore.Close()
	reopenedCore := &testCoreStore{Store: reopenedCoreStore, path: corePath}
	reopenedSandbox, reopenedService := openSessionIntegrationSandbox(t, sandboxPath, clock)
	defer reopenedSandbox.Close()

	secondRun := ingestSessionIntegrationRun(
		t, reopenedCore, "run_real_stale_pointer", "event_real_stale_pointer",
	)
	closed := &committedServiceSandbox{service: reopenedService}
	secondEngine := newEngine(t, reopenedCore, closed, clock)
	second, claimed, err := secondEngine.DispatchOne(ctx)
	if err != nil || !claimed || !second.Finished || second.CoreState != corestore.RunFailed {
		t.Fatalf("stale pointer dispatch = %#v, claimed=%v, err=%v", second, claimed, err)
	}
	storedSecond, err := reopenedCore.GetRun(ctx, secondRun.ID)
	if err != nil || storedSecond.FailureCode == nil ||
		*storedSecond.FailureCode != corestore.RunFailureInvalidSession {
		t.Fatalf("stale pointer Core failure = %#v, err=%v", storedSecond, err)
	}
	starts := closed.Starts()
	if len(starts) != 1 || starts[0].SessionRef == nil || *starts[0].SessionRef != parentRef {
		t.Fatalf("stale pointer StartRun attempts = %#v, want one resume and no fresh fallback", starts)
	}
	current, found, err = reopenedCore.GetSession(ctx, sessionKeyForRun(secondRun))
	if err != nil || !found || current.Ref != parentRef {
		t.Fatalf("stale Core pointer after reopen failure = %#v, found=%v, err=%v", current, found, err)
	}
}
