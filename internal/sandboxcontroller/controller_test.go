package sandboxcontroller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/runnerbridge"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func insertQueueHorizonFixture(
	t *testing.T,
	databasePath string,
	manifest targetmanifest.Manifest,
	parent executionwire.StartRunRequest,
	child executionwire.StartRunRequest,
	parentRef string,
	parentToken string,
	lineageStartedAt int64,
	expiresAt int64,
) {
	t.Helper()
	// Use explicit logical milliseconds instead of sleeping near a wall-clock
	// boundary. The real v7 schema and triggers remain enabled, and the child
	// Run plus parent use commit in the same transaction as durable admission.
	database, err := sql.Open(
		"sqlite",
		databasePath+"?_txlock=immediate&_pragma=foreign_keys(ON)&_pragma=recursive_triggers(ON)",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	insertAccepted := func(request executionwire.StartRunRequest, turn, createdAt int64) {
		t.Helper()
		fingerprint, fingerprintErr := executionwire.StartRunFingerprint(request)
		if fingerprintErr != nil {
			t.Fatal(fingerprintErr)
		}
		inputDigest := sha256.Sum256([]byte(request.Input.Text))
		if _, insertErr := tx.Exec(`INSERT INTO runs(
            run_id, request_fingerprint, target_id, target_revision,
            workspace_id, writable, input_sha256, requested_session_ref,
            session_scope_digest, session_mode, session_max_age_seconds,
            session_max_turns, session_turn_number, deadline_unix_ms,
            state, last_event_seq, created_at_unix_ms, updated_at_unix_ms
        ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, 'opaque_resume', ?, ?, ?, ?,
                  'accepted', 0, ?, ?)`,
			request.RunID, fingerprint, request.TargetID, request.ExpectedRevision,
			manifest.WorkspaceRef, fmt.Sprintf("%x", inputDigest), request.SessionRef,
			request.SessionScopeDigest, manifest.Limits.MaxSessionAgeSeconds,
			manifest.Limits.MaxSessionTurns, turn, request.Deadline.UnixMilli(),
			createdAt, createdAt,
		); insertErr != nil {
			t.Fatalf("insert accepted Run %s: %v", request.RunID, insertErr)
		}
	}

	insertAccepted(parent, 1, lineageStartedAt)
	if _, err := tx.Exec(`INSERT INTO run_events(
        run_id, seq, event_type, created_at_unix_ms
    ) VALUES (?, 1, 'started', ?)`, parent.RunID, lineageStartedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE runs SET state = 'running', last_event_seq = 1,
        updated_at_unix_ms = ? WHERE run_id = ?`, lineageStartedAt, parent.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO sessions(
        session_ref, target_id, target_revision, session_scope_digest,
        vendor_token, parent_session_ref, created_by_run_id,
        lineage_started_at_unix_ms, expires_at_unix_ms, turn_number,
        created_at_unix_ms
    ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, 1, ?)`,
		parentRef, parent.TargetID, parent.ExpectedRevision, parent.SessionScopeDigest,
		parentToken, parent.RunID, lineageStartedAt, expiresAt, lineageStartedAt,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO run_events(
        run_id, seq, event_type, message_text, output_media_type,
        result_session_ref, created_at_unix_ms
    ) VALUES (?, 2, 'completed', 'parent ready', 'text/plain', ?, ?)`,
		parent.RunID, parentRef, lineageStartedAt,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE runs SET state = 'completed', last_event_seq = 2,
        output_media_type = 'text/plain', output_text = 'parent ready',
        result_session_ref = ?, updated_at_unix_ms = ?, terminal_at_unix_ms = ?
        WHERE run_id = ?`, parentRef, lineageStartedAt, lineageStartedAt, parent.RunID); err != nil {
		t.Fatal(err)
	}

	admittedAt := expiresAt - 1
	insertAccepted(child, 2, admittedAt)
	if _, err := tx.Exec(`INSERT INTO session_uses(
        session_ref, run_id, used_at_unix_ms
    ) VALUES (?, ?, ?)`, parentRef, child.RunID, admittedAt); err != nil {
		t.Fatalf("insert expiry-minus-one admission: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestControllerCompletesDelegatesGetAndNeverPersistsPrompt(t *testing.T) {
	manifest := controllerManifest(
		"target-basic", "target-basic-r1", "workspace-basic",
		targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	controller := newTestController(t, dependencies, runtime, completeBridge)
	secret := "UNIQUE_PROMPT_MUST_NOT_REACH_SQLITE_7d25d41f"
	request := controllerRequest("run_basic", manifest, secret)

	status, err := controller.StartRun(context.Background(), request)
	if err != nil {
		t.Fatalf("StartRun() error = %v", err)
	}
	if status.RunID != request.RunID || status.State != executionwire.RunStateAccepted {
		t.Fatalf("StartRun() status = %#v", status)
	}
	run := awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
		return run.State == executionwire.RunStateCompleted && run.RuntimeRef == nil && !run.WorkspaceLockHeld
	})
	if run.Output == nil || run.Output.Text != "done" {
		t.Fatalf("durable output = %#v", run.Output)
	}

	response, err := controller.GetRun(context.Background(), executionwire.GetRunRequest{RunID: request.RunID})
	if err != nil {
		t.Fatalf("GetRun() error = %v", err)
	}
	if response.Status.State != executionwire.RunStateCompleted || len(response.Events) != 2 {
		t.Fatalf("GetRun() response = %#v", response)
	}

	database, err := os.ReadFile(dependencies.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(database, []byte(secret)) {
		t.Fatal("SQLite database contains the full prompt")
	}
}

func TestOfferQueueDedupeFullAndDurableReoffer(t *testing.T) {
	manifest := controllerManifest(
		"target-queue", "target-queue-r1", "workspace-queue",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	active := make(chan struct{})
	release := make(chan struct{})
	var activeOnce sync.Once
	bridge := func(
		ctx context.Context,
		request executionwire.StartRunRequest,
		manifest targetmanifest.Manifest,
		token *string,
		output io.Reader,
		input io.Writer,
		sink runnerbridge.Sink,
	) error {
		if request.RunID == "run_queue_1" {
			if err := sink(ctx, startedEmission(request.RunID)); err != nil {
				return err
			}
			activeOnce.Do(func() { close(active) })
			select {
			case <-release:
				return sink(ctx, completedEmission(request.RunID, 2, "done", nil))
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return completeBridge(ctx, request, manifest, token, output, input, sink)
	}
	controller := newTestController(t, dependencies, runtime, bridge, WithQueueCapacity(1))
	first := controllerRequest("run_queue_1", manifest, "first")
	second := controllerRequest("run_queue_2", manifest, "second")
	third := controllerRequest("run_queue_3", manifest, "third")
	second.SessionScopeDigest = strings.Repeat("b", 64)
	third.SessionScopeDigest = strings.Repeat("c", 64)

	if _, err := controller.StartRun(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	select {
	case <-active:
	case <-time.After(time.Second):
		t.Fatal("first run did not become active")
	}
	if _, err := controller.StartRun(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if err := controller.Offer(context.Background(), second); err != nil {
		t.Fatalf("duplicate Offer() error = %v", err)
	}
	if _, err := controller.StartRun(context.Background(), third); serviceErrorCode(err) != executionhttp.ErrorUnavailable {
		t.Fatalf("queue-full StartRun() error = %v", err)
	}
	thirdRun, err := dependencies.store.GetRun(context.Background(), third.RunID)
	if err != nil || thirdRun.State != executionwire.RunStateAccepted {
		t.Fatalf("durable queue-full run = %#v, %v", thirdRun, err)
	}

	close(release)
	awaitTerminal(t, dependencies.store, first.RunID)
	awaitTerminal(t, dependencies.store, second.RunID)
	if err := controller.Offer(context.Background(), third); err != nil {
		t.Fatalf("response-loss re-Offer() error = %v", err)
	}
	if run := awaitTerminal(t, dependencies.store, third.RunID); run.State != executionwire.RunStateCompleted {
		t.Fatalf("re-offered run = %#v", run)
	}
}

func TestCancelQueuedAndQueueFullRunsDoesNotWaitForActiveExecution(t *testing.T) {
	manifest := controllerManifest(
		"target-cancel-queue", "target-cancel-queue-r1", "workspace-cancel-queue",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	active := make(chan struct{})
	release := make(chan struct{})
	bridge := func(
		ctx context.Context,
		request executionwire.StartRunRequest,
		_ targetmanifest.Manifest,
		_ *string,
		_ io.Reader,
		_ io.Writer,
		sink runnerbridge.Sink,
	) error {
		if err := sink(ctx, startedEmission(request.RunID)); err != nil {
			return err
		}
		if request.RunID == "run_cancel_active_blocker" {
			close(active)
			select {
			case <-release:
				return sink(ctx, completedEmission(request.RunID, 2, "done", nil))
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return sink(ctx, completedEmission(request.RunID, 2, "done", nil))
	}
	controller := newTestController(t, dependencies, runtime, bridge, WithQueueCapacity(1))
	blocker := controllerRequest("run_cancel_active_blocker", manifest, "block")
	queued := controllerRequest("run_cancel_queued", manifest, "queued")
	detached := controllerRequest("run_cancel_detached", manifest, "detached")
	queued.SessionScopeDigest = strings.Repeat("b", 64)
	detached.SessionScopeDigest = strings.Repeat("c", 64)
	if _, err := controller.StartRun(context.Background(), blocker); err != nil {
		t.Fatal(err)
	}
	select {
	case <-active:
	case <-time.After(time.Second):
		t.Fatal("blocker did not become active")
	}
	if _, err := controller.StartRun(context.Background(), queued); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.StartRun(context.Background(), detached); serviceErrorCode(err) != executionhttp.ErrorUnavailable {
		t.Fatalf("queue-full error = %v", err)
	}

	for _, runID := range []string{queued.RunID, detached.RunID} {
		status, err := controller.CancelRun(context.Background(), executionwire.CancelRunRequest{RunID: runID})
		if err != nil || status.State != executionwire.RunStateCancelling {
			t.Fatalf("CancelRun(%q) = %#v, %v", runID, status, err)
		}
	}
	for _, runID := range []string{queued.RunID, detached.RunID} {
		run := awaitTerminal(t, dependencies.store, runID)
		if run.State != executionwire.RunStateCancelled {
			t.Fatalf("cancelled detached run = %#v", run)
		}
	}
	for _, call := range runtime.callSnapshot() {
		if call == "create:"+queued.RunID || call == "create:"+detached.RunID {
			t.Fatalf("cancellation launched a new runtime: calls=%v", runtime.callSnapshot())
		}
	}
	close(release)
}

func TestActiveCancelBecomesCancelledAndCleansRuntime(t *testing.T) {
	manifest := controllerManifest(
		"target-active-cancel", "target-active-cancel-r1", "workspace-active-cancel",
		targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	started := make(chan struct{})
	bridge := func(
		ctx context.Context,
		request executionwire.StartRunRequest,
		_ targetmanifest.Manifest,
		_ *string,
		_ io.Reader,
		_ io.Writer,
		sink runnerbridge.Sink,
	) error {
		if err := sink(ctx, startedEmission(request.RunID)); err != nil {
			return err
		}
		close(started)
		<-ctx.Done()
		return &runnerbridge.BridgeError{Class: runnerbridge.ErrorCancelled}
	}
	controller := newTestController(t, dependencies, runtime, bridge)
	request := controllerRequest("run_active_cancel", manifest, "cancel me")
	if _, err := controller.StartRun(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("run did not start")
	}
	if _, err := controller.CancelRun(context.Background(), executionwire.CancelRunRequest{RunID: request.RunID}); err != nil {
		t.Fatal(err)
	}
	run := awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
		return run.State == executionwire.RunStateCancelled && run.RuntimeRef == nil && !run.WorkspaceLockHeld
	})
	if run.Failure != nil {
		t.Fatalf("cancelled run has failure = %#v", run.Failure)
	}
}

func TestSessionMappingIsScopedAndVendorTokenNeverCrossesExecutionWire(t *testing.T) {
	firstManifest := controllerManifest(
		"target-session", "target-session-r1", "workspace-session",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionOpaqueResume,
	)
	otherManifest := controllerManifest(
		"target-session-other", "target-session-other-r1", "workspace-session-other",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionOpaqueResume,
	)
	dependencies := newTestDependencies(t, firstManifest, otherManifest)
	runtime := newFakeRuntime()
	resolved := make(chan string, 1)
	bridge := func(
		ctx context.Context,
		request executionwire.StartRunRequest,
		_ targetmanifest.Manifest,
		token *string,
		_ io.Reader,
		_ io.Writer,
		sink runnerbridge.Sink,
	) error {
		if token != nil {
			resolved <- *token
		}
		if err := sink(ctx, startedEmission(request.RunID)); err != nil {
			return err
		}
		vendor := "vendor-private-token-" + request.RunID
		return sink(ctx, completedEmission(request.RunID, 2, "done", &vendor))
	}
	var generated atomic.Uint32
	controller := newTestController(
		t, dependencies, runtime, bridge,
		WithSessionRefGenerator(func() (string, error) {
			return fmt.Sprintf("session_ref_%d", generated.Add(1)), nil
		}),
	)
	first := controllerRequest("run_session_1", firstManifest, "new session")
	if _, err := controller.StartRun(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	firstRun := awaitTerminal(t, dependencies.store, first.RunID)
	if firstRun.ResultSessionRef == nil || *firstRun.ResultSessionRef != "session_ref_1" {
		t.Fatalf("external session ref = %#v", firstRun.ResultSessionRef)
	}
	vendor := "vendor-private-token-" + first.RunID
	snapshot, err := controller.GetRun(context.Background(), executionwire.GetRunRequest{RunID: first.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%#v", snapshot), "vendor-private-token") {
		t.Fatalf("execution snapshot leaked vendor token: %#v", snapshot)
	}

	second := controllerRequest("run_session_2", firstManifest, "resume")
	second.SessionRef = firstRun.ResultSessionRef
	if _, err := controller.StartRun(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if _, err := dependencies.store.ResolveSessionForRun(
		context.Background(), second.RunID, *firstRun.ResultSessionRef,
		otherManifest.ID, otherManifest.Revision, first.SessionScopeDigest,
	); !errors.Is(err, sandboxstore.ErrSessionScope) {
		t.Fatalf("cross-scope ResolveSessionForRun() error = %v", err)
	}
	awaitTerminal(t, dependencies.store, second.RunID)
	select {
	case got := <-resolved:
		if got != vendor {
			t.Fatalf("resolved vendor token = %q, want %q", got, vendor)
		}
	case <-time.After(time.Second):
		t.Fatal("resume token was not passed to the bridge")
	}
}

func TestControllerQueueHorizonKeepsDurableAdmissionAuthoritative(t *testing.T) {
	resumeManifest := controllerManifest(
		"target-session-horizon", "target-session-horizon-r1", "workspace-session-horizon",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionOpaqueResume,
	)
	resumeManifest.Limits.MaxSessionAgeSeconds = 1
	blockerManifest := controllerManifest(
		"target-session-horizon-blocker", "target-session-horizon-blocker-r1",
		"workspace-session-horizon-blocker",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, resumeManifest, blockerManifest)

	const (
		parentRef       = "session_queue_horizon_parent"
		parentToken     = "vendor-queue-horizon-parent"
		successorRef    = "session_queue_horizon_successor"
		successorToken  = "vendor-queue-horizon-successor"
		parentRunID     = "run_queue_horizon_parent"
		admittedRunID   = "run_queue_horizon_admitted"
		blockerRunID    = "run_queue_horizon_blocker"
		nextRunID       = "run_queue_horizon_next"
		lineageDuration = int64(time.Second / time.Millisecond)
	)
	wallNow := time.Now().UTC().Truncate(time.Millisecond)
	lineageStartedAt := wallNow.Add(-3 * time.Second).UnixMilli()
	expiresAt := lineageStartedAt + lineageDuration
	admittedAt := expiresAt - 1

	parent := controllerRequest(parentRunID, resumeManifest, "establish horizon parent")
	parent.Deadline = time.UnixMilli(admittedAt).Add(time.Hour)
	child := controllerRequest(admittedRunID, resumeManifest, "resume before horizon")
	child.Deadline = parent.Deadline
	childParentRef := parentRef
	child.SessionRef = &childParentRef
	insertQueueHorizonFixture(
		t, dependencies.dbPath, resumeManifest, parent, child,
		parentRef, parentToken, lineageStartedAt, expiresAt,
	)

	var controllerNow atomic.Int64
	controllerNow.Store(admittedAt)
	blockerActive := make(chan struct{})
	releaseBlocker := make(chan struct{})
	var activeOnce, releaseOnce sync.Once
	observedToken := make(chan struct {
		value string
		at    int64
	}, 1)
	bridge := func(
		ctx context.Context,
		request executionwire.StartRunRequest,
		manifest targetmanifest.Manifest,
		token *string,
		_ io.Reader,
		_ io.Writer,
		sink runnerbridge.Sink,
	) error {
		if request.RunID == blockerRunID {
			activeOnce.Do(func() { close(blockerActive) })
			select {
			case <-releaseBlocker:
			case <-ctx.Done():
				return ctx.Err()
			}
			return completeBridge(ctx, request, manifest, token, nil, nil, sink)
		}
		value := ""
		if token != nil {
			value = *token
		}
		observedToken <- struct {
			value string
			at    int64
		}{value: value, at: controllerNow.Load()}
		if err := sink(ctx, startedEmission(request.RunID)); err != nil {
			return err
		}
		nextToken := successorToken
		return sink(ctx, completedEmission(request.RunID, 2, "resumed", &nextToken))
	}
	controller := newTestController(
		t, dependencies, newFakeRuntime(), bridge,
		WithClock(func() time.Time {
			return time.UnixMilli(controllerNow.Load()).UTC()
		}),
		WithSessionRefGenerator(func() (string, error) { return successorRef, nil }),
	)
	defer releaseOnce.Do(func() { close(releaseBlocker) })

	blocker := controllerRequest(blockerRunID, blockerManifest, "hold single worker")
	if _, err := controller.StartRun(context.Background(), blocker); err != nil {
		t.Fatalf("start blocker: %v", err)
	}
	select {
	case <-blockerActive:
	case <-time.After(time.Second):
		t.Fatal("blocker did not hold the controller worker")
	}
	status, err := controller.StartRun(context.Background(), child)
	if err != nil || status.RunID != child.RunID || status.State != executionwire.RunStateAccepted {
		t.Fatalf("re-offer admitted Run = %#v, err=%v", status, err)
	}

	controllerNow.Store(expiresAt + 1)
	releaseOnce.Do(func() { close(releaseBlocker) })
	childRun := awaitRun(t, dependencies.store, child.RunID, func(run sandboxstore.Run) bool {
		return run.State == executionwire.RunStateCompleted && run.RuntimeRef == nil &&
			!run.RuntimeIntentPending
	})
	if childRun.State != executionwire.RunStateCompleted || childRun.ResultSessionRef == nil ||
		*childRun.ResultSessionRef != successorRef {
		t.Fatalf("post-horizon child = %#v", childRun)
	}
	select {
	case observed := <-observedToken:
		if observed.value != parentToken || observed.at <= expiresAt {
			t.Fatalf("post-horizon resolved token = %q at %d, want %q after %d",
				observed.value, observed.at, parentToken, expiresAt)
		}
	case <-time.After(time.Second):
		t.Fatal("controller did not resolve the admitted session")
	}

	database, err := sql.Open("sqlite", dependencies.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var lineageParent string
	var successorOrigin, successorExpiry, successorCreated, successorTurn int64
	var successorCreator string
	if err := database.QueryRow(`SELECT parent_session_ref,
        lineage_started_at_unix_ms, expires_at_unix_ms, created_at_unix_ms,
        turn_number, created_by_run_id
		FROM sessions WHERE session_ref = ?`, successorRef).Scan(
		&lineageParent, &successorOrigin, &successorExpiry, &successorCreated,
		&successorTurn, &successorCreator,
	); err != nil {
		t.Fatal(err)
	}
	if lineageParent != parentRef || successorOrigin != lineageStartedAt ||
		successorExpiry != expiresAt || successorCreated < expiresAt ||
		successorTurn != 2 || successorCreator != child.RunID {
		t.Fatalf("dead-on-arrival successor = parent:%q origin:%d expiry:%d created:%d turn:%d creator:%q",
			lineageParent, successorOrigin, successorExpiry, successorCreated,
			successorTurn, successorCreator)
	}

	next := controllerRequest(nextRunID, resumeManifest, "resume expired successor")
	nextSessionRef := successorRef
	next.SessionRef = &nextSessionRef
	if _, err := dependencies.durable.StartRun(context.Background(), next); serviceErrorCode(err) != executionhttp.ErrorInvalidSession {
		t.Fatalf("next admission after inherited expiry error = %v", err)
	}
}

func TestValidRunnerTerminalWinsCancellationRace(t *testing.T) {
	manifest := controllerManifest(
		"target-terminal-race", "target-terminal-race-r1", "workspace-terminal-race",
		targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
	)
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	started := make(chan struct{})
	complete := make(chan struct{})
	bridge := func(
		ctx context.Context,
		request executionwire.StartRunRequest,
		_ targetmanifest.Manifest,
		_ *string,
		_ io.Reader,
		_ io.Writer,
		sink runnerbridge.Sink,
	) error {
		if err := sink(context.Background(), startedEmission(request.RunID)); err != nil {
			return err
		}
		close(started)
		<-complete
		if err := sink(context.Background(), completedEmission(request.RunID, 2, "won", nil)); err != nil {
			return err
		}
		return &runnerbridge.BridgeError{Class: runnerbridge.ErrorCancelled}
	}
	controller := newTestController(t, dependencies, runtime, bridge)
	request := controllerRequest("run_terminal_race", manifest, "race")
	if _, err := controller.StartRun(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := controller.CancelRun(context.Background(), executionwire.CancelRunRequest{RunID: request.RunID}); err != nil {
		t.Fatal(err)
	}
	close(complete)
	run := awaitTerminal(t, dependencies.store, request.RunID)
	if run.State != executionwire.RunStateCompleted || run.Output == nil || run.Output.Text != "won" {
		t.Fatalf("terminal race result = %#v", run)
	}
}

func TestEveryBridgeFailureClassMapsToFixedRedactedTerminal(t *testing.T) {
	tests := []struct {
		name    string
		class   runnerbridge.ErrorClass
		state   executionwire.RunState
		code    executionwire.FailureCode
		message string
	}{
		{"protocol", runnerbridge.ErrorProtocolViolation, executionwire.RunStateFailed, executionwire.FailureProtocolViolation, messageProtocolViolation},
		{"runner", runnerbridge.ErrorRunnerFailed, executionwire.RunStateFailed, executionwire.FailureRunnerFailed, messageRunnerFailed},
		{"session", runnerbridge.ErrorInvalidSession, executionwire.RunStateFailed, executionwire.FailureInvalidSession, messageInvalidSession},
		{"policy", runnerbridge.ErrorPolicyDenied, executionwire.RunStateFailed, executionwire.FailurePolicyDenied, messagePolicyDenied},
		{"deadline", runnerbridge.ErrorDeadline, executionwire.RunStateFailed, executionwire.FailureDeadlineExceeded, messageDeadline},
		{"output", runnerbridge.ErrorOutputLimit, executionwire.RunStateFailed, executionwire.FailureOutputLimit, messageOutputLimit},
		{"cancelled_without_authority", runnerbridge.ErrorCancelled, executionwire.RunStateInterrupted, executionwire.FailureRuntimeInterrupted, messageInterrupted},
		{"internal", runnerbridge.ErrorInternal, executionwire.RunStateFailed, executionwire.FailureInternal, messageInternal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := controllerManifest(
				"target-failure-"+test.name, "target-failure-r1", "workspace-failure-"+test.name,
				targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
			)
			dependencies := newTestDependencies(t, manifest)
			runtime := newFakeRuntime()
			bridge := func(
				context.Context,
				executionwire.StartRunRequest,
				targetmanifest.Manifest,
				*string,
				io.Reader,
				io.Writer,
				runnerbridge.Sink,
			) error {
				return fmt.Errorf("DO_NOT_LEAK_BRIDGE_SECRET: %w", &runnerbridge.BridgeError{Class: test.class})
			}
			controller := newTestController(t, dependencies, runtime, bridge)
			request := controllerRequest("run_failure_"+test.name, manifest, "secret prompt")
			if _, err := controller.StartRun(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			run := awaitTerminal(t, dependencies.store, request.RunID)
			if run.State != test.state || run.Failure == nil ||
				run.Failure.Code != test.code || run.Failure.Message != test.message {
				t.Fatalf("mapped run = %#v", run)
			}
			if strings.Contains(run.Failure.Message, "SECRET") || strings.Contains(run.Failure.Message, "stderr") {
				t.Fatalf("failure leaked private cause: %#v", run.Failure)
			}
		})
	}
}

func TestCleanupOrderingRemoveResponseLossAndBlockedWait(t *testing.T) {
	t.Run("removing state converges within one budget", func(t *testing.T) {
		manifest := controllerManifest(
			"target-removing", "target-removing-r1", "workspace-removing",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		runtime := newFakeRuntime()
		var inspections atomic.Int32
		runtime.inspectFn = func(context.Context, string) (dockerruntime.Inspection, error) {
			if inspections.Add(1) <= 2 {
				return dockerruntime.Inspection{State: dockerruntime.StateRemoving}, nil
			}
			return dockerruntime.Inspection{}, dockerruntime.ErrNotFound
		}
		controller := newTestController(t, dependencies, runtime, completeBridge)
		request := controllerRequest("run_removing", manifest, "cleanup")
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return run.State == executionwire.RunStateCompleted && run.RuntimeRef == nil && !run.WorkspaceLockHeld
		})
		if inspections.Load() < 3 {
			t.Fatalf("removing state inspections = %d", inspections.Load())
		}
	})

	t.Run("stop gets a bounded convergence grace", func(t *testing.T) {
		manifest := controllerManifest(
			"target-stop-grace", "target-stop-grace-r1", "workspace-stop-grace",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		runtime := newFakeRuntime()
		runtime.stopLeavesRunning = true
		var inspections atomic.Int32
		runtime.inspectFn = func(context.Context, string) (dockerruntime.Inspection, error) {
			switch inspections.Add(1) {
			case 1, 2:
				return dockerruntime.Inspection{State: dockerruntime.StateRunning}, nil
			default:
				return dockerruntime.Inspection{State: dockerruntime.StateExited}, nil
			}
		}
		controller := newTestController(t, dependencies, runtime, completeBridge)
		request := controllerRequest("run_stop_grace", manifest, "cleanup")
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return run.State == executionwire.RunStateCompleted && run.RuntimeRef == nil
		})
		if containsCall(runtime.callSnapshot(), "kill:") {
			t.Fatalf("cleanup escalated before stop convergence: %v", runtime.callSnapshot())
		}
	})

	t.Run("stop kill remove ordering", func(t *testing.T) {
		manifest := controllerManifest(
			"target-cleanup-order", "target-cleanup-order-r1", "workspace-cleanup-order",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		runtime := newFakeRuntime()
		runtime.stopLeavesRunning = true
		controller := newTestController(t, dependencies, runtime, completeBridge)
		request := controllerRequest("run_cleanup_order", manifest, "cleanup")
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return run.State == executionwire.RunStateCompleted && run.RuntimeRef == nil
		})
		ref := fakeContainerRef(request.RunID)
		want := []string{
			"list-managed",
			"create:" + request.RunID,
			"attach:" + ref,
			"stop:" + ref,
			"kill:" + ref,
			"remove:" + ref,
		}
		calls := runtime.callSnapshot()
		got := make([]string, 0, len(calls))
		inspectionCount := 0
		for _, call := range calls {
			if call == "inspect:"+ref {
				inspectionCount++
				continue
			}
			got = append(got, call)
		}
		if !reflect.DeepEqual(got, want) || inspectionCount < 3 {
			t.Fatalf("runtime calls = %v, significant=%v, want=%v", calls, got, want)
		}
	})

	t.Run("lost remove response is proven absent", func(t *testing.T) {
		manifest := controllerManifest(
			"target-remove-loss", "target-remove-loss-r1", "workspace-remove-loss",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		runtime := newFakeRuntime()
		runtime.removeResponseLost = true
		controller := newTestController(t, dependencies, runtime, completeBridge)
		request := controllerRequest("run_remove_loss", manifest, "cleanup")
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		run := awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return run.State == executionwire.RunStateCompleted && run.RuntimeRef == nil && !run.WorkspaceLockHeld
		})
		if run.RuntimeRef != nil {
			t.Fatalf("runtime ref retained = %#v", run.RuntimeRef)
		}
		ref := fakeContainerRef(request.RunID)
		calls := runtime.callSnapshot()
		if !containsCall(calls, "remove:"+ref) || len(calls) < 2 || calls[len(calls)-1] != "inspect:"+ref {
			t.Fatalf("remove response-loss calls = %v", calls)
		}
	})

	t.Run("lost remove response polls removing to absence", func(t *testing.T) {
		manifest := controllerManifest(
			"target-remove-removing", "target-remove-removing-r1", "workspace-remove-removing",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		runtime := newFakeRuntime()
		var removing atomic.Bool
		var removingInspections atomic.Int32
		runtime.inspectFn = func(context.Context, string) (dockerruntime.Inspection, error) {
			if !removing.Load() {
				return dockerruntime.Inspection{State: dockerruntime.StateExited}, nil
			}
			if removingInspections.Add(1) <= 2 {
				return dockerruntime.Inspection{State: dockerruntime.StateRemoving}, nil
			}
			return dockerruntime.Inspection{}, dockerruntime.ErrNotFound
		}
		runtime.removeFn = func(context.Context, string) error {
			removing.Store(true)
			return errors.New("private lost remove response")
		}
		controller := newTestController(t, dependencies, runtime, completeBridge)
		request := controllerRequest("run_remove_removing", manifest, "cleanup")
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return run.State == executionwire.RunStateCompleted && run.RuntimeRef == nil && !run.WorkspaceLockHeld
		})
		if removingInspections.Load() < 3 {
			t.Fatalf("post-remove inspections = %d", removingInspections.Load())
		}
	})

	t.Run("blocked process wait cannot block cleanup", func(t *testing.T) {
		manifest := controllerManifest(
			"target-wait", "target-wait-r1", "workspace-wait",
			targetmanifest.WorkspaceReadWrite, targetmanifest.SessionNewOnly,
		)
		dependencies := newTestDependencies(t, manifest)
		runtime := newFakeRuntime()
		wait := make(chan error)
		runtime.process = func() *fakeProcess {
			process := newFakeProcess()
			process.wait = wait
			return process
		}
		controller := newTestController(t, dependencies, runtime, completeBridge)
		request := controllerRequest("run_wait_blocked", manifest, "cleanup")
		if _, err := controller.StartRun(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		awaitRun(t, dependencies.store, request.RunID, func(run sandboxstore.Run) bool {
			return run.State == executionwire.RunStateCompleted && run.RuntimeRef == nil
		})
		close(wait)
	})
}

func TestTargetTimeoutCoversCreateBeforeBridge(t *testing.T) {
	manifest := controllerManifest(
		"target-timeout", "target-timeout-r1", "workspace-timeout",
		targetmanifest.WorkspaceReadOnly, targetmanifest.SessionNewOnly,
	)
	manifest.Limits.TimeoutSeconds = 1
	dependencies := newTestDependencies(t, manifest)
	runtime := newFakeRuntime()
	var creates atomic.Int32
	runtime.createFn = func(ctx context.Context, _ string, _ targetmanifest.Manifest) (string, error) {
		creates.Add(1)
		<-ctx.Done()
		return "", ctx.Err()
	}
	controller := newTestController(t, dependencies, runtime, completeBridge)
	request := controllerRequest("run_target_timeout", manifest, "timeout")
	request.Deadline = time.Now().UTC().Add(8 * time.Second)
	started := time.Now()
	if _, err := controller.StartRun(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	run := awaitTerminal(t, dependencies.store, request.RunID)
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("target timeout did not cover Create: %v", elapsed)
	}
	if run.State != executionwire.RunStateFailed || run.Failure == nil ||
		run.Failure.Code != executionwire.FailureDeadlineExceeded {
		t.Fatalf("timeout run = %#v", run)
	}
	if creates.Load() != 1 {
		t.Fatalf("Create calls = %d; LookupIntent must not create", creates.Load())
	}
}

func TestFrameClosingWriterClosesImmediatelyAfterOneJSONLFrame(t *testing.T) {
	underlying := &trackingWriteCloser{}
	writer := newFrameClosingWriter(underlying)
	if _, err := writer.Write([]byte(`{"type":"run.start",`)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(`"input":"line\\ninside"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	data, closed := underlying.snapshot()
	if !closed || !bytes.HasSuffix(data, []byte("\n")) {
		t.Fatalf("underlying frame = %q, closed=%v", data, closed)
	}
	if _, err := writer.Write([]byte("second\n")); !errors.Is(err, errRunnerInputClosed) {
		t.Fatalf("second frame error = %v", err)
	}
}

func serviceErrorCode(err error) executionhttp.ErrorCode {
	var serviceError *executionhttp.ServiceError
	if errors.As(err, &serviceError) && serviceError != nil {
		return serviceError.Code
	}
	return ""
}
