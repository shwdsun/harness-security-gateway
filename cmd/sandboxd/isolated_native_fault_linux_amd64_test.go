//go:build linux && amd64 && codexintegration

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxcontroller"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"golang.org/x/sys/unix"
)

func isolatedNativeFaultWithinWindow(now time.Time) bool {
	start := time.Date(2026, time.October, 6, 0, 0, 0, 0, time.UTC)
	return !now.Before(start) && now.Before(start.Add(24*time.Hour-1500*time.Second))
}

// These two operator-prepared, synthetic cases have no default activation or
// remote selector. The root supervisor independently binds its exact no-NIC VM.
func TestIsolatedServiceNativeFaults(t *testing.T) {
	if os.Getenv("HSG_V4_FAULT_PROBE") != "offline-vm-fault-v1" {
		t.Skip("requires the frozen dedicated fault VM")
	}
	if os.Getuid() != 1001 || os.Geteuid() != 1001 || !isolatedNativeFaultWithinWindow(time.Now()) {
		t.Fatal("fixed identity/fault window required")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("no-NIC guest required")
	}
	var plan isolatedNativePlan
	if isolatedNativeReadJSON("/opt/hgw-v4-acceptance/composed-plan.json", &plan, 65536) != nil || len(plan.Cases) != 2 {
		t.Fatal("frozen fault case inventory unavailable")
	}
	for i, tc := range plan.Cases {
		if tc.Name != []string{"catalog401", "cancel"}[i] {
			t.Fatal("fixed fault case order required")
		}
		if ok := t.Run(tc.Name, func(t *testing.T) {
			if tc.Name == "catalog401" {
				isolatedNativeRun(t, tc, plan.ProbeSHA256)
			} else {
				isolatedNativeCancel(t, tc, plan.ProbeSHA256)
			}
		}); !ok {
			break
		}
	}
}

type isolatedNativeRecoveryAck struct {
	Name, Nonce, RequestSHA256, HelperStartTime, HelperSHA256 string
	OwnerPID, HelperPID, Invocation                           int
	Force, RequestLatched, HelperPinned, Stable, Passed       bool
}

func isolatedNativeRecoveryAcknowledged(ack isolatedNativeRecoveryAck, tc isolatedNativeCase, requestHash string, ownerPID int) bool {
	start, err := strconv.ParseUint(ack.HelperStartTime, 10, 64)
	return err == nil && start > 0 && strconv.FormatUint(start, 10) == ack.HelperStartTime && len(requestHash) == 64 &&
		ack.Name == "cancel" && ack.Name == tc.Name && ack.Nonce == tc.Nonce && ack.RequestSHA256 == requestHash &&
		ack.OwnerPID == ownerPID && ack.HelperPID > 1 && ack.HelperPID != ownerPID && ack.Invocation == 2 &&
		ack.HelperSHA256 == codexprofile.CLIBinarySHA256V1 && ack.Force && ack.RequestLatched && ack.HelperPinned && ack.Stable && ack.Passed
}

type isolatedNativeRetirement struct {
	RunID, Ref                                                                    string
	Forwarded, Revoked, Occupied, LeaseHeld, WorkspaceHeld, Pending, SourceLocked bool
	OutputAbsent, Unpublished, Passed                                             bool
}

// A passive Store witness: observation failure is retained separately and never
// changes the original RevokeRunCredential return or releases source authority.
type isolatedNativeCancelStore struct {
	*isolatedReadyWitness
	root, database, slot, target, revision string
	generation                             int64
	mu                                     sync.Mutex
	retirement                             isolatedNativeRetirement
	observeErr                             error
	revokeCalls                            int
}

func (w *isolatedNativeCancelStore) RevokeRunCredential(ctx context.Context, id string) error {
	err := w.Store.RevokeRunCredential(ctx, id)
	w.mu.Lock()
	w.revokeCalls++
	w.mu.Unlock()
	if err != nil {
		return err
	}
	observe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	run, readErr := w.Store.GetRun(observe, id)
	w.isolatedReadyWitness.mu.Lock()
	ref := w.ref
	w.isolatedReadyWitness.mu.Unlock()
	retired, occupied, stateErr := isolatedNativeCredentialCounts(observe, w.database, id, w.slot, w.generation, w.target, w.revision)
	r := isolatedNativeRetirement{RunID: id, Ref: ref, Forwarded: true, Revoked: retired == 1, Occupied: occupied == 1,
		LeaseHeld: run.CredentialLeaseHeld, WorkspaceHeld: run.WorkspaceLockHeld, Pending: run.TerminalPending,
		SourceLocked: isolatedReadySourceLock(w.auth, true) == nil, OutputAbsent: run.Output == nil, Unpublished: run.TerminalAt == nil}
	r.Passed = readErr == nil && stateErr == nil && id == w.runID && ref != "" && run.RuntimeRef != nil && *run.RuntimeRef == ref &&
		r.Forwarded && r.Revoked && r.Occupied && r.LeaseHeld && r.WorkspaceHeld && r.Pending && r.SourceLocked && r.OutputAbsent && r.Unpublished
	writeErr := isolatedNativeWriteJSON(w.root+"/retirement.json", r)
	w.mu.Lock()
	w.retirement = r
	w.observeErr = errors.Join(w.observeErr, readErr, stateErr, writeErr)
	w.mu.Unlock()
	return err
}

// One read-only SQL snapshot includes exact target/generation joins. The live
// WAL participates normally; immutable=1 would incorrectly ignore live WAL.
func isolatedNativeCredentialCounts(ctx context.Context, path, runID, slot string, generation int64, target, revision string) (int, int, error) {
	u := url.URL{Scheme: "file", Path: path}
	u.RawQuery = url.Values{"mode": {"ro"}, "_pragma": {"query_only(1)", "trusted_schema(0)", "busy_timeout(1000)"}}.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return 0, 0, err
	}
	db.SetMaxOpenConns(1)
	var retired, occupied int
	err = db.QueryRowContext(ctx, `SELECT
(SELECT count(*) FROM credential_revocations v JOIN target_credentials t USING(slot_ref,generation)
 WHERE v.slot_ref=? AND v.generation=? AND t.target_id=? AND t.target_revision=?),
(SELECT count(*) FROM credential_occupancy o JOIN credential_generations g USING(slot_ref,generation)
 JOIN runs r ON r.run_id=o.run_id JOIN target_credentials t ON t.target_id=r.target_id AND t.target_revision=r.target_revision
 WHERE o.run_id=? AND o.slot_ref=? AND o.generation=? AND o.source_digest=g.source_digest
 AND t.slot_ref=g.slot_ref AND t.generation=g.generation AND r.target_id=? AND r.target_revision=?
 AND g.workspace_ref=r.workspace_id AND g.scope_digest=r.session_scope_digest)`,
		slot, generation, target, revision, runID, slot, generation, target, revision).Scan(&retired, &occupied)
	return retired, occupied, errors.Join(err, db.Close())
}

type isolatedNativeCancelResult struct {
	Name, StartedAt, FinishedAt, State, ContainerRef, Pin        string
	Creates, Attaches, RevokeCalls, ScannedFiles                 int
	ScannedBytes                                                 int64
	Startup, Enrollment, Ready, CancelRequested, SourceUnchanged bool
	SourceObjectUnchanged, SecretsAbsent, RemovedWhileHeld       bool
	ReleasedBeforePublication, ControllerClosed, StoreClosed     bool
	ArtifactsClosed, ProcessLockClosed, Passed                   bool
	Events                                                       []string
	Recovery                                                     isolatedNativeRecoveryAck
	Retirement                                                   isolatedNativeRetirement
	Snapshot                                                     isolatedNativeSnapshot
	Upstream                                                     isolatedNativeUpstream
	Close                                                        isolatedNativeClose
}

func isolatedNativeCancel(t *testing.T, tc isolatedNativeCase, probeHash string) {
	root := composedFixtureRoot + "/cancel"
	result := isolatedNativeCancelResult{Name: tc.Name, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	var w *isolatedReadyWitness
	var store *isolatedNativeCancelStore
	defer func() {
		if w != nil {
			w.mu.Lock()
			result.Ready, result.ContainerRef, result.Creates, result.Attaches = w.ready, w.ref, w.creates, w.attaches
			result.RemovedWhileHeld, result.ReleasedBeforePublication = w.removed, w.published
			result.Events = append([]string(nil), w.events...)
			w.mu.Unlock()
		}
		if store != nil {
			store.mu.Lock()
			result.Retirement, result.RevokeCalls = store.retirement, store.revokeCalls
			if store.observeErr != nil {
				t.Error("retirement observation failed")
			}
			store.mu.Unlock()
		}
		result.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		result.Passed = !t.Failed() && result.Startup && result.Enrollment && result.Ready && result.CancelRequested &&
			result.State == "cancelled" && result.Creates == 1 && result.Attaches == 1 && result.RevokeCalls == 1 &&
			result.Retirement.Passed && result.SourceUnchanged && result.SourceObjectUnchanged && result.SecretsAbsent &&
			result.RemovedWhileHeld && result.ReleasedBeforePublication && result.ControllerClosed && result.StoreClosed && result.ArtifactsClosed && result.ProcessLockClosed
		if isolatedNativeWriteJSON(root+"/result.json", result) != nil {
			t.Error("cancel result persistence failed")
		}
	}()
	if tc.Name != "cancel" || len(tc.Nonce) != 32 || len(probeHash) != 64 || !bytes.Contains(tc.BeforeAuth, []byte(".synthetic-")) {
		t.Fatal("fixed synthetic cancel identity required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 260*time.Second)
	defer cancel()
	f := newIsolatedServiceFixture(t, ctx, "/opt/hgw-v4-acceptance/composed-cancel.json", root, tc.BeforeAuth)
	defer func() {
		f.close(t)
		result.ControllerClosed, result.StoreClosed, result.ArtifactsClosed, result.ProcessLockClosed = f.controllerClosed, f.storeClosed, f.artifactsClosed, f.lockClosed
	}()
	result.Startup, result.Enrollment = true, true
	auth := filepath.Join(f.config.Codex.Credential.Root, f.config.Codex.Credential.Directory, "auth.json")
	var before unix.Stat_t
	if unix.Lstat(auth, &before) != nil {
		t.Fatal("cancel original source object unavailable")
	}
	selection := composedFixtureRoot + "/current-cancel.json"
	if isolatedNativeWriteJSON(selection, tc) != nil || os.Rename(selection, composedFixtureRoot+"/current-case.json") != nil {
		t.Fatal("private cancel case selection unavailable")
	}
	runID := "hsg-compose-20261005-cancel"
	w = &isolatedReadyWitness{DockerRuntime: f.adapter, Store: f.db, auth: auth, runID: runID}
	diagnostics, captured := &isolatedNativeCapture{}, &isolatedNativeCapture{}
	native := &isolatedNativeWitness{isolatedReadyWitness: w, root: root, diagnostics: diagnostics}
	manifest := f.config.Targets[0]
	store = &isolatedNativeCancelStore{isolatedReadyWitness: w, root: root, database: f.config.StateDatabase,
		slot: f.config.Codex.Credential.SlotRef, generation: int64(f.config.Codex.Credential.Generation), target: manifest.ID(), revision: manifest.Revision()}
	result.Pin = isolatedNativeStart(t, f, native, sandboxcontroller.Store(store), captured)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if isolatedNativeReadJSON(root+"/refresh-identity.json", &result.Recovery, 65536) == nil {
			if !isolatedNativeRecoveryAcknowledged(result.Recovery, tc, isolatedNativeFileSHA(root+"/refresh-request.json"), os.Getpid()) {
				t.Fatal("actual recovery helper/root acknowledgment rejected")
			}
			break
		}
		run, err := f.db.GetRun(ctx, runID)
		if err != nil || run.TerminalAt != nil || run.TerminalPending {
			t.Fatal("Run ended before the actual recovery barrier")
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual recovery barrier was not observed")
		case <-tick.C:
		}
	}
	active, err := f.db.GetRun(ctx, runID)
	if err != nil || active.State != executionwire.RunStateRunning || active.RuntimeRef == nil || !active.CredentialLeaseHeld || !active.WorkspaceLockHeld || active.TerminalPending || active.TerminalAt != nil || active.Output != nil || isolatedReadySourceLock(auth, true) != nil {
		t.Fatal("recovery barrier lost active authority")
	}
	operation, stop := context.WithTimeout(ctx, 5*time.Second)
	status, err := f.controller.CancelRun(operation, executionwire.CancelRunRequest{RunID: runID})
	stop()
	if err != nil || status.State != executionwire.RunStateCancelling {
		t.Fatal("actual controller cancellation failed")
	}
	cancelled, err := f.db.GetRun(ctx, runID)
	if err != nil || cancelled.State != executionwire.RunStateCancelling || cancelled.LastEventSeq < active.LastEventSeq {
		t.Fatal("durable cancel request was not retained")
	}
	if isolatedNativeWriteJSON(root+"/cancel-call.json", struct {
		Name, Nonce, RunID, State string
		Sequence                  uint64
	}{tc.Name, tc.Nonce, runID, string(cancelled.State), cancelled.LastEventSeq}) != nil {
		t.Fatal("actual cancel call observation failed")
	}
	result.CancelRequested = true
	for {
		run, err := f.db.GetRun(ctx, runID)
		if err != nil {
			t.Fatal("cancel durable result unavailable")
		}
		if run.TerminalAt != nil {
			if run.State != executionwire.RunStateCancelled || run.Output != nil || run.TerminalPending || run.CredentialLeaseHeld || run.RuntimeRef != nil || run.RuntimeIntentPending || run.WorkspaceLockHeld {
				t.Fatal("cancel did not release joined authority")
			}
			result.State = string(run.State)
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("cancel completion deadline reached")
		case <-tick.C:
		}
	}
	if native.observationError() != nil || isolatedNativeReadJSON(root+"/snapshot-result.json", &result.Snapshot, 65536) != nil || result.Snapshot.Name != tc.Name || result.Snapshot.Nonce != tc.Nonce || result.Snapshot.OwnerPID != os.Getpid() || !result.Snapshot.Passed || !result.Snapshot.SourceNotMounted || !result.Snapshot.StableProcesses || !result.Snapshot.SeedSecretsAbsent || !result.Snapshot.SeedPositiveControl {
		t.Fatal("actual cancel Owner/Runner/source snapshot unavailable")
	}
	w.mu.Lock()
	ref := w.ref
	w.mu.Unlock()
	if _, err := f.adapter.Inspect(ctx, ref); !errors.Is(err, dockerruntime.ErrNotFound) {
		t.Fatal("exact cancelled container absence unavailable")
	}
	if refs, err := f.adapter.ListManaged(ctx); err != nil || len(refs) != 0 {
		t.Fatal("cancel managed inventory not empty")
	}
	if isolatedNativeReadJSON(root+"/upstream-result.json", &result.Upstream, 65536) != nil || result.Upstream.Name != tc.Name || result.Upstream.Nonce != tc.Nonce || !result.Upstream.HeadersVerified || result.Upstream.Inference != 1 || result.Upstream.Refresh != 1 || result.Upstream.Catalog < 0 || result.Upstream.Catalog > 2 || result.Upstream.ToolDefinitionVerified || result.Upstream.ToolOutputVerified {
		t.Fatal("cancel replay/tool or upstream schedule differs")
	}
	if isolatedNativeReadJSON(root+"/close-result.json", &result.Close, 65536) != nil || !result.Close.OwnerJoinAttempted || !result.Close.OwnerJoined || !result.Close.EndpointJoinAttempted || !result.Close.EndpointJoined || !result.Close.DrainedJoined || !result.Close.Diagnostics.Stopped || !result.Close.Diagnostics.Joined || result.Close.Diagnostics.CleanupFailed {
		t.Fatal("cancel provider/helper joins unavailable")
	}
	for _, exchange := range result.Close.Diagnostics.Exchanges {
		if exchange.LocalAuth == "refresh" {
			t.Fatal("cancel accepted downstream replacement auth")
		}
	}
	after, err := os.ReadFile(auth)
	defer clear(after)
	result.SourceUnchanged = err == nil && bytes.Equal(after, tc.BeforeAuth) && isolatedReadySourceLock(auth, false) == nil
	var final unix.Stat_t
	result.SourceObjectUnchanged = unix.Lstat(auth, &final) == nil && final.Dev == before.Dev && final.Ino == before.Ino && final.Uid == before.Uid && final.Mode == before.Mode && final.Nlink == 1
	retired, occupied, err := isolatedNativeCredentialCounts(ctx, f.config.StateDatabase, runID, store.slot, store.generation, store.target, store.revision)
	if err != nil || retired != 1 || occupied != 0 || !result.SourceUnchanged || !result.SourceObjectUnchanged {
		t.Fatal("cancel source or retirement final state differs")
	}
	workspace := filepath.Join(f.config.WorkspaceRoot, "project-main")
	if isolatedNativeFileSHA(workspace+"/native-isolation-probe") != probeHash {
		t.Fatal("cancel fixed workspace probe changed")
	}
	for _, name := range []string{"isolation-tool-report.json", "isolation-tool-report.json.pending"} {
		if _, err := os.Lstat(filepath.Join(workspace, name)); !os.IsNotExist(err) {
			t.Fatal("cancel executed an unexpected tool")
		}
	}
	needles := isolatedNativeNeedles(t, tc)
	files, count, scanErr := isolatedNativeScan([]string{workspace, f.config.RunnerStateRoot}, needles)
	if scanErr != nil || isolatedNativeContains(captured.bytes(), needles) || isolatedNativeContains(diagnostics.bytes(), needles) {
		t.Fatal("cancel bounded Runner/HRP/diagnostic secrecy scan failed")
	}
	result.ScannedFiles, result.ScannedBytes, result.SecretsAbsent = files, count, true
	t.Log("actual controller cancellation at authenticated native recovery; retirement and ordered joined cleanup, without a tool or successful inference replay")
}

func TestIsolatedNativeFaultWindow(t *testing.T) {
	start := time.Date(2026, time.October, 6, 0, 0, 0, 0, time.UTC)
	end := start.Add(24*time.Hour - 1500*time.Second)
	if isolatedNativeFaultWithinWindow(start.Add(-time.Nanosecond)) || !isolatedNativeFaultWithinWindow(start) || !isolatedNativeFaultWithinWindow(end.Add(-time.Nanosecond)) || isolatedNativeFaultWithinWindow(end) {
		t.Fatal("whole fault VM window reserve differs")
	}
}

func TestIsolatedNativeRecoveryAcknowledgment(t *testing.T) {
	tc := isolatedNativeCase{Name: "cancel", Nonce: "0123456789abcdef0123456789abcdef"}
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	good := isolatedNativeRecoveryAck{Name: tc.Name, Nonce: tc.Nonce, RequestSHA256: hash, HelperStartTime: "123", HelperSHA256: codexprofile.CLIBinarySHA256V1, OwnerPID: 17, HelperPID: 19, Invocation: 2, Force: true, RequestLatched: true, HelperPinned: true, Stable: true, Passed: true}
	if !isolatedNativeRecoveryAcknowledged(good, tc, hash, 17) {
		t.Fatal("actual-root acknowledgment positive control rejected")
	}
	for _, change := range []func(*isolatedNativeRecoveryAck){
		func(a *isolatedNativeRecoveryAck) { a.Name = "catalog401" },
		func(a *isolatedNativeRecoveryAck) { a.Nonce = "wrong" },
		func(a *isolatedNativeRecoveryAck) { a.RequestSHA256 = "wrong" },
		func(a *isolatedNativeRecoveryAck) { a.HelperStartTime = "0" },
		func(a *isolatedNativeRecoveryAck) { a.HelperStartTime = "00" },
		func(a *isolatedNativeRecoveryAck) { a.HelperStartTime = "000" },
		func(a *isolatedNativeRecoveryAck) { a.HelperStartTime = "0123" },
		func(a *isolatedNativeRecoveryAck) { a.HelperSHA256 = "wrong" },
		func(a *isolatedNativeRecoveryAck) { a.HelperPID = a.OwnerPID },
		func(a *isolatedNativeRecoveryAck) { a.Invocation = 1 },
		func(a *isolatedNativeRecoveryAck) { a.OwnerPID++ },
		func(a *isolatedNativeRecoveryAck) { a.Force = false },
		func(a *isolatedNativeRecoveryAck) { a.RequestLatched = false },
		func(a *isolatedNativeRecoveryAck) { a.HelperPinned = false },
		func(a *isolatedNativeRecoveryAck) { a.Stable = false },
		func(a *isolatedNativeRecoveryAck) { a.Passed = false },
	} {
		bad := good
		change(&bad)
		if isolatedNativeRecoveryAcknowledged(bad, tc, hash, 17) {
			t.Fatal("incomplete or mismatched recovery acknowledgment accepted")
		}
	}
}

func TestIsolatedNativeRecoverySchedule(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		refresh, denied, exchanges int
		want                       bool
	}{
		{"catalog401", 1, 0, 5, true},
		{"catalog401", 1, 1, 6, true},
		{"catalog401", 1, 8, 12, true},
		{"catalog401", 0, 1, 5, false},
		{"catalog401", 2, 0, 5, false},
		{"catalog401", 1, 16, 17, false},
		{"catalog401", 1, 2, 2, false},
		{"catalog401", 1, -1, 5, false},
		{"fresh", 0, 0, 3, true},
		{"fresh", 0, 1, 3, false},
		{"inference401", 1, 1, 6, true},
		{"inference401", 1, 0, 5, false},
		{"unknown", 1, 1, 6, false},
	} {
		if got := isolatedNativeRecoverySchedule(tc.name, tc.refresh, tc.denied, tc.exchanges); got != tc.want {
			t.Fatalf("unexpected bounded recovery schedule: %+v got %v", tc, got)
		}
	}
}

// Observe real Store transactions through another read-only connection while
// the Store remains open in WAL mode. Retirement must retain occupancy until
// the original publication transaction releases it.
func TestIsolatedNativeCredentialRetirementObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := sandboxstore.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	g := sandboxstore.CredentialGeneration{SlotRef: "slot", Generation: 1, SourceDigest: strings.Repeat("b", 64), WorkspaceRef: "workspace", AuthProfileRef: "test.auth", ScopeDigest: strings.Repeat("c", 64)}
	a := sandboxstore.TargetAuthority{TargetID: "target", TargetRevision: "revision", RevisionPin: strings.Repeat("a", 64), RunnerStateKind: targetmanifest.RunnerStateNone, Credential: &sandboxstore.CredentialRef{SlotRef: g.SlotRef, Generation: g.Generation}}
	if store.RegisterCredentialGeneration(ctx, g) != nil || store.RegisterTargetAuthorities(ctx, []sandboxstore.TargetAuthority{a}) != nil {
		t.Fatal("real credential registration failed")
	}
	r := executionwire.StartRunRequest{RunID: "retirement-probe", TargetID: a.TargetID, ExpectedRevision: a.TargetRevision,
		SessionScopeDigest: g.ScopeDigest, Input: executionwire.TextInput{MediaType: executionwire.MediaTypeTextPlain, Text: "synthetic observation"}, Deadline: time.Now().UTC().Add(time.Minute).Truncate(time.Millisecond)}
	if _, created, err := store.RegisterStart(ctx, r, a.TargetRevision, g.WorkspaceRef, true, sandboxstore.SessionPolicy{Mode: targetmanifest.SessionNewOnly}); err != nil || !created {
		t.Fatal("real occupancy admission failed")
	}
	check := func(wantRetired, wantOccupied int) {
		t.Helper()
		retired, occupied, err := isolatedNativeCredentialCounts(ctx, path, r.RunID, g.SlotRef, g.Generation, a.TargetID, a.TargetRevision)
		if err != nil || retired != wantRetired || occupied != wantOccupied {
			t.Fatal("live WAL retirement/occupancy observation differs", retired, occupied, err)
		}
	}
	check(0, 1)
	if store.RevokeRunCredential(ctx, r.RunID) != nil {
		t.Fatal("real retirement failed")
	}
	check(1, 1)
	if retired, occupied, err := isolatedNativeCredentialCounts(ctx, path, r.RunID, g.SlotRef, g.Generation, "other-target", a.TargetRevision); err != nil || retired != 0 || occupied != 0 {
		t.Fatal("unrelated target accepted by retirement observation")
	}
	if _, err := store.MarkCancelling(ctx, r.RunID); err != nil {
		t.Fatal("real cancellation failed")
	}
	if _, err := store.StageTerminal(ctx, executionwire.RunEvent{RunID: r.RunID, Seq: 1, Type: executionwire.RunEventCancelled}, nil); err != nil {
		t.Fatal("real cancelled terminal staging failed")
	}
	if _, err := store.ConfirmRuntimeStopped(ctx, r.RunID); err != nil {
		t.Fatal("real publication/release failed")
	}
	check(1, 0)
}

var _ sandboxcontroller.Store = (*isolatedNativeCancelStore)(nil)
var _ sandboxcontroller.Runtime = (*isolatedNativeWitness)(nil)
