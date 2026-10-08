//go:build linux && amd64 && codexintegration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/processlock"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxcontroller"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
	"golang.org/x/sys/unix"
)

func isolatedStructuralWithinWindow(now time.Time) bool {
	start := time.Date(2026, time.October, 6, 0, 0, 0, 0, time.UTC)
	return !now.Before(start) && now.Before(start.Add(24*time.Hour-1800*time.Second))
}

func isolatedStructuralPhaseName(phase string) (string, bool) {
	switch phase {
	case "helperloss":
		return "helperloss", true
	case "crash", "restart":
		return "ownerrestart", true
	default:
		return "", false
	}
}

// A root supervisor selects three literal phases under the SAME fixed service
// identity. Unknown values fail before production setup. No default activation.
func TestIsolatedServiceNativeStructural(t *testing.T) {
	if os.Getenv("HSG_V4_STRUCTURAL_PROBE") != "offline-vm-structural-v1" {
		t.Skip("requires the frozen dedicated structural VM")
	}
	phase := os.Getenv("HSG_V4_STRUCTURAL_PHASE")
	name, ok := isolatedStructuralPhaseName(phase)
	if !ok || os.Getuid() != 1001 || os.Geteuid() != 1001 || !isolatedStructuralWithinWindow(time.Now()) {
		t.Fatal("fixed structural phase, identity and window required")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("no-NIC guest required")
	}
	var plan isolatedNativePlan
	if isolatedNativeReadJSON("/opt/hgw-v4-acceptance/composed-plan.json", &plan, 65536) != nil || len(plan.Cases) != 2 ||
		plan.Cases[0].Name != "helperloss" || plan.Cases[1].Name != "ownerrestart" {
		t.Fatal("fixed structural case inventory required")
	}
	tc := plan.Cases[0]
	if name == "ownerrestart" {
		tc = plan.Cases[1]
	}
	if tc.Name != name || len(tc.Nonce) != 32 || len(plan.ProbeSHA256) != 64 || !bytes.Contains(tc.BeforeAuth, []byte(".synthetic-")) {
		t.Fatal("fixed synthetic identity rejected")
	}
	isolatedStructuralInitialize(t, tc, phase)
	switch phase {
	case "helperloss":
		isolatedStructuralHelperLoss(t, tc)
	case "crash":
		isolatedStructuralCrash(t, tc)
	case "restart":
		isolatedStructuralRestart(t, tc)
	}
}

func isolatedStructuralReadFlow(path string) (isolatedStructuralFlow, error) {
	data, err := isolatedNativeReadBytes(path, 65536)
	var f isolatedStructuralFlow
	var fields map[string]json.RawMessage
	if err != nil || strictjson.Decode(data, 65536, 12, &fields) != nil || len(fields) != 12 ||
		strictjson.Decode(data, 65536, 12, &f) != nil || f.Events == nil {
		return f, errors.New("complete typed observation required")
	}
	for _, key := range []string{"Name", "Nonce", "Phase", "OwnerPID", "Operations", "InFlight", "Initialized", "Invalid", "Overflow", "Finished", "AfterOriginalJoins", "Events"} {
		if _, ok := fields[key]; !ok || bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
			return f, errors.New("missing observation field")
		}
	}
	var events []map[string]json.RawMessage
	if strictjson.Decode(fields["Events"], 65536, 12, &events) != nil {
		return f, errors.New("complete typed events required")
	}
	for _, event := range events {
		if len(event) != 10 {
			return f, errors.New("complete event fields required")
		}
		for _, key := range []string{"Sequence", "ID", "Kind", "ErrorKind", "Begin", "Returned", "SuccessKnown", "OK", "Started", "SignalObserved"} {
			if value, ok := event[key]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return f, errors.New("missing event field")
			}
		}
	}
	return f, nil
}

func isolatedStructuralInitialize(t *testing.T, tc isolatedNativeCase, phase string) {
	t.Helper()
	selection := composedFixtureRoot + "/current-" + phase + ".json"
	if phase == "restart" {
		var old isolatedNativeCase
		if isolatedNativeReadJSON(composedFixtureRoot+"/current-case.json", &old, 65536) != nil || old.Name != tc.Name || old.Nonce != tc.Nonce || !bytes.Equal(old.BeforeAuth, tc.BeforeAuth) || !isolatedNativeTokensEqual(old.RefreshedTokens, tc.RefreshedTokens) {
			t.Fatal("restart case changed")
		}
	} else if isolatedNativeWriteJSON(selection, tc) != nil || os.Rename(selection, composedFixtureRoot+"/current-case.json") != nil {
		t.Fatal("fixed case selection unavailable")
	}
	init := struct {
		Name, Nonce, Phase string
		OwnerPID           int
	}{tc.Name, tc.Nonce, phase, os.Getpid()}
	if isolatedNativeWriteJSON(composedFixtureRoot+"/"+tc.Name+"/observer-init-"+phase+".json", init) != nil {
		t.Fatal("exclusive observer initialization unavailable")
	}
	// STRUCTURAL_OBSERVERS_INITIALIZE
	f, err := isolatedStructuralReadFlow(composedFixtureRoot + "/" + tc.Name + "/flow-" + phase + "-initial.json")
	if err != nil || !isolatedStructuralFlowAccepted(f, tc, phase, os.Getpid(), false) || f.Operations != 0 {
		t.Fatal("observer initialization was not actually recorded")
	}
}

type isolatedStructuralResult struct {
	Name, Nonce, Phase, StartedAt, FinishedAt, State, FailureCode, BasePin, Pin string
	OwnerPID                                                                    int
	Snapshot                                                                    isolatedStructuralSnapshot
	Flow                                                                        isolatedStructuralFlow
	Database, Source                                                            isolatedStructuralObject
	Startup, Enrollment, StoreWitness, SourceUnchanged, SecretsAbsent           bool
	ControllerClosed, StoreClosed, ArtifactsClosed, ProcessLockClosed           bool
	OriginalServeJoined, OriginalServeReturnedNil, ProcessLockReacquired        bool
	Passed                                                                      bool
}

func isolatedStructuralHelperLoss(t *testing.T, tc isolatedNativeCase) {
	root := composedFixtureRoot + "/helperloss"
	r := isolatedStructuralResult{Name: tc.Name, Nonce: tc.Nonce, Phase: "helperloss", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), OwnerPID: os.Getpid()}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := newIsolatedServiceFixture(t, ctx, "/opt/hgw-v4-acceptance/composed-helperloss.json", root, tc.BeforeAuth)
	w := &isolatedReadyWitness{DockerRuntime: f.adapter, Store: f.db, auth: filepath.Join(f.config.Codex.Credential.Root, f.config.Codex.Credential.Directory, "auth.json"), runID: "hsg-compose-20261005-helperloss"}
	native := &isolatedNativeWitness{isolatedReadyWitness: w, root: root, diagnostics: &isolatedNativeCapture{}}
	store := &isolatedStructuralStore{Store: f.db, config: f.config, runtime: f.adapter, root: root, id: w.runID, tc: tc, phase: "helperloss"}
	defer func() {
		f.close(t)
		r.ControllerClosed, r.StoreClosed, r.ArtifactsClosed, r.ProcessLockClosed = f.controllerClosed, f.storeClosed, f.artifactsClosed, f.lockClosed
		r.StoreWitness = store.accepted()
		joined := r.ControllerClosed && r.StoreClosed && r.ArtifactsClosed && r.ProcessLockClosed
		// STRUCTURAL_OBSERVERS_FINISH_HELPER
		var err error
		r.Flow, err = isolatedStructuralReadFlow(root + "/flow-helperloss-final.json")
		flowOK := err == nil && isolatedStructuralFlowAccepted(r.Flow, tc, "helperloss", os.Getpid(), true) &&
			isolatedStructuralFlowCount(r.Flow, "external-create") == 0 && isolatedStructuralFlowCount(r.Flow, "attach-start") == 0 &&
			isolatedStructuralFlowCount(r.Flow, "native-invoke") == 1 && isolatedStructuralFlowCount(r.Flow, "source-commit") == 0 &&
			isolatedStructuralFlowCount(r.Flow, "run-resource-close") >= 1
		r.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		r.Passed = !t.Failed() && joined && flowOK && r.StoreWitness && r.Startup && r.Enrollment && r.State == "failed" &&
			r.FailureCode == string(executionwire.FailurePolicyDenied) && r.SourceUnchanged && r.SecretsAbsent
		if !r.Passed {
			t.Error("helper-loss acceptance incomplete")
		}
		if isolatedNativeWriteJSON(root+"/helperloss-result.json", r) != nil {
			t.Error("helper-loss result persistence failed")
		}
	}()
	r.Startup, r.Enrollment = true, true
	var err error
	r.Source, err = isolatedStructuralObjectAt(w.auth)
	if err != nil {
		t.Fatal("source identity unavailable")
	}
	// The setup's resolver supplies the base pin; admission stores its framed
	// enrollment pin. Freeze the base before asynchronous retirement can run.
	manifest := f.config.Targets[0]
	fp, _ := manifest.Fingerprint()
	authority, err := f.setup.authority(manifest, fp)
	if err != nil {
		t.Fatal("base authority unavailable")
	}
	store.base, r.BasePin = authority.RevisionPin, authority.RevisionPin
	if isolatedNativeStart(t, f, native, sandboxcontroller.Store(store), &isolatedNativeCapture{}) != r.BasePin {
		t.Fatal("base authority changed")
	}
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		run, err := f.db.GetRun(ctx, w.runID)
		if err != nil {
			t.Fatal("original failure observation unavailable")
		}
		if run.TerminalAt != nil {
			r.State = string(run.State)
			if run.Failure != nil {
				r.FailureCode = string(run.Failure.Code)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("helper-loss bounded completion absent")
		case <-tick.C:
		}
	}
	r.Snapshot, err = isolatedStructuralReadSnapshot(ctx, f.config.StateDatabase, w.runID)
	if err != nil || !isolatedStructuralIdentity(r.Snapshot, f.config, r.BasePin) || !r.Snapshot.Published || r.Snapshot.Pending || r.Snapshot.Intent ||
		r.Snapshot.Ref != "" || r.Snapshot.Revoked != 1 || r.Snapshot.Occupied != 0 || r.Snapshot.WorkspaceHeld || r.Snapshot.OutputPresent {
		t.Fatal("helper-loss durable release incomplete")
	}
	r.Pin = r.Snapshot.Pin
	r.Database, err = isolatedStructuralObjectAt(f.config.StateDatabase)
	if err != nil {
		t.Fatal("database object unavailable")
	}
	after, object, err := isolatedStructuralReadObject(w.auth, 1001, 0077)
	defer clear(after)
	r.SourceUnchanged = err == nil && object == r.Source && bytes.Equal(after, tc.BeforeAuth)
	_, _, scanErr := isolatedNativeScan([]string{f.config.WorkspaceRoot, f.config.RunnerStateRoot}, isolatedNativeNeedles(t, tc))
	r.SecretsAbsent = scanErr == nil
}

type isolatedStructuralCrashPoint struct {
	Name, Nonce, Phase, BasePin, ConfigSHA256, SourceSHA256, RequestSHA256 string
	OwnerPID, HelperPID                                                    int
	Snapshot                                                               isolatedStructuralSnapshot
	Database, Source                                                       isolatedStructuralObject
	SourceLocked, ObservedActive, AwaitingRootSignal, GracefullyCompleted  bool
}

func isolatedStructuralCrash(t *testing.T, tc isolatedNativeCase) {
	root := composedFixtureRoot + "/ownerrestart"
	ctx, cancel := context.WithTimeout(context.Background(), 220*time.Second)
	defer cancel()
	configPath := "/opt/hgw-v4-acceptance/composed-ownerrestart.json"
	f := newIsolatedServiceFixture(t, ctx, configPath, root, tc.BeforeAuth)
	w := &isolatedReadyWitness{DockerRuntime: f.adapter, Store: f.db, auth: filepath.Join(f.config.Codex.Credential.Root, f.config.Codex.Credential.Directory, "auth.json"), runID: "hsg-compose-20261005-ownerrestart"}
	native := &isolatedNativeWitness{isolatedReadyWitness: w, root: root, diagnostics: &isolatedNativeCapture{}}
	base := isolatedNativeStart(t, f, native, sandboxcontroller.Store(w), &isolatedNativeCapture{})
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	helperPID := 0
	callbackDeadline := int64(0)
	for {
		var request struct {
			Name, Nonce, Kind                                string
			OwnerPID, HelperPID, Invocation, BaselineCommits int
			Force, RequestLatched                            bool
			CallbackDeadlineMonotonicNS                      int64
		}
		if isolatedNativeReadJSON(root+"/refresh-request.json", &request, 65536) == nil {
			if request.Name != tc.Name || request.Nonce != tc.Nonce || request.Kind != "authenticated-native-owner-refresh" || request.OwnerPID != os.Getpid() || request.HelperPID <= 1 ||
				request.HelperPID == request.OwnerPID || request.Invocation != 2 || request.BaselineCommits != 1 || !request.Force || !request.RequestLatched {
				t.Fatal("actual native recovery point rejected")
			}
			helperPID = request.HelperPID
			callbackDeadline = request.CallbackDeadlineMonotonicNS
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("native recovery point absent")
		case <-tick.C:
		}
	}
	p := isolatedStructuralCrashPoint{Name: tc.Name, Nonce: tc.Nonce, Phase: "crash", BasePin: base, ConfigSHA256: isolatedNativeFileSHA(configPath),
		RequestSHA256: isolatedNativeFileSHA(root + "/refresh-request.json"), OwnerPID: os.Getpid(), HelperPID: helperPID, AwaitingRootSignal: true}
	var err error
	p.Snapshot, err = isolatedStructuralReadSnapshot(ctx, f.config.StateDatabase, w.runID)
	if err != nil || !isolatedStructuralIdentity(p.Snapshot, f.config, base) || p.Snapshot.State != "running" || p.Snapshot.Ref == "" || p.Snapshot.Intent ||
		p.Snapshot.Pending || p.Snapshot.Published || p.Snapshot.OutputPresent || p.Snapshot.Revoked != 0 || p.Snapshot.Occupied != 1 || !p.Snapshot.WorkspaceHeld {
		t.Fatal("active durable authority absent before fault")
	}
	p.Source, err = isolatedStructuralObjectAt(w.auth)
	if err != nil {
		t.Fatal("pre-fault source object unavailable")
	}
	p.Database, err = isolatedStructuralObjectAt(f.config.StateDatabase)
	if err != nil {
		t.Fatal("pre-fault database object unavailable")
	}
	p.SourceLocked = isolatedReadySourceLock(w.auth, true) == nil
	sourceBytes, sourceObject, sourceErr := isolatedStructuralReadObject(w.auth, 1001, 0077)
	defer clear(sourceBytes)
	p.SourceSHA256 = isolatedStructuralBytesSHA(sourceBytes)
	p.ObservedActive = p.SourceLocked && len(p.SourceSHA256) == 64 && len(p.ConfigSHA256) == 64 && len(p.RequestSHA256) == 64 && native.observationError() == nil
	p.ObservedActive = p.ObservedActive && sourceErr == nil && sourceObject == p.Source && bytes.Equal(sourceBytes, tc.BeforeAuth)
	var clock unix.Timespec
	p.ObservedActive = p.ObservedActive && unix.ClockGettime(unix.CLOCK_MONOTONIC, &clock) == nil && callbackDeadline > clock.Nano() && callbackDeadline-clock.Nano() > int64(10*time.Second)
	if !p.ObservedActive || isolatedNativeWriteJSON(root+"/crash-ready.json", p) != nil {
		t.Fatal("pre-crash authority persistence unavailable")
	}
	// Successful injection kills this test process; it cannot report Go PASS or
	// flush-after-joins. Reaching the deadline is a failure, never expected death.
	<-ctx.Done()
	t.Fatal("authenticated Owner fault was not injected")
}

type isolatedStructuralRootFault struct {
	Name, Nonce, Phase, OwnerStartTime, HelperStartTime, OwnerSHA256, HelperSHA256 string
	RequestSHA256, CrashReadySHA256, UnitResult                                    string
	OwnerPID, HelperPID, Signal, UnitCode, UnitStatus, StartClientExit             int
	PIDFDPinned, SignalReturned, OldOwnerAbsent, OldHelperAbsent, CgroupEmpty      bool
	KnownRefPreserved, Passed                                                      bool
}

func isolatedStructuralFaultAccepted(f isolatedStructuralRootFault, p isolatedStructuralCrashPoint, ownerSHA string) bool {
	start, e1 := strconv.ParseUint(f.OwnerStartTime, 10, 64)
	helperStart, e2 := strconv.ParseUint(f.HelperStartTime, 10, 64)
	return e1 == nil && e2 == nil && start > 0 && helperStart > 0 && strconv.FormatUint(start, 10) == f.OwnerStartTime &&
		strconv.FormatUint(helperStart, 10) == f.HelperStartTime && f.Name == p.Name && f.Nonce == p.Nonce && f.Phase == "crash" && p.Phase == "crash" &&
		f.OwnerPID == p.OwnerPID && f.OwnerPID > 1 && f.HelperPID == p.HelperPID && f.HelperPID > 1 && f.HelperPID != f.OwnerPID && f.OwnerSHA256 == ownerSHA &&
		f.HelperSHA256 == codexprofile.CLIBinarySHA256V1 && f.RequestSHA256 == p.RequestSHA256 && len(f.CrashReadySHA256) == 64 &&
		f.Signal == 9 && f.UnitResult == "signal" && f.UnitCode == 2 && f.UnitStatus == 9 && f.StartClientExit == 1 &&
		f.PIDFDPinned && f.SignalReturned && f.OldOwnerAbsent && f.OldHelperAbsent && f.CgroupEmpty && f.KnownRefPreserved && f.Passed &&
		p.ObservedActive && p.SourceLocked && p.AwaitingRootSignal && !p.GracefullyCompleted
}

// Set only by a reversible private Store-argument overlay in the original serve.
// Without that fixture this entry fails before a recovery acceptance claim.
var isolatedStructuralRestartStore *isolatedStructuralStore

func isolatedStructuralRestart(t *testing.T, tc isolatedNativeCase) {
	root := composedFixtureRoot + "/ownerrestart"
	configPath := "/opt/hgw-v4-acceptance/composed-ownerrestart.json"
	config, err := sandboxconfig.Load(configPath)
	if err != nil || !isolatedStructuralFixedConfig(config, tc.Name) {
		t.Fatal("unchanged restart config unavailable")
	}
	point, pointSHA, pointErr := isolatedStructuralReadCrashPoint(root + "/crash-ready.json")
	fault, faultErr := isolatedStructuralReadRootFault(root + "/root-fault.json")
	if pointErr != nil || faultErr != nil ||
		!isolatedStructuralFaultAccepted(fault, point, config.Codex.OwnerSHA256) || fault.CrashReadySHA256 != pointSHA ||
		point.Name != tc.Name || point.Nonce != tc.Nonce || point.ConfigSHA256 != isolatedNativeFileSHA(configPath) ||
		!isolatedStructuralIdentity(point.Snapshot, config, point.BasePin) {
		t.Fatal("actual prior fault/same authority unavailable")
	}
	database, err := isolatedStructuralObjectAt(config.StateDatabase)
	source, sourceErr := isolatedStructuralObjectAt(filepath.Join(config.Codex.Credential.Root, config.Codex.Credential.Directory, "auth.json"))
	if err != nil || sourceErr != nil || database != point.Database || source != point.Source {
		t.Fatal("same database/source object unavailable")
	}
	r := isolatedStructuralResult{Name: tc.Name, Nonce: tc.Nonce, Phase: "restart", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), OwnerPID: os.Getpid(),
		BasePin: point.BasePin, Pin: point.Snapshot.Pin, Database: database, Source: source}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- serve(ctx, config) }()
	joined := false
	joinAttempted := false
	// One 75s budget covers all original shutdown paths, including failure.
	// A timeout cannot gain another budget through the deferred result writer.
	joinOriginal := func() {
		if joined || joinAttempted {
			return
		}
		joinAttempted = true
		select {
		case err := <-serveResult:
			joined, r.OriginalServeReturnedNil = true, err == nil
		case <-time.After(75 * time.Second):
			t.Error("original serve shutdown did not join")
		}
	}
	defer func() {
		cancel()
		joinOriginal()
		r.OriginalServeJoined = joined
		// STRUCTURAL_OBSERVERS_FINISH_RESTART
		var err error
		r.Flow, err = isolatedStructuralReadFlow(root + "/flow-restart-final.json")
		flowOK := err == nil && isolatedStructuralFlowAccepted(r.Flow, tc, "restart", os.Getpid(), true) && isolatedStructuralNoReopen(r.Flow) &&
			isolatedStructuralRestartCloses(r.Flow, joined, r.OriginalServeReturnedNil)
		if joined && isolatedStructuralRestartStore != nil {
			r.StoreWitness = isolatedStructuralRestartStore.accepted()
		}
		for kind, dst := range map[string]*bool{"controller-close": &r.ControllerClosed, "store-close": &r.StoreClosed, "artifacts-close": &r.ArtifactsClosed, "process-lock-close": &r.ProcessLockClosed} {
			*dst = flowOK && isolatedStructuralFlowCount(r.Flow, kind) == 1
		}
		if joined && r.OriginalServeReturnedNil && flowOK {
			lock, err := processlock.Acquire(config.ProcessLockPath())
			r.ProcessLockReacquired = err == nil && lock != nil
			if lock != nil && lock.Close() != nil {
				r.ProcessLockReacquired = false
			}
		}
		r.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		r.Passed = !t.Failed() && flowOK && r.StoreWitness && r.State == "interrupted" && r.SourceUnchanged && r.SecretsAbsent &&
			r.OriginalServeJoined && r.OriginalServeReturnedNil && r.ProcessLockReacquired && r.ControllerClosed && r.StoreClosed && r.ArtifactsClosed && r.ProcessLockClosed
		if !r.Passed {
			t.Error("same-DB original serve recovery acceptance incomplete")
		}
		if isolatedNativeWriteJSON(root+"/restart-result.json", r) != nil {
			t.Error("restart result persistence failed")
		}
	}()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		var ready struct {
			Name, Nonce, Phase            string
			OwnerPID                      int
			OriginalControllerReturnedNil bool
		}
		if isolatedNativeReadJSON(root+"/restart-controller-ready.json", &ready, 65536) == nil {
			if ready.Name != tc.Name || ready.Nonce != tc.Nonce || ready.Phase != "restart" || ready.OwnerPID != os.Getpid() || !ready.OriginalControllerReturnedNil {
				t.Fatal("original Controller.New return unavailable")
			}
			r.Snapshot, err = isolatedStructuralReadSnapshot(ctx, config.StateDatabase, point.Snapshot.RunID)
			if err != nil || !isolatedStructuralSameIdentity(point.Snapshot, r.Snapshot) || r.Snapshot.State != "interrupted" || !r.Snapshot.Published ||
				r.Snapshot.Pending || r.Snapshot.Intent || r.Snapshot.Ref != "" || r.Snapshot.Revoked != 1 || r.Snapshot.Occupied != 0 || r.Snapshot.WorkspaceHeld || r.Snapshot.OutputPresent {
				t.Fatal("original startup reconciliation did not release exact Run")
			}
			r.State = r.Snapshot.State
			break
		}
		select {
		case err := <-serveResult:
			joined, r.OriginalServeReturnedNil = true, err == nil
			t.Fatal("original serve ended before recovery observation")
		case <-ctx.Done():
			t.Fatal("same-DB recovery deadline expired")
		case <-tick.C:
		}
	}
	// Parent cancellation happens only after actual original recovery/publication.
	cancel()
	joinOriginal()
	if !joined || !r.OriginalServeReturnedNil {
		t.Fatal("original serve graceful shutdown absent")
	}
	auth := filepath.Join(config.Codex.Credential.Root, config.Codex.Credential.Directory, "auth.json")
	after, object, err := isolatedStructuralReadObject(auth, 1001, 0077) // synthetic equality after joins, not auth reopening
	defer clear(after)
	r.SourceUnchanged = err == nil && object == point.Source && bytes.Equal(after, tc.BeforeAuth) && isolatedStructuralBytesSHA(after) == point.SourceSHA256
	_, _, scanErr := isolatedNativeScan([]string{config.WorkspaceRoot, config.RunnerStateRoot}, isolatedNativeNeedles(t, tc))
	r.SecretsAbsent = scanErr == nil
}
