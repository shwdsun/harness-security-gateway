//go:build linux && amd64 && codexintegration

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"golang.org/x/sys/unix"
)

func TestIsolatedStructuralWindowAndPhases(t *testing.T) {
	start := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		offset time.Duration
		want   bool
	}{{-1, false}, {0, true}, {23*time.Hour + 29*time.Minute, true}, {23*time.Hour + 30*time.Minute, false}, {24 * time.Hour, false}} {
		if isolatedStructuralWithinWindow(start.Add(c.offset)) != c.want {
			t.Fatal("entry window changed", c)
		}
	}
	for _, phase := range []string{"", "ownerrestart", "crash ", "helperloss\n", "/tmp", "other"} {
		if _, ok := isolatedStructuralPhaseName(phase); ok {
			t.Fatal("unknown phase accepted", phase)
		}
	}
}

func TestIsolatedStructuralFlowEvidence(t *testing.T) {
	tc := isolatedNativeCase{Name: "ownerrestart", Nonce: strings.Repeat("a", 32)}
	gold := isolatedStructuralFlow{Name: tc.Name, Nonce: tc.Nonce, Phase: "restart", OwnerPID: 1234, Initialized: true, Finished: true, AfterOriginalJoins: true, Operations: 1,
		Events: []isolatedStructuralFlowEvent{{Sequence: 1, ID: 1, Kind: "store-close", Begin: true}, {Sequence: 2, ID: 1, Kind: "store-close", Returned: true, SuccessKnown: true, OK: true, ErrorKind: "none"}}}
	if !isolatedStructuralFlowAccepted(gold, tc, "restart", 1234, true) || !isolatedStructuralNoReopen(gold) {
		t.Fatal("complete original Close rejected")
	}
	mutations := map[string]func(*isolatedStructuralFlow){
		"phase": func(f *isolatedStructuralFlow) { f.Phase = "crash" }, "nonce": func(f *isolatedStructuralFlow) { f.Nonce = "wrong" }, "owner": func(f *isolatedStructuralFlow) { f.OwnerPID++ },
		"uninitialized": func(f *isolatedStructuralFlow) { f.Initialized = false }, "overflow": func(f *isolatedStructuralFlow) { f.Overflow = true }, "invalid": func(f *isolatedStructuralFlow) { f.Invalid = true },
		"inflight": func(f *isolatedStructuralFlow) { f.InFlight = 1 }, "unjoined": func(f *isolatedStructuralFlow) { f.AfterOriginalJoins = false }, "not-final": func(f *isolatedStructuralFlow) { f.Finished = false },
		"missing-return": func(f *isolatedStructuralFlow) { f.Events = f.Events[:1] }, "extra-operation": func(f *isolatedStructuralFlow) { f.Operations++ }, "reordered": func(f *isolatedStructuralFlow) { f.Events[1].Sequence = 1 },
		"wrong-operation": func(f *isolatedStructuralFlow) { f.Events[1].ID++ }, "close-error": func(f *isolatedStructuralFlow) { f.Events[1].OK = false }, "unknown-result": func(f *isolatedStructuralFlow) { f.Events[1].SuccessKnown = false },
		"unknown-kind": func(f *isolatedStructuralFlow) { f.Events[0].Kind = "invented"; f.Events[1].Kind = "invented" }, "signal": func(f *isolatedStructuralFlow) { f.Events[1].SignalObserved = true }, "invented-start": func(f *isolatedStructuralFlow) { f.Events[1].Started = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := gold
			f.Events = append([]isolatedStructuralFlowEvent(nil), gold.Events...)
			mutate(&f)
			if isolatedStructuralFlowAccepted(f, tc, "restart", 1234, true) {
				t.Fatal("incomplete observation accepted")
			}
		})
	}
	for _, kind := range []string{"source-hold", "source-borrow", "source-read", "source-commit", "provider-new", "native-invoke", "external-create", "attach-start"} {
		f := gold
		f.Events = append([]isolatedStructuralFlowEvent(nil), gold.Events...)
		f.Events[0].Kind, f.Events[1].Kind = kind, kind
		if isolatedStructuralNoReopen(f) {
			t.Fatal("authority reopened", kind)
		}
	}
	path := filepath.Join(t.TempDir(), "flow.json")
	data, _ := json.Marshal(gold)
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("fixture write failed")
	}
	if f, err := isolatedStructuralReadFlow(path); err != nil || !isolatedStructuralFlowAccepted(f, tc, "restart", 1234, true) {
		t.Fatal("complete typed receipt rejected", err)
	}
	for _, bad := range []string{strings.Replace(string(data), `"Initialized":true`, `"Initialized":true,"Initialized":true`, 1), strings.Replace(string(data), `"Returned":true,`, "", 1), strings.Replace(string(data), `"Started":false`, `"Started":null`, 1)} {
		if os.WriteFile(path, []byte(bad), 0600) != nil {
			t.Fatal("fixture write failed")
		}
		if _, err := isolatedStructuralReadFlow(path); err == nil {
			t.Fatal("missing/duplicate/null evidence accepted")
		}
	}
}

func TestIsolatedStructuralFaultIdentity(t *testing.T) {
	p := isolatedStructuralCrashPoint{Name: "ownerrestart", Nonce: strings.Repeat("a", 32), Phase: "crash", OwnerPID: 1234, HelperPID: 2345, RequestSHA256: strings.Repeat("b", 64), ObservedActive: true, SourceLocked: true, AwaitingRootSignal: true}
	owner := strings.Repeat("c", 64)
	f := isolatedStructuralRootFault{Name: p.Name, Nonce: p.Nonce, Phase: "crash", OwnerPID: p.OwnerPID, HelperPID: p.HelperPID, OwnerStartTime: "101", HelperStartTime: "102", OwnerSHA256: owner, HelperSHA256: codexprofile.CLIBinarySHA256V1, RequestSHA256: p.RequestSHA256, CrashReadySHA256: strings.Repeat("d", 64), UnitResult: "signal", Signal: 9, UnitCode: 2, UnitStatus: 9, StartClientExit: 1, PIDFDPinned: true, SignalReturned: true, OldOwnerAbsent: true, OldHelperAbsent: true, CgroupEmpty: true, KnownRefPreserved: true, Passed: true}
	if !isolatedStructuralFaultAccepted(f, p, owner) {
		t.Fatal("correlated expected Owner signal rejected")
	}
	for _, phase := range []string{"", "restart", "helperloss"} {
		changed := p
		changed.Phase = phase
		if isolatedStructuralFaultAccepted(f, changed, owner) {
			t.Fatal("different point phase accepted")
		}
	}
	for name, mutate := range map[string]func(*isolatedStructuralRootFault){"owner": func(f *isolatedStructuralRootFault) { f.OwnerPID++ }, "helper": func(f *isolatedStructuralRootFault) { f.HelperPID++ }, "nonce": func(f *isolatedStructuralRootFault) { f.Nonce = "wrong" }, "request": func(f *isolatedStructuralRootFault) { f.RequestSHA256 = "wrong" }, "launcher": func(f *isolatedStructuralRootFault) { f.HelperSHA256 = "wrong" }, "pidfd": func(f *isolatedStructuralRootFault) { f.PIDFDPinned = false }, "syscall": func(f *isolatedStructuralRootFault) { f.SignalReturned = false }, "signal": func(f *isolatedStructuralRootFault) { f.Signal = 15 }, "timeout": func(f *isolatedStructuralRootFault) { f.UnitResult = "timeout" }, "client": func(f *isolatedStructuralRootFault) { f.StartClientExit = 0 }, "old-owner": func(f *isolatedStructuralRootFault) { f.OldOwnerAbsent = false }, "old-helper": func(f *isolatedStructuralRootFault) { f.OldHelperAbsent = false }, "old-cgroup": func(f *isolatedStructuralRootFault) { f.CgroupEmpty = false }, "reference": func(f *isolatedStructuralRootFault) { f.KnownRefPreserved = false }, "leading-zero": func(f *isolatedStructuralRootFault) { f.HelperStartTime = "0102" }} {
		t.Run(name, func(t *testing.T) {
			changed := f
			mutate(&changed)
			if isolatedStructuralFaultAccepted(changed, p, owner) {
				t.Fatal("unrelated or incomplete fault accepted")
			}
		})
	}
}

// Real Store admission/retirement/publication; proof digests are deliberately
// constructed synthetic metadata, not physical enrollment or native readiness.
func TestIsolatedStructuralSnapshotUsesLiveWAL(t *testing.T) {
	c := startupCodexConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := os.MkdirAll(filepath.Dir(c.StateDatabase), 0700); err != nil {
		t.Fatal(err)
	}
	s, err := sandboxstore.Open(ctx, c.StateDatabase)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	scope, err := sessionauth.Digest(c.Codex.Scope.SessionScope())
	if err != nil {
		t.Fatal(err)
	}
	b := c.Codex.Credential
	base := strings.Repeat("a", 64)
	g := sandboxstore.CredentialGeneration{SlotRef: b.SlotRef, Generation: int64(b.Generation), SourceDigest: strings.Repeat("b", 64), WorkspaceRef: b.WorkspaceRef, AuthProfileRef: b.AuthProfileRef, ScopeDigest: scope}
	proof := credentialsource.Proof{Scheme: credentialsource.EnrollmentScheme, RootObjectDigest: strings.Repeat("d", 64), SlotObjectDigest: strings.Repeat("e", 64), LocatorDigest: strings.Repeat("f", 64)}
	if err := s.RegisterCredentialEnrollment(ctx, g, proof); err != nil {
		t.Fatal(err)
	}
	a := sandboxstore.TargetAuthority{TargetID: c.Targets[0].ID(), TargetRevision: c.Targets[0].Revision(), RevisionPin: base, RunnerStateKind: targetmanifest.RunnerStateNone, Credential: &sandboxstore.CredentialRef{SlotRef: g.SlotRef, Generation: g.Generation}}
	if err := s.RegisterEnrolledTargetAuthorities(ctx, []sandboxstore.EnrolledTargetAuthority{{Target: a, Scope: &sandboxstore.CredentialTargetScope{WorkspaceRef: g.WorkspaceRef, AuthProfileRef: g.AuthProfileRef, ScopeDigest: g.ScopeDigest}}}); err != nil {
		t.Fatal(err)
	}
	r := executionwire.StartRunRequest{RunID: "structural-observe", TargetID: a.TargetID, ExpectedRevision: a.TargetRevision, SessionScopeDigest: g.ScopeDigest, Input: executionwire.TextInput{MediaType: executionwire.MediaTypeTextPlain, Text: "synthetic observation"}, Deadline: time.Now().UTC().Add(time.Minute).Truncate(time.Millisecond)}
	if _, created, err := s.RegisterStart(ctx, r, a.TargetRevision, g.WorkspaceRef, true, sandboxstore.SessionPolicy{Mode: targetmanifest.SessionNewOnly}); err != nil || !created {
		t.Fatal("actual admission failed", err)
	}
	before, err := isolatedStructuralReadSnapshot(ctx, c.StateDatabase, r.RunID)
	if err != nil || !isolatedStructuralIdentity(before, c, base) || before.Revoked != 0 || before.Occupied != 1 || !before.WorkspaceHeld {
		t.Fatal("live admission observation differs", err, before)
	}
	if _, err := isolatedStructuralReadSnapshot(ctx, c.StateDatabase, "unrelated"); err == nil {
		t.Fatal("unrelated Run joined")
	}
	if err := s.RetireOccupiedCredentialGenerations(ctx); err != nil {
		t.Fatal(err)
	}
	retired, err := isolatedStructuralReadSnapshot(ctx, c.StateDatabase, r.RunID)
	if err != nil || !isolatedStructuralSameIdentity(before, retired) || retired.Revoked != 1 || retired.Occupied != 1 || !retired.WorkspaceHeld {
		t.Fatal("retirement released authority early", err)
	}
	if _, err := s.MarkCancelling(ctx, r.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StageTerminal(ctx, executionwire.RunEvent{RunID: r.RunID, Seq: 1, Type: executionwire.RunEventCancelled}, nil); err != nil {
		t.Fatal(err)
	}
	staged, err := isolatedStructuralReadSnapshot(ctx, c.StateDatabase, r.RunID)
	if err != nil || !staged.Pending || staged.Published || staged.Occupied != 1 || !staged.WorkspaceHeld {
		t.Fatal("staged outcome confused with publication", err)
	}
	if _, err := s.ConfirmRuntimeStopped(ctx, r.RunID); err != nil {
		t.Fatal(err)
	}
	after, err := isolatedStructuralReadSnapshot(ctx, c.StateDatabase, r.RunID)
	if err != nil || !isolatedStructuralSameIdentity(before, after) || !after.Published || after.Pending || after.Revoked != 1 || after.Occupied != 0 || after.WorkspaceHeld {
		t.Fatal("actual release differs", err)
	}
	changed := after
	changed.Scope = strings.Repeat("a", 64)
	changed.Generation.ScopeDigest = changed.Scope
	if isolatedStructuralIdentity(changed, c, base) || isolatedStructuralSameIdentity(before, changed) {
		t.Fatal("mutually matching wrong scope accepted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := isolatedStructuralReadSnapshot(ctx, c.StateDatabase, r.RunID)
	if err != nil || reopened != after {
		t.Fatal("closed DB lost original WAL observation", err)
	}
}

func TestIsolatedStructuralOriginalListenerClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener, err := localhttp.Listen(filepath.Join(t.TempDir(), "control.sock"), localidentity.UID(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	server := localhttp.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	// Actual HTTP listener registration is synchronized by one ordinary request.
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/", nil)
	response, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if response.Body.Close() != nil {
		t.Fatal("response close failed")
	}
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatal("original Serve return differs", err)
		}
	case <-ctx.Done():
		t.Fatal("server did not join")
	}
	if err := listener.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("actual deferred listener Close must retain already-closed result", err)
	}
}

func structuralCloseGold() isolatedStructuralFlow {
	f := isolatedStructuralFlow{Name: "ownerrestart", Nonce: strings.Repeat("a", 32), Phase: "restart", OwnerPID: 1234, Initialized: true, Finished: true, AfterOriginalJoins: true, Events: []isolatedStructuralFlowEvent{}}
	for _, kind := range []string{"controller-close", "store-close", "listener-close", "process-lock-close", "artifacts-close"} {
		f.Operations++
		id := f.Operations
		end := isolatedStructuralFlowEvent{Sequence: len(f.Events) + 2, ID: id, Kind: kind, Returned: true, SuccessKnown: true, OK: true, ErrorKind: "none"}
		if kind == "listener-close" {
			end.OK = false
			end.ErrorKind = "already-closed"
		}
		f.Events = append(f.Events, isolatedStructuralFlowEvent{Sequence: len(f.Events) + 1, ID: id, Kind: kind, Begin: true}, end)
	}
	return f
}

func TestIsolatedStructuralCompleteCloses(t *testing.T) {
	f := structuralCloseGold()
	tc := isolatedNativeCase{Name: f.Name, Nonce: f.Nonce}
	accept := func(f isolatedStructuralFlow, j, n bool) bool {
		return isolatedStructuralFlowAccepted(f, tc, "restart", 1234, true) && isolatedStructuralRestartCloses(f, j, n)
	}
	if !accept(f, true, true) {
		t.Fatal("actual original completion order rejected")
	}
	if accept(f, false, true) || accept(f, true, false) {
		t.Fatal("unjoined or failed serve accepted")
	}
	for _, kind := range []string{"controller-close", "store-close", "listener-close", "process-lock-close", "artifacts-close"} {
		for _, mutation := range []string{"missing", "other-error", "already-closed", "out-of-order"} {
			if kind == "listener-close" && mutation == "already-closed" {
				continue
			}
			t.Run(kind+"/"+mutation, func(t *testing.T) {
				changed := f
				changed.Events = append([]isolatedStructuralFlowEvent(nil), f.Events...)
				for i := range changed.Events {
					e := &changed.Events[i]
					if e.Kind != kind {
						continue
					}
					if mutation == "missing" {
						e.Kind = "publication"
					}
					if !e.Begin && mutation == "other-error" {
						e.OK = false
						e.ErrorKind = "other"
					}
					if !e.Begin && mutation == "already-closed" {
						e.OK = false
						e.ErrorKind = "already-closed"
					}
					if mutation == "out-of-order" {
						e.Sequence = 99
					}
				}
				if accept(changed, true, true) {
					t.Fatal("incomplete original close trace accepted")
				}
			})
		}
	}
	helper := isolatedStructuralFlow{Name: "helperloss", Nonce: tc.Nonce, Phase: "helperloss", OwnerPID: 1234, Initialized: true, Finished: true, AfterOriginalJoins: true, Operations: 1, Events: []isolatedStructuralFlowEvent{{Sequence: 1, ID: 1, Kind: "native-invoke", Begin: true}, {Sequence: 2, ID: 1, Kind: "native-invoke", Returned: true, SuccessKnown: true, OK: false, ErrorKind: "other"}}}
	if !isolatedStructuralFlowAccepted(helper, isolatedNativeCase{Name: helper.Name, Nonce: helper.Nonce}, "helperloss", 1234, true) {
		t.Fatal("observed original invocation failure rejected")
	}
	helper.Events[1].OK = true
	helper.Events[1].ErrorKind = "none"
	if isolatedStructuralFlowAccepted(helper, isolatedNativeCase{Name: helper.Name, Nonce: helper.Nonce}, "helperloss", 1234, true) {
		t.Fatal("successful native invocation accepted as helper loss")
	}
}

func TestIsolatedStructuralBoundedOpenedObject(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "receipt")
	uid := uint32(os.Geteuid())
	if err := os.WriteFile(path, []byte("authenticated opened bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("substitute pathname bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	data, object, err := isolatedStructuralReadOpened(f, uid, 0077)
	if err != nil || string(data) != "authenticated opened bytes" || object.UID != uid {
		t.Fatal("metadata or bytes switched to substituted pathname", err)
	}
	if _, _, err := isolatedStructuralReadObject(path, uid+1, 0077); err == nil {
		t.Fatal("wrong owner accepted")
	}
	for _, kind := range []string{"symlink", "fifo", "oversized", "empty", "mode", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			p := filepath.Join(root, kind)
			switch kind {
			case "symlink":
				err = os.Symlink(path, p)
			case "fifo":
				err = unix.Mkfifo(p, 0600)
			case "oversized":
				err = os.WriteFile(p, []byte(strings.Repeat("x", 65537)), 0600)
			case "empty":
				err = os.WriteFile(p, nil, 0600)
			case "mode":
				err = os.WriteFile(p, []byte("x"), 0600)
				if err == nil {
					err = os.Chmod(p, 0666)
				}
			case "hardlink":
				err = os.Link(path, p)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := isolatedStructuralReadObject(p, uid, 0077); err == nil {
				t.Fatal("unsafe opened object accepted")
			}
		})
	}
	point := isolatedStructuralCrashPoint{Phase: "crash"}
	gold, _ := json.Marshal(point)
	if _, err := isolatedStructuralDecodeCrashPoint(gold); err != nil {
		t.Fatal("complete typed point rejected", err)
	}
	for _, bad := range []string{strings.Replace(string(gold), `"GracefullyCompleted":false`, `"GracefullyCompleted":null`, 1), strings.Replace(string(gold), `,"GracefullyCompleted":false`, "", 1), strings.Replace(string(gold), `"Revoked":0`, `"Revoked":0,"Revoked":0`, 1), strings.Replace(string(gold), `"ScopeDigest":""`, `"ScopeDigest":null`, 1)} {
		if _, err := isolatedStructuralDecodeCrashPoint([]byte(bad)); err == nil {
			t.Fatal("incomplete or duplicate nested point accepted")
		}
	}
	fault := isolatedStructuralRootFault{}
	encoded, _ := json.Marshal(fault)
	if _, err := isolatedStructuralDecodeRootFault(encoded); err != nil {
		t.Fatal("complete typed root schema rejected", err)
	}
	if _, err := isolatedStructuralDecodeRootFault([]byte(strings.Replace(string(encoded), `"OldOwnerAbsent":false`, `"OldOwnerAbsent":null`, 1))); err == nil {
		t.Fatal("unobserved false default accepted")
	}
}
