//go:build linux && amd64 && codexintegration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxcontroller"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
	"golang.org/x/sys/unix"
)

// These receipts contain synthetic identities and proof metadata, never source
// contents. A snapshot reads the live WAL in one readonly SQL statement.
type isolatedStructuralSnapshot struct {
	RunID, Fingerprint, TargetID, Revision, Workspace, Scope, Pin, State, Ref string
	Generation                                                                sandboxstore.CredentialGeneration
	Proof                                                                     credentialsource.Proof
	RunCount, TargetCount, GenerationCount, SourceCount, Revoked, Occupied    int
	WorkspaceHeld, Pending, Intent, Published, OutputPresent, Writable        bool
	Sequence                                                                  uint64
}

func isolatedStructuralReadSnapshot(ctx context.Context, path, id string) (isolatedStructuralSnapshot, error) {
	u := url.URL{Scheme: "file", Path: path}
	u.RawQuery = url.Values{"mode": {"ro"}, "_pragma": {"query_only(1)", "trusted_schema(0)", "busy_timeout(1000)"}}.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return isolatedStructuralSnapshot{}, err
	}
	db.SetMaxOpenConns(1)
	observe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var s isolatedStructuralSnapshot
	err = db.QueryRowContext(observe, `SELECT r.run_id,r.request_fingerprint,r.target_id,r.target_revision,
r.workspace_id,r.session_scope_digest,a.semantic_fingerprint,r.state,coalesce(r.runtime_ref,''),
g.slot_ref,g.generation,g.source_digest,g.workspace_ref,g.auth_profile_ref,g.scope_digest,
g.proof_scheme,g.root_object_digest,g.slot_object_digest,g.locator_digest,
(SELECT count(*) FROM runs),(SELECT count(*) FROM target_revisions),
(SELECT count(*) FROM credential_generations),(SELECT count(*) FROM credential_sources),
(SELECT count(*) FROM credential_revocations v WHERE v.slot_ref=g.slot_ref AND v.generation=g.generation),
(SELECT count(*) FROM credential_occupancy o WHERE o.run_id=r.run_id AND o.slot_ref=g.slot_ref
 AND o.generation=g.generation AND o.source_digest=g.source_digest),
EXISTS(SELECT 1 FROM workspace_locks w WHERE w.run_id=r.run_id AND w.workspace_id=r.workspace_id),
EXISTS(SELECT 1 FROM staged_terminals p WHERE p.run_id=r.run_id),r.runtime_intent_pending,
r.terminal_at_unix_ms IS NOT NULL,r.output_text IS NOT NULL,r.writable,r.last_event_seq
FROM runs r JOIN target_revisions a ON a.target_id=r.target_id AND a.revision=r.target_revision
JOIN target_credentials t ON t.target_id=r.target_id AND t.target_revision=r.target_revision
JOIN credential_generations g USING(slot_ref,generation)
WHERE r.run_id=? AND a.credential_kind='bound' AND g.workspace_ref=r.workspace_id
 AND g.scope_digest=r.session_scope_digest`, id).Scan(
		&s.RunID, &s.Fingerprint, &s.TargetID, &s.Revision, &s.Workspace, &s.Scope, &s.Pin, &s.State, &s.Ref,
		&s.Generation.SlotRef, &s.Generation.Generation, &s.Generation.SourceDigest, &s.Generation.WorkspaceRef, &s.Generation.AuthProfileRef, &s.Generation.ScopeDigest,
		&s.Proof.Scheme, &s.Proof.RootObjectDigest, &s.Proof.SlotObjectDigest, &s.Proof.LocatorDigest,
		&s.RunCount, &s.TargetCount, &s.GenerationCount, &s.SourceCount, &s.Revoked, &s.Occupied,
		&s.WorkspaceHeld, &s.Pending, &s.Intent, &s.Published, &s.OutputPresent, &s.Writable, &s.Sequence)
	return s, errors.Join(err, db.Close())
}

func isolatedStructuralIdentity(s isolatedStructuralSnapshot, config sandboxconfig.Config, base string) bool {
	if config.Codex == nil {
		return false
	}
	scope, err := sessionauth.Digest(config.Codex.Scope.SessionScope())
	return len(s.Fingerprint) == 64 && len(base) == 64 && s.RunID != "" && s.RunCount == 1 && s.TargetCount == 1 &&
		s.GenerationCount == 1 && s.SourceCount == 1 && s.Proof.Validate() == nil && config.Codex != nil && len(config.Targets) == 1 &&
		s.TargetID == config.Targets[0].ID() && s.Revision == config.Targets[0].Revision() && s.Workspace == s.Generation.WorkspaceRef &&
		err == nil && s.Scope == scope && s.Scope == s.Generation.ScopeDigest && s.Generation.SlotRef == config.Codex.Credential.SlotRef &&
		s.Generation.Generation == int64(config.Codex.Credential.Generation) && s.Generation.AuthProfileRef == config.Codex.Credential.AuthProfileRef &&
		s.Workspace == config.Codex.Credential.WorkspaceRef && s.Writable &&
		s.Pin == isolatedNativeEnrolledPin(base, s.Generation, s.Proof)
}

func isolatedStructuralSameIdentity(a, b isolatedStructuralSnapshot) bool {
	return a.RunID == b.RunID && a.Fingerprint == b.Fingerprint && a.TargetID == b.TargetID && a.Revision == b.Revision &&
		a.Workspace == b.Workspace && a.Scope == b.Scope && a.Pin == b.Pin && a.Generation == b.Generation && a.Proof == b.Proof &&
		a.Writable == b.Writable && b.RunCount == 1 && b.TargetCount == 1 && b.GenerationCount == 1 && b.SourceCount == 1
}

type isolatedStructuralObject struct {
	Device, Inode uint64
	UID, Mode     uint32
	Links         uint64
}

// Authenticate and compare the exact opened object, never a later pathname.
// NONBLOCK rejects FIFO/device replacements before any content read can wait.
func isolatedStructuralReadObject(path string, uid, forbiddenMode uint32) ([]byte, isolatedStructuralObject, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, isolatedStructuralObject{}, err
	}
	return isolatedStructuralReadOpened(f, uid, forbiddenMode)
}

// Owns/closes f. A pathname replacement cannot change the authenticated bytes.
func isolatedStructuralReadOpened(f *os.File, uid, forbiddenMode uint32) ([]byte, isolatedStructuralObject, error) {
	var before, after unix.Stat_t
	err := unix.Fstat(int(f.Fd()), &before)
	if err == nil && (before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uid || before.Nlink != 1 || before.Mode&forbiddenMode != 0 || before.Size < 1 || before.Size > 65536) {
		err = errors.New("bounded authenticated object required")
	}
	var data []byte
	if err == nil {
		data, err = io.ReadAll(io.LimitReader(f, 65537))
	}
	statErr := unix.Fstat(int(f.Fd()), &after)
	closeErr := f.Close()
	if err != nil || statErr != nil || closeErr != nil || len(data) > 65536 || int64(len(data)) != before.Size ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Uid != after.Uid || before.Gid != after.Gid || before.Mode != after.Mode ||
		before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		clear(data)
		return nil, isolatedStructuralObject{}, errors.Join(err, statErr, closeErr, errors.New("opened object changed or read failed"))
	}
	return data, isolatedStructuralObject{uint64(before.Dev), before.Ino, before.Uid, before.Mode, before.Nlink}, nil
}

func isolatedStructuralBytesSHA(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func isolatedStructuralRequired(data []byte, keys []string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if strictjson.Decode(data, 65536, 12, &fields) != nil || len(fields) != len(keys) {
		return nil, errors.New("complete structural object required")
	}
	for _, key := range keys {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errors.New("missing structural field")
		}
	}
	return fields, nil
}

func isolatedStructuralReadCrashPoint(path string) (isolatedStructuralCrashPoint, string, error) {
	var p isolatedStructuralCrashPoint
	data, _, err := isolatedStructuralReadObject(path, 1001, 0077)
	if err != nil {
		return p, "", err
	}
	p, err = isolatedStructuralDecodeCrashPoint(data)
	return p, isolatedStructuralBytesSHA(data), err
}

func isolatedStructuralDecodeCrashPoint(data []byte) (isolatedStructuralCrashPoint, error) {
	var p isolatedStructuralCrashPoint
	fields, err := isolatedStructuralRequired(data, []string{"Name", "Nonce", "Phase", "BasePin", "ConfigSHA256", "SourceSHA256", "RequestSHA256", "OwnerPID", "HelperPID", "Snapshot", "Database", "Source", "SourceLocked", "ObservedActive", "AwaitingRootSignal", "GracefullyCompleted"})
	if err != nil || strictjson.Decode(data, 65536, 12, &p) != nil {
		return p, errors.New("complete typed crash point required")
	}
	snapshot, err := isolatedStructuralRequired(fields["Snapshot"], []string{"RunID", "Fingerprint", "TargetID", "Revision", "Workspace", "Scope", "Pin", "State", "Ref", "Generation", "Proof", "RunCount", "TargetCount", "GenerationCount", "SourceCount", "Revoked", "Occupied", "WorkspaceHeld", "Pending", "Intent", "Published", "OutputPresent", "Writable", "Sequence"})
	if err != nil {
		return p, err
	}
	if _, err = isolatedStructuralRequired(snapshot["Generation"], []string{"SlotRef", "Generation", "SourceDigest", "WorkspaceRef", "AuthProfileRef", "ScopeDigest"}); err != nil {
		return p, err
	}
	if _, err = isolatedStructuralRequired(snapshot["Proof"], []string{"Scheme", "RootObjectDigest", "SlotObjectDigest", "LocatorDigest"}); err != nil {
		return p, err
	}
	for _, key := range []string{"Database", "Source"} {
		if _, err = isolatedStructuralRequired(fields[key], []string{"Device", "Inode", "UID", "Mode", "Links"}); err != nil {
			return p, err
		}
	}
	return p, nil
}

func isolatedStructuralReadRootFault(path string) (isolatedStructuralRootFault, error) {
	var f isolatedStructuralRootFault
	data, _, err := isolatedStructuralReadObject(path, 0, 0022)
	if err != nil {
		return f, err
	}
	return isolatedStructuralDecodeRootFault(data)
}

func isolatedStructuralDecodeRootFault(data []byte) (isolatedStructuralRootFault, error) {
	var f isolatedStructuralRootFault
	if _, err := isolatedStructuralRequired(data, []string{"Name", "Nonce", "Phase", "OwnerStartTime", "HelperStartTime", "OwnerSHA256", "HelperSHA256", "RequestSHA256", "CrashReadySHA256", "UnitResult", "OwnerPID", "HelperPID", "Signal", "UnitCode", "UnitStatus", "StartClientExit", "PIDFDPinned", "SignalReturned", "OldOwnerAbsent", "OldHelperAbsent", "CgroupEmpty", "KnownRefPreserved", "Passed"}); err != nil {
		return f, err
	}
	if strictjson.Decode(data, 65536, 12, &f) != nil {
		return f, errors.New("complete typed root fault required")
	}
	return f, nil
}

func isolatedStructuralObjectAt(path string) (isolatedStructuralObject, error) {
	var s unix.Stat_t
	if err := unix.Lstat(path, &s); err != nil {
		return isolatedStructuralObject{}, err
	}
	if s.Mode&unix.S_IFMT != unix.S_IFREG || s.Uid != 1001 || s.Nlink != 1 || s.Mode&0077 != 0 {
		return isolatedStructuralObject{}, errors.New("fixed private object required")
	}
	return isolatedStructuralObject{uint64(s.Dev), s.Ino, s.Uid, s.Mode, s.Nlink}, nil
}

type isolatedStructuralStoreReceipt struct {
	Phase, Name, Nonce                      string
	Forwarded, SourceLocked, SourceUnlocked bool
	KnownRefPresent, KnownRefAbsent, Passed bool
	Before, After                           isolatedStructuralSnapshot
}

// Observation errors are sticky but never replace an original Store result.
// In particular the helper-loss refnil path must not demand a container removal.
type isolatedStructuralStore struct {
	*sandboxstore.Store
	config       sandboxconfig.Config
	runtime      sandboxcontroller.Runtime
	root, id     string
	tc           isolatedNativeCase
	phase, base  string
	baseline     isolatedStructuralSnapshot
	mu           sync.Mutex
	observeErr   error
	retireCalls  int
	publishCalls int
	retirement   isolatedStructuralStoreReceipt
	publication  isolatedStructuralStoreReceipt
}

func (w *isolatedStructuralStore) source() string {
	b := w.config.Codex.Credential
	return filepath.Join(b.Root, b.Directory, "auth.json")
}

func (w *isolatedStructuralStore) save(kind string, r isolatedStructuralStoreReceipt, observeErr error) {
	writeErr := isolatedNativeWriteJSON(w.root+"/"+w.phase+"-"+kind+".json", r)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.observeErr = errors.Join(w.observeErr, observeErr, writeErr)
	if kind == "retirement" {
		w.retirement = r
	} else {
		w.publication = r
	}
}

func (w *isolatedStructuralStore) RevokeRunCredential(ctx context.Context, id string) error {
	err := w.Store.RevokeRunCredential(ctx, id)
	w.mu.Lock()
	w.retireCalls++
	w.mu.Unlock()
	if err != nil {
		return err
	}
	s, observeErr := isolatedStructuralReadSnapshot(ctx, w.config.StateDatabase, id)
	r := isolatedStructuralStoreReceipt{Phase: w.phase, Name: w.tc.Name, Nonce: w.tc.Nonce, Forwarded: true, After: s,
		SourceLocked: isolatedReadySourceLock(w.source(), true) == nil}
	r.Passed = observeErr == nil && w.phase == "helperloss" && s.RunID == w.id && isolatedStructuralIdentity(s, w.config, w.base) &&
		s.Ref == "" && !s.Intent && s.Pending && !s.Published && !s.OutputPresent && s.Revoked == 1 && s.Occupied == 1 && s.WorkspaceHeld && r.SourceLocked
	w.save("retirement", r, observeErr)
	return err
}

func (w *isolatedStructuralStore) RetireOccupiedCredentialGenerations(ctx context.Context) error {
	err := w.Store.RetireOccupiedCredentialGenerations(ctx)
	if w.phase == "helperloss" {
		// Its initial Controller.New has no Run yet. The later real per-Run
		// Revoke is the helper-loss retirement witness.
		return err
	}
	w.mu.Lock()
	w.retireCalls++
	w.mu.Unlock()
	if err != nil {
		return err
	}
	s, observeErr := isolatedStructuralReadSnapshot(ctx, w.config.StateDatabase, w.id)
	r := isolatedStructuralStoreReceipt{Phase: w.phase, Name: w.tc.Name, Nonce: w.tc.Nonce, Forwarded: true, After: s,
		Before: w.baseline, SourceUnlocked: isolatedReadySourceLock(w.source(), false) == nil}
	// This additional readonly inspection is AFTER forwarded retirement, never
	// before it. Original reconcileRuns and cleanup have not run yet.
	if w.runtime != nil && s.Ref != "" {
		_, inspectErr := w.runtime.Inspect(ctx, s.Ref)
		r.KnownRefPresent = inspectErr == nil
		observeErr = errors.Join(observeErr, inspectErr)
	}
	r.Passed = observeErr == nil && w.phase == "restart" && isolatedStructuralSameIdentity(w.baseline, s) &&
		isolatedStructuralIdentity(s, w.config, w.base) && s.State == "running" && s.Ref == w.baseline.Ref && s.Ref != "" &&
		!s.Intent && !s.Pending && !s.Published && !s.OutputPresent && s.Revoked == 1 && s.Occupied == 1 && s.WorkspaceHeld &&
		r.SourceUnlocked && r.KnownRefPresent
	w.save("retirement", r, observeErr)
	return err
}

func (w *isolatedStructuralStore) ConfirmRuntimeStopped(ctx context.Context, id string) (sandboxstore.Run, error) {
	s, observeErr := isolatedStructuralReadSnapshot(ctx, w.config.StateDatabase, id)
	r := isolatedStructuralStoreReceipt{Phase: w.phase, Name: w.tc.Name, Nonce: w.tc.Nonce, Before: s,
		SourceUnlocked: isolatedReadySourceLock(w.source(), false) == nil}
	if w.phase == "restart" && w.runtime != nil && w.baseline.Ref != "" {
		_, inspectErr := w.runtime.Inspect(ctx, w.baseline.Ref)
		r.KnownRefAbsent = errors.Is(inspectErr, dockerruntime.ErrNotFound)
		if !r.KnownRefAbsent {
			observeErr = errors.Join(observeErr, errors.New("known ref remains before publication"))
		}
	}
	pre := observeErr == nil && id == w.id && isolatedStructuralIdentity(s, w.config, w.base) &&
		!s.Intent && s.Pending && !s.Published && !s.OutputPresent && s.Revoked == 1 && s.Occupied == 1 && s.WorkspaceHeld && r.SourceUnlocked
	if w.phase == "helperloss" {
		pre = pre && s.Ref == ""
	} else {
		pre = pre && w.phase == "restart" && isolatedStructuralSameIdentity(w.baseline, s) && s.Ref == w.baseline.Ref && r.KnownRefAbsent
	}
	// STRUCTURAL_PUBLICATION_OBSERVATION
	run, err := w.Store.ConfirmRuntimeStopped(ctx, id)
	r.Forwarded = true
	var postErr error
	r.After, postErr = isolatedStructuralReadSnapshot(ctx, w.config.StateDatabase, id)
	observeErr = errors.Join(observeErr, postErr)
	post := observeErr == nil && isolatedStructuralSameIdentity(s, r.After) && r.After.Published && !r.After.Pending &&
		!r.After.Intent && r.After.Ref == "" && !r.After.OutputPresent && r.After.Revoked == 1 && r.After.Occupied == 0 && !r.After.WorkspaceHeld
	r.Passed = pre && post && err == nil && ((w.phase == "helperloss" && r.After.State == "failed") || (w.phase == "restart" && r.After.State == "interrupted"))
	w.mu.Lock()
	w.publishCalls++
	w.mu.Unlock()
	w.save("publication", r, observeErr)
	return run, err
}

func (w *isolatedStructuralStore) accepted() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.observeErr == nil && w.retireCalls == 1 && w.publishCalls == 1 && w.retirement.Passed && w.publication.Passed
}

type isolatedStructuralFlowEvent struct {
	Sequence, ID            int
	Kind                    string
	ErrorKind               string
	Begin, Returned         bool
	SuccessKnown, OK        bool
	Started, SignalObserved bool
}

type isolatedStructuralFlow struct {
	Name, Nonce, Phase                       string
	OwnerPID, Operations, InFlight           int
	Initialized, Invalid, Overflow, Finished bool
	AfterOriginalJoins                       bool
	Events                                   []isolatedStructuralFlowEvent
}

func isolatedStructuralFlowAccepted(f isolatedStructuralFlow, tc isolatedNativeCase, phase string, pid int, final bool) bool {
	name, validPhase := isolatedStructuralPhaseName(phase)
	if !validPhase || name != tc.Name || pid <= 1 || f.Name != tc.Name || f.Nonce != tc.Nonce || f.Phase != phase || f.OwnerPID != pid || !f.Initialized || f.Invalid || f.Overflow ||
		f.Finished != final || f.AfterOriginalJoins != final || f.InFlight != 0 || f.Operations < 0 || f.Operations > 128 || len(f.Events) > 256 {
		return false
	}
	active := map[int]string{}
	seen := map[int]bool{}
	for i, e := range f.Events {
		if e.Sequence != i+1 || e.ID < 1 || e.ID > f.Operations || !isolatedStructuralFlowKind(e.Kind) || e.SignalObserved {
			return false
		}
		if e.Begin {
			if seen[e.ID] || e.Returned || e.SuccessKnown || e.OK || e.Started || e.ErrorKind != "" {
				return false
			}
			seen[e.ID], active[e.ID] = true, e.Kind
		} else {
			expectedFailure := phase == "helperloss" && e.Kind == "native-invoke" && final
			alreadyClosed := phase == "restart" && final && e.Kind == "listener-close" && e.ErrorKind == "already-closed" && !e.OK
			command := e.Kind == "external-create" || e.Kind == "attach-start"
			if active[e.ID] != e.Kind || !e.Returned || !e.SuccessKnown || (!e.OK && !expectedFailure && !alreadyClosed) || (expectedFailure && e.OK) ||
				(e.OK && e.ErrorKind != "none") || (expectedFailure && e.ErrorKind != "other") || (e.Started && !command) || (command && e.OK && !e.Started) {
				return false
			}
			delete(active, e.ID)
		}
	}
	return len(active) == 0 && len(seen) == f.Operations && len(f.Events) == 2*f.Operations
}

func isolatedStructuralRestartCloses(f isolatedStructuralFlow, joined, returnedNil bool) bool {
	if !joined || !returnedNil || isolatedStructuralFlowCount(f, "controller-close-fallback") != 0 {
		return false
	}
	last := 0
	for _, kind := range []string{"controller-close", "store-close", "listener-close", "process-lock-close", "artifacts-close"} {
		if isolatedStructuralFlowCount(f, kind) != 1 {
			return false
		}
		begin, end := 0, 0
		for _, e := range f.Events {
			if e.Kind == kind {
				if e.Begin {
					begin = e.Sequence
				} else {
					end = e.Sequence
				}
			}
		}
		if begin <= last || end <= begin {
			return false
		}
		last = end
	}
	return true
}

func isolatedStructuralFlowKind(kind string) bool {
	switch kind {
	case "source-hold", "source-borrow", "source-read", "source-commit", "provider-new", "native-invoke", "external-create", "attach-start", "run-resource-close", "publication",
		"store-close", "listener-close", "process-lock-close", "artifacts-close", "controller-close", "controller-close-fallback", "startup-retirement":
		return true
	default:
		return false
	}
}

func isolatedStructuralFlowCount(f isolatedStructuralFlow, kind string) int {
	n := 0
	for _, e := range f.Events {
		if e.Begin && e.Kind == kind {
			n++
		}
	}
	return n
}

func isolatedStructuralNoReopen(f isolatedStructuralFlow) bool {
	for _, kind := range []string{"source-hold", "source-borrow", "source-read", "source-commit", "provider-new", "native-invoke", "external-create", "attach-start"} {
		if isolatedStructuralFlowCount(f, kind) != 0 {
			return false
		}
	}
	return true
}

func isolatedStructuralFixedConfig(c sandboxconfig.Config, name string) bool {
	if c.Schema != sandboxconfig.SchemaCodexV2 || c.Codex == nil || len(c.Targets) != 1 || c.Codex.Credential.Generation != 1 ||
		c.Runtime.Endpoint != "unix:///run/user/1001/docker.sock" || c.Runtime.CLI != "/opt/hgw-v4-acceptance/docker/bin/docker" {
		return false
	}
	root := composedFixtureRoot + "/" + name
	for _, p := range []string{c.Socket, c.StateDatabase, c.WorkspaceRoot, c.RunnerStateRoot, c.Codex.ProviderRoot, c.Codex.Credential.Root} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || !strings.HasPrefix(p, root+"/") {
			return false
		}
	}
	return true
}
