//go:build linux && amd64 && codexintegration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprovider"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/runnerbridge"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxcontroller"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"golang.org/x/sys/unix"
)

const composedFixtureRoot = "/srv/hgw-v4-acceptance/composed"

func isolatedNativeWithinWindow(now time.Time) bool {
	start := time.Date(2026, time.October, 5, 0, 0, 0, 0, time.UTC)
	return !now.Before(start) && now.Before(start.Add(24*time.Hour-600*time.Second))
}

type isolatedNativeCase struct {
	Name, Nonce     string
	BeforeAuth      json.RawMessage
	RefreshedTokens map[string]string
}

type isolatedNativePlan struct {
	Cases       []isolatedNativeCase
	ProbeSHA256 string
}

type isolatedNativeProbe struct {
	Nonce, Mode                                                           string
	UID, PID                                                              int
	NoNewPrivs, Seccomp, CapEff                                           string
	Namespaces                                                            map[string]string
	NamespaceErrnos, SocketErrnos                                         map[string]int
	OwnerSourceErrno, ProviderPathErrno                                   int
	OwnerSourceReadable                                                   bool
	Environment, Arguments, FDLinks                                       []string
	ProviderConnectPath                                                   string
	ProviderConnectAttempted, ProviderConnected, ProviderConnectionClosed bool
	ProviderConnectErrno, ProviderPeerUID, ProviderPeerPID                int
	ProviderSocketDevice, ProviderSocketInode                             uint64
}

type isolatedNativeUpstream struct {
	Name, Nonce                                                 string
	Inference, Catalog, Refresh                                 int
	HeadersVerified, ToolDefinitionVerified, ToolOutputVerified bool
}

type isolatedNativeClose struct {
	OwnerJoinAttempted, OwnerJoined, EndpointJoinAttempted, EndpointJoined, DrainedJoined bool
	Diagnostics                                                                           codexprovider.Diagnostics
}

type isolatedNativeSnapshot struct {
	Name, Nonce                                                               string
	OwnerPID, RunnerPID                                                       int
	OwnerStartTime, RunnerStartTime, OwnerUIDMap, RunnerUIDMap, LocalSeedPath string
	OwnerNamespaces, RunnerNamespaces                                         map[string]string
	SeedSHA256                                                                string
	SeedScannedBytes                                                          int64
	SeedSecretsAbsent, SeedPositiveControl                                    bool
	SourceNotMounted, StableProcesses, Passed                                 bool
}

type isolatedNativeResult struct {
	Name, StartedAt, FinishedAt, State, FailureCode, ContainerRef, Pin                         string
	Creates, Attaches, ScannedFiles                                                            int
	ScannedBytes                                                                               int64
	Startup, Enrollment, Ready, Completed, SourceHealthy, SourceObjectUnchanged, SourceUpdated bool
	ToolVerified, ProbeUnchanged, SecretsAbsent, RemovedWhileHeld, ReleasedBeforePublication   bool
	ControllerClosed, StoreClosed, ArtifactsClosed, ProcessLockClosed, Passed                  bool
	Events                                                                                     []string
	Upstream                                                                                   isolatedNativeUpstream
	Close                                                                                      isolatedNativeClose
	Snapshot                                                                                   isolatedNativeSnapshot
}

// Only the frozen credential-free no-NIC VM may opt in. A private build overlay
// supplies synthetic upstream exchanges and passive after-Close observations;
// production code has no provider selector, observer or endpoint override.
func TestIsolatedServiceNativeRun(t *testing.T) {
	if os.Getenv("HSG_V4_COMPOSED_PROBE") != "offline-vm-native-v1" {
		t.Skip("requires the frozen dedicated composition VM")
	}
	if os.Getuid() != 1001 || os.Geteuid() != 1001 || !isolatedNativeWithinWindow(time.Now()) {
		t.Fatal("fixed identity/freshness window required")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("no-NIC guest required")
	}
	var plan isolatedNativePlan
	if isolatedNativeReadJSON("/opt/hgw-v4-acceptance/composed-plan.json", &plan, 65536) != nil || len(plan.Cases) != 2 {
		t.Fatal("frozen native case inventory unavailable")
	}
	for i, tc := range plan.Cases {
		if tc.Name != []string{"fresh", "inference401"}[i] {
			t.Fatal("fixed native case order required")
		}
		if ok := t.Run(tc.Name, func(t *testing.T) { isolatedNativeRun(t, tc, plan.ProbeSHA256) }); !ok {
			break
		}
	}
}

func isolatedNativeRun(t *testing.T, tc isolatedNativeCase, probeHash string) {
	root := composedFixtureRoot + "/" + tc.Name
	result := isolatedNativeResult{Name: tc.Name, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	defer func() {
		result.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		result.Passed = !t.Failed() && result.Ready && result.Completed && result.SourceHealthy && result.SourceObjectUnchanged && result.ToolVerified && result.ProbeUnchanged && result.SecretsAbsent && result.RemovedWhileHeld && result.ReleasedBeforePublication && result.ControllerClosed && result.StoreClosed && result.ArtifactsClosed && result.ProcessLockClosed
		if isolatedNativeWriteJSON(root+"/result.json", result) != nil {
			t.Error("native result persistence failed")
		}
	}()
	nonce, err := hex.DecodeString(tc.Nonce)
	if err != nil || len(nonce) != 16 || len(probeHash) != 64 || !bytes.Contains(tc.BeforeAuth, []byte(".synthetic-")) {
		t.Fatal("invalid synthetic case identity")
	}
	if _, err := codexprovider.ParseOwnerAuth(tc.BeforeAuth); err != nil {
		t.Fatal("invalid synthetic owner source")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 260*time.Second)
	defer cancel()
	f := newIsolatedServiceFixture(t, ctx, "/opt/hgw-v4-acceptance/composed-"+tc.Name+".json", root, tc.BeforeAuth)
	defer func() {
		f.close(t)
		result.ControllerClosed, result.StoreClosed, result.ArtifactsClosed, result.ProcessLockClosed = f.controllerClosed, f.storeClosed, f.artifactsClosed, f.lockClosed
	}()
	result.Startup, result.Enrollment = true, true
	auth := filepath.Join(f.config.Codex.Credential.Root, f.config.Codex.Credential.Directory, "auth.json")
	var beforeStat unix.Stat_t
	if unix.Lstat(auth, &beforeStat) != nil {
		t.Fatal("source object observation unavailable")
	}
	workspace := filepath.Join(f.config.WorkspaceRoot, "project-main")
	probe := filepath.Join(workspace, "native-isolation-probe")
	if isolatedNativeFileSHA(probe) != probeHash {
		t.Fatal("workspace probe does not match frozen executable")
	}
	var control isolatedNativeProbe
	if isolatedNativeReadJSON(workspace+"/isolation-control-report.json", &control, 32768) != nil || control.Nonce != tc.Nonce || control.Mode != "control" || control.UID != 1001 || !control.OwnerSourceReadable || control.OwnerSourceErrno != 0 {
		t.Fatal("independent source control missing")
	}
	for _, name := range []string{"inet4", "inet6", "unix"} {
		if code, ok := control.SocketErrnos[name]; !ok || code != 0 {
			t.Fatal("socket positive control missing")
		}
	}
	selection := composedFixtureRoot + "/current-" + tc.Name + ".json"
	if isolatedNativeWriteJSON(selection, tc) != nil || os.Rename(selection, composedFixtureRoot+"/current-case.json") != nil {
		t.Fatal("private synthetic case selection unavailable")
	}
	runID := "hsg-compose-20261005-" + tc.Name
	w := &isolatedReadyWitness{DockerRuntime: f.adapter, Store: f.db, auth: auth, runID: runID}
	diagnostics := &isolatedNativeCapture{}
	nativeWitness := &isolatedNativeWitness{isolatedReadyWitness: w, root: root, diagnostics: diagnostics}
	captured := &isolatedNativeCapture{}
	result.Pin = isolatedNativeStart(t, f, nativeWitness, sandboxcontroller.Store(w), captured)
	manifest := f.config.Targets[0]
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	var terminal sandboxstore.Run
	for {
		run, err := f.db.GetRun(ctx, runID)
		if err != nil {
			t.Fatal("durable native result unavailable")
		}
		if run.TerminalAt != nil {
			terminal = run
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("native fixture deadline reached")
		case <-tick.C:
		}
	}
	result.State = string(terminal.State)
	if terminal.Failure != nil {
		result.FailureCode = string(terminal.Failure.Code)
	}
	if terminal.State != executionwire.RunStateCompleted || terminal.Output == nil || terminal.Output.Text != "HSG_COMPOSED_OK" || terminal.TerminalPending || terminal.CredentialLeaseHeld || terminal.RuntimeRef != nil || terminal.RuntimeIntentPending || terminal.WorkspaceLockHeld {
		t.Fatal("native Run did not complete with released authority")
	}
	result.Completed = true
	w.mu.Lock()
	result.Ready, result.ContainerRef, result.Creates, result.Attaches = w.ready, w.ref, w.creates, w.attaches
	result.RemovedWhileHeld, result.ReleasedBeforePublication = w.removed, w.published
	result.Events = append([]string(nil), w.events...)
	w.mu.Unlock()
	if !result.Ready || result.Creates != 1 || result.Attaches != 1 || !result.RemovedWhileHeld || !result.ReleasedBeforePublication {
		t.Fatal("composed execution witnesses incomplete")
	}
	if nativeWitness.observationError() != nil || isolatedNativeReadJSON(root+"/snapshot-result.json", &result.Snapshot, 65536) != nil || result.Snapshot.Name != tc.Name || result.Snapshot.Nonce != tc.Nonce || result.Snapshot.OwnerPID != os.Getpid() || !result.Snapshot.Passed || !result.Snapshot.SourceNotMounted || !result.Snapshot.StableProcesses || !result.Snapshot.SeedSecretsAbsent || !result.Snapshot.SeedPositiveControl || result.Snapshot.SeedScannedBytes <= 0 || len(result.Snapshot.SeedSHA256) != 64 {
		t.Fatal("independent exact process/mount snapshot unavailable")
	}
	for _, name := range []string{"pid", "mnt", "user"} {
		if result.Snapshot.OwnerNamespaces[name] == "" || result.Snapshot.OwnerNamespaces[name] == result.Snapshot.RunnerNamespaces[name] {
			t.Fatal("owner/Runner namespace separation missing")
		}
	}
	if _, err := f.adapter.Inspect(ctx, result.ContainerRef); !errors.Is(err, dockerruntime.ErrNotFound) {
		t.Fatal("exact native container absence unavailable")
	}
	if refs, err := f.adapter.ListManaged(ctx); err != nil || len(refs) != 0 {
		t.Fatal("managed native runtime inventory not empty")
	}
	var tool isolatedNativeProbe
	if isolatedNativeReadJSON(workspace+"/isolation-tool-report.json", &tool, 32768) != nil || tool.Nonce != tc.Nonce || tool.Mode != "tool" || tool.UID != 1000 || tool.OwnerSourceReadable || tool.OwnerSourceErrno != int(unix.ENOENT) || tool.NoNewPrivs != "1" || tool.Seccomp != "2" || tool.CapEff != "0000000000000000" {
		t.Fatal("actual native tool boundary observations differ")
	}
	for _, name := range []string{"inet4", "inet6"} {
		code, ok := tool.SocketErrnos[name]
		if !ok || (code != int(unix.EPERM) && code != int(unix.EACCES)) {
			t.Fatal("native socket policy denial missing")
		}
	}
	var providerControl isolatedNativeProbe
	if isolatedNativeReadJSON(workspace+"/isolation-provider-control-report.json", &providerControl, 32768) != nil ||
		providerControl.Nonce != tc.Nonce || providerControl.Mode != "provider-control" || providerControl.UID != 1001 ||
		providerControl.ProviderPeerPID != result.Snapshot.OwnerPID || !isolatedNativeProviderDenied(tool, providerControl) {
		t.Fatal("actual live provider connection denial/control missing")
	}
	for _, link := range tool.FDLinks {
		if strings.Contains(link, "/credentials/") || strings.Contains(link, "/provider/") {
			t.Fatal("owner descriptor path reached native tool")
		}
	}
	if isolatedNativeReadJSON(root+"/upstream-result.json", &result.Upstream, 65536) != nil || result.Upstream.Name != tc.Name || result.Upstream.Nonce != tc.Nonce || !result.Upstream.HeadersVerified || !result.Upstream.ToolDefinitionVerified || !result.Upstream.ToolOutputVerified {
		t.Fatal("native upstream/output correlation missing")
	}
	wantInference, wantRefresh := 2, 0
	if tc.Name == "inference401" {
		wantInference, wantRefresh = 3, 1
	}
	if tc.Name == "catalog401" {
		wantRefresh = 1
		if result.Upstream.Catalog < 1 {
			t.Fatal("native Catalog401 was not observable")
		}
	}
	if result.Upstream.Inference != wantInference || result.Upstream.Refresh != wantRefresh || result.Upstream.Catalog > 2 {
		t.Fatal("native exchange schedule changed")
	}
	result.ToolVerified = true
	result.ProbeUnchanged = isolatedNativeFileSHA(probe) == probeHash
	if !result.ProbeUnchanged {
		t.Fatal("native tool changed the fixed probe executable")
	}
	if isolatedNativeReadJSON(root+"/close-result.json", &result.Close, 65536) != nil || !result.Close.OwnerJoinAttempted || !result.Close.OwnerJoined || !result.Close.EndpointJoinAttempted || !result.Close.EndpointJoined || !result.Close.DrainedJoined || !result.Close.Diagnostics.Stopped || !result.Close.Diagnostics.Joined || result.Close.Diagnostics.CleanupFailed {
		t.Fatal("actual provider/helper close observation missing")
	}
	localRefresh, localDenied := 0, 0
	for _, exchange := range result.Close.Diagnostics.Exchanges {
		if exchange.Operation == "refresh" && exchange.LocalAuth == "refresh" {
			localRefresh++
		}
		if exchange.LocalAuth == "denied" {
			localDenied++
		}
	}
	if !isolatedNativeRecoverySchedule(tc.Name, localRefresh, localDenied, len(result.Close.Diagnostics.Exchanges)) {
		t.Fatal("native local recovery schedule differs")
	}
	t.Logf("observed local recovery: refresh=%d denied=%d", localRefresh, localDenied)
	after, err := os.ReadFile(auth)
	defer clear(after)
	if err != nil || isolatedReadySourceLock(auth, false) != nil {
		t.Fatal("owner source unavailable after release")
	}
	var afterStat unix.Stat_t
	result.SourceObjectUnchanged = unix.Lstat(auth, &afterStat) == nil && beforeStat.Dev == afterStat.Dev && beforeStat.Ino == afterStat.Ino && beforeStat.Uid == afterStat.Uid && afterStat.Mode == beforeStat.Mode && afterStat.Nlink == 1
	if !result.SourceObjectUnchanged {
		t.Fatal("owner source object changed")
	}
	generation, proof, err := f.db.GetCredentialEnrollment(ctx, sandboxstore.CredentialRef{SlotRef: f.config.Codex.Credential.SlotRef, Generation: int64(f.config.Codex.Credential.Generation)})
	if err != nil || proof.Validate() != nil {
		t.Fatal("immutable source enrollment unavailable")
	}
	result.Pin = isolatedNativeEnrolledPin(result.Pin, generation, proof)
	if isolatedNativeCurrentSource(ctx, f.config.StateDatabase, generation, manifest.ID(), manifest.Revision(), result.Pin) != nil {
		t.Fatal("successful exact source generation is not currently authorized and idle")
	}
	held, err := holdEnrollmentSource(f.config.Codex.Credential.Root, f.config.Codex.Credential.Directory)
	if err != nil || held == nil {
		t.Fatal("physical source proof unavailable after completion")
	}
	sourceDigest, currentProof, proofErr := held.CaptureProof()
	validateErr := held.Validate()
	closeErr := held.Close()
	if proofErr != nil || validateErr != nil || closeErr != nil || sourceDigest != generation.SourceDigest || currentProof != proof {
		t.Fatal("successful source physical enrollment changed")
	}
	result.SourceHealthy = true
	if tc.Name == "fresh" {
		if !bytes.Equal(after, tc.BeforeAuth) {
			t.Fatal("fresh path changed source")
		}
	} else {
		if _, err := codexprovider.ValidateOwnerAuthUpdate(tc.BeforeAuth, after); err != nil {
			t.Fatal("actual refresh candidate invalid")
		}
		var saved struct {
			Tokens      map[string]string
			LastRefresh string `json:"last_refresh"`
		}
		if json.Unmarshal(after, &saved) != nil || !isolatedNativeTokensEqual(saved.Tokens, tc.RefreshedTokens) {
			t.Fatal("native refresh did not persist full expected tokens")
		}
		stamp, err := time.Parse(time.RFC3339Nano, saved.LastRefresh)
		started, _ := time.Parse(time.RFC3339Nano, result.StartedAt)
		if err != nil || stamp.Before(started) || stamp.After(time.Now().UTC()) {
			t.Fatal("native refresh timestamp not observed")
		}
		result.SourceUpdated = true
	}
	needles := isolatedNativeNeedles(t, tc)
	seed := result.Snapshot.LocalSeedPath
	if filepath.Clean(seed) != seed || !strings.HasPrefix(seed, f.config.Codex.ProviderRoot+"/") || !strings.HasSuffix(seed, "/client-seed/local/auth.json") {
		t.Fatal("actual mounted local seed is outside its fixed domain")
	}
	files, count, scanErr := isolatedNativeScan([]string{workspace, f.config.RunnerStateRoot, filepath.Dir(seed)}, needles)
	if scanErr != nil || isolatedNativeContains(captured.bytes(), needles) || isolatedNativeContains(diagnostics.bytes(), needles) {
		t.Fatal("bounded Runner/workspace/HRP/diagnostic secret scan failed")
	}
	result.ScannedFiles, result.ScannedBytes, result.SecretsAbsent = files, count, true
	t.Log("actual canonical Runner native tool, independent output/file correlation, owner source health and joined cleanup; bounded secret scan only")
}

func isolatedNativeRecoverySchedule(name string, refresh, denied, exchanges int) bool {
	if refresh < 0 || denied < 0 || exchanges < 0 || exchanges > codexprovider.MaxConnections || refresh+denied > exchanges {
		return false
	}
	switch name {
	case "fresh":
		return refresh == 0 && denied == 0
	case "inference401":
		return refresh == 1 && denied == 1
	case "catalog401":
		// The CLI may refresh directly after Catalog401 or first encounter a
		// local old-token denial. Original admission bounds either schedule.
		return refresh == 1
	default:
		return false
	}
}

func isolatedNativeStart(t *testing.T, f *isolatedServiceFixture, nativeWitness *isolatedNativeWitness, store sandboxcontroller.Store, captured *isolatedNativeCapture) string {
	t.Helper()
	ctx, w := f.ctx, nativeWitness.isolatedReadyWitness
	runID := w.runID
	registry, err := f.config.Registry()
	if err != nil {
		t.Fatal("fixed registry unavailable")
	}
	bridge := func(ctx context.Context, request executionwire.StartRunRequest, manifest targetmanifest.Definition, token *string, output io.Reader, input io.Writer, sink runnerbridge.Sink) error {
		if token != nil {
			return errors.New("new-only native fixture received a session token")
		}
		err := runnerbridge.Run(ctx, request, manifest, token, io.TeeReader(output, captured), input, sink)
		frame, decodeErr := runnerwire.NewDecoder(bytes.NewReader(captured.bytes())).DecodeRunnerFrame()
		ready, ok := frame.(*runnerwire.RunnerReady)
		if decodeErr == nil && ok && ready.Adapter.Family == manifest.Common().Runner.Family && ready.Adapter.Version == manifest.Common().Runner.AdapterVersion {
			w.mu.Lock()
			w.ready = true
			w.mu.Unlock()
		}
		return err
	}
	controllerStore := store
	controllerRuntime := sandboxcontroller.Runtime(nativeWitness)
	f.controller, err = sandboxcontroller.New(ctx, f.durable, registry, controllerStore, controllerRuntime, sandboxcontroller.WithCredentialBindings(f.setup.bindings), sandboxcontroller.WithBridge(bridge), sandboxcontroller.WithCleanupTimeout(20*time.Second))
	if err != nil {
		t.Fatal("actual composed controller unavailable")
	}
	manifest := f.config.Targets[0]
	fp, _ := manifest.Fingerprint()
	authority, err := f.setup.authority(manifest, fp)
	if err != nil {
		t.Fatal("actual fixed authority unavailable")
	}
	pin := authority.RevisionPin
	scope, err := sessionauth.Digest(f.config.Codex.Scope.SessionScope())
	if err != nil {
		t.Fatal("fixed session scope unavailable")
	}
	request := executionwire.StartRunRequest{RunID: runID, TargetID: manifest.ID(), ExpectedRevision: manifest.Revision(), SessionScopeDigest: scope, Input: executionwire.TextInput{MediaType: executionwire.MediaTypeTextPlain, Text: "Execute the fixed workspace isolation probe once and return its completion marker."}, Deadline: time.Now().UTC().Add(220 * time.Second).Truncate(time.Millisecond)}
	if _, err = f.controller.StartRun(ctx, request); err != nil {
		t.Fatal("actual admission failed")
	}
	if _, err = f.controller.StartRun(ctx, request); err != nil {
		t.Fatal("exact replay failed")
	}
	return pin
}

func isolatedNativeProviderDenied(tool, control isolatedNativeProbe) bool {
	return tool.ProviderConnectAttempted && tool.ProviderConnectionClosed && !tool.ProviderConnected && tool.ProviderConnectPath == "/run/hsg-provider.sock" &&
		(tool.ProviderConnectErrno == int(unix.EPERM) || tool.ProviderConnectErrno == int(unix.EACCES)) &&
		control.ProviderConnectAttempted && control.ProviderConnectionClosed && control.ProviderConnected && control.ProviderConnectErrno == 0 && control.ProviderPeerUID == 1001 && control.ProviderPeerPID > 1 &&
		control.ProviderSocketInode > 0 && tool.ProviderSocketDevice == control.ProviderSocketDevice && tool.ProviderSocketInode == control.ProviderSocketInode
}

// Observation never changes a dispatched Create's return/certainty contract.
type isolatedNativeWitness struct {
	*isolatedReadyWitness
	root          string
	observationMu sync.Mutex
	observeErr    error
	diagnostics   *isolatedNativeCapture
}

func (w *isolatedNativeWitness) CreateWithOwner(ctx context.Context, id string, m targetmanifest.Definition, owner *credentialsource.OwnerAccess) (string, error) {
	ref, err := w.isolatedReadyWitness.CreateWithOwner(ctx, id, m, owner)
	if err == nil {
		writeErr := isolatedNativeWriteJSON(w.root+"/container-ref.json", struct {
			Ref, RunID string
			OwnerPID   int
		}{ref, id, os.Getpid()})
		w.observationMu.Lock()
		w.observeErr = writeErr
		w.observationMu.Unlock()
	}
	return ref, err
}
func (w *isolatedNativeWitness) observationError() error {
	w.observationMu.Lock()
	defer w.observationMu.Unlock()
	return w.observeErr
}
func (w *isolatedNativeWitness) AttachStart(ctx context.Context, ref string) (sandboxcontroller.Process, error) {
	p, err := w.isolatedReadyWitness.AttachStart(ctx, ref)
	if err != nil {
		return p, err
	}
	return &isolatedNativeProcess{Process: p, diagnostics: &isolatedNativeDiagnosticReader{ReadCloser: p.Diagnostics(), capture: w.diagnostics}}, nil
}

type isolatedNativeProcess struct {
	sandboxcontroller.Process
	diagnostics io.ReadCloser
}

func (p *isolatedNativeProcess) Diagnostics() io.ReadCloser { return p.diagnostics }

type isolatedNativeDiagnosticReader struct {
	io.ReadCloser
	capture *isolatedNativeCapture
}

func (r *isolatedNativeDiagnosticReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		if _, observeErr := r.capture.Write(p[:n]); observeErr != nil {
			return n, observeErr
		}
	}
	return n, err
}

type isolatedNativeCapture struct {
	mu   sync.Mutex
	data []byte
}

func (b *isolatedNativeCapture) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.data)+len(p) > 256<<10 {
		return 0, errors.New("bounded HRP capture exceeded")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}
func (b *isolatedNativeCapture) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.data)
}

// Open once, reject special objects without blocking, and enforce the actual
// read limit as well as the initial size. Parsing and hashing share these bytes.
func isolatedNativeReadBytes(path string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > 32<<20 {
		return nil, errors.New("invalid evidence bound")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Size() < 0 || s.Size() > limit {
		_ = f.Close()
		return nil, errors.New("bounded regular evidence required")
	}
	data, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := f.Stat()
	closeErr := f.Close()
	if readErr != nil || statErr != nil || closeErr != nil || int64(len(data)) > limit || int64(len(data)) != s.Size() || after.Size() != s.Size() || !after.ModTime().Equal(s.ModTime()) {
		return nil, errors.New("evidence changed or exceeded bound")
	}
	return data, nil
}
func isolatedNativeReadJSON(path string, v any, limit int64) error {
	data, err := isolatedNativeReadBytes(path, limit)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("closed JSON required")
	}
	return nil
}

// Independent read-only observation: historical enrollment alone is not
// current authority. Do not admit another Run merely to probe source health.
// Reconstruct the documented credential-target/v1 framed hash independently
// of the store. A real registration-path control checks this observation.
func isolatedNativeEnrolledPin(base string, g sandboxstore.CredentialGeneration, proof credentialsource.Proof) string {
	h := sha256.New()
	for _, value := range []string{"harness-security-gateway.sandboxstore.credential-target/v1", base, g.SlotRef, strconv.FormatInt(g.Generation, 10), proof.Scheme, g.SourceDigest, proof.RootObjectDigest, proof.SlotObjectDigest, proof.LocatorDigest, g.WorkspaceRef, g.AuthProfileRef, g.ScopeDigest} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func isolatedNativeCurrentSource(ctx context.Context, path string, g sandboxstore.CredentialGeneration, target, revision, pin string) error {
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{"mode": {"ro"}, "_pragma": {"query_only(1)", "busy_timeout(1000)"}}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	var valid bool
	err = db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM credential_generations g
JOIN target_credentials t USING(slot_ref,generation)
JOIN target_revisions a ON a.target_id=t.target_id AND a.revision=t.target_revision
WHERE g.slot_ref=? AND g.generation=? AND g.source_digest=? AND g.workspace_ref=? AND g.auth_profile_ref=? AND g.scope_digest=?
AND t.target_id=? AND t.target_revision=? AND a.semantic_fingerprint=?
AND g.generation=(SELECT MAX(generation) FROM credential_generations WHERE slot_ref=g.slot_ref)
AND NOT EXISTS(SELECT 1 FROM credential_revocations v WHERE v.slot_ref=g.slot_ref AND v.generation=g.generation)
AND NOT EXISTS(SELECT 1 FROM credential_occupancy o WHERE o.slot_ref=g.slot_ref OR o.source_digest=g.source_digest))`,
		g.SlotRef, g.Generation, g.SourceDigest, g.WorkspaceRef, g.AuthProfileRef, g.ScopeDigest, target, revision, pin).Scan(&valid)
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	if !valid {
		return errors.New("exact source is revoked, superseded, busy or outside target authority")
	}
	return nil
}
func isolatedNativeWriteJSON(path string, v any) error {
	pending := path + ".pending"
	f, err := os.OpenFile(pending, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	err = json.NewEncoder(f).Encode(v)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err != nil || syncErr != nil || closeErr != nil {
		return errors.Join(err, syncErr, closeErr)
	}
	// Publish only a fully closed receipt; never replace an existing witness.
	return unix.Renameat2(unix.AT_FDCWD, pending, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE)
}
func isolatedNativeFileSHA(path string) string {
	data, err := isolatedNativeReadBytes(path, 32<<20)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
func isolatedNativeTokensEqual(a, b map[string]string) bool {
	if len(a) != 4 || len(b) != 4 {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
func isolatedNativeNeedles(t *testing.T, tc isolatedNativeCase) [][]byte {
	t.Helper()
	var auth struct{ Tokens map[string]string }
	if json.Unmarshal(tc.BeforeAuth, &auth) != nil {
		t.Fatal("synthetic scan controls invalid")
	}
	var result [][]byte
	for _, tokens := range []map[string]string{auth.Tokens, tc.RefreshedTokens} {
		for _, key := range []string{"access_token", "refresh_token", "id_token", "account_id"} {
			if len(tokens[key]) < 16 {
				t.Fatal("synthetic scan needle too small")
			}
			result = append(result, []byte(tokens[key]))
		}
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	parts := strings.Split(auth.Tokens["id_token"], ".")
	if len(parts) != 3 {
		t.Fatal("invalid synthetic identity")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(decoded, &claims) != nil || len(claims.Subject) < 16 {
		t.Fatal("synthetic subject scan control unavailable")
	}
	result = append(result, []byte(claims.Subject))
	return result
}
func isolatedNativeContains(data []byte, needles [][]byte) bool {
	for _, needle := range needles {
		if bytes.Contains(data, needle) {
			return true
		}
	}
	return false
}
func isolatedNativeScan(roots []string, needles [][]byte) (int, int64, error) {
	type directory struct {
		path  string
		depth int
	}
	stack := make([]directory, 0, len(roots))
	for _, root := range roots {
		stack = append(stack, directory{root, 0})
	}
	count, entries, dirs := 0, 0, 0
	var total int64
	for len(stack) > 0 {
		next := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		dirs++
		if dirs > 128 || next.depth > 16 {
			return count, total, errors.New("directory scan bound exceeded")
		}
		observed, err := os.Lstat(next.path)
		if err != nil || !observed.IsDir() || observed.Mode()&os.ModeSymlink != 0 {
			return count, total, errors.New("unsafe scan directory")
		}
		fd, err := unix.Open(next.path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return count, total, err
		}
		dir := os.NewFile(uintptr(fd), next.path)
		opened, err := dir.Stat()
		if err != nil || !os.SameFile(observed, opened) {
			_ = dir.Close()
			return count, total, errors.New("scan directory changed")
		}
		var readErr error
		for {
			names, err := dir.Readdirnames(64)
			if err != nil && err != io.EOF {
				readErr = err
				break
			}
			for _, name := range names {
				entries++
				if entries > 512 {
					readErr = errors.New("scan entry bound exceeded")
					break
				}
				path := filepath.Join(next.path, name)
				info, err := os.Lstat(path)
				if err != nil || info.Mode()&os.ModeSymlink != 0 {
					readErr = errors.New("unsafe scan entry")
					break
				}
				if info.IsDir() {
					stack = append(stack, directory{path, next.depth + 1})
					continue
				}
				if !info.Mode().IsRegular() || info.Size() > 32<<20 || total+info.Size() > 64<<20 {
					readErr = errors.New("scan file bound exceeded")
					break
				}
				f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
				if err != nil {
					readErr = err
					break
				}
				current, statErr := f.Stat()
				if statErr != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) || current.Size() != info.Size() {
					_ = f.Close()
					readErr = errors.New("scan file changed")
					break
				}
				data, readFailure := io.ReadAll(io.LimitReader(f, 32<<20+1))
				closeFailure := f.Close()
				if readFailure != nil || closeFailure != nil || int64(len(data)) != info.Size() || isolatedNativeContains(data, needles) {
					readErr = errors.New("scan failed or owner canary reached Runner")
					break
				}
				count++
				total += info.Size()
			}
			if readErr != nil || err == io.EOF {
				break
			}
		}
		closeErr := dir.Close()
		if readErr != nil || closeErr != nil {
			return count, total, errors.Join(readErr, closeErr)
		}
	}
	return count, total, nil
}
