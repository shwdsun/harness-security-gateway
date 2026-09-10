//go:build linux && amd64 && codexintegration

package codexcanary

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
)

// Continuation is trusted operator configuration, never remote Run input.
// These file identities fence replacement by a fresh database. As with the
// stores, an operator rollback of the same database object is outside the model.
type DatabaseIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type Continuation struct {
	PreviousRunID        string           `json:"previous_run_id"`
	PreviousConfigSHA256 string           `json:"previous_config_sha256"`
	HistorySHA256        string           `json:"history_sha256"`
	Core                 DatabaseIdentity `json:"core"`
	Sandbox              DatabaseIdentity `json:"sandbox"`
}

type continuationHistory struct {
	pin        Continuation
	generation sandboxstore.CredentialGeneration
	proof      credentialsource.Proof
	used       bool
	retired    bool
}

func validHash(value string) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == 32 && hex.EncodeToString(data) == value
}

func pinnedContinuation(c Config) bool {
	p := c.Continuation
	return p != nil && validHash(p.PreviousConfigSHA256) && validHash(p.HistorySHA256) &&
		p.Core.Device != 0 && p.Core.Inode != 0 && p.Sandbox.Device != 0 && p.Sandbox.Inode != 0
}

func previousConfig(c Config) (Config, error) {
	p := c.Continuation
	if !validMode(c) || p == nil || !validHash(p.PreviousConfigSHA256) {
		return Config{}, ErrPreparation
	}
	previous, hash, err := loadConfigFile(filepath.Join(c.StateRoot, "canary.json"))
	if err != nil || previous.RunID != p.PreviousRunID {
		previous, hash, err = loadConfigFile(filepath.Join(c.StateRoot, "plans", p.PreviousRunID+".json"))
	}
	if err != nil || !validMode(previous) || hash != p.PreviousConfigSHA256 || previous.RunID != p.PreviousRunID ||
		previous.StateRoot != c.StateRoot || previous.Runtime.ProviderRoot != c.Runtime.ProviderRoot {
		return Config{}, ErrPreparation
	}
	old, next := previous.Runtime.Runtime, c.Runtime.Runtime
	if old.Credential.Generation >= math.MaxInt64 || next.Credential.Generation != old.Credential.Generation+1 {
		return Config{}, ErrPreparation
	}
	old.Credential.Generation = next.Credential.Generation
	if old.Credential != next.Credential {
		return Config{}, ErrPreparation
	}
	oldManifest, ok := old.Manifest.ManifestV2()
	nextManifest, nextOK := next.Manifest.ManifestV2()
	if !ok || !nextOK || oldManifest.Revision == nextManifest.Revision {
		return Config{}, ErrPreparation
	}
	oldManifest.Revision = nextManifest.Revision
	if !reflect.DeepEqual(oldManifest, nextManifest) {
		return Config{}, ErrPreparation
	}
	// Only the target revision, generation and reviewed Runner/owner build may
	// change. Keep image, source location, workspace, tools and containment fixed.
	old.Manifest, old.Runner = next.Manifest, next.Runner
	if !reflect.DeepEqual(old, next) {
		return Config{}, ErrPreparation
	}
	return previous, nil
}

func databaseIdentity(path string) (DatabaseIdentity, error) {
	resolved, err := filepath.EvalSymlinks(path)
	var file, directory syscall.Stat_t
	if err != nil || resolved != path || syscall.Lstat(path, &file) != nil ||
		file.Mode&syscall.S_IFMT != syscall.S_IFREG || file.Mode&0o777 != 0o600 ||
		file.Uid != uint32(os.Geteuid()) || file.Nlink != 1 ||
		syscall.Lstat(filepath.Dir(path), &directory) != nil || directory.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		directory.Mode&0o777 != 0o700 || directory.Uid != uint32(os.Geteuid()) {
		return DatabaseIdentity{}, ErrPreparation
	}
	return DatabaseIdentity{uint64(file.Dev), file.Ino}, nil
}

func checkDatabaseIdentities(c Config) error {
	for _, item := range []struct {
		name string
		want DatabaseIdentity
	}{{"core", c.Continuation.Core}, {"sandbox", c.Continuation.Sandbox}} {
		got, err := databaseIdentity(filepath.Join(c.StateRoot, item.name, "state.sqlite3"))
		if err != nil || got != item.want {
			return ErrPreparation
		}
	}
	return nil
}

// Do not call the writable Store.Open APIs from a preview. They can create,
// migrate and recover files. This local reader projects bounded metadata only.
func historyDB(ctx context.Context, path string) (*sql.DB, DatabaseIdentity, error) {
	identity, err := databaseIdentity(path)
	if err != nil {
		return nil, identity, ErrPreparation
	}
	u := url.URL{Scheme: "file", Path: path}
	query := url.Values{"mode": {"ro"}, "_pragma": {"query_only(ON)", "trusted_schema(OFF)", "busy_timeout(2000)"}}
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, identity, ErrPreparation
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, identity, ErrPreparation
	}
	current, err := databaseIdentity(path)
	if err != nil || current != identity {
		db.Close()
		return nil, identity, ErrPreparation
	}
	return db, identity, nil
}

func canaryScope(c Config) (sessionauth.Scope, error) {
	policy, err := agentpolicy.Compile(settings(c))
	if err != nil {
		return sessionauth.Scope{}, ErrPreparation
	}
	endpoint, err := policy.Endpoint(connectorID(c))
	if err != nil {
		return sessionauth.Scope{}, ErrPreparation
	}
	return endpoint.SessionScope("operator", "local")
}

func inspectHistory(ctx context.Context, c, previous Config) (continuationHistory, error) {
	var h continuationHistory
	core, coreID, err := historyDB(ctx, filepath.Join(c.StateRoot, "core", "state.sqlite3"))
	if err != nil {
		return h, ErrPreparation
	}
	defer core.Close()
	sandbox, sandboxID, err := historyDB(ctx, filepath.Join(c.StateRoot, "sandbox", "state.sqlite3"))
	if err != nil {
		return h, ErrPreparation
	}
	defer sandbox.Close()
	oldScope, err := canaryScope(previous)
	if err != nil {
		return h, ErrPreparation
	}
	oldDigest, err := sessionauth.Digest(oldScope)
	if err != nil {
		return h, ErrPreparation
	}
	// Require the current schemas; normal opens must not silently migrate a
	// different historical lineage when the plan is later armed.
	for _, item := range []struct {
		db      *sql.DB
		version int
	}{{core, 7}, {sandbox, sandboxstore.CurrentSchemaVersion}} {
		var count, maximum int
		if item.db.QueryRowContext(ctx, `SELECT count(*),COALESCE(max(version),0) FROM schema_migrations`).Scan(&count, &maximum) != nil || count != item.version || maximum != item.version {
			return h, ErrPreparation
		}
	}
	var coreState, sandboxState, targetPin, requestPin string
	var terminal int64
	if core.QueryRowContext(ctx, `SELECT state FROM runs WHERE id=? AND connector_id=? AND actor_ref=? AND conversation_ref=?
AND binding_fingerprint=? AND target_id=? AND target_revision=? AND input_text=?`,
		previous.RunID, oldScope.ConnectorID, oldScope.ActorRef, oldScope.ConversationRef,
		oldScope.BindingFingerprint, oldScope.TargetID, oldScope.TargetRevision, promptFor(previous)).Scan(&coreState) != nil {
		return h, ErrPreparation
	}
	inputHash := sha256.Sum256([]byte(promptFor(previous)))
	if sandbox.QueryRowContext(ctx, `SELECT r.state,r.terminal_at_unix_ms,tr.semantic_fingerprint,r.request_fingerprint
FROM runs r JOIN target_revisions tr ON tr.target_id=r.target_id AND tr.revision=r.target_revision
JOIN target_credentials tc ON tc.target_id=r.target_id AND tc.target_revision=r.target_revision
WHERE r.run_id=? AND r.target_id=? AND r.target_revision=? AND r.workspace_id=? AND r.session_scope_digest=?
AND r.input_sha256=? AND r.runtime_ref IS NULL AND r.runtime_intent_pending=0
AND tr.runner_state_kind='none' AND tr.credential_kind='bound' AND tc.slot_ref=? AND tc.generation=?`,
		previous.RunID, oldScope.TargetID, oldScope.TargetRevision, previous.Runtime.Runtime.Credential.WorkspaceRef,
		oldDigest, hex.EncodeToString(inputHash[:]), previous.Runtime.Runtime.Credential.SlotRef,
		previous.Runtime.Runtime.Credential.Generation).Scan(&sandboxState, &terminal, &targetPin, &requestPin) != nil ||
		terminal <= 0 || !validHash(targetPin) || !validHash(requestPin) {
		return h, ErrPreparation
	}
	wantCore := map[string]string{"completed": "completed", "failed": "failed", "cancelled": "cancelled", "interrupted": "interrupted"}[sandboxState]
	if wantCore == "" || coreState != wantCore {
		return h, ErrPreparation
	}
	ref := sandboxstore.CredentialRef{SlotRef: previous.Runtime.Runtime.Credential.SlotRef, Generation: int64(previous.Runtime.Runtime.Credential.Generation)}
	h.generation, h.proof, err = readEnrollment(ctx, sandbox, ref)
	if err != nil || h.generation.WorkspaceRef != previous.Runtime.Runtime.Credential.WorkspaceRef ||
		h.generation.AuthProfileRef != previous.Runtime.Runtime.Credential.AuthProfileRef || h.generation.ScopeDigest != oldDigest {
		return h, ErrPreparation
	}
	var foreignCore, foreignSandbox, coreUsed, sandboxUsed bool
	if core.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM runs WHERE id=?),
EXISTS(SELECT 1 FROM runs WHERE id<>? AND state NOT IN ('completed','failed','cancelled','interrupted'))`, c.RunID, c.RunID).Scan(&coreUsed, &foreignCore) != nil ||
		sandbox.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM runs WHERE run_id=?),
EXISTS(SELECT 1 FROM runs WHERE run_id<>? AND (state NOT IN ('completed','failed','cancelled','interrupted') OR runtime_ref IS NOT NULL OR runtime_intent_pending=1))
OR EXISTS(SELECT 1 FROM credential_occupancy WHERE run_id<>?)
OR EXISTS(SELECT 1 FROM workspace_locks WHERE run_id<>?)
OR EXISTS(SELECT 1 FROM staged_terminals WHERE run_id<>?)`, c.RunID, c.RunID, c.RunID, c.RunID, c.RunID).Scan(&sandboxUsed, &foreignSandbox) != nil || foreignCore || foreignSandbox {
		return h, ErrPreparation
	}
	h.used = coreUsed || sandboxUsed
	var maximum int64
	if sandbox.QueryRowContext(ctx, `SELECT max(generation) FROM credential_generations WHERE slot_ref=?`, ref.SlotRef).Scan(&maximum) != nil ||
		(maximum != ref.Generation && maximum != ref.Generation+1) {
		return h, ErrPreparation
	}
	if maximum == ref.Generation+1 {
		got, proof, err := readEnrollment(ctx, sandbox, sandboxstore.CredentialRef{SlotRef: ref.SlotRef, Generation: maximum})
		want, errScope := nextGeneration(c, h.generation)
		var previousRetired bool
		if err != nil || errScope != nil || got != want || proof != h.proof ||
			sandbox.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM credential_revocations WHERE slot_ref=? AND generation=?),
EXISTS(SELECT 1 FROM credential_revocations WHERE slot_ref=? AND generation=?)`, ref.SlotRef, ref.Generation, ref.SlotRef, maximum).Scan(&previousRetired, &h.retired) != nil || !previousRetired {
			return h, ErrPreparation
		}
	}
	data, err := json.Marshal(struct {
		Core, Sandbox                                                               DatabaseIdentity
		PreviousConfig, PreviousRun, TargetPin, RequestPin, CoreState, SandboxState string
		Terminal                                                                    int64
		Generation                                                                  sandboxstore.CredentialGeneration
		Proof                                                                       credentialsource.Proof
	}{coreID, sandboxID, c.Continuation.PreviousConfigSHA256, previous.RunID, targetPin, requestPin, coreState, sandboxState, terminal, h.generation, h.proof})
	if err != nil {
		return h, ErrPreparation
	}
	digest := sha256.Sum256(append([]byte("harness-security-gateway.canary-continuation/v1\x00"), data...))
	h.pin = Continuation{previous.RunID, c.Continuation.PreviousConfigSHA256, hex.EncodeToString(digest[:]), coreID, sandboxID}
	return h, nil
}

func readEnrollment(ctx context.Context, db *sql.DB, ref sandboxstore.CredentialRef) (sandboxstore.CredentialGeneration, credentialsource.Proof, error) {
	g := sandboxstore.CredentialGeneration{SlotRef: ref.SlotRef, Generation: ref.Generation}
	var proof credentialsource.Proof
	err := db.QueryRowContext(ctx, `SELECT source_digest,workspace_ref,auth_profile_ref,scope_digest,proof_scheme,root_object_digest,slot_object_digest,locator_digest
FROM credential_generations WHERE slot_ref=? AND generation=?`, ref.SlotRef, ref.Generation).Scan(
		&g.SourceDigest, &g.WorkspaceRef, &g.AuthProfileRef, &g.ScopeDigest, &proof.Scheme, &proof.RootObjectDigest, &proof.SlotObjectDigest, &proof.LocatorDigest)
	if err != nil || !validHash(g.SourceDigest) || !validHash(g.ScopeDigest) || proof.Validate() != nil {
		return g, proof, ErrPreparation
	}
	return g, proof, nil
}

func nextGeneration(c Config, previous sandboxstore.CredentialGeneration) (sandboxstore.CredentialGeneration, error) {
	scope, err := canaryScope(c)
	if err != nil {
		return previous, ErrPreparation
	}
	digest, err := sessionauth.Digest(scope)
	previous.Generation, previous.ScopeDigest = int64(c.Runtime.Runtime.Credential.Generation), digest
	return previous, err
}

// The caller holds the canary process lock and has just rechecked history.
// Both steps are existing idempotent store APIs. A failure after retirement
// leaves the previous generation retired; repeating this exact pre-admission
// plan can finish registration, never remove history or revive the old target.
func transitionEnrollment(ctx context.Context, c Config, db *sandboxstore.Store, h continuationHistory, source string, proof credentialsource.Proof) error {
	if h.used || h.retired || c.Continuation == nil || h.pin != *c.Continuation || source != h.generation.SourceDigest || proof != h.proof {
		return ErrPreparation
	}
	g, pins, err := db.GetCredentialEnrollment(ctx, sandboxstore.CredentialRef{SlotRef: h.generation.SlotRef, Generation: h.generation.Generation})
	if err != nil || g != h.generation || pins != h.proof {
		return ErrPreparation
	}
	next, err := nextGeneration(c, g)
	if err != nil {
		return ErrPreparation
	}
	if db.RevokeCredentialGeneration(ctx, sandboxstore.CredentialRef{SlotRef: g.SlotRef, Generation: g.Generation}) != nil ||
		db.RegisterCredentialEnrollment(ctx, next, proof) != nil {
		return ErrExecution
	}
	return nil
}
