package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/processlock"
)

func TestParseCommandIsStrict(t *testing.T) {
	validStatus := []string{"session", "status", "-config", "agentd.json", "-binding", "private"}
	if got, err := parseCommand(validStatus); err != nil || got.action != "status" {
		t.Fatalf("parse status = %#v, %v", got, err)
	}
	validReset := append(append([]string{}, validStatus[:1]...), "reset", "-config", "agentd.json", "-binding", "private", "-expected-session-ref", "session_1")
	if got, err := parseCommand(validReset); err != nil || got.expectedSessionRef != "session_1" {
		t.Fatalf("parse reset = %#v, %v", got, err)
	}
	invalid := [][]string{
		nil, {"status"}, {"session"}, {"session", "other"},
		{"session", "status", "-config", "x"},
		{"session", "status", "-config", "x", "-binding", "b", "extra"},
		{"session", "status", "-config", "x", "-binding", "b", "-expected-session-ref", "s"},
		{"session", "reset", "-config", "x", "-binding", "b"},
		{"session", "reset", "-config", "x", "-binding", "b", "-force"},
	}
	for _, arguments := range invalid {
		if _, err := parseCommand(arguments); err == nil {
			t.Fatalf("parseCommand(%q) unexpectedly succeeded", arguments)
		}
	}
}

func TestResolveSessionKeyUsesCompiledBinding(t *testing.T) {
	config := testConfig(t)
	key, err := resolveSessionKey(config, "private")
	if err != nil {
		t.Fatal(err)
	}
	if key.ConnectorID != "discord" || key.ActorRef != "actor" ||
		key.ConversationRef != "conversation" || key.TargetID != "codex" ||
		key.TargetRevision != "codex-r1" || len(key.BindingFingerprint) != 64 {
		t.Fatalf("resolved key = %#v", key)
	}
	if _, err := resolveSessionKey(config, "missing"); err == nil {
		t.Fatal("unknown binding ID accepted")
	}
}

func TestRunRefusesLiveAgentdLockBeforeDatabaseAccess(t *testing.T) {
	config := testConfig(t)
	path := writeConfig(t, config)
	owner, err := processlock.Acquire(config.ProcessLockPath())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	var output bytes.Buffer
	err = run(context.Background(), []string{
		"session", "status", "-config", path, "-binding", "private",
	}, &output)
	if !errors.Is(err, processlock.ErrLocked) {
		t.Fatalf("run error = %v, want ErrLocked", err)
	}
	if output.Len() != 0 {
		t.Fatalf("output on lock refusal = %q", output.String())
	}
}

func TestRunEmitsOneLineJSONForStatusAndReset(t *testing.T) {
	config := testConfig(t)
	store, err := corestore.Open(context.Background(), config.Database, corestore.Options{
		Admission: corestore.AdmissionOptions{
			AcceptWindow: 5 * time.Minute, ReceiptWindow: time.Hour, FutureSkew: time.Minute,
			MaxReceiptsPerConnector: 128, MaxQueuedRunsPerConnector: 16,
			MaxNonTerminalRunsPerConnector: 32, MaxPendingDeliveriesPerConnector: 128,
			MaxRetainedInputBytesPerConnector: 4 << 20, MaxDatabasePages: 16384,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, config)

	var status bytes.Buffer
	if err := run(context.Background(), []string{
		"session", "status", "-config", path, "-binding", "private",
	}, &status); err != nil {
		t.Fatal(err)
	}
	if strings.Count(status.String(), "\n") != 1 ||
		!strings.Contains(status.String(), `"schema":"hgwctl/session-status/v1"`) ||
		!strings.Contains(status.String(), `"session_present":false`) {
		t.Fatalf("status output = %q", status.String())
	}

	var reset bytes.Buffer
	if err := run(context.Background(), []string{
		"session", "reset", "-config", path, "-binding", "private",
		"-expected-session-ref", "session_expected",
	}, &reset); !errors.Is(err, errResetNotApplied) {
		t.Fatalf("missing-session reset error = %v, want errResetNotApplied", err)
	}
	if strings.Count(reset.String(), "\n") != 1 ||
		!strings.Contains(reset.String(), `"schema":"hgwctl/session-reset/v1"`) ||
		!strings.Contains(reset.String(), `"result":"not_found"`) {
		t.Fatalf("reset output = %q", reset.String())
	}
}

func TestRunStatusAndResetExistingConfiguredBindingSession(t *testing.T) {
	config := testConfig(t)
	store, err := corestore.Open(context.Background(), config.Database, corestore.Options{
		Admission: corestore.AdmissionOptions{
			AcceptWindow: 5 * time.Minute, ReceiptWindow: time.Hour, FutureSkew: time.Minute,
			MaxReceiptsPerConnector: 128, MaxQueuedRunsPerConnector: 16,
			MaxNonTerminalRunsPerConnector: 32, MaxPendingDeliveriesPerConnector: 128,
			MaxRetainedInputBytesPerConnector: 4 << 20, MaxDatabasePages: 16384,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	key, err := resolveSessionKey(config, "private")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", config.Database)
	if err != nil {
		t.Fatal(err)
	}
	const ref = "session_existing"
	if _, err := db.Exec(`INSERT INTO sessions(
        binding_fingerprint, connector_id, actor_ref, conversation_ref,
        target_id, target_revision, session_ref, updated_at_ms
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		key.BindingFingerprint, key.ConnectorID, key.ActorRef, key.ConversationRef,
		key.TargetID, key.TargetRevision, ref, time.Now().UTC().UnixMilli(),
	); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, config)

	var status bytes.Buffer
	if err := run(context.Background(), []string{
		"session", "status", "-config", path, "-binding", "private",
	}, &status); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status.String(), `"session_present":true`) ||
		!strings.Contains(status.String(), `"session_ref":"`+ref+`"`) {
		t.Fatalf("present status output = %q", status.String())
	}

	var reset bytes.Buffer
	if err := run(context.Background(), []string{
		"session", "reset", "-config", path, "-binding", "private",
		"-expected-session-ref", ref,
	}, &reset); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reset.String(), `"result":"reset"`) {
		t.Fatalf("successful reset output = %q", reset.String())
	}

	status.Reset()
	if err := run(context.Background(), []string{
		"session", "status", "-config", path, "-binding", "private",
	}, &status); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status.String(), `"session_present":false`) {
		t.Fatalf("post-reset status output = %q", status.String())
	}
}

func testConfig(t *testing.T) agentconfig.Config {
	t.Helper()
	root := t.TempDir()
	return agentconfig.Config{
		Schema: agentconfig.SchemaV3, Database: filepath.Join(root, "core.sqlite3"),
		SandboxSocket:     filepath.Join(root, "sandbox", "sandboxd.sock"),
		RunTimeoutSeconds: 300, DeliveryLeaseSeconds: 30, RunDispatchLeaseSeconds: 30,
		Ingress: agentconfig.Ingress{
			AcceptWindowSeconds: 300, ReceiptWindowSeconds: 3600, FutureSkewSeconds: 60,
			MaxReceiptsPerConnector: 128, MaxQueuedRunsPerConnector: 16,
			MaxNonTerminalRunsPerConnector: 32, MaxPendingDeliveriesPerConnector: 128,
			MaxRetainedInputBytesPerConnector: 4 << 20, MaxDatabasePages: 16384,
		},
		Connectors: []agentconfig.Connector{{
			ID: "discord", Socket: filepath.Join(root, "connectors", "discord", "agentd.sock"),
			PeerUID: localidentity.UID(1000), SelfActorRef: "bot",
		}},
		Bindings: []agentconfig.Binding{{
			ID: "private", ConnectorID: "discord", ActorRef: "actor", ConversationRef: "conversation",
			Target: agentconfig.TargetRef{ID: "codex", Revision: "codex-r1"},
		}},
	}
}

func writeConfig(t *testing.T, config agentconfig.Config) string {
	t.Helper()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "agentd.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
