//go:build linux && amd64 && codexintegration

package codexcanary

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func TestCanarySettingsCompileWithControlIsolation(t *testing.T) {
	data, err := os.ReadFile("../../config/codex-tools-candidate.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var example struct {
		Target targetmanifest.Definition `json:"target"`
	}
	if err := json.Unmarshal(data, &example); err != nil {
		t.Fatal(err)
	}
	c := Config{StateRoot: "/private-canary"}
	c.Runtime.Runtime.Manifest = example.Target
	policy, err := agentpolicy.Compile(settings(c))
	if err != nil {
		t.Fatalf("fixed canary configuration violates Core policy: %v", err)
	}
	endpoint, err := policy.Endpoint("canary")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := endpoint.SessionScope("operator", "local")
	if err != nil || scope.TargetID != example.Target.ID() || scope.TargetRevision != example.Target.Revision() {
		t.Fatalf("canary binding does not select the fixed target: %v", err)
	}
	unsafe := settings(c)
	unsafe.Connectors[0].Socket = filepath.Join(c.StateRoot, "unused-ingress.sock")
	if _, err := agentpolicy.Compile(unsafe); err == nil {
		t.Fatal("connector directory may not expose the control state")
	}
}

func TestCleanupReportRequiresDurablePublication(t *testing.T) {
	now := time.Now()
	complete := sandboxstore.Run{RunID: "canary", State: executionwire.RunStateCompleted, TerminalAt: &now}
	for _, name := range []string{"published", "published-cancelled", "published-failed", "published-interrupted", "absent-before-admission", "read-failure", "wrong-run", "nonterminal", "no-terminal-time", "pending-result", "uncertain-create", "bound-runtime", "workspace-held", "credential-held"} {
		t.Run(name, func(t *testing.T) {
			run := complete
			var err error
			switch name {
			case "published-cancelled":
				run.State = executionwire.RunStateCancelled
			case "published-failed":
				run.State = executionwire.RunStateFailed
			case "published-interrupted":
				run.State = executionwire.RunStateInterrupted
			case "absent-before-admission":
				run = sandboxstore.Run{}
				err = sandboxstore.ErrNotFound
			case "read-failure":
				err = errors.New("unavailable")
			case "wrong-run":
				run.RunID = "other"
			case "nonterminal":
				run.State = executionwire.RunStateRunning
			case "no-terminal-time":
				run.TerminalAt = nil
			case "pending-result":
				run.TerminalPending = true
			case "uncertain-create":
				run.State = executionwire.RunStateInterrupted
				run.RuntimeIntentPending = true
			case "bound-runtime":
				ref := "owned"
				run.RuntimeRef = &ref
			case "workspace-held":
				run.WorkspaceLockHeld = true
			case "credential-held":
				run.CredentialLeaseHeld = true
			}
			want := name == "published" || name == "published-cancelled" || name == "published-failed" || name == "published-interrupted" || name == "absent-before-admission"
			if cleanupPublished("canary", run, err) != want {
				t.Fatal("operator cleanup report hid a durable obligation")
			}
		})
	}
}
