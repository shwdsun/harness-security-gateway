package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/processlock"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
)

func TestScopeExportsCompiledConfigurationWithoutCoreAccess(t *testing.T) {
	c := testConfig(t)
	path := writeConfig(t, c)
	owner, err := processlock.Acquire(c.ProcessLockPath())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	var output bytes.Buffer
	if err := run(context.Background(), []string{"session", "scope", "-config", path, "-binding", "private"}, &output); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Schema string                      `json:"schema"`
		Scope  sandboxconfig.ApprovedScope `json:"scope"`
	}
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	key, err := resolveSessionKey(c, "private")
	if err != nil {
		t.Fatal(err)
	}
	want := sessionauth.Scope{BindingFingerprint: key.BindingFingerprint, ConnectorID: key.ConnectorID, ActorRef: key.ActorRef, ConversationRef: key.ConversationRef, TargetID: key.TargetID, TargetRevision: key.TargetRevision}
	if response.Schema != "hgwctl/session-scope/v1" || response.Scope.SessionScope() != want {
		t.Fatal("export changed the configured scope")
	}
	if _, err := os.Lstat(c.Database); !os.IsNotExist(err) {
		t.Fatal("scope export accessed/created Core DB", err)
	}
	output.Reset()
	if err := run(context.Background(), []string{"session", "scope", "-config", path, "-binding", "missing"}, &output); err == nil || output.Len() != 0 {
		t.Fatal("unknown binding exported authority")
	}
	for _, flag := range []string{"-actor", "-target", "-database", "-expected-session-ref"} {
		if _, err := parseCommand([]string{"session", "scope", "-config", path, "-binding", "private", flag, "override"}); err == nil {
			t.Fatal("scope accepted raw override", flag)
		}
	}
}
