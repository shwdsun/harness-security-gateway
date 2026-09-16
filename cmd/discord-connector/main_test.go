package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkFixture writes a valid installation layout and returns its
// configuration path and root. Installation checks run as the Connector's own
// identity, so the fixture uses this process's UID.
func checkFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	// The token never shares a directory with mutable state; the configuration
	// rejects that layout, so the fixture must not use it either.
	credentials := filepath.Join(root, "credentials")
	state := filepath.Join(root, "state")
	for _, directory := range []string{credentials, state} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tokenPath := filepath.Join(credentials, "bot-token")
	if err := os.WriteFile(tokenPath, []byte("fixture-token-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenPath, 0o600); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"schema":             "discord-connector/v1",
		"agentd_socket":      filepath.Join(root, "agentd.sock"),
		"state_database":     filepath.Join(state, "connector.sqlite3"),
		"token_file":         tokenPath,
		"api_base_url":       "https://discord.com/api/v10",
		"self_user_id":       "111111111111111111",
		"channel_id":         "333333333333333333",
		"allowed_author_ids": []string{"222222222222222222"},
		"poll_interval_ms":   3000,
		"catch_up_limit":     20,
		"claim_limit":        5,
		"request_timeout_ms": 10000,
		"max_reply_chunks":   4,
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "discord-connector.json")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, root
}

func TestCheckValidatesWithoutCreatingStateOrContactingAnything(t *testing.T) {
	configPath, root := checkFixture(t)
	var out strings.Builder
	if err := run(context.Background(), []string{"-config", configPath, "-check"}, &out, io.Discard); err != nil {
		t.Fatalf("check rejected a valid installation: %v", err)
	}
	if !strings.Contains(out.String(), "no platform request, state or delivery performed") {
		t.Fatalf("unexpected check output: %q", out.String())
	}
	// A check that creates the cursor database would leave the Connector's
	// first real start replaying against state the installer invented.
	if _, err := os.Lstat(filepath.Join(root, "state", "connector.sqlite3")); !os.IsNotExist(err) {
		t.Fatal("check created the state database")
	}
	if _, err := os.Lstat(filepath.Join(root, "agentd.sock")); !os.IsNotExist(err) {
		t.Fatal("check created a socket")
	}
}

func TestCheckRejectsATokenFileAnotherIdentityCouldRead(t *testing.T) {
	configPath, root := checkFixture(t)
	if err := os.Chmod(filepath.Join(root, "credentials", "bot-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := run(context.Background(), []string{"-config", configPath, "-check"}, &out, io.Discard); err == nil {
		t.Fatal("check accepted a world-readable bot token")
	}
	if out.Len() != 0 {
		t.Fatalf("a rejected check still reported success: %q", out.String())
	}
}

func TestCheckRejectsAnUnusableConfiguration(t *testing.T) {
	configPath, _ := checkFixture(t)
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(raw), `"channel_id":"333333333333333333"`,
		`"channel_id":"not-a-snowflake"`, 1)
	if broken == string(raw) {
		t.Fatal("fixture layout changed; the mutation no longer applies")
	}
	if err := os.WriteFile(configPath, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := run(context.Background(), []string{"-config", configPath, "-check"}, &out, io.Discard); err == nil {
		t.Fatal("check accepted a non-snowflake channel")
	}
}

// sandboxd writes its check receipt to stdout; the Connector wrote its own to
// the cycle log's stream, so a script capturing stdout saw nothing.
func TestTheCheckReceiptIsACommandResultNotALogLine(t *testing.T) {
	configPath, _ := checkFixture(t)
	var out, logged strings.Builder
	if err := run(context.Background(), []string{"-config", configPath, "-check"}, &out, &logged); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no platform request, state or delivery performed") {
		t.Fatalf("the receipt is not on stdout: %q", out.String())
	}
	if logged.Len() != 0 {
		t.Fatalf("the check wrote to the diagnostic stream: %q", logged.String())
	}
}
