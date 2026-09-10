package sandboxconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func codexConfig(t *testing.T) Config {
	t.Helper()
	data, err := os.ReadFile("../../config/sandboxd.codex.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	c.Runtime.CLI = executable(t, t.TempDir())
	c.Runtime.SocketPath, c.Runtime.Endpoint = localRootlessSocket(), localRootlessEndpoint()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCodexConfigIsExplicitAndMockAuthorityStaysClosed(t *testing.T) {
	c := codexConfig(t)
	data, _ := json.Marshal(c)
	path := writeConfig(t, t.TempDir(), string(data), 0o600)
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := loaded.Registry()
	if err != nil || len(registry.Entries()) != 1 {
		t.Fatalf("registry: %v", err)
	}
	m := loaded.Targets[0]
	fp, _ := m.Fingerprint()
	if _, err := loaded.ResolveTargetAuthority(m, fp); err == nil {
		t.Fatal("mock resolver granted native authority")
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(path), "runtime")); !os.IsNotExist(err) {
		t.Fatal("configuration load created state")
	}
}

func TestCodexConfigRejectsAuthorityConfusion(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"old schema":              func(c *Config) { c.Schema = SchemaV3 },
		"missing authority":       func(c *Config) { c.Codex = nil },
		"two targets":             func(c *Config) { c.Targets = append(c.Targets, c.Targets[0].Clone()) },
		"extra workspace":         func(c *Config) { c.Workspaces = append(c.Workspaces, StorageEntry{Ref: "other", Directory: "other"}) },
		"state catalog":           func(c *Config) { c.RunnerStates = []StorageEntry{{Ref: "unused", Directory: "unused"}} },
		"workspace mismatch":      func(c *Config) { c.Codex.Credential.WorkspaceRef = "other" },
		"auth mismatch":           func(c *Config) { c.Codex.Credential.AuthProfileRef = "other" },
		"generation overflow":     func(c *Config) { c.Codex.Credential.Generation = 1 << 63 },
		"missing scope":           func(c *Config) { c.Codex.Scope.BindingFingerprint = "" },
		"other revision":          func(c *Config) { c.Codex.Scope.TargetRevision = "other" },
		"other target":            func(c *Config) { c.Codex.Scope.TargetID = "other" },
		"relative credential":     func(c *Config) { c.Codex.Credential.Root = "credentials" },
		"hidden slot":             func(c *Config) { c.Codex.Credential.Directory = ".hidden" },
		"credential in workspace": func(c *Config) { c.Codex.Credential.Root = c.WorkspaceRoot + "/credentials" },
		"provider in state":       func(c *Config) { c.Codex.ProviderRoot = c.RunnerStateRoot + "/provider" },
		"database exposed":        func(c *Config) { c.StateDatabase = c.Codex.ToolPackage + "/state.sqlite3" },
		"artifact in credential":  func(c *Config) { c.Codex.Runner.Path = c.Codex.Credential.Root + "/runner" },
		"artifact is control":     func(c *Config) { c.Codex.Runner.Path = c.StateDatabase },
		"duplicate artifact":      func(c *Config) { c.Codex.Runner = c.Codex.Bootstrap },
		"unknown image": func(c *Config) {
			m, _ := c.Targets[0].ManifestV2()
			m.Runner.Image = "other/image@sha256:" + strings.Repeat("a", 64)
			c.Targets[0], _ = targetmanifest.FromV2(m)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := codexConfig(t)
			mutate(&c)
			if c.Validate() == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestCodexConfigurationFieldsAreExactNonNullAndClosed(t *testing.T) {
	c := codexConfig(t)
	data, _ := json.Marshal(c)
	for name, document := range map[string]string{
		"case alias":         strings.Replace(string(data), `"owner_sha256"`, `"Owner_SHA256"`, 1),
		"null owner":         strings.Replace(string(data), `"owner_sha256":"`+c.Codex.OwnerSHA256+`"`, `"owner_sha256":null`, 1),
		"null state":         strings.Replace(string(data), `"runner_states":[]`, `"runner_states":null`, 1),
		"null session limit": strings.Replace(string(data), `"max_session_turns":0`, `"max_session_turns":null`, 1),
		"unknown URL":        strings.Replace(string(data), `"provider_root":`, `"url":"https://elsewhere.invalid","provider_root":`, 1),
		"duplicate":          strings.Replace(string(data), `"owner_sha256":`, `"owner_sha256":"`+strings.Repeat("b", 64)+`","owner_sha256":`, 1),
		"omitted artifact":   strings.Replace(string(data), `"canary":{"path":"`+c.Codex.Canary.Path+`","sha256":"`+c.Codex.Canary.SHA256+`"},`, ``, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if document == string(data) {
				t.Fatal("fixture did not mutate")
			}
			path := writeConfig(t, t.TempDir(), document, 0o600)
			if _, err := Load(path); err == nil {
				t.Fatal("unclosed configuration accepted")
			}
		})
	}
}
