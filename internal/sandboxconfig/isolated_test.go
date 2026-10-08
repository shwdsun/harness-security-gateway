package sandboxconfig

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func isolatedConfig(t *testing.T) Config {
	c := codexConfig(t)
	c.Schema = SchemaCodexV2
	m, _ := c.Targets[0].ManifestV2()
	m.Revision += "-isolated"
	m.Runner.AdapterVersion = codexprofile.AdapterVersionV4
	m.PolicyRef, m.AuthProfileRef = codexprofile.PolicyProfileRefV4, codexprofile.AuthProfileRefV4
	c.Targets[0], _ = targetmanifest.FromV2(m)
	c.Codex.Credential.AuthProfileRef = m.AuthProfileRef
	c.Codex.Scope.TargetRevision = m.Revision
	c.Codex.OwnerLauncher = &Artifact{Path: filepath.Join(filepath.Dir(c.Codex.Runner.Path), "owner-launcher"), SHA256: codexprofile.OwnerLauncherSHA256V4}
	return c
}

func TestIsolatedSchemaRequiresIndependentAuthorityAndClosedArtifacts(t *testing.T) {
	c := isolatedConfig(t)
	data, _ := json.Marshal(c)
	if _, err := Load(writeConfig(t, t.TempDir(), string(data), 0600)); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Schema = SchemaCodexV1 },
		func(c *Config) { c.Codex.OwnerLauncher = nil },
		func(c *Config) { c.Codex.OwnerLauncher.SHA256 = strings.Repeat("a", 64) },
		func(c *Config) { c.Codex.OwnerLauncher.Path = c.Codex.ToolPackage + "/launcher" },
		func(c *Config) { c.Targets = codexConfig(t).Targets },
	} {
		v := isolatedConfig(t)
		mutate(&v)
		if v.Validate() == nil {
			t.Fatal("unsealed schema/profile mix accepted")
		}
	}
	for _, bad := range []string{
		strings.Replace(string(data), `"owner_launcher"`, `"Owner_Launcher"`, 1),
		strings.Replace(string(data), `"owner_launcher":{`, `"owner_launcher":{"url":"https://bad.invalid",`, 1),
	} {
		if _, err := Load(writeConfig(t, t.TempDir(), bad, 0600)); err == nil {
			t.Fatal("open/case-aliased owner artifact config")
		}
	}
}
