//go:build linux && amd64 && codexintegration

package dockerruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
)

func configuredFixture(t *testing.T, f testFixture) sandboxconfig.Config {
	t.Helper()
	data, err := os.ReadFile("../../config/sandboxd.codex.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var c sandboxconfig.Config
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	c.Runtime = f.config.Runtime
	return c
}

func configuredBuild(c ProviderCanaryConfig) (*Runtime, string, error) {
	m := c.Runtime.Manifest
	fp, _ := m.Fingerprint()
	return &Runtime{targets: map[targetKey]targetSpec{{m.ID(), m.Revision()}: {fingerprint: fp, credential: &credentialSpec{binding: c.Runtime.Credential}}},
		inventoryPin: strings.Repeat("a", 64)}, strings.Repeat("a", 64), nil
}

func TestConfiguredCodexBindsResolvedAuthorityAndUsesWholeInventory(t *testing.T) {
	f := newFixture(t)
	c := configuredFixture(t, f)
	r, pin, err := configuredCodex(c, configuredBuild)
	if err != nil {
		t.Fatal(err)
	}
	if pin == strings.Repeat("a", 64) || r.inventoryPin != "" {
		t.Fatal("daemon retained synthetic pin or filtered inventory")
	}
	for _, spec := range r.targets {
		if spec.credential.pin != pin {
			t.Fatal("Create authority and daemon registration differ")
		}
	}
	f.setPlan(t, rootlessInfoStep(), helperStep{Stdout: testContainerID + "\n"},
		helperStep{Stdout: managedRecord(t, f, "old-run", testContainerID, StateRunning)})
	refs, err := r.ListManaged(context.Background())
	if refs != nil || !errors.Is(err, ErrForeignContainer) {
		t.Fatalf("foreign managed container did not block: %v", err)
	}
	calls := f.calls(t)
	if len(calls) != 3 {
		t.Fatalf("expected inspect of old container: %d calls", len(calls))
	}
	requireArguments(t, calls[1], []string{"--host", c.Runtime.Endpoint, "container", "ls", "--all", "--no-trunc", "--filter", "label=" + labelManaged + "=v1", "--format", managedListFormat})
}

func TestConfiguredCodexAuthorityChangesRequireNewPin(t *testing.T) {
	f := newFixture(t)
	c := configuredFixture(t, f)
	_, original, err := configuredCodex(c, configuredBuild)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*sandboxconfig.Config){
		"owner bytes":        func(c *sandboxconfig.Config) { c.Codex.OwnerSHA256 = strings.Repeat("b", 64) },
		"runner bytes":       func(c *sandboxconfig.Config) { c.Codex.Runner.SHA256 = strings.Repeat("b", 64) },
		"seccomp bytes":      func(c *sandboxconfig.Config) { c.Codex.Seccomp.SHA256 = strings.Repeat("b", 64) },
		"runner locator":     func(c *sandboxconfig.Config) { c.Codex.Runner.Path += "-other" },
		"credential locator": func(c *sandboxconfig.Config) { c.Codex.Credential.Directory = "other-slot" },
		"generation":         func(c *sandboxconfig.Config) { c.Codex.Credential.Generation++ },
		"scope":              func(c *sandboxconfig.Config) { c.Codex.Scope.ActorRef = "other" },
		"binding":            func(c *sandboxconfig.Config) { c.Codex.Scope.BindingFingerprint = strings.Repeat("b", 64) },
		"workspace":          func(c *sandboxconfig.Config) { c.WorkspaceRoot += "-other" },
		"provider storage":   func(c *sandboxconfig.Config) { c.Codex.ProviderRoot += "-other" },
		"tool package":       func(c *sandboxconfig.Config) { c.Codex.ToolPackage += "-other" },
		"database lineage":   func(c *sandboxconfig.Config) { c.StateDatabase += "-other" },
		"control peer":       func(c *sandboxconfig.Config) { c.PeerUID++ },
	} {
		t.Run(name, func(t *testing.T) {
			c := configuredFixture(t, f)
			mutate(&c)
			_, pin, err := configuredCodex(c, configuredBuild)
			if err != nil || pin == original {
				t.Fatalf("changed authority was not bound: %v", err)
			}
		})
	}
	if _, _, err := configuredCodex(c, func(ProviderCanaryConfig) (*Runtime, string, error) { return nil, "", ErrInvalidStorage }); !errors.Is(err, ErrInvalidStorage) {
		t.Fatal("factory failure gained a fallback")
	}
}
