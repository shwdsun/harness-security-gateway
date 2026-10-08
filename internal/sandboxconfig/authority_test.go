package sandboxconfig

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func TestAuthorityResolutionPreservesRegisteredMockPins(t *testing.T) {
	for _, version := range []string{"v1", "v2-none", "v2-persistent"} {
		t.Run(version, func(t *testing.T) {
			config := loadedFingerprintConfig(t)
			if version == "v2-none" {
				config = loadedV2Config(t, `{"kind":"none"}`)
			} else if version == "v2-persistent" {
				config = loadedV2Config(t, `{"kind":"persistent","ref":"mock-state"}`)
			}
			manifest := config.Targets[0]
			fingerprint := manifestFingerprint(t, manifest)
			legacyPin, err := config.RevisionSecurityFingerprint(manifest, fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := config.ResolveTargetAuthority(manifest, fingerprint)
			if err != nil || resolved.RevisionPin != legacyPin || resolved.Credential != nil || resolved.RunnerState.Kind != manifest.RunnerState().Kind() {
				t.Fatalf("new resolver changed mock authority: %#v, %v", resolved, err)
			}
			ctx := context.Background()
			store, err := sandboxstore.Open(ctx, filepath.Join(t.TempDir(), "sandbox.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			registry, err := config.Registry()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sandboxservice.New(ctx, registry, store, config.RunnerStateOwnership, sandboxservice.WithRevisionPin(config.RevisionSecurityFingerprint)); err != nil {
				t.Fatal(err)
			}
			if _, err := sandboxservice.New(ctx, registry, store, nil, sandboxservice.WithAuthorityResolver(config.ResolveTargetAuthority)); err != nil {
				t.Fatalf("new resolver conflicted with exact legacy registration: %v", err)
			}
			config.Workspaces[0].Directory += "-changed"
			if service, err := sandboxservice.New(ctx, registry, store, nil, sandboxservice.WithAuthorityResolver(config.ResolveTargetAuthority)); service != nil || !errors.Is(err, sandboxstore.ErrConflict) {
				t.Fatalf("changed workspace mapping retained revision: %v", err)
			}
		})
	}
}

func TestAuthorityResolutionRefusesUnimplementedProfilesEvenOnLegacyV1(t *testing.T) {
	for _, field := range []string{"family", "adapter", "policy", "auth", "skill", "network"} {
		t.Run(field, func(t *testing.T) {
			config := loadedFingerprintConfig(t)
			changed := editV1(t, config.Targets[0], func(m *targetmanifest.Manifest) {
				switch field {
				case "family":
					m.Runner.Family = "codex"
				case "adapter":
					m.Runner.AdapterVersion = "0.2.0-new-only"
				case "policy":
					m.PolicyRef = "codex.locked-v1"
				case "auth":
					m.AuthProfileRef = "codex.chatgpt-file-personal-v1"
				case "skill":
					m.SkillBundleRef = "custom.skills"
				case "network":
					m.NetworkProfileRef = "codex.provider-control-v1"
				}
			})
			config.Targets[0] = changed
			fingerprint := manifestFingerprint(t, changed)
			// The historical hash helper retains its old v1 semantics. The
			// new resolver must refuse unimplemented authority before registration.
			if _, err := config.RevisionSecurityFingerprint(changed, fingerprint); err != nil {
				t.Fatalf("legacy helper changed: %v", err)
			}
			if authority, err := config.ResolveTargetAuthority(changed, fingerprint); err == nil || authority != (sandboxservice.ResolvedAuthority{}) {
				t.Fatalf("unimplemented profile acquired authority: %#v, %v", authority, err)
			}
		})
	}
}

func TestAuthorityResolutionRequiresExactConfiguredManifest(t *testing.T) {
	config := loadedFingerprintConfig(t)
	original := config.Targets[0]
	for _, target := range []targetmanifest.Definition{
		{},
		editV1(t, original, func(m *targetmanifest.Manifest) { m.ID = "unconfigured" }),
		editV1(t, original, func(m *targetmanifest.Manifest) { m.Revision = "unconfigured-revision" }),
		editV1(t, original, func(m *targetmanifest.Manifest) { m.Limits.TimeoutSeconds++ }),
	} {
		fingerprint, _ := target.Fingerprint()
		if authority, err := config.ResolveTargetAuthority(target, fingerprint); err == nil || authority != (sandboxservice.ResolvedAuthority{}) {
			t.Fatalf("unconfigured manifest resolved: %#v, %v", authority, err)
		}
	}
	if _, err := config.ResolveTargetAuthority(original, strings.Repeat("a", 64)); err == nil {
		t.Fatal("wrong fingerprint resolved")
	}
	changed := editV1(t, original, func(m *targetmanifest.Manifest) { m.Limits.TimeoutSeconds++ })
	if _, err := config.ResolveTargetAuthority(changed, manifestFingerprint(t, original)); err == nil {
		t.Fatal("changed manifest paired with the old fingerprint")
	}
}
