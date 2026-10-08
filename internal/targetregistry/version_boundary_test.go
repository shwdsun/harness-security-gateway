package targetregistry

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func TestLegacyConstructorRemainsV1Only(t *testing.T) {
	manifest := fixture()
	manifest.Schema = "harness-target/v2"
	registry, err := New([]targetmanifest.Manifest{manifest})
	if !errors.Is(err, targetmanifest.ErrInvalid) || registry != nil {
		t.Fatalf("v2 entered the execution registry: registry=%v err=%v", registry, err)
	}
}

func TestVersionAwareRegistrySharesIdentityAndPinsOriginalManifest(t *testing.T) {
	wire := fixture()
	v1, err := targetmanifest.FromV1(wire)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	document := strings.Replace(string(data), `"harness-target/v1"`, `"harness-target/v2"`, 1)
	document = strings.Replace(document, `"state_ref":"state-one"`, `"runner_state":{"kind":"none"}`, 1)
	v2, err := targetmanifest.DecodeDefinition([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDefinitions([]targetmanifest.Definition{v1, v2}); !errors.Is(err, ErrDuplicateTarget) {
		t.Fatalf("cross-version duplicate identity accepted: %v", err)
	}
	definitions := []targetmanifest.Definition{v2}
	registry, err := NewDefinitions(definitions)
	if err != nil {
		t.Fatal(err)
	}
	definitions[0] = targetmanifest.Definition{}
	entry, err := registry.Resolve(v2.ID(), v2.Revision())
	if err != nil {
		t.Fatal(err)
	}
	originalHash, _ := v2.Fingerprint()
	if entry.Fingerprint != originalHash || entry.Manifest.Schema() != targetmanifest.SchemaV2 {
		t.Fatal("registry projected v2")
	}
	entries := registry.Entries()
	entries[0].Manifest = targetmanifest.Definition{}
	if err := json.Unmarshal([]byte(document), &entry.Manifest); err != nil {
		t.Fatal(err)
	}
	again, err := registry.Resolve(v2.ID(), v2.Revision())
	if err != nil || again.Fingerprint != originalHash {
		t.Fatal("caller mutated registry authority")
	}
}
