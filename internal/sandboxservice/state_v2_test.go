package sandboxservice

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
)

func TestV2CannotRepinLegacyRevisionOrReassignHistoricalState(t *testing.T) {
	ctx := context.Background()
	store := openStore(t)
	wire := manifest("target-a", "target-a-r1", "workspace", targetmanifest.WorkspaceReadWrite)
	if _, err := New(ctx, newRegistry(t, wire), store, testRunnerStateOwnership); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	document := strings.Replace(string(data), `"harness-target/v1"`, `"harness-target/v2"`, 1)
	document = strings.Replace(document, `"state_ref":"`+wire.StateRef+`"`, `"runner_state":{"kind":"persistent","ref":"`+wire.StateRef+`"}`, 1)
	for _, candidate := range []string{
		document, strings.Replace(document, `"revision":"target-a-r1"`, `"revision":"target-a-r2"`, 1),
	} {
		target, err := targetmanifest.DecodeDefinition([]byte(candidate))
		if err != nil {
			t.Fatal(err)
		}
		registry, err := targetregistry.NewDefinitions([]targetmanifest.Definition{target})
		if err != nil {
			t.Fatal(err)
		}
		if service, err := New(ctx, registry, store, testRunnerStateOwnership); service != nil || !errors.Is(err, sandboxstore.ErrConflict) {
			t.Fatalf("v2 changed historical revision or state owner: %v", err)
		}
	}
}

func TestServiceRejectsNoneWithFabricatedOwnershipBeforeStore(t *testing.T) {
	wire := manifest("target-none", "target-none-r1", "workspace", targetmanifest.WorkspaceReadWrite)
	wire.SessionMode = targetmanifest.SessionNewOnly
	wire.Limits.MaxSessionAgeSeconds, wire.Limits.MaxSessionTurns = 0, 0
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	document := strings.Replace(string(data), `"harness-target/v1"`, `"harness-target/v2"`, 1)
	document = strings.Replace(document, `"state_ref":"`+wire.StateRef+`"`, `"runner_state":{"kind":"none"}`, 1)
	target, err := targetmanifest.DecodeDefinition([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := targetregistry.NewDefinitions([]targetmanifest.Definition{target})
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []sandboxstore.RunnerStateOwnership{
		{Kind: targetmanifest.RunnerStateNone, Ref: "fake"},
		{Kind: targetmanifest.RunnerStateNone, PathDigest: strings.Repeat("a", 64)},
		{Kind: targetmanifest.RunnerStateNone, PathAbsent: true},
		{Kind: targetmanifest.RunnerStatePersistent, Ref: "fake", PathDigest: strings.Repeat("a", 64), PathAbsent: true},
		{},
	} {
		store := &fakeStore{}
		if _, err := New(context.Background(), registry, store, func(targetmanifest.Definition) (sandboxstore.RunnerStateOwnership, error) { return owner, nil }); err == nil {
			t.Fatal("accepted fabricated none ownership")
		}
		if store.registerCalls != 0 {
			t.Fatal("invalid ownership reached durable store")
		}
	}
}
