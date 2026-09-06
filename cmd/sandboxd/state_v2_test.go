package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func TestV3NoStateStartupDoesNotPrepareAnyStateLeaf(t *testing.T) {
	config := runnerStateOwnershipConfig(t)
	raw, _ := config.Targets[0].Manifest()
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	document := strings.Replace(string(data), `"harness-target/v1"`, `"harness-target/v2"`, 1)
	document = strings.Replace(document, `"state_ref":"`+raw.StateRef+`"`, `"runner_state":{"kind":"none"}`, 1)
	target, err := targetmanifest.DecodeDefinition([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	config.Schema = sandboxconfig.SchemaV3
	config.Targets = []targetmanifest.Definition{target}
	// Retain the old unused catalog entry: it cannot request directory creation.
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := prepareFilesystem(config); err != nil {
		t.Fatal(err)
	}
	registry, err := config.Registry()
	if err != nil {
		t.Fatal(err)
	}
	store, err := sandboxstore.Open(context.Background(), config.StateDatabase)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := sandboxservice.New(context.Background(), registry, store, config.RunnerStateOwnership,
		sandboxservice.WithRevisionPin(config.RevisionSecurityFingerprint)); err != nil {
		t.Fatal(err)
	}
	if err := prepareRunnerStateFilesystem(config); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(config.RunnerStateRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("none prepared runner state: %#v %v", entries, err)
	}
}
