package main

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
	"github.com/shwdsun/harness-security-gateway/internal/processlock"
)

func TestParseOptions(t *testing.T) {
	parsed, err := parseOptions([]string{"-config", "config/agentd.json"})
	if err != nil || parsed.configPath != "config/agentd.json" {
		t.Fatalf("parseOptions = %#v, %v", parsed, err)
	}
	for _, arguments := range [][]string{nil, {"-config", "x", "extra"}, {"-unknown"}} {
		if _, err := parseOptions(arguments); err == nil {
			t.Fatalf("parseOptions(%q) unexpectedly succeeded", arguments)
		}
	}
}

func TestAcquireCoreOwnershipFencesSameDatabaseUntilClose(t *testing.T) {
	database := filepath.Join(t.TempDir(), "control", "agentd.sqlite3")
	config := agentconfig.Config{Database: database}
	first, err := acquireCoreOwnership(config)
	if err != nil {
		t.Fatalf("acquireCoreOwnership(first): %v", err)
	}
	if _, err := acquireCoreOwnership(config); !errors.Is(err, processlock.ErrLocked) {
		t.Fatalf("acquireCoreOwnership(second) error = %v, want ErrLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first ownership: %v", err)
	}
	second, err := acquireCoreOwnership(config)
	if err != nil {
		t.Fatalf("acquireCoreOwnership(after close): %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second ownership: %v", err)
	}
}

func TestRunRejectsMissingInputsBeforeSideEffects(t *testing.T) {
	if err := run(nil, []string{"-config", "missing"}, io.Discard); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := run(context.Background(), []string{"-config", "missing"}, nil); err == nil {
		t.Fatal("nil log output accepted")
	}
}
