package main

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/processlock"
)

func TestServeUsesProvisionedDistinctUIDSocketDirectory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("authenticated Unix listeners require Linux")
	}
	config, err := agentconfig.Load("../../config/agentd.example.json")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "edge")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, os.ModeSetgid|0o710); err != nil {
		t.Fatal(err)
	}
	config.Database = filepath.Join(root, "core", "state.sqlite3")
	config.SandboxSocket = filepath.Join(root, "unused-sandbox.sock")
	config.Connectors[0].Socket = filepath.Join(parent, "agentd.sock")
	config.Connectors[0].PeerUID = localidentity.UID(os.Geteuid()) + 1
	if err := config.Connectors[0].PeerUID.Validate(); err != nil {
		t.Skip("requires a valid synthetic distinct peer UID")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, config, log.New(io.Discard, "", 0)) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("agentd did not stop")
		}
	}()
	deadline := time.After(3 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatal("agentd did not create the socket in its provisioned shared directory")
		case <-ticker.C:
			info, err := os.Lstat(config.Connectors[0].Socket)
			if err == nil && info.Mode()&os.ModeSocket != 0 {
				if info.Mode().Perm() != 0o660 {
					t.Fatal("distinct UID socket is not group-accessible")
				}
				return
			}
		}
	}
}

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
