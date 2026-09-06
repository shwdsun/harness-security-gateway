package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/codexcandidate"
	"github.com/shwdsun/harness-security-gateway/internal/processlock"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
)

func candidateFile(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../config/codex-candidate.example.json")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCodexCheckNeverOpensCoreOrExecutableConfig(t *testing.T) {
	core := testConfig(t)
	owner, err := processlock.Acquire(core.ProcessLockPath())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	path := candidateFile(t)
	var output bytes.Buffer
	err = run(context.Background(), []string{"codex", "check", "-config", path}, &output)
	if !errors.Is(err, errCodexBlocked) || commandExitCode(err) != 3 {
		t.Fatalf("exit = %d, %v", commandExitCode(err), err)
	}
	var report codexcandidate.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "blocked" || report.LocalMetadata != "not_checked" {
		t.Fatalf("report = %+v", report)
	}
	if _, err := os.Lstat(core.Database); !os.IsNotExist(err) {
		t.Fatal("Core DB unexpectedly accessed/created")
	}
	if _, err := sandboxconfig.Load(path); err == nil {
		t.Fatal("candidate accepted as executable sandbox config")
	}
}

func TestCodexArgumentsAndExitCodes(t *testing.T) {
	path := candidateFile(t)
	for _, args := range [][]string{
		{"codex"}, {"codex", "check"}, {"codex", "run", "-config", path},
		{"codex", "check", "-config", path, "-ready"},
		{"codex", "check", "-config", path, "-token", "PRIVATE_SENTINEL"},
		{"codex", "check", "-config", path, "extra"},
	} {
		var out bytes.Buffer
		err := run(context.Background(), args, &out)
		if commandExitCode(err) != 2 || out.Len() != 0 || strings.Contains(err.Error(), "PRIVATE_SENTINEL") {
			t.Fatalf("invalid args: %v", err)
		}
	}
	var output bytes.Buffer
	err := run(context.Background(), []string{"codex", "check", "-config", path, "-inspect"}, &output)
	if !errors.Is(err, errCodexBlocked) || !strings.Contains(output.String(), `"status":"blocked"`) {
		t.Fatalf("inspection: %s, %v", output.String(), err)
	}
	if err := os.WriteFile(path, []byte(`{"PRIVATE_SENTINEL":"not a config"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	err = run(context.Background(), []string{"codex", "check", "-config", path}, &output)
	if commandExitCode(err) != 1 || output.Len() != 0 || strings.Contains(err.Error(), "PRIVATE_SENTINEL") {
		t.Fatalf("invalid config: %v", err)
	}
}

func TestCodexBinaryReportsBlockedExit(t *testing.T) {
	// The lock is held in the parent while the real child command runs.
	core := testConfig(t)
	owner, err := processlock.Acquire(core.ProcessLockPath())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	binary := filepath.Join(t.TempDir(), "hgwctl")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", binary, ".")
	if data, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, data)
	}
	// Empty environment and no Core config/runtime are sufficient for the
	// hermetic default. Test the real process exit, not go run's wrapper code.
	cmd := exec.Command(binary, "codex", "check", "-config", candidateFile(t))
	cmd.Env = []string{}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Fatalf("exit = %v, stderr=%s", err, stderr.String())
	}
	if strings.Count(stdout.String(), "\n") != 1 || !strings.Contains(stdout.String(), `"local_metadata":"not_checked"`) {
		t.Fatalf("stdout = %s", stdout.String())
	}
	if _, err := os.Lstat(core.Database); !os.IsNotExist(err) {
		t.Fatal("child touched Core database")
	}
}
