package codexadapter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
)

func TestProductionConfigSeparatesDisposableState(t *testing.T) {
	config := ProductionConfig("release-selected-model")
	if config.Binary != "/usr/local/bin/codex" || config.Workspace != "/workspace" ||
		config.CodexHome != "/tmp/hgw-codex-home" || config.OutputDirectory != "/tmp/hgw-codex-runner" {
		t.Fatalf("ProductionConfig() = %#v", config)
	}
	if pathsOverlap(config.CodexHome, config.OutputDirectory) || pathsOverlap(config.CodexHome, config.Workspace) {
		t.Fatalf("production trust domains overlap: %#v", config)
	}
}

func TestRunEmitsNewOnlyLifecycleAndUsesClosedInvocation(t *testing.T) {
	config := testConfig(t)
	start := testStart()
	start.Input.Text = "untrusted prompt --model attacker"

	var captured Invocation
	launcher := launcherFunc(func(_ context.Context, invocation Invocation) (Process, error) {
		captured = invocation
		prompt, err := io.ReadAll(invocation.Stdin)
		if err != nil {
			t.Fatalf("read child stdin: %v", err)
		}
		if string(prompt) != start.Input.Text {
			t.Fatalf("child stdin = %q, want prompt", prompt)
		}
		_, _ = invocation.Stdout.Write([]byte(`{"type":"item.completed","private":"stdout-secret"}` + "\n"))
		_, _ = invocation.Stderr.Write([]byte("stderr-secret"))
		writeFinal(t, outputPath(t, invocation.Args), "Codex completed safely")
		return processFunc(func() error { return nil }), nil
	})

	frames, wire, err := execute(t, context.Background(), start, config, launcher)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("frame count = %d, want 3", len(frames))
	}
	ready, ok := frames[0].(*runnerwire.RunnerReady)
	if !ok {
		t.Fatalf("frame 0 = %T, want RunnerReady", frames[0])
	}
	if ready.Adapter.Family != AdapterFamily || ready.Adapter.Version != AdapterVersion || len(ready.Features) != 0 {
		t.Fatalf("ready = %#v", ready)
	}
	if _, ok := frames[1].(*runnerwire.RunStarted); !ok {
		t.Fatalf("frame 1 = %T, want RunStarted", frames[1])
	}
	completed, ok := frames[2].(*runnerwire.RunCompleted)
	if !ok {
		t.Fatalf("frame 2 = %T, want RunCompleted", frames[2])
	}
	if completed.Seq != 2 || completed.Output.Text != "Codex completed safely" || completed.SessionToken != "" {
		t.Fatalf("completed = %#v", completed)
	}
	if strings.Contains(wire, "stdout-secret") || strings.Contains(wire, "stderr-secret") {
		t.Fatalf("HRP output leaked provider diagnostics: %q", wire)
	}

	wantArgs := []string{
		"exec",
		"--json",
		"--ephemeral",
		"--ignore-user-config",
		"--ignore-rules",
		"--strict-config",
		"--color", "never",
		"--sandbox", "workspace-write",
		"--model", config.Model,
		"--cd", config.Workspace,
		"--output-last-message", filepath.Join(config.OutputDirectory, finalFilename),
		"--config", `approval_policy="never"`,
		"--config", `sandbox_workspace_write.network_access=false`,
		"--config", `sandbox_workspace_write.exclude_slash_tmp=true`,
		"--config", `sandbox_workspace_write.exclude_tmpdir_env_var=true`,
		"--config", `shell_environment_policy.inherit="none"`,
		"--config", `shell_environment_policy.ignore_default_excludes=false`,
		"--config", `shell_environment_policy.set={PATH="/usr/local/bin:/usr/bin:/bin",LANG="C.UTF-8",LC_ALL="C.UTF-8",HOME="/nonexistent"}`,
		"--config", `projects={"` + config.Workspace + `"={trust_level="untrusted"}}`,
		"--config", `project_doc_max_bytes=0`,
		"--config", `web_search="disabled"`,
		"--config", `tools.web_search=false`,
		"--config", `forced_login_method="chatgpt"`,
		"--config", `cli_auth_credentials_store="file"`,
		"--config", `check_for_update_on_startup=false`,
		"--config", `allow_login_shell=false`,
		"--config", `apps._default.enabled=false`,
		"--config", `features.apps=false`,
		"--config", `features.auth_elicitation=false`,
		"--config", `features.browser_use=false`,
		"--config", `features.browser_use_external=false`,
		"--config", `features.browser_use_full_cdp_access=false`,
		"--config", `features.code_mode.enabled=false`,
		"--config", `features.code_mode_host=false`,
		"--config", `features.computer_use=false`,
		"--config", `features.fast_mode=false`,
		"--config", `features.goals=false`,
		"--config", `features.guardian_approval=false`,
		"--config", `features.hooks=false`,
		"--config", `features.image_generation=false`,
		"--config", `features.memories=false`,
		"--config", `features.multi_agent=false`,
		"--config", `features.network_proxy=false`,
		"--config", `features.plugin_sharing=false`,
		"--config", `features.plugins=false`,
		"--config", `features.recommended_plugins=false`,
		"--config", `features.remote_compaction_v2=false`,
		"--config", `features.remote_plugin=false`,
		"--config", `features.shell_snapshot=false`,
		"--config", `features.skill_mcp_dependency_install=false`,
		"--config", `features.skill_search=false`,
		"--config", `features.tool_call_mcp_elicitation=false`,
		"--config", `features.tool_suggest=false`,
		"--config", `features.unbounded_connection_retries=false`,
		"--config", `features.view_image=false`,
		"--config", `features.workspace_dependencies=false`,
		"--config", `feedback.enabled=false`,
		"--config", `history.persistence="none"`,
		"-",
	}
	if !reflect.DeepEqual(captured.Args, wantArgs) {
		t.Fatalf("args = %#v, want %#v", captured.Args, wantArgs)
	}
	if contains(captured.Args, start.Input.Text) {
		t.Fatalf("prompt appeared in argv: %#v", captured.Args)
	}
	if contains(captured.Args, "--approve-for-me") || contains(captured.Args, "--dangerously-bypass-approvals-and-sandbox") ||
		contains(captured.Args, "--dangerously-bypass-hook-trust") || contains(captured.Args, "--skip-git-repo-check") {
		t.Fatalf("unsafe or unapproved flag present: %#v", captured.Args)
	}
	wantEnv := []string{
		"CODEX_HOME=" + config.CodexHome,
		"CODEX_SQLITE_HOME=" + config.OutputDirectory,
		"HOME=/nonexistent",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"TERM=dumb",
	}
	if !reflect.DeepEqual(captured.Env, wantEnv) {
		t.Fatalf("env = %#v, want %#v", captured.Env, wantEnv)
	}
}

func TestRunCreatesMissingDisposableCodexHomeBeforeLaunch(t *testing.T) {
	config := testConfig(t)
	if err := os.Remove(config.CodexHome); err != nil {
		t.Fatalf("remove pre-created Codex home: %v", err)
	}
	launcher := launcherFunc(func(_ context.Context, invocation Invocation) (Process, error) {
		info, err := os.Lstat(config.CodexHome)
		if err != nil {
			t.Fatalf("Codex home missing at launch: %v", err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 || !ownedByEffectiveUser(info) {
			t.Fatalf("Codex home = %#v, want owner-only directory", info)
		}
		entries, err := os.ReadDir(config.CodexHome)
		if err != nil || len(entries) != 0 {
			t.Fatalf("Codex home entries = %v, %v, want empty", entries, err)
		}
		writeFinal(t, outputPath(t, invocation.Args), "created private state")
		return processFunc(func() error { return nil }), nil
	})

	frames, _, err := execute(t, context.Background(), testStart(), config, launcher)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	completed, ok := frames[len(frames)-1].(*runnerwire.RunCompleted)
	if !ok || completed.Output.Text != "created private state" {
		t.Fatalf("terminal = %#v, want completion", frames[len(frames)-1])
	}
}

func TestRunAcceptsAttestedAuthFileShape(t *testing.T) {
	config := testConfig(t)
	authPath := filepath.Join(config.CodexHome, authFilename)
	if err := os.WriteFile(authPath, []byte(`{"tokens":"fixture-only"}`), 0o600); err != nil {
		t.Fatalf("write auth shape fixture: %v", err)
	}
	launcher := launcherFunc(func(_ context.Context, invocation Invocation) (Process, error) {
		writeFinal(t, outputPath(t, invocation.Args), "auth shape accepted")
		return processFunc(func() error { return nil }), nil
	})

	frames, wire, err := execute(t, context.Background(), testStart(), config, launcher)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	completed, ok := frames[len(frames)-1].(*runnerwire.RunCompleted)
	if !ok || completed.Output.Text != "auth shape accepted" {
		t.Fatalf("terminal = %#v, want completion; wire=%q", frames[len(frames)-1], wire)
	}
}

func TestRunRejectsUnsafeCodexHomeBeforeLaunch(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, config Config)
	}{
		{
			name: "direct symlink",
			setup: func(t *testing.T, config Config) {
				if err := os.Remove(config.CodexHome); err != nil {
					t.Fatalf("remove Codex home: %v", err)
				}
				target := filepath.Join(filepath.Dir(config.CodexHome), "redirected")
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatalf("create symlink target: %v", err)
				}
				if err := os.Symlink(target, config.CodexHome); err != nil {
					t.Fatalf("symlink Codex home: %v", err)
				}
			},
		},
		{
			name: "symlinked parent",
			setup: func(t *testing.T, config Config) {
				parent := filepath.Dir(config.CodexHome)
				if err := os.Remove(config.CodexHome); err != nil {
					t.Fatalf("remove Codex home: %v", err)
				}
				if err := os.Remove(parent); err != nil {
					t.Fatalf("remove Codex parent: %v", err)
				}
				target := filepath.Join(filepath.Dir(parent), "redirected-parent")
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatalf("create parent target: %v", err)
				}
				if err := os.Symlink(target, parent); err != nil {
					t.Fatalf("symlink Codex parent: %v", err)
				}
			},
		},
		{
			name: "regular file",
			setup: func(t *testing.T, config Config) {
				if err := os.Remove(config.CodexHome); err != nil {
					t.Fatalf("remove Codex home: %v", err)
				}
				if err := os.WriteFile(config.CodexHome, []byte("not a directory"), 0o600); err != nil {
					t.Fatalf("write file at Codex home: %v", err)
				}
			},
		},
		{
			name: "broad directory mode",
			setup: func(t *testing.T, config Config) {
				if err := os.Chmod(config.CodexHome, 0o755); err != nil {
					t.Fatalf("chmod Codex home: %v", err)
				}
			},
		},
		{
			name: "unexpected entry",
			setup: func(t *testing.T, config Config) {
				if err := os.WriteFile(filepath.Join(config.CodexHome, "config.toml"), []byte("untrusted"), 0o600); err != nil {
					t.Fatalf("write unexpected entry: %v", err)
				}
			},
		},
		{
			name: "auth symlink",
			setup: func(t *testing.T, config Config) {
				target := filepath.Join(filepath.Dir(config.CodexHome), "auth-target")
				if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
					t.Fatalf("write auth target: %v", err)
				}
				if err := os.Symlink(target, filepath.Join(config.CodexHome, authFilename)); err != nil {
					t.Fatalf("symlink auth file: %v", err)
				}
			},
		},
		{
			name: "auth directory",
			setup: func(t *testing.T, config Config) {
				if err := os.Mkdir(filepath.Join(config.CodexHome, authFilename), 0o700); err != nil {
					t.Fatalf("create auth directory: %v", err)
				}
			},
		},
		{
			name: "auth broad mode",
			setup: func(t *testing.T, config Config) {
				path := filepath.Join(config.CodexHome, authFilename)
				if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
					t.Fatalf("write broad auth file: %v", err)
				}
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatalf("chmod broad auth file: %v", err)
				}
			},
		},
		{
			name: "auth hardlink",
			setup: func(t *testing.T, config Config) {
				target := filepath.Join(filepath.Dir(config.CodexHome), "linked-auth")
				if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
					t.Fatalf("write hardlink target: %v", err)
				}
				if err := os.Link(target, filepath.Join(config.CodexHome, authFilename)); err != nil {
					t.Fatalf("hardlink auth file: %v", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testConfig(t)
			test.setup(t, config)
			launcher := &countingLauncher{}
			frames, wire, err := execute(t, context.Background(), testStart(), config, launcher)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if launcher.calls != 0 {
				t.Fatalf("launcher calls = %d, want 0", launcher.calls)
			}
			requireFailure(t, frames, 2, runnerwire.ErrorCodeRunnerInternal, "Codex runner could not prepare state")
			if strings.Contains(wire, config.CodexHome) || strings.Contains(wire, authFilename) || strings.Contains(wire, "config.toml") {
				t.Fatalf("wire leaked private-state detail: %q", wire)
			}
		})
	}
}

func TestRunRejectsResumeWithoutLaunching(t *testing.T) {
	start := testStart()
	start.Session = runnerwire.Session{Mode: runnerwire.SessionModeResume, Token: "vendor-session"}
	launcher := &countingLauncher{}

	frames, _, err := execute(t, context.Background(), start, testConfig(t), launcher)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if launcher.calls != 0 {
		t.Fatalf("launcher calls = %d, want 0", launcher.calls)
	}
	requireFailure(t, frames, 2, runnerwire.ErrorCodePolicyDenied, "Codex target accepts new sessions only")
}

func TestRunSanitizesStartAndWaitFailures(t *testing.T) {
	t.Run("start", func(t *testing.T) {
		launcher := launcherFunc(func(context.Context, Invocation) (Process, error) {
			return nil, errors.New("private executable path and provider token")
		})
		frames, wire, err := execute(t, context.Background(), testStart(), testConfig(t), launcher)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		requireFailure(t, frames, 2, runnerwire.ErrorCodeRunnerInternal, "Codex runner could not start")
		if strings.Contains(wire, "private") || strings.Contains(wire, "token") {
			t.Fatalf("wire leaked start error: %q", wire)
		}
	})

	t.Run("wait", func(t *testing.T) {
		launcher := launcherFunc(func(_ context.Context, invocation Invocation) (Process, error) {
			_, _ = invocation.Stderr.Write([]byte("provider bearer private"))
			return processFunc(func() error { return errors.New("provider bearer private") }), nil
		})
		frames, wire, err := execute(t, context.Background(), testStart(), testConfig(t), launcher)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		requireFailure(t, frames, 2, runnerwire.ErrorCodeHarnessError, "Codex execution failed")
		if strings.Contains(wire, "bearer") || strings.Contains(wire, "private") {
			t.Fatalf("wire leaked wait error: %q", wire)
		}
	})
}

func TestRunRejectsReplacedFinalFileWithoutReadingReplacement(t *testing.T) {
	config := testConfig(t)
	secretPath := filepath.Join(filepath.Dir(config.OutputDirectory), "forbidden-secret")
	if err := os.WriteFile(secretPath, []byte("DO-NOT-LEAK"), 0o600); err != nil {
		t.Fatalf("write secret fixture: %v", err)
	}
	launcher := launcherFunc(func(_ context.Context, invocation Invocation) (Process, error) {
		path := outputPath(t, invocation.Args)
		return processFunc(func() error {
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove final fixture: %v", err)
			}
			if err := os.Symlink(secretPath, path); err != nil {
				t.Fatalf("replace final fixture: %v", err)
			}
			return nil
		}), nil
	})

	frames, wire, err := execute(t, context.Background(), testStart(), config, launcher)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	requireFailure(t, frames, 2, runnerwire.ErrorCodeRunnerInternal, "Codex result was unavailable")
	if strings.Contains(wire, "DO-NOT-LEAK") {
		t.Fatalf("wire leaked replacement target: %q", wire)
	}
}

func TestRunRejectsPartialFinalAfterReportedWriteFailure(t *testing.T) {
	launcher := launcherFunc(func(_ context.Context, invocation Invocation) (Process, error) {
		writeFinal(t, outputPath(t, invocation.Args), "partial result must not commit")
		_, _ = invocation.Stderr.Write([]byte("Failed to write last "))
		_, _ = invocation.Stderr.Write([]byte("message file /private/path: storage error"))
		return processFunc(func() error { return nil }), nil
	})

	frames, wire, err := execute(t, context.Background(), testStart(), testConfig(t), launcher)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	requireFailure(t, frames, 2, runnerwire.ErrorCodeRunnerInternal, "Codex result was unavailable")
	if strings.Contains(wire, "partial result") || strings.Contains(wire, "/private/path") {
		t.Fatalf("wire leaked partial result or diagnostic: %q", wire)
	}
}

func TestRunBoundsFinalAndDiagnosticOutput(t *testing.T) {
	tests := []struct {
		name  string
		start func(t *testing.T, invocation Invocation) Process
		want  string
	}{
		{
			name: "final output",
			start: func(t *testing.T, invocation Invocation) Process {
				writeFinal(t, outputPath(t, invocation.Args), strings.Repeat("x", runnerwire.MaxOutputTextBytes+1))
				return processFunc(func() error { return nil })
			},
			want: "Codex result was unavailable",
		},
		{
			name: "blank final output",
			start: func(t *testing.T, invocation Invocation) Process {
				writeFinal(t, outputPath(t, invocation.Args), " \n\t")
				return processFunc(func() error { return nil })
			},
			want: "Codex result was unavailable",
		},
		{
			name: "stdout",
			start: func(t *testing.T, invocation Invocation) Process {
				_, _ = invocation.Stdout.Write(make([]byte, maxCodexStdoutBytes+1))
				writeFinal(t, outputPath(t, invocation.Args), "unreachable")
				return processFunc(func() error { return nil })
			},
			want: "Codex diagnostic output exceeded its limit",
		},
		{
			name: "stderr",
			start: func(t *testing.T, invocation Invocation) Process {
				_, _ = invocation.Stderr.Write(make([]byte, maxCodexStderrBytes+1))
				writeFinal(t, outputPath(t, invocation.Args), "unreachable")
				return processFunc(func() error { return nil })
			},
			want: "Codex diagnostic output exceeded its limit",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			launcher := launcherFunc(func(_ context.Context, invocation Invocation) (Process, error) {
				return test.start(t, invocation), nil
			})
			frames, _, err := execute(t, context.Background(), testStart(), testConfig(t), launcher)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			requireFailure(t, frames, 2, runnerwire.ErrorCodeRunnerInternal, test.want)
		})
	}
}

func TestRunDiagnosticOverflowCancelsChildBeforeWaitReturns(t *testing.T) {
	launcher := launcherFunc(func(childCtx context.Context, invocation Invocation) (Process, error) {
		written, writeErr := invocation.Stderr.Write(make([]byte, maxCodexStderrBytes+1))
		if !errors.Is(writeErr, errOutputLimit) || written != maxCodexStderrBytes {
			t.Fatalf("diagnostic Write() = (%d, %v), want (%d, errOutputLimit)", written, writeErr, maxCodexStderrBytes)
		}
		return processFunc(func() error {
			<-childCtx.Done()
			return childCtx.Err()
		}), nil
	})

	frames, _, err := execute(t, context.Background(), testStart(), testConfig(t), launcher)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	requireFailure(t, frames, 2, runnerwire.ErrorCodeRunnerInternal, "Codex diagnostic output exceeded its limit")
}

func TestRunEmitsCancellationOnlyAfterChildStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	launcher := launcherFunc(func(childCtx context.Context, _ Invocation) (Process, error) {
		return processFunc(func() error {
			cancel()
			<-childCtx.Done()
			return childCtx.Err()
		}), nil
	})
	frames, _, err := execute(t, ctx, testStart(), testConfig(t), launcher)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("frame count = %d, want 3", len(frames))
	}
	cancelled, ok := frames[2].(*runnerwire.RunCancelled)
	if !ok || cancelled.Seq != 2 {
		t.Fatalf("terminal = %#v, want seq-2 cancellation", frames[2])
	}
}

func TestRunPrelaunchFailuresFollowStarted(t *testing.T) {
	t.Run("expired deadline", func(t *testing.T) {
		start := testStart()
		start.DeadlineUnixMS = time.Now().Add(-time.Second).UnixMilli()
		launcher := &countingLauncher{}
		frames, _, err := execute(t, context.Background(), start, testConfig(t), launcher)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if launcher.calls != 0 {
			t.Fatalf("launcher calls = %d, want 0", launcher.calls)
		}
		if len(frames) != 3 {
			t.Fatalf("frame count = %d, want 3", len(frames))
		}
		cancelled, ok := frames[2].(*runnerwire.RunCancelled)
		if !ok || cancelled.Seq != 2 {
			t.Fatalf("terminal = %#v, want seq-2 cancellation", frames[2])
		}
	})

	t.Run("output preparation", func(t *testing.T) {
		config := testConfig(t)
		if err := os.Mkdir(config.OutputDirectory, 0o700); err != nil {
			t.Fatalf("occupy output directory: %v", err)
		}
		launcher := &countingLauncher{}
		frames, _, err := execute(t, context.Background(), testStart(), config, launcher)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if launcher.calls != 0 {
			t.Fatalf("launcher calls = %d, want 0", launcher.calls)
		}
		requireFailure(t, frames, 2, runnerwire.ErrorCodeRunnerInternal, "Codex runner could not prepare output")
	})
}

func TestConfigRejectsAuthorityOverlapAndUnsafeModel(t *testing.T) {
	base := testConfig(t)
	tests := []Config{
		func() Config { c := base; c.Model = ""; return c }(),
		func() Config { c := base; c.Model = "bad model"; return c }(),
		func() Config { c := base; c.CodexHome = filepath.Join(c.Workspace, "auth"); return c }(),
		func() Config { c := base; c.OutputDirectory = filepath.Join(c.Workspace, "result"); return c }(),
		func() Config { c := base; c.OutputDirectory = filepath.Join(c.CodexHome, "result"); return c }(),
		func() Config { c := base; c.Binary = filepath.Join(c.Workspace, "codex"); return c }(),
		func() Config { c := base; c.Workspace += `"quoted`; return c }(),
		func() Config { c := base; c.Workspace += `\escaped`; return c }(),
		func() Config { c := base; c.Binary = "codex"; return c }(),
	}
	for index, config := range tests {
		if err := Run(context.Background(), strings.NewReader(""), io.Discard, config, &countingLauncher{}); err == nil {
			t.Fatalf("case %d: Run() error = nil", index)
		}
	}
}

func testConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	codexHome := filepath.Join(root, "auth", "codex")
	temporary := filepath.Join(root, "tmp")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if err := os.MkdirAll(codexHome, 0o700); err != nil {
		t.Fatalf("create Codex home: %v", err)
	}
	if err := os.MkdirAll(temporary, 0o700); err != nil {
		t.Fatalf("create temporary root: %v", err)
	}
	return Config{
		Binary:          filepath.Join(root, "image", "codex"),
		Model:           "gpt-test-pinned",
		Workspace:       workspace,
		CodexHome:       codexHome,
		OutputDirectory: filepath.Join(temporary, "hgw-codex-runner"),
	}
}

func testStart() *runnerwire.RunStart {
	return &runnerwire.RunStart{
		Protocol:       runnerwire.ProtocolV1,
		Type:           runnerwire.TypeRunStart,
		RunID:          "run-codex-1",
		TargetRevision: "project-codex-r1",
		Input: runnerwire.TextContent{
			MediaType: runnerwire.MediaTypeTextPlain,
			Text:      "inspect the project",
		},
		Session:        runnerwire.Session{Mode: runnerwire.SessionModeNew},
		DeadlineUnixMS: time.Now().Add(time.Minute).UnixMilli(),
	}
}

func execute(t *testing.T, ctx context.Context, start *runnerwire.RunStart, config Config, launcher Launcher) ([]runnerwire.RunnerFrame, string, error) {
	t.Helper()
	var input bytes.Buffer
	if err := runnerwire.NewEncoder(&input).Encode(start); err != nil {
		t.Fatalf("encode start: %v", err)
	}
	var output bytes.Buffer
	err := Run(ctx, &input, &output, config, launcher)
	wire := output.String()
	decoder := runnerwire.NewDecoder(&output)
	var frames []runnerwire.RunnerFrame
	for {
		frame, decodeErr := decoder.DecodeRunnerFrame()
		if errors.Is(decodeErr, io.EOF) {
			break
		}
		if decodeErr != nil {
			t.Fatalf("decode HRP output: %v; wire=%q", decodeErr, wire)
		}
		frames = append(frames, frame)
	}
	if len(frames) > 1 {
		sequence, sequenceErr := runnerwire.NewSequence(start.RunID)
		if sequenceErr != nil {
			t.Fatalf("NewSequence() error = %v", sequenceErr)
		}
		for index, frame := range frames[1:] {
			event, ok := frame.(runnerwire.RunEvent)
			if !ok {
				t.Fatalf("frame %d = %T, want RunEvent", index+1, frame)
			}
			if sequenceErr := sequence.Accept(event); sequenceErr != nil {
				t.Fatalf("sequence Accept(frame %d %T) error = %v", index+1, frame, sequenceErr)
			}
		}
		if sequenceErr := sequence.Finalize(); sequenceErr != nil {
			t.Fatalf("sequence Finalize() error = %v", sequenceErr)
		}
	}
	return frames, wire, err
}

func requireFailure(t *testing.T, frames []runnerwire.RunnerFrame, seq uint64, code runnerwire.ErrorCode, message string) {
	t.Helper()
	if len(frames) != int(seq)+1 {
		t.Fatalf("frame count = %d, want %d", len(frames), seq+1)
	}
	failure, ok := frames[len(frames)-1].(*runnerwire.RunFailed)
	if !ok {
		t.Fatalf("terminal = %T, want RunFailed", frames[len(frames)-1])
	}
	if failure.Seq != seq || failure.Error.Code != code || failure.Error.Message != message {
		t.Fatalf("failure = %#v", failure)
	}
}

func writeFinal(t *testing.T, path, value string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatalf("open final output: %v", err)
	}
	if _, err := io.WriteString(file, value); err != nil {
		_ = file.Close()
		t.Fatalf("write final output: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close final output: %v", err)
	}
}

func outputPath(t *testing.T, args []string) string {
	t.Helper()
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "--output-last-message" {
			return args[index+1]
		}
	}
	t.Fatal("missing --output-last-message")
	return ""
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

type launcherFunc func(context.Context, Invocation) (Process, error)

func (function launcherFunc) Start(ctx context.Context, invocation Invocation) (Process, error) {
	return function(ctx, invocation)
}

type processFunc func() error

func (function processFunc) Wait() error { return function() }

type countingLauncher struct{ calls int }

func (launcher *countingLauncher) Start(context.Context, Invocation) (Process, error) {
	launcher.calls++
	return processFunc(func() error { return nil }), nil
}
