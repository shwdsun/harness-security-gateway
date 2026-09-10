package codexadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
)

func TestToolsConfigUsesVersionedNativePackage(t *testing.T) {
	c := MessagingToolsConfig(codexprofile.ModelNameV1)
	p, developer, err := c.resolve()
	if err != nil || p != codexprofile.V3() || c.Binary != codexprofile.CLIBinaryPathV3 || developer == "" {
		t.Fatalf("tools config: %v, %#v", err, p)
	}
	old := MessagingConfig(codexprofile.ModelNameV1).invocation("user", developer, "/tmp/result", io.Discard, io.Discard)
	got := c.invocation("user", developer, "/tmp/result", io.Discard, io.Discard)
	if !reflect.DeepEqual(old.Env, got.Env) || old.Dir != got.Dir {
		t.Fatal("tool configuration changed the environment or workspace")
	}
	config := make(map[string]string)
	for i, arg := range got.Args {
		if arg == "--config" {
			key, value, ok := strings.Cut(got.Args[i+1], "=")
			if !ok || config[key] != "" {
				t.Fatal("duplicate or invalid config key")
			}
			config[key] = value
		}
	}
	for key, want := range map[string]string{
		"features.code_mode.enabled":             "false",
		"features.code_mode_host":                "{enabled=true,disable_in_process_fallback=true}",
		"features.multi_agent_v2":                "{enabled=false,max_concurrent_threads_per_session=1,usage_hint_enabled=false}",
		"agents.max_threads":                     "1",
		"sandbox_workspace_write.network_access": "false",
		"features.shell_tool":                    "true",
		"features.unified_exec":                  "true",
		"features.skip_host_skill_discovery":     "true",
		"analytics.enabled":                      "false",
		"features.runtime_metrics":               "false",
	} {
		if config[key] != want {
			t.Fatalf("%s = %q, want %q", key, config[key], want)
		}
	}
	if _, ok := config["model_catalog_json"]; ok {
		t.Fatal("synthetic catalog entered native configuration")
	}
	for _, path := range []string{"/opt/hsg/codex/workspace", "/opt/hsg/codex/codex-path"} {
		bad := c
		bad.Workspace = path
		if _, _, err := bad.resolve(); !errors.Is(err, errInvalidConfig) {
			t.Fatal("writable package overlap accepted")
		}
	}
}

func TestToolsPackageFailurePrecedesReadinessAndLaunch(t *testing.T) {
	c := testConfig(t)
	c.ProfileID = codexprofile.IDV3
	c.Binary = filepath.Join(t.TempDir(), "package", "bin", "codex")
	var output bytes.Buffer
	err := Run(context.Background(), strings.NewReader(""), &output, c, launcherFunc(func(context.Context, Invocation) (Process, error) {
		t.Fatal("missing package reached launcher")
		return nil, nil
	}))
	if !errors.Is(err, errInvalidConfig) || output.Len() != 0 {
		t.Fatalf("missing package: %v, output %q", err, output.String())
	}
	if strings.Contains(err.Error(), c.Binary) {
		t.Fatal("package diagnostic exposed a local path")
	}
}

func TestPackageArtifactsRejectMissingSubstitutedAndUnsafeFiles(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "same-size-corruption", "symlink", "parent-symlink", "hardlink", "fifo", "writable-file", "writable-directory", "not-executable", "oversized", "extra-file", "extra-directory"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, "bin")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "helper")
			data := []byte("fixed package fixture")
			if err := os.WriteFile(path, data, 0o500); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			switch mode {
			case "missing", "symlink", "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if mode == "symlink" {
					if err := os.Symlink("elsewhere", path); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "fifo" {
					if err := syscall.Mkfifo(path, 0o500); err != nil {
						t.Fatal(err)
					}
				}
			case "same-size-corruption", "oversized":
				if err := os.Chmod(path, 0o700); err != nil {
					t.Fatal(err)
				}
				bad := bytes.Repeat([]byte("x"), len(data))
				if mode == "oversized" {
					bad = append(bad, 'x')
				}
				if err := os.WriteFile(path, bad, 0o500); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(t.TempDir(), "alias")); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				if err := os.Rename(dir, filepath.Join(root, "other")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("other", dir); err != nil {
					t.Fatal(err)
				}
			case "writable-file":
				if err := os.Chmod(path, 0o777); err != nil {
					t.Fatal(err)
				}
			case "writable-directory":
				if err := os.Chmod(dir, 0o777); err != nil {
					t.Fatal(err)
				}
			case "not-executable":
				if err := os.Chmod(path, 0o400); err != nil {
					t.Fatal(err)
				}
			case "extra-file":
				if err := os.WriteFile(filepath.Join(dir, "unreviewed"), []byte("extra executable"), 0o500); err != nil {
					t.Fatal(err)
				}
			case "extra-directory":
				if err := os.Mkdir(filepath.Join(root, "unreviewed"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			err := verifyPackageArtifacts(root, []packageArtifact{{"bin/helper", hex.EncodeToString(digest[:]), int64(len(data)), true}})
			if (err == nil) != (mode == "valid") {
				t.Fatalf("verification = %v", err)
			}
		})
	}
}
