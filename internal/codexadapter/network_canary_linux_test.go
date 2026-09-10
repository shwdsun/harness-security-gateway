//go:build linux

package codexadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"golang.org/x/sys/unix"
)

const networkCanaryEnv = "HSG_CODEX_NETWORK_CANARY"

// TestCodexNetworkCanary tests a native sandbox primitive, not the adapter's
// exec path or an approved container. The pinned CLI's sandbox helper requires
// an explicit named permission profile; it cannot use the adapter's legacy
// sandbox_workspace_write settings as an equivalent invocation. The positive
// control prevents an outer sandbox restriction from looking like a pass.
// Neither case connects, listens, resolves DNS, or calls a model/provider.
func TestCodexNetworkCanary(t *testing.T) {
	if os.Getenv(networkCanaryEnv) != "1" {
		t.Skip("set " + networkCanaryEnv + "=1 to run the pinned native sandbox canary")
	}
	binary, err := exec.LookPath("codex")
	if err != nil {
		t.Fatal("find codex:", err)
	}
	artifact, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("read pinned codex artifact:", err)
	}
	digest := sha256.Sum256(artifact)
	if got := hex.EncodeToString(digest[:]); got != codexprofile.CLIBinarySHA256V1 {
		t.Fatalf("codex binary SHA256 = %s, want %s", got, codexprofile.CLIBinarySHA256V1)
	}
	probe, err := os.Executable()
	if err != nil {
		t.Fatal("find test executable:", err)
	}
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	for _, name := range []string{"workspace", "codex-home", "sqlite-home", "tmp"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal("create disposable canary directory:", err)
		}
	}
	// This complete environment contains no inherited proxy, credentials,
	// provider routing, config paths, or active Codex sandbox state. TMPDIR
	// confines the CLI's synthetic mount registry to this fixture.
	environment := []string{
		"CODEX_HOME=" + filepath.Join(root, "codex-home"),
		"CODEX_SQLITE_HOME=" + filepath.Join(root, "sqlite-home"),
		"TMPDIR=" + filepath.Join(root, "tmp"),
		"HOME=/nonexistent",
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TERM=dumb",
	}
	run := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Dir, cmd.Env = workspace, environment
		cmd.WaitDelay = time.Second
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("native CLI did not complete: %w; stderr=%q", err, stderr.String())
		}
		return out, nil
	}
	version, err := run("--version")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(version)); got != "codex-cli "+codexprofile.CLIVersionV1 {
		t.Fatalf("codex version = %q", got)
	}
	t.Logf("pinned CLI: %s sha256=%s", strings.TrimSpace(string(version)), codexprofile.CLIBinarySHA256V1)

	for _, enabled := range []bool{true, false} {
		label := "deny"
		if enabled {
			label = "positive-control"
		}
		// Explicit -P excludes managed requirements unless the operator adds
		// --include-managed-config. The home and project config are empty.
		out, err := run(
			"sandbox", "--permission-profile", "hsg-network-canary",
			"--config", `permissions.hsg-network-canary.extends=":workspace"`,
			"--config", "permissions.hsg-network-canary.network.enabled="+strconv.FormatBool(enabled),
			"--config", "features.network_proxy=false",
			"--cd", workspace, "--", probe,
			"-test.run=^TestCodexNetworkProbeProcess$", "--", "hsg-network-probe",
		)
		if err != nil {
			t.Fatalf("%s could not exercise the primitive (not an isolation verdict): %v", label, err)
		}
		var results []networkProbeResult
		if err := json.Unmarshal(out, &results); err != nil {
			t.Fatalf("%s probe did not return complete JSON: %v", label, err)
		}
		if len(results) != len(networkSocketCases) {
			t.Fatalf("%s returned %d cases, want %d", label, len(results), len(networkSocketCases))
		}
		for i, result := range results {
			if result.Name != networkSocketCases[i].name {
				t.Fatalf("%s unexpected probe case %q", label, result.Name)
			}
			t.Logf("%s %s: socket errno=%d", label, result.Name, result.Errno)
			if enabled && result.Errno != 0 {
				t.Fatalf("positive control could not open %s socket; environment cannot establish this witness", result.Name)
			}
			if !enabled && result.Errno != int(unix.EPERM) && result.Errno != int(unix.EACCES) {
				t.Fatalf("%s did not demonstrate socket-creation denial; errno=%d (this alone does not establish reachable egress)", result.Name, result.Errno)
			}
		}
	}
}

var networkSocketCases = []struct {
	name   string
	family int
	kind   int
}{
	{"ipv4-tcp", unix.AF_INET, unix.SOCK_STREAM},
	{"ipv4-udp", unix.AF_INET, unix.SOCK_DGRAM},
	{"ipv6-tcp", unix.AF_INET6, unix.SOCK_STREAM},
	{"ipv6-udp", unix.AF_INET6, unix.SOCK_DGRAM},
}

type networkProbeResult struct {
	Name  string `json:"name"`
	Errno int    `json:"errno"`
}

// This deterministic child opens and immediately closes four unconnected
// sockets. It never reads configuration/credentials or uses network endpoints.
func TestCodexNetworkProbeProcess(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-2] != "--" || os.Args[len(os.Args)-1] != "hsg-network-probe" {
		return
	}
	results := make([]networkProbeResult, 0, len(networkSocketCases))
	for _, tc := range networkSocketCases {
		fd, err := unix.Socket(tc.family, tc.kind|unix.SOCK_CLOEXEC, 0)
		result := networkProbeResult{Name: tc.name}
		if err != nil {
			errno, ok := err.(unix.Errno)
			if !ok {
				os.Exit(2)
			}
			result.Errno = int(errno)
		} else if err := unix.Close(fd); err != nil {
			os.Exit(3)
		}
		results = append(results, result)
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		os.Exit(4)
	}
	os.Exit(0)
}
