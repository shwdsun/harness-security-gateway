//go:build linux && amd64

package codexprovider

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func compileAuthC(t *testing.T, source, name string, flags ...string) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal("C compiler needed to verify the account helper restriction")
	}
	output := filepath.Join(t.TempDir(), name)
	args := append([]string{"-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"}, flags...)
	args = append(args, source, "-o", output)
	cmd := exec.Command(cc, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C.UTF-8"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixed launcher build: %v %s", err, out)
	}
	if err := os.Chmod(output, 0500); err != nil {
		t.Fatal(err)
	}
	return output
}

func TestNativeUnknownWaitRetainsLiveProcessObligation(t *testing.T) {
	pidfd := -1
	cmd := exec.Command("/bin/sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
	}()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	done := make(chan struct{})
	close(done)
	p := &nativeAccountProcess{cmd: cmd, stdin: w, pidfd: pidfd, waitEnd: done, outEnd: done, errEnd: done, waitErr: syscall.EIO}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if p.stop(ctx) != ErrCleanup || p.released || p.pidfd < 0 {
		t.Fatal("Wait failure falsely discharged a live process obligation")
	}
}

func TestNativeNotificationMetadataIsClosedAndCarriesNoAuthority(t *testing.T) {
	for _, data := range []string{
		`{"method":"notice","params":{},"emittedAtMs":0}`,
		`{"method":"notice","params":{},"emittedAtMs":1790000000000}`,
		`{"method":"notice","params":{}}`,
		`{"id":1,"result":{}}`,
	} {
		var m nativeAccountEnvelope
		if !decodeNativeAccountEnvelope([]byte(data), &m) {
			t.Fatal("supported native envelope rejected")
		}
	}
	for _, data := range []string{
		`{"method":"notice","emittedAtMs":null}`,
		`{"method":"notice","emittedAtMs":-1}`,
		`{"method":"notice","emittedAtMs":1.0}`,
		`{"method":"notice","emittedAtMs":"1"}`,
		`{"method":"notice","emittedAtMs":9223372036854775808}`,
		`{"method":"notice","EmittedAtMs":1}`,
		`{"method":"notice","emittedAtMs":1,"emittedAtMs":2}`,
		`{"method":"notice","unknown":1}`,
		`{"id":1,"result":{},"emittedAtMs":1}`,
		`{"id":1,"method":"account/read","params":{},"emittedAtMs":1}`,
		`{"id":1,"ID":2,"result":{}}`,
		`{"method":"notice","result":{}}`,
	} {
		var m nativeAccountEnvelope
		if decodeNativeAccountEnvelope([]byte(data), &m) {
			t.Fatal("invalid or authoritative notification accepted")
		}
	}
}

func TestNativeProcessFilterKernelBoundary(t *testing.T) {
	probe := compileAuthC(t, "testdata/process-filter.c", "probe", "-pthread")
	cmd := exec.Command(probe)
	cmd.Env = []string{"PATH=/nonexistent", "HOME=/nonexistent"}
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "threads allowed; new TGIDs denied") {
		t.Fatalf("actual kernel restriction failed: %v %q", err, out)
	}
}

func TestNativeLauncherRejectsArgumentsAndMissingArtifact(t *testing.T) {
	launcher := compileAuthC(t, "native_launcher/main.c", "launcher")
	for _, args := range [][]string{nil, {"/bin/true"}} {
		cmd := exec.Command(launcher, args...)
		cmd.Env = []string{"PATH=/nonexistent", "HOME=/nonexistent"}
		if err := cmd.Run(); err == nil || cmd.ProcessState.ExitCode() != 125 {
			t.Fatal("launcher accepted unverified command or missing artifact")
		}
	}
	// The FD contract is exercised with a non-secret synthetic ELF. The real
	// fixed Codex/filter compatibility witness is a separate opt-in gate.
	probe := compileAuthC(t, "testdata/process-filter.c", "probe", "-pthread", "-DHGW_FILTER_ALREADY_INSTALLED")
	f, err := os.Open(probe)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command(launcher)
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = []string{"PATH=/nonexistent", "HOME=/nonexistent"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixed FD exec under inherited filter failed: %v %q", err, out)
	}
}
