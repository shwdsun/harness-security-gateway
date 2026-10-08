//go:build linux && codexintegration

package codexadapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Every operand describes fresh synthetic data in an owned experiment. A
// fixed native command runs this helper; no model-selected target is accepted.
type providerProbePlan struct {
	Nonce, StartTime, PIDNamespace string
	OwnerPID, SeedFD               int
	Address                        uintptr
	ProtectedFDs                   []string
	TCP, Pathname, Abstract        string
}

type providerProbeOutcome struct {
	Access bool
	Errno  int
}

type providerProbeReport struct {
	Nonce            string
	OwnerMatched     bool
	AncestorProcView bool
	ProtectedCount   int
	Inherited        int
	Results          map[string]providerProbeOutcome
	PIDView          providerPIDView
}

type providerPIDView struct {
	SelfPID                                                                int
	SelfLink, SelfNamespace, OwnerNamespace                                string
	SelfLinkErrno, SelfNamespaceErrno, OwnerNamespaceErrno, OwnerStatErrno int
	OwnerStartMatches                                                      bool
	SelfIDs, OwnerIDs                                                      []int
}

func providerNamespaceIDs(path string) []int {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 16<<10 {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "NStgid:") {
			continue
		}
		var ids []int
		for _, field := range strings.Fields(strings.TrimPrefix(line, "NStgid:")) {
			id, err := strconv.Atoi(field)
			if err != nil || id < 1 || len(ids) >= 33 {
				return nil
			}
			ids = append(ids, id)
		}
		return ids
	}
	return nil
}

type providerProbeSeed struct {
	plan   providerProbePlan
	marker []byte
	file   *os.File
}

func newProviderProbeSeed(t *testing.T) *providerProbeSeed {
	t.Helper()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	seed := &providerProbeSeed{marker: []byte(hex.EncodeToString(nonce[:]))}
	fd, err := unix.MemfdCreate("hsg-synthetic-probe", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	seed.file = os.NewFile(uintptr(fd), "synthetic-probe")
	if _, err := seed.file.Write(seed.marker); err != nil {
		t.Fatal(err)
	}
	seed.plan = providerProbePlan{Nonce: string(seed.marker), OwnerPID: os.Getpid(), SeedFD: fd,
		Address: uintptr(unsafe.Pointer(&seed.marker[0])), StartTime: providerProcessStart(os.Getpid()),
		PIDNamespace: providerPIDNamespace(os.Getpid())}
	identity, err := providerFDIdentity(fd)
	if err != nil || seed.plan.StartTime == "" || seed.plan.PIDNamespace == "" {
		t.Fatal("synthetic seed identity unavailable")
	}
	seed.plan.ProtectedFDs = []string{identity}
	t.Cleanup(func() { _ = seed.file.Close(); runtime.KeepAlive(seed.marker) })
	return seed
}

func providerProcessStart(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return ""
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 {
		return ""
	}
	return fields[19] // field 22, after comm's closing parenthesis.
}

func providerPIDNamespace(pid int) string {
	value, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	return value
}

func providerFDIdentity(fd int) (string, error) {
	var stat unix.Stat_t
	err := unix.Fstat(fd, &stat)
	return fmt.Sprintf("%d:%d:%d", stat.Dev, stat.Ino, stat.Mode&unix.S_IFMT), err
}

func providerErrno(err error) int {
	if err == nil {
		return 0
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		return int(errno)
	}
	return -1 // Retain an unknown failure; never call it a kernel denial.
}

func providerReadFD(fd int, nonce string) providerProbeOutcome {
	buffer := make([]byte, len(nonce))
	n, err := unix.Pread(fd, buffer, 0)
	return providerProbeOutcome{Access: n == len(nonce) && string(buffer) == nonce, Errno: providerErrno(err)}
}

func runProviderProbe(plan providerProbePlan) providerProbeReport {
	report := providerProbeReport{Nonce: plan.Nonce, ProtectedCount: len(plan.ProtectedFDs), Results: make(map[string]providerProbeOutcome)}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		report.Inherited = -1
	} else {
		for _, entry := range entries {
			fd, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			identity, err := providerFDIdentity(fd)
			for _, protected := range plan.ProtectedFDs {
				if err == nil && identity == protected {
					report.Inherited++
				}
			}
		}
	}
	for _, socket := range []struct{ name, network, address string }{
		{"tcp", "tcp", plan.TCP}, {"pathname", "unix", plan.Pathname}, {"abstract", "unix", plan.Abstract},
	} {
		if socket.address == "" {
			continue
		}
		conn, err := net.DialTimeout(socket.network, socket.address, time.Second)
		result := providerProbeOutcome{Access: err == nil, Errno: providerErrno(err)}
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if socket.network == "unix" {
				buffer := make([]byte, len(plan.Nonce))
				_, err = io.ReadFull(conn, buffer)
				result = providerProbeOutcome{Access: err == nil && string(buffer) == plan.Nonce, Errno: providerErrno(err)}
			}
			_ = conn.Close()
		}
		report.Results[socket.name] = result
	}
	// The owner must still be the exact live process, including its PID
	// namespace. A remapped/hidden PID is not a license to inspect another PID 1.
	start := providerProcessStart(plan.OwnerPID)
	namespace, namespaceErr := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", plan.OwnerPID))
	selfLink, selfErr := os.Readlink("/proc/self")
	ownNamespace, ownErr := os.Readlink("/proc/self/ns/pid")
	_, statErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", plan.OwnerPID))
	report.PIDView = providerPIDView{SelfPID: os.Getpid(), SelfLink: selfLink, SelfNamespace: ownNamespace, OwnerNamespace: namespace,
		SelfLinkErrno: providerErrno(selfErr), SelfNamespaceErrno: providerErrno(ownErr), OwnerNamespaceErrno: providerErrno(namespaceErr), OwnerStatErrno: providerErrno(statErr), OwnerStartMatches: start == plan.StartTime && start != ""}
	selfView := selfErr == nil && selfLink == strconv.Itoa(os.Getpid())
	report.OwnerMatched = start == plan.StartTime && plan.StartTime != "" && selfView && ownNamespace == plan.PIDNamespace
	report.PIDView.SelfIDs = providerNamespaceIDs("/proc/self/status")
	report.PIDView.OwnerIDs = providerNamespaceIDs(fmt.Sprintf("/proc/%d/status", plan.OwnerPID))
	selfIDs, ownerIDs := report.PIDView.SelfIDs, report.PIDView.OwnerIDs
	// A child PID namespace may retain an ancestor's procfs mount. NStgid
	// lists the mount's PID, then IDs in successively nested namespaces.
	// Bind both views before reading the owner's exact procfs files. PID
	// syscalls must NOT reuse that procfs PID in the child's numeric view.
	report.AncestorProcView = plan.OwnerPID == 1 && report.PIDView.OwnerStartMatches &&
		len(ownerIDs) == 1 && ownerIDs[0] == 1 && len(selfIDs) == 2 && selfIDs[0] > 1 &&
		selfIDs[1] == os.Getpid() && selfErr == nil && selfLink == strconv.Itoa(selfIDs[0]) &&
		ownErr == nil && ownNamespace != "" && ownNamespace != plan.PIDNamespace
	if !report.OwnerMatched && !report.AncestorProcView {
		return report
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/fd/%d", plan.OwnerPID, plan.SeedFD), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	report.Results["proc_fd"] = providerProbeOutcome{Errno: providerErrno(err)}
	if err == nil {
		report.Results["proc_fd"] = providerReadFD(fd, plan.Nonce)
		_ = unix.Close(fd)
	}
	fd, err = unix.Open(fmt.Sprintf("/proc/%d/mem", plan.OwnerPID), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	report.Results["proc_mem"] = providerProbeOutcome{Errno: providerErrno(err)}
	if err == nil {
		buffer := make([]byte, len(plan.Nonce))
		n, err := unix.Pread(fd, buffer, int64(plan.Address))
		report.Results["proc_mem"] = providerProbeOutcome{Access: n == len(buffer) && string(buffer) == plan.Nonce, Errno: providerErrno(err)}
		_ = unix.Close(fd)
	}
	if !report.OwnerMatched {
		return report // Owner has no numeric PID in the tool's child namespace.
	}
	buffer := make([]byte, len(plan.Nonce))
	local := []unix.Iovec{{Base: &buffer[0]}}
	local[0].SetLen(len(buffer))
	n, err := unix.ProcessVMReadv(plan.OwnerPID, local, []unix.RemoteIovec{{Base: plan.Address, Len: len(buffer)}}, 0)
	report.Results["process_vm"] = providerProbeOutcome{Access: n == len(buffer) && string(buffer) == plan.Nonce, Errno: providerErrno(err)}
	pidfd, err := unix.PidfdOpen(plan.OwnerPID, 0)
	report.Results["pidfd_open"] = providerProbeOutcome{Access: err == nil, Errno: providerErrno(err)}
	if err == nil {
		fd, err := unix.PidfdGetfd(pidfd, plan.SeedFD, 0)
		report.Results["pidfd_getfd"] = providerProbeOutcome{Errno: providerErrno(err)}
		if err == nil {
			report.Results["pidfd_getfd"] = providerReadFD(fd, plan.Nonce)
			_ = unix.Close(fd)
		}
		_ = unix.Close(pidfd)
	}
	// SEIZE does not stop the tracee. No options, register writes or arbitrary
	// memory reads. The command helper exits immediately after its report,
	// releasing any unexpected attachment. A successful attach is a failure of
	// the native boundary, not a permission to do additional work in the owner.
	err = unix.PtraceSeize(plan.OwnerPID)
	report.Results["ptrace_seize"] = providerProbeOutcome{Access: err == nil, Errno: providerErrno(err)}
	return report
}

func TestProviderProbeProcess(t *testing.T) {
	if len(os.Args) < 4 || os.Args[len(os.Args)-3] != "--" || os.Args[len(os.Args)-2] != "hsg-provider-probe" {
		return
	}
	workspace := os.Args[len(os.Args)-1]
	if !filepath.IsAbs(workspace) || !strings.HasPrefix(filepath.Clean(workspace), "/tmp/") {
		t.Fatal("owned probe workspace required")
	}
	data, err := os.ReadFile(filepath.Join(workspace, "provider-probe-plan.json"))
	var plan providerProbePlan
	if err != nil || len(data) > 32<<10 || json.Unmarshal(data, &plan) != nil || len(plan.Nonce) != 32 || plan.OwnerPID != 1 {
		t.Fatal("invalid synthetic probe plan")
	}
	if _, err := hex.DecodeString(plan.Nonce); err != nil {
		t.Fatal("invalid synthetic nonce")
	}
	report := runProviderProbe(plan)
	encoded, _ := json.Marshal(report)
	if err := os.WriteFile(filepath.Join(workspace, "provider-probe-report.json"), encoded, 0o600); err != nil {
		t.Fatal("cannot retain synthetic probe")
	}
	fmt.Println(string(encoded))
}

func TestProviderProbeSeedProcess(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--" || os.Args[len(os.Args)-1] != "hsg-provider-seed" {
		return
	}
	seed := newProviderProbeSeed(t)
	_ = json.NewEncoder(os.Stdout).Encode(seed.plan)
	var done [1]byte
	_, _ = os.Stdin.Read(done[:])
	runtime.KeepAlive(seed)
}

// Same probe against our own fresh child, under unchanged ordinary-user
// policy. Mechanisms denied here are unavailable controls, not negative proof.
func TestProviderProbeControls(t *testing.T) {
	if os.Getenv("HSG_PROVIDER_PROBE_CONTROLS") != "1" {
		t.Skip("opt-in owned-child descriptor/memory positive controls")
	}
	runtime.LockOSThread() // ptrace relationship belongs to the tracing thread.
	defer runtime.UnlockOSThread()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, self, "-test.run=^TestProviderProbeSeedProcess$", "--", "hsg-provider-seed")
	child.Env = []string{"HOME=/nonexistent", "PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	input, _ := child.StdinPipe()
	output, _ := child.StdoutPipe()
	var diagnostics bytes.Buffer
	child.Stderr = &diagnostics
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close(); _ = child.Process.Kill(); _ = child.Wait() }()
	var plan providerProbePlan
	if json.NewDecoder(io.LimitReader(output, 8<<10)).Decode(&plan) != nil || plan.OwnerPID != child.Process.Pid {
		t.Fatal("owned child seed unavailable")
	}
	report := runProviderProbe(plan)
	encoded, _ := json.Marshal(report)
	t.Logf("HSG_PROVIDER_PROBE_CONTROL %s", encoded)
	if !report.OwnerMatched || report.Inherited != 0 {
		t.Fatal("owned-child positive control identity failed")
	}
	for _, name := range []string{"proc_fd", "proc_mem", "process_vm", "pidfd_open", "ptrace_seize"} {
		if !report.Results[name].Access {
			t.Errorf("positive control unavailable: %s errno=%d", name, report.Results[name].Errno)
		}
	}
	// pidfd_getfd is intentionally reported separately: an outer seccomp
	// policy can deny the syscall even for this correctly owned child.
}
