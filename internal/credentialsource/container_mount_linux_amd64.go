//go:build linux && amd64

package credentialsource

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const MountedCredentialPath = "/tmp/hgw-codex-home/auth.json"

// MountError exposes a closed verification stage and, when available, errno.
// It never includes a path, process output, raw identity or credential data.
type MountError struct {
	Stage string
	Errno unix.Errno
}

func (e *MountError) Error() string {
	return "credentialsource: container mount rejected at " + e.Stage
}
func (e *MountError) Unwrap() error { return ErrUnavailable }
func mountFailure(stage string, err error) error {
	var errno unix.Errno
	_ = errors.As(err, &errno)
	return &MountError{stage, errno}
}

// ContainerMount retains a pidfd and a proc directory for an independently
// inspected rootless Docker init. It exposes neither an FD nor credential
// bytes. The trusted runtime owns attribution to one Run, the daemon's PID
// namespace, the private attach channel and cleanup before source Close.
// Validation is an observation under an inert immutable bootstrap, not a
// durable or transferable launch permit. The execution owner must serialize
// validation, permit delivery, cancellation and source lifetime.
type ContainerMount struct {
	mu                                 sync.Mutex
	held                               *HeldSource
	pid                                int
	ref, bootstrapDigest, sourceDigest string
	proof                              Proof
	innerUID                           uint32
	pidfd, proc                        *os.File
	invalid, closed                    bool
}

// OpenContainerMount accepts facts from a trusted, freshly attested local
// runtime, never a Runner report or wire input. Only native ext4 and a unified
// rootless Docker cgroup containing the complete container ID are supported.
// This does not register an executable target or release durable occupancy.
func (h *HeldSource) OpenContainerMount(pid int, ref, bootstrapDigest, sourceDigest string, proof Proof) (*ContainerMount, error) {
	if h == nil || pid <= 1 || !digestText(ref) || !digestText(bootstrapDigest) || !digestText(sourceDigest) || proof.Validate() != nil {
		return nil, mountFailure("expectation", nil)
	}
	g := &ContainerMount{held: h, pid: pid, ref: ref, bootstrapDigest: bootstrapDigest, sourceDigest: sourceDigest, proof: proof}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, mountFailure("pidfd", err)
	}
	g.pidfd = os.NewFile(uintptr(fd), "container-process")
	fd, err = unix.Open("/proc/"+strconv.Itoa(pid), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		_ = g.Close()
		return nil, mountFailure("proc", err)
	}
	g.proc = os.NewFile(uintptr(fd), "container-proc")
	var fs unix.Statfs_t
	var st unix.Stat_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC || unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) {
		_ = g.Close()
		return nil, mountFailure("proc_identity", nil)
	}
	if err := g.Validate(); err != nil {
		_ = g.Close()
		return nil, err
	}
	return g, nil
}

// Validate reopens only the fixed destination through the held process view.
// A failed check latches this receiver invalid. The held source retains its
// own locks; the caller still owes exact cleanup on every failure path.
func (g *ContainerMount) Validate() error {
	if g == nil {
		return mountFailure("closed", nil)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.invalid {
		return mountFailure("closed", nil)
	}
	err := g.validate()
	if err != nil {
		g.invalid = true
	}
	return err
}

func (g *ContainerMount) validate() error {
	if err := g.held.VerifyProof(g.sourceDigest, g.proof); err != nil {
		return mountFailure("source", err)
	}
	if err := g.process(); err != nil {
		return err
	}
	if err := g.validateMappedIdentity(); err != nil {
		return err
	}
	root, err := g.openProc("root", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return mountFailure("process_root", err)
	}
	defer root.Close()
	namespace, err := g.openProc("ns/mnt", unix.O_RDONLY)
	if err != nil {
		return mountFailure("mount_namespace", err)
	}
	defer namespace.Close()
	parent, err := openAt(int(root.Fd()), "tmp/hgw-codex-home", unix.O_PATH|unix.O_DIRECTORY, unix.RESOLVE_BENEATH|unix.RESOLVE_NO_SYMLINKS)
	if err != nil {
		return mountFailure("parent", err)
	}
	defer parent.Close()
	parentID, err := privateObject(parent, uint32(os.Geteuid()), false)
	var fs unix.Statfs_t
	if err != nil || unix.Fstatfs(int(parent.Fd()), &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return mountFailure("parent_identity", err)
	}
	pinned, err := openAt(int(root.Fd()), strings.TrimPrefix(MountedCredentialPath, "/"), unix.O_PATH, unix.RESOLVE_BENEATH|unix.RESOLVE_NO_SYMLINKS)
	if err != nil {
		return mountFailure("destination", err)
	}
	defer pinned.Close()
	id, err := privateObject(pinned, uint32(os.Geteuid()), true)
	if err != nil || id.mount == parentID.mount {
		return mountFailure("destination_identity", err)
	}
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(int(pinned.Fd())), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return mountFailure("destination_handle", err)
	}
	file := os.NewFile(uintptr(fd), "mounted-credential")
	defer file.Close()
	again, err := privateObject(file, uint32(os.Geteuid()), true)
	if err != nil || again != id || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC {
		return mountFailure("destination_identity", err)
	}
	mounts, err := g.readProc("mountinfo", maxMountInfoBytes)
	if err != nil || !credentialFileMount(mounts, id) {
		return mountFailure("mount_view", err)
	}
	uuid, err := filesystemUUID(file)
	if err != nil {
		return mountFailure("filesystem_uuid", err)
	}
	handle, err := descriptorHandle(file, id.mount)
	if err != nil {
		return mountFailure("file_handle", err)
	}
	digest, err := objectDigest(uuid, handle)
	if err != nil || digest != g.sourceDigest {
		return mountFailure("object_mismatch", err)
	}
	last, err := filesystemUUID(file)
	if err != nil || !bytes.Equal(last, uuid) {
		return mountFailure("filesystem_uuid", err)
	}
	newMounts, err := g.readProc("mountinfo", maxMountInfoBytes)
	if err != nil || !bytes.Equal(mounts, newMounts) {
		return mountFailure("mount_view_changed", err)
	}
	for _, item := range []struct {
		name  string
		held  *os.File
		flags int
	}{{"root", root, unix.O_PATH | unix.O_DIRECTORY}, {"ns/mnt", namespace, unix.O_RDONLY}} {
		fresh, err := g.openProc(item.name, item.flags)
		if err != nil {
			return mountFailure("process_view_changed", err)
		}
		var a, b unix.Stat_t
		same := unix.Fstat(int(item.held.Fd()), &a) == nil && unix.Fstat(int(fresh.Fd()), &b) == nil && a.Dev == b.Dev && a.Ino == b.Ino
		_ = fresh.Close()
		if !same {
			return mountFailure("process_view_changed", nil)
		}
	}
	if err := g.process(); err != nil {
		return err
	}
	if err := g.held.VerifyProof(g.sourceDigest, g.proof); err != nil {
		return mountFailure("source", err)
	}
	return nil
}

func (g *ContainerMount) process() error {
	poll := []unix.PollFd{{Fd: int32(g.pidfd.Fd()), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	if err != nil || n != 0 || poll[0].Revents != 0 {
		return mountFailure("process_exited", err)
	}
	status, err := g.readProc("status", 64<<10)
	if err != nil || !containerInitStatus(status, g.pid, uint32(os.Geteuid())) {
		return mountFailure("process_status", err)
	}
	cgroup, err := g.readProc("cgroup", 64<<10)
	if err != nil || !containerCgroup(cgroup, g.ref) {
		return mountFailure("process_cgroup", err)
	}
	exe, err := g.openProc("exe", unix.O_RDONLY)
	if err != nil {
		return mountFailure("bootstrap_executable", err)
	}
	defer exe.Close()
	hash := sha256.New()
	nbytes, err := io.Copy(hash, io.LimitReader(exe, (32<<20)+1))
	if err != nil || nbytes == 0 || nbytes > 32<<20 || hex.EncodeToString(hash.Sum(nil)) != g.bootstrapDigest {
		return mountFailure("bootstrap_executable", err)
	}
	n, err = unix.Poll(poll, 0)
	if err != nil || n != 0 || poll[0].Revents != 0 {
		return mountFailure("process_exited", err)
	}
	return nil
}

func (g *ContainerMount) openProc(name string, flags int) (*os.File, error) {
	fd, err := unix.Openat(int(g.proc.Fd()), name, flags|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "container-observation"), nil
}
func (g *ContainerMount) readProc(name string, limit int64) ([]byte, error) {
	file, err := g.openProc(name, unix.O_RDONLY|unix.O_NOFOLLOW)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit || data[len(data)-1] != '\n' {
		return nil, ErrUnavailable
	}
	return data, nil
}

func containerCgroup(data []byte, ref string) bool {
	if !digestText(ref) || !bytes.HasSuffix(data, []byte("\n")) {
		return false
	}
	line := string(data[:len(data)-1])
	if strings.ContainsAny(line, "\n\r\x00") || !strings.HasPrefix(line, "0::/") {
		return false
	}
	return strings.HasSuffix(line, "/docker-"+ref+".scope") || strings.HasSuffix(line, "/docker/"+ref)
}

func containerInitStatus(data []byte, pid int, uid uint32) bool {
	want := map[string]bool{"Uid:": false, "NSpid:": false, "CapEff:": false, "NoNewPrivs:": false, "TracerPid:": false}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		seen, needed := want[f[0]]
		if !needed {
			continue
		}
		if seen {
			return false
		}
		want[f[0]] = true
		switch f[0] {
		case "Uid:":
			if len(f) != 5 {
				return false
			}
			for _, v := range f[1:] {
				if v != strconv.FormatUint(uint64(uid), 10) {
					return false
				}
			}
		case "NSpid:":
			if len(f) < 3 || f[1] != strconv.Itoa(pid) || f[len(f)-1] != "1" {
				return false
			}
			for _, v := range f[1:] {
				n, e := strconv.Atoi(v)
				if e != nil || n < 1 || strconv.Itoa(n) != v {
					return false
				}
			}
		case "CapEff:":
			if len(f) != 2 || f[1] != "0000000000000000" {
				return false
			}
		case "NoNewPrivs:":
			if len(f) != 2 || f[1] != "1" {
				return false
			}
		case "TracerPid:":
			if len(f) != 2 || f[1] != "0" {
				return false
			}
		}
	}
	for _, v := range want {
		if !v {
			return false
		}
	}
	return true
}

func credentialFileMount(data []byte, id objectID) bool {
	if !mountIsExt4(bytes.NewReader(data), id) {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[0] != strconv.FormatUint(id.mount, 10) {
			continue
		}
		sep := 0
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(f) != sep+4 || f[4] != MountedCredentialPath || f[3] == "/" {
			return false
		}
		return hasMountOption(f[5], "rw") && !hasMountOption(f[5], "ro") && hasMountOption(f[sep+3], "rw") && !hasMountOption(f[sep+3], "ro")
	}
	return false
}
func hasMountOption(list, option string) bool {
	for _, v := range strings.Split(list, ",") {
		if v == option {
			return true
		}
	}
	return false
}

// Close releases only receiver observations. It neither stops the container
// nor closes the held source, and can never release durable Run ownership.
func (g *ContainerMount) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	var result error
	for _, f := range []*os.File{g.proc, g.pidfd} {
		if f != nil && f.Close() != nil {
			result = ErrUnavailable
		}
	}
	return result
}
