//go:build linux

package codexprovider

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const ownerServiceCgroup = "/system.slice/hgw-sandboxd.service"

// ownerStartup is an unwired candidate capability, not a config assertion. The
// isolated-profile entrypoint must acquire it AFTER the global process lock and
// BEFORE opening the durable stores or constructing/recovering the controller.
// The old exposed entrypoint does not select it. Unit root ownership prevents
// migration/delegation by this unprivileged service. The closed launcher contract
// prevents old native helpers from spawning/migrating descendants during this
// observation; this is not a snapshot proof against arbitrary fork churn.
type ownerStartup struct{ pid int }

type serviceObservation struct {
	uid, euid  int
	pid        int
	cgroup     string
	uidMap     string
	status     string
	mountRoot  bool
	boundaries bool
	leaf       bool
	domain     string
	members    string
}

func checkOwnerStartup() (*ownerStartup, error) {
	o := serviceObservation{uid: os.Getuid(), euid: os.Geteuid(), pid: os.Getpid()}
	var err error
	if o.cgroup, err = readOwnerProc("/proc/self/cgroup"); err != nil {
		return nil, ErrOwnerAuth
	}
	if o.uidMap, err = readOwnerProc("/proc/self/uid_map"); err != nil {
		return nil, ErrOwnerAuth
	}
	if o.status, err = readOwnerProc("/proc/self/status"); err != nil {
		return nil, ErrOwnerAuth
	}
	mounts, err := readOwnerProc("/proc/self/mountinfo")
	if err != nil {
		return nil, ErrOwnerAuth
	}
	for _, line := range strings.Split(mounts, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[3] != "/" || f[4] != "/sys/fs/cgroup" {
			continue
		}
		for i, field := range f {
			if field == "-" && i+1 < len(f) && f[i+1] == "cgroup2" {
				o.mountRoot = true
			}
		}
	}
	var fs unix.Statfs_t
	if unix.Statfs("/sys/fs/cgroup", &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, ErrOwnerAuth
	}
	o.boundaries = true
	for _, path := range []string{"/sys", "/sys/fs", "/sys/fs/cgroup", "/sys/fs/cgroup/system.slice", "/sys/fs/cgroup" + ownerServiceCgroup} {
		if !rootControlled(path, true) {
			o.boundaries = false
		}
		if strings.HasPrefix(path, "/sys/fs/cgroup") {
			for _, control := range []string{"cgroup.procs", "cgroup.threads", "cgroup.subtree_control"} {
				if !rootControlled(filepath.Join(path, control), false) {
					o.boundaries = false
				}
			}
		}
	}
	unit := "/sys/fs/cgroup" + ownerServiceCgroup
	if o.domain, err = readOwnerProc(filepath.Join(unit, "cgroup.type")); err != nil {
		return nil, ErrOwnerAuth
	}
	entries, err := os.ReadDir(unit)
	if err != nil {
		return nil, ErrOwnerAuth
	}
	o.leaf = true
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			o.leaf = false
		}
	}
	if o.members, err = readOwnerProc(filepath.Join(unit, "cgroup.procs")); err != nil {
		return nil, ErrOwnerAuth
	}
	return verifyOwnerStartup(o)
}

func rootControlled(path string, directory bool) bool {
	var stat unix.Stat_t
	want := uint32(unix.S_IFREG)
	if directory {
		want = unix.S_IFDIR
	}
	return unix.Lstat(path, &stat) == nil && stat.Uid == 0 && stat.Gid == 0 &&
		stat.Mode&0022 == 0 && stat.Mode&unix.S_IFMT == want
}

func readOwnerProc(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", ErrOwnerAuth
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err != nil || len(data) > 64<<10 || bytes.IndexByte(data, 0) >= 0 {
		return "", ErrOwnerAuth
	}
	return string(data), nil
}

// Pure evidence predicate used by deterministic negative tests. No public
// constructor accepts these booleans or a replacement cgroup/proc path.
func verifyOwnerStartup(o serviceObservation) (*ownerStartup, error) {
	if o.pid <= 1 || o.uid <= 0 || o.uid != o.euid || !o.mountRoot || !o.boundaries || !o.leaf || o.domain != "domain\n" ||
		o.cgroup != "0::"+ownerServiceCgroup+"\n" ||
		strings.Join(strings.Fields(o.uidMap), " ") != "0 0 4294967295" ||
		strings.Join(strings.Fields(o.members), " ") != strconv.Itoa(o.pid) {
		return nil, ErrOwnerAuth
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(o.status, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, ErrOwnerAuth
		}
		fields[key] = strings.TrimSpace(value)
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if fields[key] != "0000000000000000" {
			return nil, ErrOwnerAuth
		}
	}
	if fields["NoNewPrivs"] != "1" {
		return nil, ErrOwnerAuth
	}
	uid := strconv.Itoa(o.uid)
	if strings.Join(strings.Fields(fields["Uid"]), " ") != strings.Join([]string{uid, uid, uid, uid}, " ") {
		return nil, ErrOwnerAuth
	}
	return &ownerStartup{pid: o.pid}, nil
}
