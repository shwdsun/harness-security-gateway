// This executable has no provider credentials. A frozen offline fixture runs
// the same bytes once as an unprivileged control and once through native tools.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type report struct {
	Nonce, Mode                                                           string
	UID, PID                                                              int
	NoNewPrivs, Seccomp, CapEff                                           string
	Namespaces                                                            map[string]string
	NamespaceErrnos                                                       map[string]int
	SocketErrnos                                                          map[string]int
	OwnerSourceErrno                                                      int
	OwnerSourceReadable                                                   bool
	ProviderPathErrno                                                     int
	ProviderConnectPath                                                   string
	ProviderConnectAttempted, ProviderConnected, ProviderConnectionClosed bool
	ProviderConnectErrno, ProviderPeerUID, ProviderPeerPID                int
	ProviderSocketDevice, ProviderSocketInode                             uint64
	Environment, Arguments, FDLinks                                       []string
}

func errno(err error) int {
	if err == nil {
		return 0
	}
	var value unix.Errno
	if errors.As(err, &value) {
		return int(value)
	}
	return -1
}

func run() error {
	if len(os.Args) != 5 && len(os.Args) != 6 {
		return errors.New("fixed probe operands required")
	}
	mode, name, nonce, root := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	decoded, err := hex.DecodeString(nonce)
	if err != nil || len(decoded) != 16 || !fixedCase(name) || (mode != "tool" && mode != "control" && mode != "provider-control") {
		return errors.New("invalid probe identity")
	}
	expected := "/workspace"
	if mode != "tool" {
		expected = "/srv/hgw-v4-acceptance/composed/" + name + "/workspaces/project-main"
	}
	if root != expected || filepath.Clean(root) != root {
		return errors.New("fixed probe workspace required")
	}
	address := "/run/hsg-provider.sock"
	if mode == "provider-control" {
		pattern := "^/srv/hgw-v4-acceptance/composed/" + name + "/provider/hg-run-[0-9a-f]{32}/owner\\.sock$"
		if len(os.Args) != 6 || len(os.Args[5]) > 107 || !regexp.MustCompile(pattern).MatchString(os.Args[5]) {
			return errors.New("fixed actual provider control required")
		}
		address = os.Args[5]
	} else if len(os.Args) != 5 {
		return errors.New("unexpected provider operand")
	}
	r := report{Nonce: nonce, Mode: mode, UID: os.Getuid(), PID: os.Getpid(), Namespaces: map[string]string{}, NamespaceErrnos: map[string]int{}, SocketErrnos: map[string]int{}}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || len(status) > 65536 {
		return errors.New("bounded process status unavailable")
	}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "NoNewPrivs":
			r.NoNewPrivs = strings.TrimSpace(value)
		case "Seccomp":
			r.Seccomp = strings.TrimSpace(value)
		case "CapEff":
			r.CapEff = strings.TrimSpace(value)
		}
	}
	r.ProviderConnectPath = address
	r.ProviderPeerUID, r.ProviderPeerPID = -1, -1
	var object unix.Stat_t
	if unix.Lstat(address, &object) == nil && object.Mode&unix.S_IFMT == unix.S_IFSOCK {
		r.ProviderSocketDevice, r.ProviderSocketInode = uint64(object.Dev), object.Ino
	}
	// Creation of an AF_UNIX socket does not establish access to a protected
	// channel. Attempt one bounded connection; send/read no protocol or auth.
	fd, socketErr := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if socketErr != nil {
		r.ProviderConnectErrno = errno(socketErr)
	} else {
		r.ProviderConnectAttempted = true
		connectErr := unix.Connect(fd, &unix.SockaddrUnix{Name: address})
		if errors.Is(connectErr, unix.EINPROGRESS) {
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
			count, pollErr := unix.Poll(poll, 250)
			switch {
			case pollErr != nil:
				connectErr = pollErr
			case count != 1 || poll[0].Revents&(unix.POLLOUT|unix.POLLERR|unix.POLLHUP) == 0:
				connectErr = unix.ETIMEDOUT
			default:
				code, statusErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
				connectErr = statusErr
				if statusErr == nil && code != 0 {
					connectErr = unix.Errno(code)
				}
			}
		}
		r.ProviderConnectErrno = errno(connectErr)
		r.ProviderConnected = connectErr == nil
		var peerErr error
		if connectErr == nil {
			peer, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
			peerErr = err
			if peer != nil {
				r.ProviderPeerUID, r.ProviderPeerPID = int(peer.Uid), int(peer.Pid)
			}
		}
		closeErr := unix.Close(fd)
		r.ProviderConnectionClosed = closeErr == nil
		if peerErr != nil || closeErr != nil {
			return errors.New("provider peer observation or close failed")
		}
	}
	for _, name := range []string{"pid", "mnt", "user", "net"} {
		value, err := os.Readlink("/proc/self/ns/" + name)
		r.Namespaces[name] = value
		r.NamespaceErrnos[name] = errno(err)
	}
	for _, tc := range []struct {
		name   string
		family int
	}{{"inet4", unix.AF_INET}, {"inet6", unix.AF_INET6}, {"unix", unix.AF_UNIX}} {
		fd, err := unix.Socket(tc.family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		r.SocketErrnos[tc.name] = errno(err)
		if err == nil && unix.Close(fd) != nil {
			return errors.New("control socket close failed")
		}
	}
	owner := "/srv/hgw-v4-acceptance/composed/" + name + "/credentials/source/auth.json"
	f, err := os.OpenFile(owner, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	r.OwnerSourceErrno = errno(err)
	r.OwnerSourceReadable = err == nil
	if err == nil && f.Close() != nil {
		return errors.New("unexpected source descriptor close failed")
	}
	_, err = os.Lstat("/run/hsg-provider.sock")
	r.ProviderPathErrno = errno(err)
	r.Environment = os.Environ()
	r.Arguments = append([]string(nil), os.Args...)
	if len(strings.Join(r.Environment, "\x00")) > 65536 || len(strings.Join(r.Arguments, "\x00")) > 8192 {
		return errors.New("process projection exceeded bound")
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(entries) > 64 {
		return errors.New("descriptor inventory exceeded bound")
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			return errors.New("descriptor name differs")
		}
		value, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		} // ReadDir's own closed FD.
		if err != nil || len(value) > 4096 {
			return errors.New("descriptor observation unavailable")
		}
		r.FDLinks = append(r.FDLinks, entry.Name()+":"+value)
	}
	data, err := json.Marshal(r)
	if err != nil || len(data) > 32768 {
		return errors.New("probe report exceeded bound")
	}
	path := filepath.Join(root, "isolation-"+mode+"-report.json")
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("fresh probe report required")
	}
	if _, err = out.Write(data); err != nil {
		_ = out.Close()
		return errors.New("probe report write failed")
	}
	if out.Sync() != nil || out.Close() != nil {
		return errors.New("probe report close failed")
	}
	digest := sha256.Sum256(data)
	fmt.Printf("HSG_ISOLATION_PROBE_OK %s %s\n", nonce, hex.EncodeToString(digest[:]))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func fixedCase(name string) bool {
	switch name {
	case "fresh", "inference401", "catalog401", "cancel", "helperloss", "ownerrestart":
		return true
	default:
		return false
	}
}
