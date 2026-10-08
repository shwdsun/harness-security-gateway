// identity-witness is an opt-in, synthetic deployment-boundary check. It is
// deliberately outside the ordinary test suite and ships in no service binary.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/privatefs"
	"golang.org/x/sys/unix"
)

type identity struct {
	uid    uint32
	groups []uint32
}

var identities = map[string]identity{
	"core":      {21001, []uint32{21101, 21102}},
	"sandbox":   {21002, []uint32{21102}},
	"connector": {21003, []uint32{21101}},
	"outsider":  {21004, []uint32{21101, 21102}},
}

var services = []string{"core", "sandbox", "connector"}

type edge struct {
	server, client, path string
	group                uint32
}

var edges = []edge{
	{"core", "connector", "/fixture/run/hgw/local/agentd.sock", 21101},
	{"sandbox", "core", "/fixture/run/hgw/sandbox/sandboxd.sock", 21102},
}

type report struct {
	Role   string   `json:"role"`
	Phase  string   `json:"phase"`
	UID    uint32   `json:"uid"`
	Groups []uint32 `json:"groups"`
	Checks []string `json:"checks"`
}

func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func status() map[string]string {
	data, err := os.ReadFile("/proc/self/status")
	must(err)
	result := make(map[string]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			result[key] = strings.TrimSpace(value)
		}
	}
	return result
}

func checkIdentity(role string) report {
	id := identities[strings.TrimSuffix(role, "-server")]
	require(id.uid != 0 && os.Geteuid() == int(id.uid) && os.Getegid() == int(id.uid), "unexpected identity")
	s := status()
	for _, key := range []string{"Uid", "Gid"} {
		fields := strings.Fields(s[key])
		require(len(fields) == 4, "missing kernel identity fields")
		for _, field := range fields {
			require(field == strconv.Itoa(int(id.uid)), "real/effective/saved/fs identity mismatch")
		}
	}
	groups, err := os.Getgroups()
	must(err)
	actual := make([]uint32, 0, len(groups))
	for _, group := range groups {
		actual = append(actual, uint32(group))
	}
	slices.Sort(actual)
	require(slices.Equal(actual, id.groups), "unexpected supplementary groups")
	for _, key := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb"} {
		require(s[key] == "0000000000000000", "child retains capabilities: "+key)
	}
	require(s["NoNewPrivs"] == "1", "child missing no-new-privileges")
	return report{Role: role, Phase: "done", UID: id.uid, Groups: actual,
		Checks: []string{"kernel-identities", "zero-process-capabilities", "no-new-privileges"}}
}

func checkContainer() {
	require(os.Geteuid() == 0 && os.Getpid() == 1, "controller requires container PID 1 and UID 0")
	s := status()
	// CHOWN, FOWNER, KILL, SETGID, SETUID: fixture provisioning and child cleanup.
	for _, key := range []string{"CapEff", "CapPrm", "CapBnd"} {
		require(s[key] == "00000000000000e9", "unexpected controller capabilities: "+key)
	}
	require(s["CapInh"] == "0000000000000000" && s["CapAmb"] == "0000000000000000" && s["NoNewPrivs"] == "1", "unsafe controller privilege state")
	for _, path := range []string{"/", "/identity-witness"} {
		var fs unix.Statfs_t
		must(unix.Statfs(path, &fs))
		require(fs.Flags&unix.ST_RDONLY != 0, "expected read-only mount: "+path)
	}
	var fs unix.Statfs_t
	must(unix.Statfs("/fixture", &fs))
	flags := int64(unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC)
	require(fs.Type == unix.TMPFS_MAGIC && fs.Flags&flags == flags && fs.Flags&unix.ST_RDONLY == 0, "unsafe fixture mount")
	checkFile("/fixture", os.ModeDir|0o755, 0, 0)
	entries, err := os.ReadDir("/fixture")
	must(err)
	require(len(entries) == 0, "fixture must start empty")
	interfaces, err := net.Interfaces()
	must(err)
	require(len(interfaces) == 1 && interfaces[0].Name == "lo", "fixture must have only loopback")
}

func checkFile(path string, mode os.FileMode, uid, gid uint32) os.FileInfo {
	info, err := os.Lstat(path)
	must(err)
	st, ok := info.Sys().(*syscall.Stat_t)
	require(ok && info.Mode() == mode && st.Uid == uid && st.Gid == gid, "unexpected file ownership/mode: "+path)
	return info
}

func privateDir(role string) string { return "/fixture/var/lib/hgw-" + role }
func configFile(role string) string { return "/fixture/etc/hgw/" + role + ".json" }

func provision() {
	// The controller never uses DAC_OVERRIDE. Populate each private directory
	// before handing it to its final owner; descendants then become inaccessible.
	for _, path := range []string{"/fixture/run/hgw", "/fixture/var/lib", "/fixture/etc/hgw"} {
		must(os.MkdirAll(path, 0o755))
	}
	for _, role := range services {
		id := identities[role]
		dir := privateDir(role)
		must(os.Mkdir(dir, 0o700))
		must(os.WriteFile(dir+"/marker", []byte("synthetic:"+role), 0o600))
		must(os.Chown(dir+"/marker", int(id.uid), int(id.uid)))
		must(os.Chown(dir, int(id.uid), int(id.uid)))
		must(os.WriteFile(configFile(role), []byte("{}\n"), 0o640))
		must(os.Chown(configFile(role), 0, int(id.uid)))
		checkFile(dir, os.ModeDir|0o700, id.uid, id.uid)
		checkFile(configFile(role), 0o640, 0, id.uid)
	}
	for _, e := range edges {
		dir := filepath.Dir(e.path)
		must(os.Mkdir(dir, 0o700))
		must(os.Chown(dir, int(identities[e.server].uid), int(e.group)))
		must(os.Chmod(dir, os.ModeSetgid|0o710))
		checkFile(dir, os.ModeDir|os.ModeSetgid|0o710, identities[e.server].uid, e.group)
	}
}

type child struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *os.File
	decode *json.Decoder
	stderr bytes.Buffer
	waited bool
}

func start(ctx context.Context, role string) *child {
	id, ok := identities[strings.TrimSuffix(role, "-server")]
	require(ok, "unknown child identity")
	r, w, err := os.Pipe()
	must(err)
	c := &child{cmd: exec.CommandContext(ctx, "/identity-witness", role), output: r}
	c.decode = json.NewDecoder(io.LimitReader(r, 8192))
	c.cmd.Env = []string{"HSG_IDENTITY_WITNESS=1", "PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C.UTF-8", "GOMAXPROCS=2"}
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: id.uid, Gid: id.uid, Groups: id.groups}}
	c.cmd.ExtraFiles = []*os.File{w}
	c.cmd.Stderr = &c.stderr
	c.cmd.WaitDelay = time.Second
	c.input, err = c.cmd.StdinPipe()
	must(err)
	err = c.cmd.Start()
	_ = w.Close()
	if err != nil {
		_ = r.Close()
		_ = c.input.Close()
		must(err)
	}
	return c
}

func (c *child) receive(role, phase string) report {
	var r report
	if err := c.decode.Decode(&r); err != nil {
		panic(fmt.Errorf("%s %s report: %w", role, phase, err))
	}
	id := identities[strings.TrimSuffix(role, "-server")]
	require(r.Role == role && r.Phase == phase && r.UID == id.uid && slices.Equal(r.Groups, id.groups), "unexpected child report")
	return r
}

func (c *child) finish() {
	err := c.cmd.Wait()
	c.waited = true
	if err != nil {
		panic(fmt.Errorf("child exit: %w: %.4096s", err, c.stderr.String()))
	}
	var extra any
	require(c.decode.Decode(&extra) == io.EOF, "unexpected trailing child report")
}

func controller() {
	checkContainer()
	syscall.Umask(0o022)
	provision()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	var children []*child
	defer func() {
		cancel()
		for _, c := range children {
			_ = c.input.Close()
			if !c.waited {
				if err := c.cmd.Wait(); err != nil {
					fmt.Fprintf(os.Stderr, "%s: %v: %.4096s\n", c.cmd.Args[1], err, c.stderr.String())
				}
			}
			_ = c.output.Close()
		}
	}()
	var receipts []report
	var sockets []os.FileInfo
	for _, e := range edges {
		c := start(ctx, e.server+"-server")
		children = append(children, c)
		receipts = append(receipts, c.receive(e.server+"-server", "ready"))
		sockets = append(sockets, checkFile(e.path, os.ModeSocket|0o660, identities[e.server].uid, e.group))
	}
	for _, role := range []string{"connector", "core", "sandbox", "outsider"} {
		c := start(ctx, role)
		children = append(children, c)
		receipts = append(receipts, c.receive(role, "done"))
		c.finish()
	}
	for i, e := range edges {
		after := checkFile(e.path, os.ModeSocket|0o660, identities[e.server].uid, e.group)
		require(os.SameFile(sockets[i], after), "socket replaced during probes")
		c := children[i]
		must(c.input.Close())
		receipts = append(receipts, c.receive(e.server+"-server", "done"))
		c.finish()
		_, err := os.Lstat(e.path)
		require(errors.Is(err, os.ErrNotExist), "socket remains after listener shutdown")
	}
	must(json.NewEncoder(os.Stdout).Encode(struct {
		Schema   string   `json:"schema"`
		Passed   bool     `json:"passed"`
		Checks   []string `json:"checks"`
		Receipts []report `json:"receipts"`
	}{"hsg-identity-witness/v1", true,
		[]string{"container-guards", "provisioned-ownership-modes", "socket-inodes-unchanged", "all-children-joined", "sockets-removed"}, receipts}))
}

func server(role string, r report, out *json.Encoder) {
	var e edge
	for _, candidate := range edges {
		if candidate.server+"-server" == role {
			e = candidate
		}
	}
	require(e.path != "", "unknown listener")
	peer := localidentity.UID(identities[e.client].uid)
	must(localhttp.PrepareSocketParent(e.path, peer))
	listener, err := localhttp.Listen(e.path, peer)
	must(err)
	defer listener.Close()
	checkFile(e.path, os.ModeSocket|0o660, r.UID, e.group)
	var calls atomic.Int32
	srv := localhttp.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		var body struct {
			Marker string `json:"marker"`
		}
		if req.Method != http.MethodPost || req.URL.Path != "/probe" ||
			localhttp.ReadJSON(req, 128, 4, &body) != nil || body.Marker != "synthetic" {
			localhttp.WriteProblem(w, http.StatusBadRequest, "unexpected_probe")
			return
		}
		_ = localhttp.WriteJSON(w, http.StatusOK, body)
	}))
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	r.Phase = "ready"
	r.Checks = append(r.Checks, "production-listener", "socket-mode-owner-group")
	must(out.Encode(r))
	var input [1]byte
	n, err := os.Stdin.Read(input[:])
	require(n == 0 && err == io.EOF, "unexpected server control input")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	must(srv.Shutdown(ctx))
	require(errors.Is(<-done, http.ErrServerClosed), "unexpected server exit")
	require(calls.Load() == 1, "handler must see exactly the intended peer's single request")
	r.Phase = "done"
	r.Checks = append(r.Checks, "exactly-one-handler-call")
	must(out.Encode(r))
}

func allowed(path string) {
	client, err := localhttp.NewClient(path, 3*time.Second)
	must(err)
	defer client.CloseIdleConnections()
	req, err := localhttp.NewRequest(context.Background(), http.MethodPost, "/probe", []byte(`{"marker":"synthetic"}`))
	must(err)
	resp, err := client.Do(req)
	must(err)
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 129))
	must(err)
	require(resp.StatusCode == http.StatusOK && string(body) == "{\"marker\":\"synthetic\"}\n", "intended peer request failed")
}

func wrongUID(path string) {
	// A successful raw dial proves that the shared group can reach the listener.
	// Rejection must then be byte-silent, without entering the HTTP handler.
	c, err := net.DialTimeout("unix", path, 3*time.Second)
	must(err)
	defer c.Close()
	must(c.SetDeadline(time.Now().Add(3 * time.Second)))
	_, err = io.WriteString(c, "POST /probe HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n{\"marker\":\"synthetic\"}")
	require(err == nil || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET), "unexpected rejected-peer write result")
	var b [1]byte
	n, err := c.Read(b[:])
	require(n == 0 && (errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)), "wrong UID was not rejected byte-silently")
}

func denied(err error, code syscall.Errno, operation string) {
	require(errors.Is(err, code), fmt.Sprintf("%s: expected %s, got %v", operation, code, err))
}

func deniedOpen(path string, flags int) {
	f, err := os.OpenFile(path, flags, 0o600)
	if f != nil {
		_ = f.Close()
	}
	denied(err, syscall.EACCES, "open "+path)
}

func peerCannotReplace(path string) {
	dir := filepath.Dir(path)
	_, err := os.ReadDir(dir)
	denied(err, syscall.EACCES, "list shared socket parent")
	deniedOpen(dir+"/unexpected", os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	denied(os.Remove(path), syscall.EACCES, "unlink socket")
	denied(os.Rename(path, path+".moved"), syscall.EACCES, "rename socket")
}

func probe(role string, r report) report {
	for _, e := range edges {
		switch {
		case role == e.client:
			allowed(e.path)
			peerCannotReplace(e.path)
			r.Checks = append(r.Checks, "allowed:"+e.server, "socket-parent-immutable:"+e.server)
		case role == "outsider":
			wrongUID(e.path)
			peerCannotReplace(e.path)
			r.Checks = append(r.Checks, "reachable-but-byte-silent:"+e.server, "socket-parent-immutable:"+e.server)
		case role != e.server:
			c, err := net.DialTimeout("unix", e.path, 3*time.Second)
			if c != nil {
				_ = c.Close()
			}
			denied(err, syscall.EACCES, "wrong IPC group")
			r.Checks = append(r.Checks, "wrong-edge-denied:"+e.server)
		}
	}
	for _, owner := range services {
		dir := privateDir(owner)
		if role == owner {
			must(privatefs.EnsureDir(dir, 0o700))
			checkFile(dir+"/marker", 0o600, r.UID, r.UID)
			data, err := os.ReadFile(dir + "/marker")
			must(err)
			require(string(data) == "synthetic:"+role, "private marker changed")
			config := configFile(role)
			data, err = os.ReadFile(config)
			must(err)
			require(string(data) == "{}\n", "synthetic operator config changed")
			deniedOpen(config, os.O_WRONLY)
			denied(os.Chmod(config, 0o600), syscall.EPERM, "chmod operator config")
			denied(os.Remove(config), syscall.EACCES, "unlink operator config")
			denied(os.Rename(config, config+".moved"), syscall.EACCES, "rename operator config")
			r.Checks = append(r.Checks, "own-private-data-readable", "own-operator-config-read-only")
		} else {
			deniedOpen(dir+"/marker", os.O_RDONLY)
			deniedOpen(dir+"/marker", os.O_WRONLY)
			deniedOpen(dir+"/unexpected", os.O_WRONLY|os.O_CREATE|os.O_EXCL)
			deniedOpen(configFile(owner), os.O_RDONLY)
			r.Checks = append(r.Checks, "foreign-private-data-denied:"+owner, "foreign-config-denied:"+owner)
		}
	}
	return r
}

func main() {
	defer func() {
		if failure := recover(); failure != nil {
			fmt.Fprintf(os.Stderr, "identity witness failed: %v\n", failure)
			os.Exit(1)
		}
	}()
	require(os.Getenv("HSG_IDENTITY_WITNESS") == "1" && len(os.Args) == 2, "explicit container-only opt-in and fixed role required")
	role := os.Args[1]
	if role == "controller" {
		controller()
		return
	}
	require(os.Getppid() == 1, "child requires fixture controller parent")
	r := checkIdentity(role)
	fd := os.NewFile(3, "fixture-report")
	require(fd != nil, "missing controller report pipe")
	defer fd.Close()
	out := json.NewEncoder(fd)
	if strings.HasSuffix(role, "-server") {
		server(role, r, out)
	} else {
		must(out.Encode(probe(role, r)))
	}
}
