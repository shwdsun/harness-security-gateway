// Offline native-auth compatibility fixture. No threads, turns, tools, real
// credentials or upstream dialer. The owner process is the container's PID 1.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const authPath = "/tmp/native-auth-home/auth.json"
const account = "hsg-native-auth-synthetic"

type authFile struct {
	AuthMode string `json:"auth_mode"`
	Tokens   struct {
		Access   string `json:"access_token"`
		Refresh  string `json:"refresh_token"`
		Identity string `json:"id_token"`
		Account  string `json:"account_id"`
	} `json:"tokens"`
	LastRefresh string `json:"last_refresh"`
}

func jwt(generation int) string {
	b, _ := json.Marshal(map[string]any{"sub": "synthetic", "email": "probe@example.invalid", "exp": 4102444800, "generation": generation, "https://api.openai.com/auth": map[string]string{"chatgpt_account_id": account, "chatgpt_plan_type": "pro"}})
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(b) + ".synthetic"
}
func tokens(generation int) map[string]any {
	return map[string]any{"access_token": fmt.Sprintf("native-owner-access-%d", generation), "refresh_token": fmt.Sprintf("native-owner-refresh-%d", generation), "id_token": jwt(generation), "token_type": "Bearer", "expires_in": 3600}
}
func readAuth() (authFile, []byte, error) {
	var a authFile
	f, e := os.Open(authPath)
	if e != nil {
		return a, nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(b) > 65536 {
		return a, nil, errors.New("auth bound")
	}
	e = json.Unmarshal(b, &a)
	return a, b, e
}
func matches(a authFile, g int) bool {
	return a.AuthMode == "chatgpt" && a.Tokens.Account == account && a.Tokens.Access == tokens(g)["access_token"] && a.Tokens.Refresh == tokens(g)["refresh_token"] && a.Tokens.Identity == jwt(g)
}

type mockOwner struct {
	mu                          sync.Mutex
	mode                        string
	generation, attempts, valid int
	active                      int
	responses                   int
}

func (o *mockOwner) serve(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	o.attempts++
	o.active++
	n := o.attempts
	generation := o.generation
	o.mu.Unlock()
	defer func() { o.mu.Lock(); o.active--; o.mu.Unlock() }()
	if n > 4 || r.Method != "POST" || r.URL.Path != "/token" {
		http.Error(w, "closed fixture", 400)
		return
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 8193))
	if e != nil || len(b) > 8192 {
		http.Error(w, "request bound", 400)
		return
	}
	var fields map[string]string
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		v, e := url.ParseQuery(string(b))
		if e != nil {
			http.Error(w, "form", 400)
			return
		}
		fields = map[string]string{"grant_type": v.Get("grant_type"), "refresh_token": v.Get("refresh_token")}
	} else if json.Unmarshal(b, &fields) != nil {
		http.Error(w, "json", 400)
		return
	}
	if fields["grant_type"] != "refresh_token" || fields["refresh_token"] != tokens(generation)["refresh_token"] {
		http.Error(w, "generation mismatch", 400)
		return
	}
	o.mu.Lock()
	o.valid++
	o.mu.Unlock()
	if o.mode == "timeout" {
		<-r.Context().Done()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if o.mode == "rejected" {
		w.WriteHeader(400)
		if _, e := io.WriteString(w, `{"error":"invalid_grant","error_description":"synthetic refusal"}`); e == nil {
			o.mu.Lock()
			o.responses++
			o.mu.Unlock()
		}
		return
	}
	o.mu.Lock()
	o.generation++
	next := o.generation
	o.mu.Unlock()
	if e := json.NewEncoder(w).Encode(tokens(next)); e == nil {
		o.mu.Lock()
		o.responses++
		o.mu.Unlock()
	}
}
func (o *mockOwner) counts() (int, int, int, int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.generation, o.attempts, o.valid, o.responses
}
func (o *mockOwner) quiescent() bool {
	deadline := time.Now().Add(2 * time.Second)
	for {
		o.mu.Lock()
		active := o.active
		o.mu.Unlock()
		if active == 0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type bounded struct {
	mu       sync.Mutex
	b        []byte
	overflow bool
}

func (b *bounded) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	left := 65536 - len(b.b)
	if n > left {
		b.overflow = true
		p = p[:left]
	}
	b.b = append(b.b, p...)
	return n, nil
}
func (b *bounded) summary() (int, bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	h := sha256.Sum256(b.b)
	return len(b.b), b.overflow, hex.EncodeToString(h[:])
}

type envelope struct {
	ID     *int            `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}
type runResult struct {
	ExplicitRefresh       bool   `json:"explicit_refresh"`
	AttemptsAfterInit     int    `json:"attempts_after_initialize"`
	AttemptsBeforeRead    int    `json:"attempts_before_read"`
	AttemptsAfterRead     int    `json:"attempts_after_read"`
	ReadOnlyControl       bool   `json:"fresh_read_without_refresh"`
	SourceUnchanged       bool   `json:"source_unchanged"`
	Initialized           bool   `json:"initialized"`
	RPCReceived           bool   `json:"rpc_received"`
	RPCError              bool   `json:"rpc_error"`
	ManagedAccount        bool   `json:"managed_account"`
	TimedOut              bool   `json:"timed_out"`
	Stop                  string `json:"stop"`
	ExitCode              int    `json:"exit_code"`
	ExitSignal            int    `json:"exit_signal"`
	Joined                bool   `json:"joined"`
	StdoutJoined          bool   `json:"stdout_joined"`
	ProtocolValid         bool   `json:"protocol_valid"`
	DiagnosticsBytes      int    `json:"diagnostics_bytes"`
	DiagnosticsOverflow   bool   `json:"diagnostics_overflow"`
	DiagnosticsSHA        string `json:"diagnostics_sha256"`
	ProcessNamespaceEmpty bool   `json:"process_namespace_empty"`
	RequestsQuiescent     bool   `json:"requests_quiescent"`
	StorageMatches        bool   `json:"storage_matches"`
	RefreshTimestampValid bool   `json:"refresh_timestamp_valid"`
	SameObject            bool   `json:"same_object"`
	Synced                bool   `json:"supervisor_fsync"`
	Accepted              bool   `json:"accepted"`
}

func exchange(stdin io.Writer, ch <-chan envelope, id int, method string, params any, timeout time.Duration) (envelope, error) {
	if e := json.NewEncoder(stdin).Encode(map[string]any{"id": id, "method": method, "params": params}); e != nil {
		return envelope{}, e
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case m, ok := <-ch:
			if !ok {
				return envelope{}, io.EOF
			}
			if m.ID != nil && *m.ID == id {
				return m, nil
			}
		case <-timer.C:
			return envelope{}, context.DeadlineExceeded
		}
	}
}
func emptyNamespace() bool {
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return false
	}
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e == nil && pid != os.Getpid() {
			return false
		}
	}
	return true
}
func native(endpoint string, owner *mockOwner, control, force bool) (result runResult, err error) {
	result.ExplicitRefresh = force
	cmd := exec.Command("/codex", "--config", `cli_auth_credentials_store="file"`, "--config", `forced_login_method="chatgpt"`, "--config", `features.code_mode.enabled=false`, "--config", `features.code_mode_host=false`, "--config", `features.plugins=false`, "--config", `features.apps=false`, "--config", `check_for_update_on_startup=false`, "app-server", "--listen", "stdio://")
	cmd.Env = []string{"HOME=/tmp/native-auth-user", "CODEX_HOME=/tmp/native-auth-home", "CODEX_SQLITE_HOME=/tmp/native-auth-state", "TMPDIR=/tmp", "PATH=/nonexistent", "LANG=C.UTF-8", "CODEX_REFRESH_TOKEN_URL_OVERRIDE=" + endpoint}
	cmd.Dir = "/tmp/native-auth-user"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, e := cmd.StdinPipe()
	if e != nil {
		return result, e
	}
	stdout, output, e := os.Pipe()
	if e != nil {
		_ = stdin.Close()
		return result, e
	}
	defer stdout.Close()
	defer output.Close()
	cmd.Stdout = output
	diag := &bounded{}
	cmd.Stderr = diag
	if e = cmd.Start(); e != nil {
		_ = stdin.Close()
		return result, e
	}
	_ = output.Close()
	responses := make(chan envelope, 64)
	readDone := make(chan bool, 1)
	go func() {
		valid := false
		defer func() { readDone <- valid }()
		defer close(responses)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 4096), 65536)
		total := 0
		for scanner.Scan() {
			total += len(scanner.Bytes()) + 1
			var m envelope
			if total > 1<<20 || json.Unmarshal(scanner.Bytes(), &m) != nil {
				return
			}
			select {
			case responses <- m:
			default:
				return
			}
		}
		valid = scanner.Err() == nil
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		_ = stdin.Close()
		result.Stop = "eof"
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			result.Stop = "sigterm"
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				result.Stop = "sigkill"
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					return
				}
			}
		}
		result.Joined = true
		result.ExitCode = cmd.ProcessState.ExitCode()
		if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			result.ExitSignal = int(status.Signal())
		}
		select {
		case result.ProtocolValid = <-readDone:
			result.StdoutJoined = true
		case <-time.After(time.Second):
		}
		result.DiagnosticsBytes, result.DiagnosticsOverflow, result.DiagnosticsSHA = diag.summary()
		// PID 1 reaps any adopted descendants before checking the entire namespace.
		for {
			var status syscall.WaitStatus
			pid, e := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
			if pid <= 0 || e != nil {
				break
			}
		}
		result.ProcessNamespaceEmpty = emptyNamespace()
	}()
	msg, e := exchange(stdin, responses, 1, "initialize", map[string]any{"clientInfo": map[string]string{"name": "hsg_native_auth_probe", "version": "0.1.0"}}, 5*time.Second)
	if e != nil || (len(msg.Error) > 0 && !bytes.Equal(msg.Error, []byte("null"))) {
		return result, errors.New("initialize failed")
	}
	result.Initialized = true
	_, result.AttemptsAfterInit, _, _ = owner.counts()
	if e = json.NewEncoder(stdin).Encode(map[string]any{"method": "initialized", "params": map[string]any{}}); e != nil {
		return result, e
	}
	if control {
		_, attempts, _, _ := owner.counts()
		msg, e = exchange(stdin, responses, 2, "account/read", map[string]bool{"refreshToken": false}, 5*time.Second)
		_, after, _, _ := owner.counts()
		var a struct {
			Account *struct {
				Type string `json:"type"`
			} `json:"account"`
		}
		result.ReadOnlyControl = e == nil && (len(msg.Error) == 0 || bytes.Equal(msg.Error, []byte("null"))) && json.Unmarshal(msg.Result, &a) == nil && a.Account != nil && a.Account.Type == "chatgpt" && after == attempts
		if !result.ReadOnlyControl {
			return result, errors.New("fresh read control failed")
		}
	}
	_, result.AttemptsBeforeRead, _, _ = owner.counts()
	msg, e = exchange(stdin, responses, 3, "account/read", map[string]bool{"refreshToken": force}, 5*time.Second)
	_, result.AttemptsAfterRead, _, _ = owner.counts()
	if e != nil {
		result.TimedOut = errors.Is(e, context.DeadlineExceeded)
		if result.TimedOut {
			return result, nil
		}
		return result, errors.New("account/read transport failed")
	}
	result.RPCReceived = true
	result.RPCError = len(msg.Error) > 0 && !bytes.Equal(msg.Error, []byte("null"))
	var accountResult struct {
		Account *struct {
			Type string `json:"type"`
		} `json:"account"`
	}
	result.ManagedAccount = json.Unmarshal(msg.Result, &accountResult) == nil && accountResult.Account != nil && accountResult.Account.Type == "chatgpt"
	return result, nil
}
func experiment(mode string) (map[string]any, error) {
	report := map[string]any{"mode": mode, "synthetic_only": true, "model_turns": 0}
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		return report, errors.New("requires isolated rootless PID namespace owner")
	}
	if mode != "fresh" && mode != "stale" && mode != "readonly" && mode != "rejected" && mode != "timeout" {
		return report, errors.New("invalid closed case")
	}
	interfaces, e := net.Interfaces()
	if e != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		return report, errors.New("requires isolated loopback-only network")
	}
	initial, e := os.Stat(authPath)
	if e != nil {
		return report, e
	}
	if !initial.Mode().IsRegular() || initial.Mode().Perm() != 0600 || initial.Sys().(*syscall.Stat_t).Nlink != 1 {
		return report, errors.New("invalid synthetic source metadata")
	}
	a, before, e := readAuth()
	if e != nil || !matches(a, 0) {
		return report, errors.New("not exact synthetic auth")
	}
	for _, p := range []string{"/tmp/native-auth-user", "/tmp/native-auth-state"} {
		if e := os.MkdirAll(p, 0700); e != nil {
			return report, e
		}
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return report, e
	}
	owner := &mockOwner{mode: mode}
	server := &http.Server{Handler: http.HandlerFunc(owner.serve), ReadHeaderTimeout: time.Second}
	served := make(chan struct{})
	go func() { defer close(served); _ = server.Serve(listener) }()
	defer func() { _ = server.Close(); <-served }()
	rounds := 1
	if mode == "fresh" || mode == "stale" {
		rounds = 2
	}
	results := []runResult{}
	passed := true
	for i := 1; i <= rounds; i++ {
		started := time.Now()
		// A stale first read lets the native automatic refresh complete. Forcing
		// another refresh in that same call caused two observed rotations. The
		// next process verifies a forced refresh from the persisted fresh state.
		r, err := native("http://"+listener.Addr().String()+"/token", owner, mode == "fresh" || (mode == "stale" && i == 2), mode != "stale" || i != 1)
		// Only inspect storage after the client and its callbacks have stopped.
		r.RequestsQuiescent = r.Joined && r.ProcessNamespaceEmpty && owner.quiescent()
		generation, attempts, valid, responses := owner.counts()
		a, after, readErr := readAuth()
		current, statErr := os.Stat(authPath)
		r.SourceUnchanged = readErr == nil && bytes.Equal(before, after)
		r.StorageMatches = readErr == nil && generation > 0 && matches(a, generation)
		refreshed, parseErr := time.Parse(time.RFC3339Nano, a.LastRefresh)
		r.RefreshTimestampValid = parseErr == nil && !refreshed.Before(started.Add(-time.Second)) && !refreshed.After(time.Now())
		r.SameObject = statErr == nil && os.SameFile(initial, current) && current.Mode().Perm() == 0600 && current.Sys().(*syscall.Stat_t).Nlink == 1 && current.Sys().(*syscall.Stat_t).Uid == initial.Sys().(*syscall.Stat_t).Uid && current.Sys().(*syscall.Stat_t).Gid == initial.Sys().(*syscall.Stat_t).Gid
		if r.StorageMatches && r.SameObject && r.RequestsQuiescent {
			f, e := os.OpenFile(authPath, os.O_RDWR, 0)
			if e == nil {
				r.Synced = f.Sync() == nil
				_ = f.Close()
			}
		}
		stopped := r.ExitCode == 0 || (r.Stop == "sigterm" && r.ExitSignal == int(syscall.SIGTERM))
		r.Accepted = err == nil && r.Initialized && r.RPCReceived && !r.RPCError && r.ManagedAccount && r.StorageMatches && r.RefreshTimestampValid && r.SameObject && r.Synced && r.Joined && r.StdoutJoined && r.ProtocolValid && r.ProcessNamespaceEmpty && r.RequestsQuiescent && r.Stop != "sigkill" && stopped && !r.DiagnosticsOverflow
		resultOK := err == nil && r.Joined && r.StdoutJoined && r.ProtocolValid && r.ProcessNamespaceEmpty && r.RequestsQuiescent && r.SameObject && stopped && r.Stop != "sigkill" && !r.DiagnosticsOverflow && valid == attempts && attempts == i
		if rounds == 2 {
			resultOK = resultOK && r.Accepted && generation == i && responses == i
		} else {
			resultOK = resultOK && !r.Accepted
			if mode == "readonly" {
				resultOK = resultOK && r.SourceUnchanged && r.RPCReceived && !r.RPCError && r.ManagedAccount && generation == 1 && responses == 1
			}
			if mode == "rejected" {
				resultOK = resultOK && r.RPCReceived && generation == 0 && responses == 1
			}
			if mode == "timeout" {
				resultOK = resultOK && r.TimedOut && generation == 0 && responses == 0
			}
		}
		results = append(results, r)
		passed = passed && resultOK
		if !resultOK {
			break
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	shutdownErr := server.Shutdown(shutdown)
	cancel()
	_ = server.Close()
	<-served
	joined := shutdownErr == nil && owner.quiescent()
	report["server_joined"] = joined
	passed = passed && joined
	generation, attempts, valid, responses := owner.counts()
	report["generation"] = generation
	report["attempts"] = attempts
	report["valid_requests"] = valid
	report["responses_written"] = responses
	report["rounds"] = results
	report["passed"] = passed && len(results) == rounds
	if report["passed"] != true {
		return report, errors.New("native refresh contract not satisfied")
	}
	return report, nil
}
func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	report, err := experiment(os.Args[1])
	if err != nil {
		report["error"] = err.Error()
	}
	// Inventory names only; no synthetic auth contents or raw native diagnostics.
	var names []string
	_ = filepath.WalkDir("/tmp/native-auth-home", func(p string, d os.DirEntry, e error) error {
		if e == nil {
			rel, _ := filepath.Rel("/tmp/native-auth-home", p)
			names = append(names, rel)
		}
		return nil
	})
	report["home_entries"] = names
	_ = json.NewEncoder(os.Stdout).Encode(report)
	if err != nil {
		os.Exit(1)
	}
}
