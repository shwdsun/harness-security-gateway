package localhttp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

func TestListenAndClientRoundTrip(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "service.sock")
	ln, err := Listen(socketPath, localidentity.UID(os.Geteuid()))
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	server := NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		_ = WriteJSON(w, http.StatusOK, struct {
			Status string `json:"status"`
		}{Status: "ok"})
	}))
	go func() {
		_ = server.Serve(ln)
	}()
	defer server.Close()

	client, err := NewClient(socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	req, err := NewRequest(context.Background(), http.MethodGet, "/health", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "{\"status\":\"ok\"}\n" {
		t.Fatalf("response = %d %q", resp.StatusCode, body)
	}
	second, err := client.Do(req.Clone(context.Background()))
	if err != nil {
		t.Fatalf("second Do() error = %v", err)
	}
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("second response status = %d", second.StatusCode)
	}
}

func TestListenRefusesExistingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(path, []byte("do not remove"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, localidentity.UID(os.Geteuid())); !errors.Is(err, ErrSocketExists) {
		t.Fatalf("Listen() error = %v, want ErrSocketExists", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "do not remove" {
		t.Fatalf("existing path changed: data=%q err=%v", data, err)
	}
}

func TestListenRejectsPeerBeforeHTTPAndWritesNoBytes(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "service.sock")
	ln, err := Listen(socketPath, otherPeerUID())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var handlerCalls atomic.Int64
	server := NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		handlerCalls.Add(1)
	}))
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ln) }()

	connection, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// The kernel may report a broken pipe if the authentication close wins the
	// race with this write. That is still a byte-silent rejection.
	_, _ = io.WriteString(connection,
		"POST /health HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
	)
	response, _ := io.ReadAll(connection)
	_ = connection.Close()
	if len(response) != 0 {
		t.Fatalf("rejected connection returned application bytes %q", response)
	}
	if handlerCalls.Load() != 0 {
		t.Fatalf("unauthorized peer reached HTTP handler %d times", handlerCalls.Load())
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveResult; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve() error = %v, want closed listener", err)
	}
}

func TestListenDerivesSocketModeFromPeerIdentity(t *testing.T) {
	tests := []struct {
		name string
		uid  localidentity.UID
		mode os.FileMode
	}{
		{name: "same uid", uid: localidentity.UID(os.Geteuid()), mode: 0o600},
		{name: "distinct uid", uid: otherPeerUID(), mode: 0o660},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mode.sock")
			listener, err := Listen(path, test.uid)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != test.mode {
				t.Fatalf("socket mode = %04o, want %04o", info.Mode().Perm(), test.mode)
			}
		})
	}
	if _, err := listenUnix(filepath.Join(t.TempDir(), "unsafe.sock"), 0o606); err == nil {
		t.Fatal("listenUnix accepted permissions for other users")
	}
}

func TestPeerUIDListenerClosesMismatchAndPropagatesCredentialFailure(t *testing.T) {
	acceptedMismatch, remoteMismatch := net.Pipe()
	acceptedMatch, remoteMatch := net.Pipe()
	defer remoteMismatch.Close()
	defer remoteMatch.Close()
	underlying := &scriptedListener{results: []acceptResult{
		{connection: acceptedMismatch},
		{connection: acceptedMatch},
	}}
	reads := 0
	wrapper, err := newPeerUIDListener(underlying, 1000, func(net.Conn) (localidentity.UID, error) {
		reads++
		if reads == 1 {
			return 1001, nil
		}
		return 1000, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := wrapper.Accept()
	if err != nil || got != acceptedMatch {
		t.Fatalf("Accept() = %v, %v, want matching second connection", got, err)
	}
	_ = got.Close()
	data, _ := io.ReadAll(remoteMismatch)
	if len(data) != 0 {
		t.Fatalf("mismatched connection returned bytes %q", data)
	}

	acceptedError, remoteError := net.Pipe()
	defer remoteError.Close()
	wrapper, err = newPeerUIDListener(&scriptedListener{results: []acceptResult{{connection: acceptedError}}}, 1000,
		func(net.Conn) (localidentity.UID, error) { return 0, errors.New("credential syscall failed") })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrapper.Accept(); !errors.Is(err, ErrPeerCredentials) {
		t.Fatalf("credential error = %v, want ErrPeerCredentials", err)
	}
	if data, _ := io.ReadAll(remoteError); len(data) != 0 {
		t.Fatalf("credential-error connection returned bytes %q", data)
	}

	acceptFailure := errors.New("underlying accept failure")
	wrapper, err = newPeerUIDListener(&scriptedListener{results: []acceptResult{{err: acceptFailure}}}, 1000,
		func(net.Conn) (localidentity.UID, error) { return 1000, nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrapper.Accept(); !errors.Is(err, acceptFailure) {
		t.Fatalf("underlying error = %v, want original Accept error", err)
	}
}

func otherPeerUID() localidentity.UID {
	uid := localidentity.UID(os.Geteuid()) + 1
	if err := uid.Validate(); err == nil {
		return uid
	}
	return 1
}

type acceptResult struct {
	connection net.Conn
	err        error
}

type scriptedListener struct {
	results []acceptResult
}

func (listener *scriptedListener) Accept() (net.Conn, error) {
	if len(listener.results) == 0 {
		return nil, net.ErrClosed
	}
	result := listener.results[0]
	listener.results = listener.results[1:]
	return result.connection, result.err
}

func (*scriptedListener) Close() error   { return nil }
func (*scriptedListener) Addr() net.Addr { return &net.UnixAddr{Name: "scripted", Net: "unix"} }

func TestRemoveStaleSocketRefusesUnsafeAndActivePaths(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if removed, err := RemoveStaleSocket(regular, time.Second); removed || !errors.Is(err, ErrUnsafeSocket) {
		t.Fatalf("regular removal = %v, %v", removed, err)
	}

	activePath := filepath.Join(t.TempDir(), "active.sock")
	active, err := net.ListenUnix("unix", &net.UnixAddr{Name: activePath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if removed, err := RemoveStaleSocket(activePath, time.Second); removed || !errors.Is(err, ErrSocketInUse) {
		t.Fatalf("active removal = %v, %v", removed, err)
	}
}

func TestRemoveStaleSocketChecksAndRemovesExactInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if removed, err := RemoveStaleSocket(path, time.Second); err != nil || !removed {
		t.Fatalf("stale removal = %v, %v", removed, err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale path still exists: %v", err)
	}
}

func TestReadJSONIsStrictAndBounded(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}
	request := func(body string) *http.Request {
		req, err := http.NewRequest(http.MethodPost, "http://local/v1", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		return req
	}

	var got payload
	if err := ReadJSON(request(`{"name":"ok"}`), 64, 4, &got); err != nil {
		t.Fatalf("ReadJSON() error = %v", err)
	}
	if got.Name != "ok" {
		t.Fatalf("ReadJSON() = %#v", got)
	}
	if err := ReadJSON(request(`{"name":"a","name":"b"}`), 64, 4, &got); !errors.Is(err, strictjson.ErrDuplicateKey) {
		t.Fatalf("duplicate key error = %v", err)
	}
	if err := ReadJSON(request(`{"name":"payload too long"}`), 8, 4, &got); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("body limit error = %v", err)
	}
}
