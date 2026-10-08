package providerrelay

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
)

func endpoint(t *testing.T) (string, *net.UnixListener) {
	t.Helper()
	if localidentity.UID(os.Geteuid()).Validate() != nil {
		t.Skip("requires a concrete non-root Unix peer UID")
	}
	path := filepath.Join(t.TempDir(), "owner.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return path, listener
}

func startRelay(t *testing.T, path string) *Relay {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	relay, err := Start(ctx, path, localidentity.UID(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relay.Close() })
	return relay
}

func TestPinnedEndpointDoesNotFollowReplacement(t *testing.T) {
	path, original := endpoint(t)
	// Keep the original listener/inode alive while replacing only its name.
	original.SetUnlinkOnClose(false)
	relay := startRelay(t, path)
	if err := os.Rename(path, path+".retained"); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := original.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var request [4]byte
		_, err = io.ReadFull(conn, request[:])
		if err == nil && string(request[:]) != "ping" {
			err = errors.New("wrong payload")
		}
		if err == nil {
			_, err = io.WriteString(conn, "original")
		}
		done <- err
	}()
	client, err := net.DialTimeout("tcp", relay.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(client, "ping")
	got, err := io.ReadAll(client)
	if err != nil || string(got) != "original" {
		t.Fatalf("held socket was not the dial target: response=%q error=%v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = replacement.SetDeadline(time.Now().Add(20 * time.Millisecond))
	if conn, err := replacement.Accept(); err == nil {
		conn.Close()
		t.Fatal("replacement received authority")
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	// An original owner gone does not authorize the replacement at its path.
	client2, err := net.DialTimeout("tcp", relay.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = client2.SetDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(client2, "must not switch")
	data, _ := io.ReadAll(client2)
	_ = client2.Close()
	if len(data) != 0 || !errors.Is(relay.Wait(), ErrEndpoint) {
		t.Fatal("endpoint loss did not close the fixed relay")
	}
	_ = replacement.SetDeadline(time.Now().Add(20 * time.Millisecond))
	if conn, err := replacement.Accept(); err == nil {
		conn.Close()
		t.Fatal("owner loss dialed the replacement")
	}
}

func TestCloseJoinsActiveCopies(t *testing.T) {
	path, listener := endpoint(t)
	relay := startRelay(t, path)
	client, err := net.DialTimeout("tcp", relay.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = listener.SetDeadline(time.Now().Add(time.Second))
	owner, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	var closers sync.WaitGroup
	for range 4 {
		closers.Go(func() {
			if err := relay.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	closers.Wait()
	for _, conn := range []net.Conn{owner, client} {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Fatal("connection survived joined close")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("cleanup was only a timeout")
		}
	}
	if conn, err := net.DialTimeout("tcp", relay.Address(), time.Second); err == nil {
		conn.Close()
		t.Fatal("closed listener accepted new work")
	}
}

func TestByteBudget(t *testing.T) {
	path, listener := endpoint(t)
	relay := startRelay(t, path)
	count := make(chan int64, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			count <- -1
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		n, _ := io.Copy(io.Discard, conn)
		count <- n
	}()
	client, err := net.DialTimeout("tcp", relay.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.Copy(client, strings.NewReader(strings.Repeat("x", MaxBytes+1)))
	if err := relay.Wait(); !errors.Is(err, ErrBudget) {
		t.Fatal("byte budget did not close the relay:", err)
	}
	_ = client.Close()
	if n := <-count; n != MaxBytes {
		t.Fatal("forwarded beyond or failed before exact byte ceiling:", n)
	}
}

func TestConstructionFailsClosed(t *testing.T) {
	path, _ := endpoint(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	symlink := path + ".link"
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []struct {
		ctx  context.Context
		path string
		uid  localidentity.UID
	}{
		{context.Background(), path, localidentity.UID(os.Geteuid())},
		{ctx, symlink, localidentity.UID(os.Geteuid())},
		{ctx, path, 0},
		{ctx, path, localidentity.NobodyUID},
		{ctx, path, localidentity.UID(os.Geteuid() + 1)},
		{ctx, filepath.Dir(path), localidentity.UID(os.Geteuid())},
	} {
		if relay, err := Start(candidate.ctx, candidate.path, candidate.uid); err == nil {
			relay.Close()
			t.Fatal("invalid fixed endpoint accepted")
		}
	}
}

func TestConnectionBudgets(t *testing.T) {
	t.Run("concurrent", func(t *testing.T) {
		path, listener := endpoint(t)
		relay := startRelay(t, path)
		for range MaxConcurrent {
			client, err := net.DialTimeout("tcp", relay.Address(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = listener.SetDeadline(time.Now().Add(time.Second))
			owner, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
		}
		client, err := net.DialTimeout("tcp", relay.Address(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		_ = client.SetDeadline(time.Now().Add(time.Second))
		if _, err := client.Read(make([]byte, 1)); err == nil {
			t.Fatal("excess concurrent connection survived")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("excess connection was only timed out")
		}
		_ = listener.SetDeadline(time.Now().Add(20 * time.Millisecond))
		if owner, err := listener.Accept(); err == nil {
			owner.Close()
			t.Fatal("excess connection reached the owner")
		}
		if err := relay.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("total", func(t *testing.T) {
		path, listener := endpoint(t)
		relay := startRelay(t, path)
		done := make(chan error, 1)
		go func() {
			for range MaxConnections {
				_ = listener.SetDeadline(time.Now().Add(time.Second))
				owner, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				_, _ = io.WriteString(owner, "x")
				_ = owner.Close()
			}
			done <- nil
		}()
		for range MaxConnections {
			client, err := net.DialTimeout("tcp", relay.Address(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_ = client.SetDeadline(time.Now().Add(time.Second))
			data, err := io.ReadAll(client)
			_ = client.Close()
			if err != nil || string(data) != "x" {
				t.Fatal("admitted connection lost progress")
			}
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := relay.Wait(); err != nil {
			t.Fatal(err)
		}
		if client, err := net.DialTimeout("tcp", relay.Address(), time.Second); err == nil {
			client.Close()
			t.Fatal("total admission budget did not close listener")
		}
	})
}

func TestRunContextEndsIdleChannel(t *testing.T) {
	path, listener := endpoint(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	relay, err := Start(ctx, path, localidentity.UID(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	client, err := net.DialTimeout("tcp", relay.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = listener.SetDeadline(time.Now().Add(time.Second))
	owner, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if !matchesPeer(owner, localidentity.UID(os.Geteuid())) || matchesPeer(owner, localidentity.UID(os.Geteuid()+1)) {
		t.Fatal("connect-time peer identity was not checked")
	}
	if err := relay.Wait(); err != nil || ctx.Err() != context.DeadlineExceeded {
		t.Fatal("admitted context did not join idle transport:", err)
	}
	_ = owner.SetDeadline(time.Now().Add(time.Second))
	if n, err := owner.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatal("idle upstream survived Run deadline")
	}
}
