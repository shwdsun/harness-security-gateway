//go:build linux

// A fixed adversarial HRP fixture, never a Codex implementation or daemon.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
	"golang.org/x/sys/unix"
)

const workspace = "/workspace"

type proof struct {
	Nonce                           string
	PID, PPID, PGID, SID, LeaderPID int
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fixed resistant fixture failed")
		os.Exit(125)
	}
}

func run() error {
	if os.Geteuid() != 1000 {
		return errors.New("wrong fixture UID")
	}
	if len(os.Args) == 2 && os.Args[1] == "descendant" {
		return descendant()
	}
	if len(os.Args) == 2 && os.Args[1] == "leader" {
		return leader()
	}
	if len(os.Args) != 1 || os.Getpid() != 1 {
		return errors.New("not fixed PID 1")
	}
	signal.Ignore(syscall.SIGHUP)
	terms := make(chan os.Signal, 1)
	signal.Notify(terms, syscall.SIGTERM)
	defer signal.Stop(terms)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	if err := write("nonce.json", hex.EncodeToString(nonce[:])); err != nil {
		return err
	}
	encoder := runnerwire.NewEncoder(os.Stdout)
	if err := encoder.Encode(&runnerwire.RunnerReady{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunnerReady,
		Adapter: runnerwire.Adapter{Family: codexprofile.RunnerFamilyV1, Version: codexprofile.AdapterVersionV3}, Features: []runnerwire.Feature{}}); err != nil {
		return err
	}
	frame, err := runnerwire.NewDecoder(os.Stdin).DecodeControllerFrame()
	start, ok := frame.(*runnerwire.RunStart)
	if err != nil || !ok || start.Session.Mode != runnerwire.SessionModeNew {
		return errors.New("fixed new-only start required")
	}
	if err := encoder.Encode(&runnerwire.RunStarted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunStarted, RunID: start.RunID, Seq: 1}); err != nil {
		return err
	}
	command := fixedChild("leader")
	if err := command.Start(); err != nil {
		return err
	}
	leaderPID := command.Process.Pid
	if err := command.Wait(); err != nil {
		return err
	}
	var p proof
	if err := read("descendant.json", &p); err != nil {
		return err
	}
	p.LeaderPID = leaderPID
	if p.PID == leaderPID || p.PGID != p.PID || p.SID != p.PID || p.Nonce != hex.EncodeToString(nonce[:]) {
		return errors.New("missing detached descendant")
	}
	if err := write("resistant-ready.json", p); err != nil {
		return err
	}
	if err := await("release-terminal"); err != nil {
		return err
	}
	if err := encoder.Encode(&runnerwire.RunCompleted{Protocol: runnerwire.ProtocolV1, Type: runnerwire.TypeRunCompleted, RunID: start.RunID, Seq: 2,
		Output: runnerwire.TextContent{MediaType: runnerwire.MediaTypeTextPlain, Text: "fixed resistant-runner result"}}); err != nil {
		return err
	}
	// Keep PID 1 alive after its terminal frame and across the actual TERM.
	// No exit on stdin EOF or attach-client death; outer teardown must finish.
	select {
	case <-terms:
		if err := write("term-observed.json", map[string]any{"Nonce": p.Nonce, "PID": os.Getpid(), "UTC": time.Now().UTC().Format(time.RFC3339Nano)}); err != nil {
			return err
		}
	case <-time.After(180 * time.Second):
		return errors.New("TERM not delivered")
	}
	time.Sleep(180 * time.Second)
	return errors.New("outer forced teardown did not happen")
}

func fixedChild(role string) *exec.Cmd {
	command := exec.Command("/codex-tools-runner", role)
	command.Env = []string{"HOME=/nonexistent", "PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	command.Dir = workspace
	// Nil stdio becomes /dev/null, so the departed leader leaves no pipe held.
	return command
}

func leader() error {
	command := fixedChild("descendant")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		return err
	}
	if err := await("descendant.json"); err != nil {
		return err
	}
	var p proof
	if err := read("descendant.json", &p); err != nil {
		return err
	}
	if p.PID != command.Process.Pid || p.PPID != os.Getpid() {
		return errors.New("wrong descendant")
	}
	return nil // PID 1 reaps this leader; the separate-session child remains.
}

func descendant() error {
	signal.Ignore(syscall.SIGTERM, syscall.SIGHUP)
	lock, err := os.OpenFile(filepath.Join(workspace, "descendant.lock"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	var nonce string
	if err := read("nonce.json", &nonce); err != nil {
		return err
	}
	pgid, err := unix.Getpgid(0)
	if err != nil {
		return err
	}
	sid, err := unix.Getsid(0)
	if err != nil {
		return err
	}
	if err := write("descendant.json", proof{Nonce: nonce, PID: os.Getpid(), PPID: os.Getppid(), PGID: pgid, SID: sid}); err != nil {
		return err
	}
	time.Sleep(180 * time.Second)
	return errors.New("descendant escaped outer termination budget")
}

func write(name string, value any) error {
	path := filepath.Join(workspace, name)
	file, err := os.OpenFile(path+".writing", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	err = json.NewEncoder(file).Encode(value)
	err = errors.Join(err, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	return os.Rename(path+".writing", path)
}

func read(name string, value any) error {
	data, err := os.ReadFile(filepath.Join(workspace, name))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func await(name string) error {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(workspace, name)); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("missing fixed fixture observation")
}
