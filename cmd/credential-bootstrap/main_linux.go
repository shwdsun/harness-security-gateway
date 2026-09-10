//go:build linux

// credential-bootstrap is a blocked candidate entrypoint, omitted from the
// default build. An immutable image fixes its only successor; stdin supplies
// a one-use permit, never a command or runtime option.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shwdsun/harness-security-gateway/internal/bootstrapgate"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	if len(os.Args) != 1 || prepareHome() != nil || bootstrapgate.Await(ctx, os.Stdin, os.Stdout) != nil || ctx.Err() != nil {
		stop()
		_, _ = fmt.Fprintln(os.Stderr, "credential-bootstrap: launch denied")
		os.Exit(125)
	}
	stop()
	if err := syscall.Exec("/codex-tools-runner", []string{"/codex-tools-runner"}, []string{"HOME=/nonexistent", "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "credential-bootstrap: fixed runner unavailable")
		os.Exit(125)
	}
}

// The runtime creates this directory in disposable tmpfs when preparing the
// file bind. Before announcing readiness, make the private parent owner-only.
// This never reads or modifies auth.json, or treats its metadata as permission.
func prepareHome() error {
	const directory = "/tmp/hgw-codex-home"
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return bootstrapgate.ErrDenied
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return bootstrapgate.ErrDenied
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != "auth.json" {
		return bootstrapgate.ErrDenied
	}
	return os.Chmod(directory, 0o700)
}
