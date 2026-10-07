//go:build linux && amd64 && codexintegration

// Fixed V4 successor. Selection is an immutable local artifact, never HRP input.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shwdsun/harness-security-gateway/internal/codexadapter"
	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
)

func main() {
	if len(os.Args) != 1 || os.Getpid() != 1 || os.Geteuid() != 1000 {
		os.Exit(125)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := codexadapter.Run(ctx, os.Stdin, os.Stdout, codexadapter.IsolatedToolsConfig(codexprofile.ModelNameV1), codexadapter.ProviderCanaryLauncher{}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "isolated runner: configuration or protocol failure")
		os.Exit(1)
	}
}
