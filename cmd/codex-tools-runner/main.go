// codex-tools-runner is the blocked V3 candidate entrypoint. It is deliberately
// absent from the default build and has no shipped image or executable target.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shwdsun/harness-security-gateway/internal/codexadapter"
)

var codexModel string

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := codexadapter.Run(ctx, os.Stdin, os.Stdout, codexadapter.MessagingToolsConfig(codexModel), codexadapter.ExecLauncher{}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "codex-tools-runner: configuration or protocol run failed")
		os.Exit(1)
	}
}
